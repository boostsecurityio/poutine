// Package analyze can analyze things.
package analyze

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/boostsecurityio/poutine/models"
	"golang.org/x/sync/semaphore"

	"github.com/boostsecurityio/poutine/opa"
	"github.com/boostsecurityio/poutine/providers/pkgsupply"
	"github.com/boostsecurityio/poutine/scanner"
	"github.com/rs/zerolog/log"
	"github.com/schollz/progressbar/v3"
)

const TEMP_DIR_PREFIX = "poutine-*"

type Repository interface {
	GetProviderName() string
	GetRepoIdentifier() string
	GetIsFork() bool
	BuildGitURL(baseURL string) string
}

type RepoBatch struct {
	TotalCount   int
	Repositories []Repository
	Err          error
}

type ScmClient interface {
	GetOrgRepos(ctx context.Context, org string) <-chan RepoBatch
	GetRepo(ctx context.Context, org string, name string) (Repository, error)
	GetToken() string
	GetProviderName() string
	GetProviderVersion(ctx context.Context) (string, error)
	GetProviderBaseURL() string
	ParseRepoAndOrg(string) (string, string, error)
}

type GitClient interface {
	Clone(ctx context.Context, clonePath string, url string, token string, ref string) error
	CommitSHA(clonePath string) (string, error)
	LastCommitDate(ctx context.Context, clonePath string) (time.Time, error)
	GetRemoteOriginURL(ctx context.Context, repoPath string) (string, error)
	GetRepoHeadBranchName(ctx context.Context, repoPath string) (string, error)
}

func NewAnalyzer(scmClient ScmClient, gitClient GitClient, formatter Formatter, config *models.Config, opaClient *opa.Opa) *Analyzer {
	if config == nil {
		config = &models.Config{}
	}
	return &Analyzer{
		ScmClient: scmClient,
		GitClient: gitClient,
		Formatter: formatter,
		Config:    config,
		Opa:       opaClient,
	}
}

type Analyzer struct {
	ScmClient ScmClient
	GitClient GitClient
	Formatter Formatter
	Config    *models.Config
	Opa       *opa.Opa
}

func (a *Analyzer) AnalyzeOrg(ctx context.Context, org string, numberOfGoroutines *int) error {
	provider := a.ScmClient.GetProviderName()

	providerVersion, err := a.ScmClient.GetProviderVersion(ctx)
	if err != nil {
		log.Debug().Err(err).Msgf("Failed to get provider version for %s", provider)
	}

	log.Debug().Msgf("Provider: %s, Version: %s, BaseURL: %s", provider, providerVersion, a.ScmClient.GetProviderBaseURL())

	log.Debug().Msgf("Fetching list of repositories for organization: %s on %s", org, provider)
	orgReposBatches := a.ScmClient.GetOrgRepos(ctx, org)

	pkgsupplyClient := pkgsupply.NewStaticClient()
	inventory := scanner.NewInventory(a.Opa, pkgsupplyClient, provider, providerVersion)

	log.Debug().Msgf("Starting repository analysis for organization: %s on %s", org, provider)
	bar := a.progressBar(0, "Analyzing repositories")

	var wg sync.WaitGroup
	errChan := make(chan error, 1)
	maxGoroutines := 2
	if numberOfGoroutines != nil {
		maxGoroutines = *numberOfGoroutines
	}
	sem := semaphore.NewWeighted(int64(maxGoroutines))

	for repoBatch := range orgReposBatches {
		if repoBatch.Err != nil {
			return fmt.Errorf("failed to get batch of repos: %w", repoBatch.Err)
		}
		if repoBatch.TotalCount != 0 {
			bar.ChangeMax(repoBatch.TotalCount)
		}

		for _, repo := range repoBatch.Repositories {
			if a.Config.IgnoreForks && repo.GetIsFork() {
				bar.ChangeMax(repoBatch.TotalCount - 1)
				continue
			}
			if err := sem.Acquire(ctx, 1); err != nil {
				close(errChan)
				return fmt.Errorf("failed to acquire semaphore: %w", err)
			}

			wg.Add(1)
			go func(repo Repository) {
				defer sem.Release(1)
				defer wg.Done()
				repoNameWithOwner := repo.GetRepoIdentifier()
				tempDir, err := a.cloneRepoToTemp(ctx, repo.BuildGitURL(a.ScmClient.GetProviderBaseURL()), a.ScmClient.GetToken(), "HEAD")
				if err != nil {
					log.Error().Err(err).Str("repo", repoNameWithOwner).Msg("failed to clone repo")
					return
				}
				defer os.RemoveAll(tempDir)

				pkg, err := a.generatePackageInsights(ctx, tempDir, repo, "HEAD")
				if err != nil {
					log.Error().Err(err).Str("repo", repoNameWithOwner).Msg("failed to generate package insights")
					return
				}

				err = inventory.AddPackage(ctx, pkg, tempDir)
				if err != nil {
					log.Error().Err(err).Str("repo", repoNameWithOwner).Msg("failed to add package to inventory")
					return
				}
				_ = bar.Add(1)
			}(repo)
		}
	}

	go func() {
		wg.Wait()
		close(errChan)
	}()

	for err := range errChan {
		if err != nil {
			return err
		}
	}

	_ = bar.Finish()

	return a.finalizeAnalysis(ctx, inventory)
}

func (a *Analyzer) AnalyzeRepo(ctx context.Context, repoString string, ref string) error {
	org, repoName, err := a.ScmClient.ParseRepoAndOrg(repoString)
	if err != nil {
		return fmt.Errorf("failed to parse repository: %w", err)
	}
	repo, err := a.ScmClient.GetRepo(ctx, org, repoName)
	if err != nil {
		return fmt.Errorf("failed to get repo: %w", err)
	}
	provider := repo.GetProviderName()

	providerVersion, err := a.ScmClient.GetProviderVersion(ctx)
	if err != nil {
		log.Debug().Err(err).Msgf("Failed to get provider version for %s", provider)
	}

	log.Debug().Msgf("Provider: %s, Version: %s, BaseURL: %s", provider, providerVersion, a.ScmClient.GetProviderBaseURL())

	pkgsupplyClient := pkgsupply.NewStaticClient()
	inventory := scanner.NewInventory(a.Opa, pkgsupplyClient, provider, providerVersion)

	log.Debug().Msgf("Starting repository analysis for: %s/%s on %s", org, repoName, provider)
	bar := a.progressBar(2, "Cloning repository")
	_ = bar.RenderBlank()

	tempDir, err := a.cloneRepoToTemp(ctx, repo.BuildGitURL(a.ScmClient.GetProviderBaseURL()), a.ScmClient.GetToken(), ref)
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	bar.Describe("Analyzing repository")
	_ = bar.Add(1)

	pkg, err := a.generatePackageInsights(ctx, tempDir, repo, ref)
	if err != nil {
		return err
	}

	err = inventory.AddPackage(ctx, pkg, tempDir)
	if err != nil {
		return err
	}
	_ = bar.Finish()

	return a.finalizeAnalysis(ctx, inventory)
}

func (a *Analyzer) AnalyzeLocalRepo(ctx context.Context, repoPath string) error {
	org, repoName, err := a.ScmClient.ParseRepoAndOrg(repoPath)
	if err != nil {
		return fmt.Errorf("failed to parse repository: %w", err)
	}
	repo, err := a.ScmClient.GetRepo(ctx, org, repoName)
	if err != nil {
		return fmt.Errorf("failed to get repo: %w", err)
	}
	provider := repo.GetProviderName()

	providerVersion, err := a.ScmClient.GetProviderVersion(ctx)
	if err != nil {
		log.Debug().Err(err).Msgf("Failed to get provider version for %s", provider)
	}

	log.Debug().Msgf("Provider: %s, Version: %s, BaseURL: %s", provider, providerVersion, a.ScmClient.GetProviderBaseURL())

	pkgsupplyClient := pkgsupply.NewStaticClient()
	inventory := scanner.NewInventory(a.Opa, pkgsupplyClient, provider, providerVersion)

	log.Debug().Msgf("Starting repository analysis for: %s/%s on %s", org, repoName, provider)

	pkg, err := a.generatePackageInsights(ctx, repoPath, repo, "")
	if err != nil {
		return err
	}

	err = inventory.AddPackage(ctx, pkg, repoPath)
	if err != nil {
		return err
	}

	return a.finalizeAnalysis(ctx, inventory)
}

type Formatter interface {
	Format(ctx context.Context, report *opa.FindingsResult, packages []*models.PackageInsights) error
}

func (a *Analyzer) finalizeAnalysis(ctx context.Context, inventory *scanner.Inventory) error {
	report, err := inventory.Findings(ctx)
	if err != nil {
		return err
	}

	err = a.Formatter.Format(ctx, report, inventory.Packages)
	if err != nil {
		return err
	}

	return nil
}

func (a *Analyzer) generatePackageInsights(ctx context.Context, tempDir string, repo Repository, ref string) (*models.PackageInsights, error) {
	commitDate, err := a.GitClient.LastCommitDate(ctx, tempDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get last commit date: %w", err)
	}

	commitSha, err := a.GitClient.CommitSHA(tempDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit SHA: %w", err)
	}

	purl, _ := models.NewPurl(fmt.Sprintf("pkg:%s/%s", repo.GetProviderName(), repo.GetRepoIdentifier()))
	switch ref {
	case "HEAD", "":
		ref, err = a.GitClient.GetRepoHeadBranchName(ctx, tempDir)
		if err != nil {
			return nil, fmt.Errorf("failed to get head branch name: %w", err)
		}
	default:
		purl.Version = ref
	}

	pkg := &models.PackageInsights{
		Purl:               purl.String(),
		LastCommitedAt:     commitDate.String(),
		SourceGitCommitSha: commitSha,
		SourceScmType:      repo.GetProviderName(),
		SourceGitRepo:      repo.GetRepoIdentifier(),
		SourceGitRef:       ref,
	}
	err = pkg.NormalizePurl()
	if err != nil {
		return nil, err
	}
	return pkg, nil
}

func (a *Analyzer) cloneRepoToTemp(ctx context.Context, gitURL string, token string, ref string) (string, error) {
	tempDir, err := os.MkdirTemp("", TEMP_DIR_PREFIX)
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	err = a.GitClient.Clone(ctx, tempDir, gitURL, token, ref)
	if err != nil {
		os.RemoveAll(tempDir) // Clean up if cloning fails
		return "", fmt.Errorf("failed to clone repo: %s", err)
	}
	return tempDir, nil
}

func (a *Analyzer) progressBar(max int64, description string) *progressbar.ProgressBar {
	if a.Config.Quiet {
		return progressbar.DefaultSilent(max, description)
	} else {
		return progressbar.NewOptions64(
			max,
			progressbar.OptionSetDescription(description),
			progressbar.OptionShowCount(),
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionClearOnFinish(),
		)

	}
}
