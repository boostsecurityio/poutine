// Package analyze can analyze things.
package analyze

import (
	"context"
	"fmt"
	"github.com/boostsecurityio/poutine/models"
	"golang.org/x/sync/semaphore"
	"os"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/boostsecurityio/poutine/opa"
	"github.com/boostsecurityio/poutine/providers/gitops"
	"github.com/boostsecurityio/poutine/providers/pkgsupply"
	"github.com/boostsecurityio/poutine/scanner"
	"github.com/schollz/progressbar/v3"
)

const TEMP_DIR_PREFIX = "poutine-*"

type Repository interface {
	GetProviderName() string
	GetRepoIdentifier() string
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

func AnalyzeOrg(ctx context.Context, org string, scmClient ScmClient, numberOfGoroutines *int, formatter Formatter) error {
	provider := scmClient.GetProviderName()

	providerVersion, err := scmClient.GetProviderVersion(ctx)
	if err != nil {
		log.Debug().Err(err).Msgf("Failed to get provider version for %s", provider)
	}

	log.Debug().Msgf("Provider: %s, Version: %s", provider, providerVersion)

	log.Debug().Msgf("Fetching list of repositories for organization: %s on %s", org, provider)
	orgReposBatches := scmClient.GetOrgRepos(ctx, org)

	opaClient, _ := opa.NewOpa()
	pkgsupplyClient := pkgsupply.NewStaticClient()

	inventory := scanner.NewInventory(opaClient, pkgsupplyClient)

	log.Debug().Msgf("Starting repository analysis for organization: %s on %s", org, provider)
	bar := progressbar.NewOptions(
		0,
		progressbar.OptionSetDescription("Analyzing repositories"),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWriter(os.Stderr),
	)

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
			if err := sem.Acquire(ctx, 1); err != nil {
				close(errChan)
				return fmt.Errorf("failed to acquire semaphore: %w", err)
			}

			wg.Add(1)
			go func(repo Repository) {
				defer sem.Release(1)
				defer wg.Done()
				repoNameWithOwner := repo.GetRepoIdentifier()
				tempDir, err := cloneRepoToTemp(ctx, repo.BuildGitURL(scmClient.GetProviderBaseURL()), scmClient.GetToken())
				if err != nil {
					log.Error().Err(err).Str("repo", repoNameWithOwner).Msg("failed to clone repo")
					return
				}
				defer os.RemoveAll(tempDir)

				pkg, err := generatePackageInsights(ctx, tempDir, repo)
				if err != nil {
					errChan <- err
					return
				}

				err = inventory.AddPackage(ctx, pkg, tempDir)
				if err != nil {
					errChan <- err
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

	fmt.Print("\n\n")

	return finalizeAnalysis(ctx, inventory, formatter)
}

func AnalyzeRepo(ctx context.Context, repoString string, scmClient ScmClient, formatter Formatter) error {
	org, repoName, err := scmClient.ParseRepoAndOrg(repoString)
	if err != nil {
		return fmt.Errorf("failed to parse repository: %w", err)
	}
	repo, err := scmClient.GetRepo(ctx, org, repoName)
	if err != nil {
		return fmt.Errorf("failed to get repo: %w", err)
	}
	provider := repo.GetProviderName()

	providerVersion, err := scmClient.GetProviderVersion(ctx)
	if err != nil {
		log.Debug().Err(err).Msgf("Failed to get provider version for %s", provider)
	}

	log.Debug().Msgf("Provider: %s, Version: %s", provider, providerVersion)

	opaClient, _ := opa.NewOpa()
	pkgsupplyClient := pkgsupply.NewStaticClient()

	inventory := scanner.NewInventory(opaClient, pkgsupplyClient)

	log.Debug().Msgf("Starting repository analysis for: %s/%s on %s", org, repoName, provider)
	bar := progressbar.NewOptions(
		1,
		progressbar.OptionSetDescription("Analyzing repository"),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWriter(os.Stderr),
	)

	tempDir, err := cloneRepoToTemp(ctx, repo.BuildGitURL(scmClient.GetProviderBaseURL()), scmClient.GetToken())
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	pkg, err := generatePackageInsights(ctx, tempDir, repo)
	if err != nil {
		return err
	}

	err = inventory.AddPackage(ctx, pkg, tempDir)
	if err != nil {
		return err
	}
	_ = bar.Add(1)

	fmt.Print("\n\n")
	return finalizeAnalysis(ctx, inventory, formatter)
}

func AnalyzeLocalRepo(ctx context.Context, repoPath string, scmClient ScmClient, formatter Formatter) error {
	org, repoName, err := scmClient.ParseRepoAndOrg(repoPath)
	if err != nil {
		return fmt.Errorf("failed to parse repository: %w", err)
	}
	repo, err := scmClient.GetRepo(ctx, org, repoName)
	if err != nil {
		return fmt.Errorf("failed to get repo: %w", err)
	}
	provider := repo.GetProviderName()

	providerVersion, err := scmClient.GetProviderVersion(ctx)
	if err != nil {
		log.Debug().Err(err).Msgf("Failed to get provider version for %s", provider)
	}

	log.Debug().Msgf("Provider: %s, Version: %s", provider, providerVersion)

	opaClient, _ := opa.NewOpa()
	pkgsupplyClient := pkgsupply.NewStaticClient()

	inventory := scanner.NewInventory(opaClient, pkgsupplyClient)

	log.Debug().Msgf("Starting repository analysis for: %s/%s on %s", org, repoName, provider)
	bar := progressbar.NewOptions(
		1,
		progressbar.OptionSetDescription("Analyzing repository"),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWriter(os.Stderr),
	)

	pkg, err := generatePackageInsights(ctx, repoPath, repo)
	if err != nil {
		return err
	}

	err = inventory.AddPackage(ctx, pkg, repoPath)
	if err != nil {
		return err
	}
	_ = bar.Add(1)

	fmt.Print("\n\n")
	return finalizeAnalysis(ctx, inventory, formatter)
}

type Formatter interface {
	Format(ctx context.Context, report *opa.FindingsResult, packages []*models.PackageInsights) error
}

func finalizeAnalysis(ctx context.Context, inventory *scanner.Inventory, formatter Formatter) error {
	report, err := inventory.Findings(ctx)
	if err != nil {
		return err
	}

	err = formatter.Format(ctx, report, inventory.Packages)
	if err != nil {
		return err
	}

	return nil
}

func generatePackageInsights(ctx context.Context, tempDir string, repo Repository) (*models.PackageInsights, error) {
	gitClient := gitops.NewGitClient(nil)
	commitDate, err := gitClient.LastCommitDate(ctx, tempDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get last commit date: %w", err)
	}

	commitSha, err := gitClient.CommitSHA(tempDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit SHA: %w", err)
	}

	headBranchName, err := gitClient.GetRepoHeadBranchName(ctx, tempDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get head branch name: %w", err)
	}

	purl := fmt.Sprintf("pkg:%s/%s", repo.GetProviderName(), strings.ToLower(repo.GetRepoIdentifier()))
	pkg := &models.PackageInsights{
		Purl:               purl,
		LastCommitedAt:     commitDate.String(),
		SourceGitCommitSha: commitSha,
		SourceScmType:      repo.GetProviderName(),
		SourceGitRepo:      repo.GetRepoIdentifier(),
		SourceGitRef:       headBranchName,
	}
	err = pkg.NormalizePurl()
	if err != nil {
		return nil, err
	}
	return pkg, nil
}

func cloneRepoToTemp(ctx context.Context, gitURL string, token string) (string, error) {
	tempDir, err := os.MkdirTemp("", TEMP_DIR_PREFIX)
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	gitClient := gitops.NewGitClient(nil)
	err = gitClient.Clone(ctx, tempDir, gitURL, token, "HEAD")
	if err != nil {
		os.RemoveAll(tempDir) // Clean up if cloning fails
		return "", fmt.Errorf("failed to clone repo: %s", err)
	}
	return tempDir, nil
}
