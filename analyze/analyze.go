// Package analyze can analyze things.
package analyze

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/results"
	"golang.org/x/sync/semaphore"

	"github.com/boostsecurityio/poutine/opa"
	"github.com/boostsecurityio/poutine/providers/pkgsupply"
	scm_domain "github.com/boostsecurityio/poutine/providers/scm/domain"
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
	GetHasIssues() bool
	GetHasWiki() bool
	GetHasDiscussion() bool
	GetOpenIssuesCount() int
	GetForksCount() int
	GetStarsCount() int
	GetPrimaryLanguage() string
	GetSize() int
	GetDefaultBranch() string
	GetLicense() string
	GetIsTemplate() bool
	GetOrganizationID() int
	GetRepositoryID() int
	GetIsEmpty() bool
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
	FetchCone(ctx context.Context, clonePath string, url string, token string, ref string, cone string) error
	CommitSHA(clonePath string) (string, error)
	LastCommitDate(ctx context.Context, clonePath string) (time.Time, error)
	GetRemoteOriginURL(ctx context.Context, repoPath string) (string, error)
	GetRepoHeadBranchName(ctx context.Context, repoPath string) (string, error)
	GetUniqWorkflowsBranches(ctx context.Context, clonePath string) (map[string][]models.BranchInfo, error)
	BlobMatches(ctx context.Context, clonePath string, blobsha string, regex *regexp.Regexp) (bool, []byte, error)
	ListFiles(clonePath string, extensions []string) (map[string][]byte, error)
	Cleanup(clonePath string)
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
	Observer  ProgressObserver
}

func (a *Analyzer) observer() ProgressObserver {
	if a.Observer != nil {
		return a.Observer
	}
	return noopObserver{}
}

func (a *Analyzer) AnalyzeOrg(ctx context.Context, org string, numberOfGoroutines *int) ([]*models.PackageInsights, error) {
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
	obs := a.observer()

	var reposWg sync.WaitGroup
	errChan := make(chan error, 1)
	maxGoroutines := 2
	if numberOfGoroutines != nil {
		maxGoroutines = *numberOfGoroutines
	}
	goRoutineLimitSem := semaphore.NewWeighted(int64(maxGoroutines))

	scannedPackages := make([]*models.PackageInsights, 0)

	pkgChan := make(chan *models.PackageInsights)
	pkgWg := sync.WaitGroup{}
	pkgWg.Add(1)
	go func() {
		defer pkgWg.Done()
		for pkg := range pkgChan {
			scannedPackages = append(scannedPackages, pkg)
		}
	}()

	discoveryCompleted := false
	for repoBatch := range orgReposBatches {
		if repoBatch.Err != nil {
			log.Error().Err(repoBatch.Err).Msg("failed to fetch batch of repos, skipping batch")
			continue
		}
		if !discoveryCompleted && repoBatch.TotalCount != 0 {
			discoveryCompleted = true
			obs.OnDiscoveryCompleted(org, repoBatch.TotalCount)
		}

		for _, repo := range repoBatch.Repositories {
			if a.Config.IgnoreForks && repo.GetIsFork() {
				obs.OnRepoSkipped(repo.GetRepoIdentifier(), "fork")
				continue
			}
			if repo.GetSize() == 0 {
				obs.OnRepoSkipped(repo.GetRepoIdentifier(), "empty")
				continue
			}
			if err := goRoutineLimitSem.Acquire(ctx, 1); err != nil {
				close(errChan)
				return scannedPackages, fmt.Errorf("failed to acquire semaphore: %w", err)
			}

			reposWg.Add(1)
			go func(repo Repository) {
				defer goRoutineLimitSem.Release(1)
				defer reposWg.Done()
				repoNameWithOwner := repo.GetRepoIdentifier()
				obs.OnRepoStarted(repoNameWithOwner)
				repoKey, err := a.cloneRepo(ctx, repo.BuildGitURL(a.ScmClient.GetProviderBaseURL()), a.ScmClient.GetToken(), "HEAD")
				if err != nil {
					log.Error().Err(err).Str("repo", repoNameWithOwner).Msg("failed to clone repo")
					obs.OnRepoError(repoNameWithOwner, err)
					return
				}
				defer a.GitClient.Cleanup(repoKey)

				pkg, err := a.GeneratePackageInsights(ctx, repoKey, repo, "HEAD")
				if err != nil {
					log.Error().Err(err).Str("repo", repoNameWithOwner).Msg("failed to generate package insights")
					obs.OnRepoError(repoNameWithOwner, err)
					return
				}

				files, err := a.GitClient.ListFiles(repoKey, []string{".yml", ".yaml"})
				if err != nil {
					log.Error().Err(err).Str("repo", repoNameWithOwner).Msg("failed to list files")
					obs.OnRepoError(repoNameWithOwner, err)
					return
				}

				memScanner := &scanner.InventoryScannerMem{
					Files: files,
					Parsers: []scanner.MemParser{
						scanner.NewGithubActionsMetadataParser(),
						scanner.NewGithubActionWorkflowParser(),
						scanner.NewAzurePipelinesParser(),
						scanner.NewGitlabCiParser(),
						scanner.NewPipelineAsCodeTektonParser(),
					},
				}

				scannedPkg, err := inventory.ScanPackageScanner(ctx, *pkg, memScanner)
				if err != nil {
					log.Error().Err(err).Str("repo", repoNameWithOwner).Msg("failed to scan package")
					obs.OnRepoError(repoNameWithOwner, err)
					return
				}

				select {
				case pkgChan <- scannedPkg:
				case <-ctx.Done():
					log.Error().Msg("Context canceled while sending package to channel")
					return
				}
				obs.OnRepoCompleted(repoNameWithOwner, scannedPkg)
			}(repo)
		}
	}

	go func() {
		reposWg.Wait()
		close(pkgChan)
		close(errChan)
	}()

	pkgWg.Wait()

	for err := range errChan {
		if err != nil {
			return scannedPackages, err
		}
	}

	obs.OnFinalizeStarted(len(scannedPackages))
	err = a.finalizeAnalysis(ctx, scannedPackages)
	if err != nil {
		return scannedPackages, err
	}
	obs.OnFinalizeCompleted()

	return scannedPackages, nil
}

func (a *Analyzer) AnalyzeStaleBranches(ctx context.Context, repoString string, numberOfGoroutines *int, expand *bool, regex *regexp.Regexp) (*models.PackageInsights, error) {
	org, repoName, err := a.ScmClient.ParseRepoAndOrg(repoString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse repository: %w", err)
	}
	repo, err := a.ScmClient.GetRepo(ctx, org, repoName)
	if err != nil {
		return nil, fmt.Errorf("failed to get repo: %w", err)
	}
	provider := repo.GetProviderName()

	providerVersion, err := a.ScmClient.GetProviderVersion(ctx)
	if err != nil {
		log.Debug().Err(err).Msgf("Failed to get provider version for %s", provider)
	}

	log.Debug().Msgf("Provider: %s, Version: %s, BaseURL: %s", provider, providerVersion, a.ScmClient.GetProviderBaseURL())

	pkgsupplyClient := pkgsupply.NewStaticClient()

	inventory := scanner.NewInventory(a.Opa, pkgsupplyClient, provider, providerVersion)

	obs := a.observer()
	log.Debug().Msgf("Starting repository analysis for: %s/%s on %s", org, repoName, provider)
	bar := a.ProgressBar(3, "Cloning repository")
	_ = bar.RenderBlank()

	obs.OnRepoStarted(repoString)
	repoUrl := repo.BuildGitURL(a.ScmClient.GetProviderBaseURL())
	repoKey, err := a.fetchCone(ctx, repoUrl, a.ScmClient.GetToken(), "refs/heads/*:refs/remotes/origin/*", ".github/workflows")
	if err != nil {
		obs.OnRepoError(repoString, err)
		return nil, fmt.Errorf("failed to fetch cone: %w", err)
	}
	defer a.GitClient.Cleanup(repoKey)

	bar.Describe("Listing unique workflows")
	_ = bar.Add(1)

	workflows, err := a.GitClient.GetUniqWorkflowsBranches(ctx, repoKey)
	if err != nil {
		obs.OnRepoError(repoString, err)
		return nil, fmt.Errorf("failed to get unique workflow: %w", err)
	}

	bar.Describe("Check which workflows match regex: " + regex.String())
	_ = bar.Add(1)

	errChan := make(chan error, 1)
	maxGoroutines := 5
	if numberOfGoroutines != nil {
		maxGoroutines = *numberOfGoroutines
	}
	sem := semaphore.NewWeighted(int64(maxGoroutines))
	m := sync.Mutex{}
	type file struct {
		path string
		data []byte
	}
	filesChan := make(chan *file)
	files := make(map[string][]byte)

	wgConsumer := sync.WaitGroup{}
	wgProducer := sync.WaitGroup{}

	wgConsumer.Add(1)
	go func() {
		defer wgConsumer.Done()
		for v := range filesChan {
			files[v.path] = v.data
		}
	}()
	blobShas := make([]string, 0, len(workflows))
	for sha := range workflows {
		blobShas = append(blobShas, sha)
	}
	for _, blobSha := range blobShas {
		if err := sem.Acquire(ctx, 1); err != nil {
			errChan <- fmt.Errorf("failed to acquire semaphore: %w", err)
			break
		}
		wgProducer.Add(1)
		go func(blobSha string) {
			defer wgProducer.Done()
			defer sem.Release(1)
			match, content, err := a.GitClient.BlobMatches(ctx, repoKey, blobSha, regex)
			if err != nil {
				errChan <- fmt.Errorf("failed to blob match %s: %w", blobSha, err)
				return
			}
			if match {
				filesChan <- &file{
					path: ".github/workflows/" + blobSha + ".yaml",
					data: content,
				}
			} else {
				m.Lock()
				delete(workflows, blobSha)
				m.Unlock()
			}
		}(blobSha)
	}
	wgProducer.Wait()
	close(errChan)
	close(filesChan)
	wgConsumer.Wait()
	for err := range errChan {
		obs.OnRepoError(repoString, err)
		return nil, err
	}

	bar.Describe("Scanning package")
	_ = bar.Add(1)
	pkg, err := a.GeneratePackageInsights(ctx, repoKey, repo, "HEAD")
	if err != nil {
		obs.OnRepoError(repoString, err)
		return nil, fmt.Errorf("failed to generate package insight: %w", err)
	}

	inventoryScanner := scanner.InventoryScannerMem{
		Files: files,
		Parsers: []scanner.MemParser{
			scanner.NewGithubActionWorkflowParser(),
		},
	}

	scannedPackage, err := inventory.ScanPackageScanner(ctx, *pkg, &inventoryScanner)
	if err != nil {
		obs.OnRepoError(repoString, err)
		return nil, fmt.Errorf("failed to scan package: %w", err)
	}

	_ = bar.Finish()
	obs.OnRepoCompleted(repoString, scannedPackage)

	obs.OnFinalizeStarted(1)
	if *expand {
		expanded := []results.Finding{}
		for _, finding := range scannedPackage.FindingsResults.Findings {
			filename := filepath.Base(finding.Meta.Path)
			blobsha := strings.TrimSuffix(filename, filepath.Ext(filename))
			purl, err := models.NewPurl(finding.Purl)
			if err != nil {
				log.Warn().Err(err).Str("purl", finding.Purl).Msg("failed to evaluate PURL, skipping")
				continue
			}
			for _, branchInfo := range workflows[blobsha] {
				for _, path := range branchInfo.FilePath {
					finding.Meta.Path = path
					purl.Version = branchInfo.BranchName
					finding.Purl = purl.String()
					expanded = append(expanded, finding)
				}
			}
		}
		scannedPackage.FindingsResults.Findings = expanded

		if err := a.Formatter.Format(ctx, []*models.PackageInsights{scannedPackage}); err != nil {
			return nil, fmt.Errorf("failed to finalize analysis of package: %w", err)
		}
	} else {
		results := make(map[string][]*models.RepoInfo, len(workflows))
		for blobsha, branchinfos := range workflows {
			results[blobsha] = []*models.RepoInfo{{
				RepoName:    repoName,
				Purl:        pkg.Purl,
				BranchInfos: branchinfos,
			}}
		}

		if err := a.Formatter.FormatWithPath(ctx, []*models.PackageInsights{scannedPackage}, results); err != nil {
			return nil, fmt.Errorf("failed to finalize analysis of package: %w", err)
		}
	}
	obs.OnFinalizeCompleted()

	return scannedPackage, nil
}

func (a *Analyzer) AnalyzeRepo(ctx context.Context, repoString string, ref string) (*models.PackageInsights, error) {
	org, repoName, err := a.ScmClient.ParseRepoAndOrg(repoString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse repository: %w", err)
	}
	repo, err := a.ScmClient.GetRepo(ctx, org, repoName)
	if err != nil {
		return nil, fmt.Errorf("failed to get repo: %w", err)
	}
	provider := repo.GetProviderName()

	providerVersion, err := a.ScmClient.GetProviderVersion(ctx)
	if err != nil {
		log.Debug().Err(err).Msgf("Failed to get provider version for %s", provider)
	}

	log.Debug().Msgf("Provider: %s, Version: %s, BaseURL: %s", provider, providerVersion, a.ScmClient.GetProviderBaseURL())

	pkgsupplyClient := pkgsupply.NewStaticClient()
	inventory := scanner.NewInventory(a.Opa, pkgsupplyClient, provider, providerVersion)

	obs := a.observer()
	log.Debug().Msgf("Starting repository analysis for: %s/%s on %s", org, repoName, provider)
	bar := a.ProgressBar(2, "Cloning repository")
	_ = bar.RenderBlank()

	obs.OnRepoStarted(repoString)
	repoKey, err := a.cloneRepo(ctx, repo.BuildGitURL(a.ScmClient.GetProviderBaseURL()), a.ScmClient.GetToken(), ref)
	if err != nil {
		obs.OnRepoError(repoString, err)
		return nil, err
	}
	defer a.GitClient.Cleanup(repoKey)

	bar.Describe("Analyzing repository")
	_ = bar.Add(1)

	pkg, err := a.GeneratePackageInsights(ctx, repoKey, repo, ref)
	if err != nil {
		obs.OnRepoError(repoString, err)
		return nil, err
	}

	files, err := a.GitClient.ListFiles(repoKey, []string{".yml", ".yaml"})
	if err != nil {
		obs.OnRepoError(repoString, err)
		return nil, fmt.Errorf("failed to list files: %w", err)
	}

	memScanner := &scanner.InventoryScannerMem{
		Files: files,
		Parsers: []scanner.MemParser{
			scanner.NewGithubActionsMetadataParser(),
			scanner.NewGithubActionWorkflowParser(),
			scanner.NewAzurePipelinesParser(),
			scanner.NewGitlabCiParser(),
			scanner.NewPipelineAsCodeTektonParser(),
		},
	}

	scannedPackage, err := inventory.ScanPackageScanner(ctx, *pkg, memScanner)
	if err != nil {
		obs.OnRepoError(repoString, err)
		return nil, err
	}
	_ = bar.Finish()
	obs.OnRepoCompleted(repoString, scannedPackage)

	obs.OnFinalizeStarted(1)
	err = a.finalizeAnalysis(ctx, []*models.PackageInsights{scannedPackage})
	if err != nil {
		return nil, err
	}
	obs.OnFinalizeCompleted()

	return scannedPackage, nil
}

func (a *Analyzer) AnalyzeLocalRepo(ctx context.Context, repoPath string) (*models.PackageInsights, error) {
	org, repoName, err := a.ScmClient.ParseRepoAndOrg(repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse repository: %w", err)
	}
	repo, err := a.ScmClient.GetRepo(ctx, org, repoName)
	if err != nil {
		return nil, fmt.Errorf("failed to get repo: %w", err)
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

	pkg, err := a.GeneratePackageInsights(ctx, repoPath, repo, "")
	if err != nil {
		return nil, err
	}

	scannedPackage, err := inventory.ScanPackage(ctx, *pkg, repoPath)
	if err != nil {
		return nil, err
	}

	err = a.finalizeAnalysis(ctx, []*models.PackageInsights{scannedPackage})
	if err != nil {
		return nil, err
	}

	return scannedPackage, nil
}

func (a *Analyzer) AnalyzeManifest(ctx context.Context, manifestReader io.Reader, manifestType string) (*models.PackageInsights, error) {
	provider := "manifest"
	providerVersion := "unknown"

	pkgSupplyClient := pkgsupply.NewStaticClient()
	inventory := scanner.NewInventory(a.Opa, pkgSupplyClient, provider, providerVersion)

	log.Debug().Msg("Starting manifest analysis")

	manifestData, err := io.ReadAll(manifestReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	if manifestType == "" {
		return nil, errors.New("invalid manifest type")
	}

	filename := a.getManifestFilename(manifestType)

	pkg := a.createManifestPackageInsights(manifestType)

	inventoryScanner := scanner.InventoryScannerMem{
		Files: map[string][]byte{
			filename: manifestData,
		},
		Parsers: []scanner.MemParser{
			scanner.NewGithubActionWorkflowParser(),
			scanner.NewGithubActionsMetadataParser(),
			scanner.NewGitlabCiParser(),
			scanner.NewAzurePipelinesParser(),
			scanner.NewPipelineAsCodeTektonParser(),
		},
	}

	scannedPackage, err := inventory.ScanPackageScanner(ctx, *pkg, &inventoryScanner)
	if err != nil {
		return nil, fmt.Errorf("failed to scan manifest: %w", err)
	}

	err = a.finalizeAnalysis(ctx, []*models.PackageInsights{scannedPackage})
	if err != nil {
		return nil, err
	}

	return scannedPackage, nil
}

func (a *Analyzer) getManifestFilename(manifestType string) string {
	switch manifestType {
	case "github-actions":
		return ".github/workflows/manifest.yml"
	case "gitlab-ci":
		return ".gitlab-ci.yml"
	case "azure-pipelines":
		return "azure-pipelines.yml"
	case "tekton":
		return ".tekton/manifest.yml"
	default:
		return ".github/workflows/manifest.yml"
	}
}

func (a *Analyzer) createManifestPackageInsights(manifestType string) *models.PackageInsights {
	var purlString string
	switch manifestType {
	case "github-actions":
		purlString = "pkg:generic/github-actions-workflow"
	case "gitlab-ci":
		purlString = "pkg:generic/gitlab-ci-config"
	case "azure-pipelines":
		purlString = "pkg:generic/azure-pipelines-config"
	case "tekton":
		purlString = "pkg:generic/tekton-pipeline"
	default:
		purlString = "pkg:generic/ci-workflow"
	}

	purl, _ := models.NewPurl(purlString)

	pkg := &models.PackageInsights{
		LastCommitedAt:     time.Now().Format(time.RFC3339),
		Purl:               purl.String(),
		SourceScmType:      "manifest",
		SourceGitRepo:      "workflow/" + manifestType,
		SourceGitRef:       "HEAD",
		SourceGitCommitSha: "unknown",
		OrgID:              0,
		RepoID:             0,
		RepoSize:           0,
		DefaultBranch:      "main",
		IsFork:             false,
		IsEmpty:            false,
		ForksCount:         0,
		StarsCount:         0,
		IsTemplate:         false,
		HasIssues:          false,
		OpenIssuesCount:    0,
		HasWiki:            false,
		HasDiscussions:     false,
		PrimaryLanguage:    "YAML",
		License:            "",
	}

	err := pkg.NormalizePurl()
	if err != nil {
		log.Warn().Err(err).Msg("failed to normalize purl for manifest")
	}

	return pkg
}

type Formatter interface {
	Format(ctx context.Context, packages []*models.PackageInsights) error
	FormatWithPath(ctx context.Context, packages []*models.PackageInsights, pathAssociation map[string][]*models.RepoInfo) error
}

func (a *Analyzer) finalizeAnalysis(ctx context.Context, scannedPackages []*models.PackageInsights) error {
	err := a.Formatter.Format(ctx, scannedPackages)
	if err != nil {
		return err
	}

	return nil
}

func (a *Analyzer) GeneratePackageInsights(ctx context.Context, tempDir string, repo Repository, ref string) (*models.PackageInsights, error) {
	var err error
	commitDate, err := a.GitClient.LastCommitDate(ctx, tempDir)
	if err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("failed to get last commit date")
	}

	commitSha, err := a.GitClient.CommitSHA(tempDir)
	if err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("failed to get commit SHA")
	}

	var (
		purl   models.Purl
		domain = a.ScmClient.GetProviderBaseURL()
	)
	if domain != scm_domain.DefaultGitHubDomain && domain != scm_domain.DefaultGitLabDomain {
		purl, _ = models.NewPurl(fmt.Sprintf("pkg:%s/%s?repository_url=%s", repo.GetProviderName(), repo.GetRepoIdentifier(), domain))
	} else {
		purl, _ = models.NewPurl(fmt.Sprintf("pkg:%s/%s", repo.GetProviderName(), repo.GetRepoIdentifier()))
	}

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
		LastCommitedAt:     commitDate.Format(time.RFC3339),
		Purl:               purl.String(),
		SourceScmType:      repo.GetProviderName(),
		SourceGitRepo:      repo.GetRepoIdentifier(),
		SourceGitRef:       ref,
		SourceGitCommitSha: commitSha,
		OrgID:              repo.GetOrganizationID(),
		RepoID:             repo.GetRepositoryID(),
		RepoSize:           repo.GetSize(),
		DefaultBranch:      repo.GetDefaultBranch(),
		IsFork:             repo.GetIsFork(),
		IsEmpty:            repo.GetIsEmpty(),
		ForksCount:         repo.GetForksCount(),
		StarsCount:         repo.GetStarsCount(),
		IsTemplate:         repo.GetIsTemplate(),
		HasIssues:          repo.GetHasIssues(),
		OpenIssuesCount:    repo.GetOpenIssuesCount(),
		HasWiki:            repo.GetHasWiki(),
		HasDiscussions:     repo.GetHasDiscussion(),
		PrimaryLanguage:    repo.GetPrimaryLanguage(),
		License:            repo.GetLicense(),
	}
	err = pkg.NormalizePurl()
	if err != nil {
		return nil, fmt.Errorf("failed to normalize purl: %w", err)
	}
	return pkg, nil
}

func (a *Analyzer) fetchCone(ctx context.Context, gitURL, token, ref string, cone string) (string, error) {
	key := fmt.Sprintf("repo:%s:cone:%d", gitURL, time.Now().UnixNano())
	err := a.GitClient.FetchCone(ctx, key, gitURL, token, ref, cone)
	if err != nil {
		return "", fmt.Errorf("failed to fetch cone: %w", err)
	}
	return key, nil
}

func (a *Analyzer) cloneRepo(ctx context.Context, gitURL string, token string, ref string) (string, error) {
	key := fmt.Sprintf("repo:%s:%d", gitURL, time.Now().UnixNano())
	err := a.GitClient.Clone(ctx, key, gitURL, token, ref)
	if err != nil {
		return "", fmt.Errorf("failed to clone repo: %w", err)
	}
	return key, nil
}

func (a *Analyzer) ProgressBar(maxValue int64, description string) *progressbar.ProgressBar {
	if a.Config.Quiet {
		return progressbar.DefaultSilent(maxValue, description)
	} else {
		return progressbar.NewOptions64(
			maxValue,
			progressbar.OptionSetDescription(description),
			progressbar.OptionShowCount(),
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionClearOnFinish(),
		)

	}
}
