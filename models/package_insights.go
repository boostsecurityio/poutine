package models

import "fmt"

type PackageInsights struct {
	Version string `json:"version"`

	FirstSeenAt    string `json:"first_seen_at"`
	UpdatedAt      string `json:"updated_at"`
	LastCommitedAt string `json:"last_commited_at"`

	Purl string `json:"purl"`

	AnalysisResult   string `json:"analysis_result"`
	AnalysisDetails  string `json:"analysis_details"`
	PackageEcosystem string `json:"package_ecosystem"`
	PackageName      string `json:"package_name"`
	PackageNamespace string `json:"package_namespace"`
	PackageVersion   string `json:"package_version"`

	SourceScmType      string `json:"source_scm_type"`
	SourceGitRepo      string `json:"source_git_repo"`
	SourceGitRepoPath  string `json:"source_git_repo_path"`
	SourceGitRef       string `json:"source_git_ref"`
	SourceGitCommitSha string `json:"source_git_commit_sha"`

	PackageDependencies []string `json:"package_dependencies"`
	BuildDependencies   []string `json:"build_dependencies"`

	GithubActionsWorkflows []GithubActionsWorkflow `json:"github_actions_workflows"`
	GithubActionsMetadata  []GithubActionsMetadata `json:"github_actions_metadata"`
	GitlabciConfigs        []GitlabciConfig        `json:"gitlabci_configs"`
	AzurePipelines         []AzurePipeline         `json:"azure_pipelines"`
}

func (p *PackageInsights) GetSourceGitRepoURI() string {
	if p.SourceScmType == "github" {
		return fmt.Sprintf("https://github.com/%s", p.SourceGitRepo)
	}

	if p.SourceScmType == "gitlab" {
		return fmt.Sprintf("https://gitlab.com/%s", p.SourceGitRepo)
	}
	// TODO this is to make it work properly when scanning locally
	return fmt.Sprintf("https://%s", p.SourceGitRepo)
}

func (p *PackageInsights) NormalizePurl() error {
	purl, err := NewPurl(p.Purl)
	if err != nil {
		return err
	}

	p.Purl = purl.String()
	p.PackageEcosystem = purl.Type
	p.PackageName = purl.Name
	p.PackageNamespace = purl.Namespace
	p.PackageVersion = purl.Version
	return nil
}
