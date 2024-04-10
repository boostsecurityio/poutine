package models

import (
	_ "embed"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

//go:embed tests/actions-checkout-v4.json
var insightsSample []byte

func TestPackageInsights(t *testing.T) {
	pi := PackageInsights{}

	err := json.Unmarshal(insightsSample, &pi)
	assert.Nil(t, err)

	assert.Equal(t, "1.0", pi.Version)
	assert.Equal(t, "pkg:githubactions/actions/checkout@v4", pi.Purl)
	assert.Equal(t, "githubactions", pi.PackageEcosystem)
	assert.Equal(t, "checkout", pi.PackageName)
	assert.Equal(t, "actions", pi.PackageNamespace)
	assert.Equal(t, "v4", pi.PackageVersion)
	assert.Equal(t, "github", pi.SourceScmType)
	assert.Equal(t, "actions/checkout", pi.SourceGitRepo)
	assert.Equal(t, "", pi.SourceGitRepoPath)
	assert.Equal(t, "v4", pi.SourceGitRef)
	assert.Equal(t, "b4ffde65f46336ab88eb53be808477a3936bae11", pi.SourceGitCommitSha)
	assert.Equal(t, 0, len(pi.PackageDependencies))
	assert.Subset(t, []string{
		"pkg:githubactions/actions/setup-node@v1",
		"pkg:githubactions/actions/upload-artifact@v2",
		"pkg:githubactions/actions/checkout@v3",
		"pkg:githubactions/github/codeql-action/analyze@v2",
		"pkg:githubactions/github/codeql-action/init@v2",
	}, pi.BuildDependencies)

	assert.Equal(t, 5, len(pi.GithubActionsWorkflows))
	assert.Equal(t, 1, len(pi.GithubActionsMetadata))
}
