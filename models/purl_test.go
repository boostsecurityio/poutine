package models

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewPurl(t *testing.T) {
	cases := []struct {
		purl     string
		expected string
	}{
		{
			purl:     "pkg:githubactions/Actions/Checkout@v4",
			expected: "pkg:githubactions/actions/checkout@v4",
		},
		{
			purl:     "pkg:githubactions/github/codeql-action/Analyze@v4",
			expected: "pkg:githubactions/github/codeql-action@v4#Analyze",
		},
		{
			purl:     "pkg:githubactions/Actions/Checkout@v4#dir/SubPath",
			expected: "pkg:githubactions/actions/checkout@v4#dir/SubPath",
		},
	}

	for _, c := range cases {
		p, err := NewPurl(c.purl)
		assert.Nil(t, err)

		p.Normalize()

		assert.Equal(t, c.expected, p.String())
	}
}

func TestPurlFromGithubActions(t *testing.T) {
	cases := []struct {
		uses          string
		sourceGitRepo string
		sourceGitRef  string
		expected      string
		error         bool
	}{

		{
			uses:     "actions/checkout@v4",
			expected: "pkg:githubactions/actions/checkout@v4",
		},
		{
			uses:     "github/codeql-action/Analyze@v4",
			expected: "pkg:githubactions/github/codeql-action@v4#Analyze",
		},
		{
			uses:     "docker://alpine:latest",
			expected: "pkg:docker/alpine%3Alatest",
		},
		{
			uses:     "docker://ghcr.io/org/owner/image:tag",
			expected: "pkg:docker/ghcr.io/org/owner/image%3Atag",
		},
		{
			uses:     "docker://ghcr.io/org/owner/image@sha256:digest",
			expected: "pkg:docker/ghcr.io/org/owner/image@sha256%3Adigest",
		},
		{
			uses:  "",
			error: true,
		},
		{
			uses:  "invalid",
			error: true,
		},
		{
			uses:          "./.github/workflows/trigger_dep_builds.yml",
			sourceGitRepo: "FasterXML/jackson-databind",
			sourceGitRef:  "2.18",
			expected:      "pkg:githubactions/fasterxml/jackson-databind@2.18#.github/workflows/trigger_dep_builds.yml",
		},
		{
			uses:  "./../action/init",
			error: true,
		},
	}

	for _, c := range cases {
		p, err := PurlFromGithubActions(c.uses, c.sourceGitRepo, c.sourceGitRef)

		if !c.error {
			assert.Nil(t, err)
			assert.Equal(t, c.expected, p.String())
		} else {
			assert.NotNil(t, err)
		}
	}
}

func TestPurlLink(t *testing.T) {
	cases := []struct {
		name     string
		purl     string
		expected string
	}{
		// GitHub
		{
			name:     "github.com default",
			purl:     "pkg:githubactions/actions/checkout@v4",
			expected: "https://github.com/actions/checkout",
		},
		{
			name:     "github custom base ",
			purl:     "pkg:githubactions/actions/checkout@v4?repository_url=github.example.com",
			expected: "https://github.example.com/actions/checkout",
		},
		// GitLab
		{
			name:     "gitlab.com default",
			purl:     "pkg:gitlab/include/remote?download_url=https%3A%2F%2Fexample.com%2F.gitlab-ci.yml",
			expected: "https://gitlab.com/include/remote",
		},
		{
			name:     "gitlab custom base",
			purl:     "pkg:gitlab/include/remote?download_url=https%3A%2F%2Fexample.com%2F.gitlab-ci.yml&repository_url=gitlab.example.com",
			expected: "https://gitlab.example.com/include/remote",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := NewPurl(c.purl)
			assert.Nil(t, err)

			link := p.Link()
			assert.Equal(t, c.expected, link)
		})
	}
}
