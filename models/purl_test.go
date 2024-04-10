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
		uses     string
		expected string
		error    bool
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
			uses:     "./.github/actions/custom",
			expected: "",
			error:    true,
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
	}

	for _, c := range cases {
		p, err := PurlFromGithubActions(c.uses)

		if !c.error {
			assert.Nil(t, err)
			assert.Equal(t, c.expected, p.String())
		} else {
			assert.NotNil(t, err)
		}
	}
}
