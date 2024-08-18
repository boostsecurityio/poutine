package scm_domain

import "strings"

// ScmBaseDomain represent the base domain for a SCM provider.
type ScmBaseDomain string

const DefaultGitHubDomain string = "github.com"
const DefaultGitLabDomain string = "gitlab.com"

var schemePrefixes = []string{"https://", "http://"}

func (d *ScmBaseDomain) Set(value string) error {
	for _, prefix := range schemePrefixes {
		value = strings.TrimPrefix(value, prefix)
	}
	value = strings.TrimRight(value, "/")

	*d = ScmBaseDomain(value)
	return nil
}

func (d *ScmBaseDomain) String() string {
	if d == nil {
		return ""
	}
	return string(*d)
}

func (d *ScmBaseDomain) Type() string {
	return "string"
}
