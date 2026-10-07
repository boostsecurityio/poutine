package models

import "strings"

type ConfigSkip struct {
	Purl  StringList `json:"purl,omitempty"`
	Path  StringList `json:"path,omitempty"`
	Rule  StringList `json:"rule,omitempty"`
	OsvId StringList `json:"osv_id,omitempty"`
	Job   StringList `json:"job,omitempty"`
	Level StringList `json:"level,omitempty"`
}

func (c *ConfigSkip) HasOnlyRule() bool {
	return len(c.Purl) == 0 &&
		len(c.Path) == 0 &&
		len(c.OsvId) == 0 &&
		len(c.Job) == 0 &&
		len(c.Level) == 0 &&
		len(c.Rule) != 0
}

type ConfigInclude struct {
	Path StringList `json:"path,omitempty"`
}

type Config struct {
	Skip                []ConfigSkip                      `json:"skip"`
	AllowedRules        []string                          `json:"allowed_rules"`
	Include             []ConfigInclude                   `json:"include"`
	IgnoreForks         bool                              `json:"ignore_forks"`
	ExcludeRepos        []string                          `json:"exclude_repos,omitempty"`
	Quiet               bool                              `json:"quiet,omitempty"`
	RulesConfig         map[string]map[string]interface{} `json:"rules_config"`
	DisableVersionCheck bool                              `json:"disable_version_check,omitempty"`
}

func (c *Config) IsRepoExcluded(repoIdentifier string) bool {
	if c == nil || len(c.ExcludeRepos) == 0 {
		return false
	}
	parts := strings.Split(repoIdentifier, "/")
	repoName := parts[len(parts)-1]
	for _, excluded := range c.ExcludeRepos {
		if strings.EqualFold(excluded, repoIdentifier) || strings.EqualFold(excluded, repoName) {
			return true
		}
	}
	return false
}

func DefaultConfig() *Config {
	return &Config{}
}
