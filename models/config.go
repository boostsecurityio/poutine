package models

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
	Skip         []ConfigSkip                      `json:"skip"`
	AllowedRules []string                          `json:"allowed_rules"`
	Include      []ConfigInclude                   `json:"include"`
	IgnoreForks  bool                              `json:"ignore_forks"`
	Quiet        bool                              `json:"quiet,omitempty"`
	RulesConfig  map[string]map[string]interface{} `json:"rules_config"`
}

func DefaultConfig() *Config {
	return &Config{}
}
