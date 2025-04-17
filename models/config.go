package models

type ConfigSkip struct {
	Purl  StringList `json:"purl,omitempty"`
	Path  StringList `json:"path,omitempty"`
	Rule  StringList `json:"rule,omitempty"`
	OsvId StringList `json:"osv_id,omitempty"`
	Job   StringList `json:"job,omitempty"`
	Level StringList `json:"level,omitempty"`
}

type ConfigInclude struct {
	Path StringList `json:"path,omitempty"`
}

type Config struct {
	Skip        []ConfigSkip                      `json:"skip"`
	Include     []ConfigInclude                   `json:"include"`
	IgnoreForks bool                              `json:"ignore_forks"`
	Quiet       bool                              `json:"quiet,omitempty"`
	RulesConfig map[string]map[string]interface{} `json:"rules_config"`
}

func DefaultConfig() *Config {
	return &Config{}
}
