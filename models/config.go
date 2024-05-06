package models

type ConfigSkip struct {
	Purl  StringList `json:"purl,omitempty"`
	Path  StringList `json:"path,omitempty"`
	Rule  StringList `json:"rule,omitempty"`
	OsvId StringList `json:"osv_id,omitempty"`
	Job   StringList `json:"job,omitempty"`
	Level StringList `json:"level,omitempty"`
}

type Config struct {
	Skip []ConfigSkip `json:"skip"`
}

func DefaultConfig() *Config {
	return &Config{}
}
