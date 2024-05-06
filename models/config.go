package models

type ConfigSkip struct {
	Purl  string `json:"purl,omitempty"`
	Path  string `json:"path,omitempty"`
	Rule  string `json:"rule,omitempty"`
	OsvId string `json:"osv_id,omitempty"`
	Job   string `json:"job,omitempty"`
}

type Config struct {
	Skip []ConfigSkip `json:"skip"`
}

func DefaultConfig() *Config {
	return &Config{}
}
