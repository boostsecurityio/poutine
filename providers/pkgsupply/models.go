package pkgsupply

type PackageReputation struct {
	Purl       string            `json:"purl"`
	Repo       string            `json:"repo"`
	Risk       float64           `json:"risk"`
	Attributes map[string]string `json:"attributes"`
}

type RepoReputation struct {
	Repo       string            `json:"repo"`
	Attributes map[string]string `json:"attributes"`
}

type ReputationResponse struct {
	Packages []PackageReputation `json:"packages"`
	Repos    []RepoReputation    `json:"repos"`
}
