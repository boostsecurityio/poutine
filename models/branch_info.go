package models

type BranchInfo struct {
	BranchName string   `json:"branch_name"`
	FilePath   []string `json:"file_path"`
}

type RepoInfo struct {
	RepoName    string       `json:"repo_name"`
	BranchInfos []BranchInfo `json:"branch_infos"`
}
