package models

type BranchInfo struct {
	BranchName string   `json:"branch_name"`
	FilePath   []string `json:"file_path"`
}
