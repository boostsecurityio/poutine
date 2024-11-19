package opa

type InventoryResult struct {
	BuildDependencies   []string `json:"build_dependencies"`
	PackageDependencies []string `json:"package_dependencies"`
}
