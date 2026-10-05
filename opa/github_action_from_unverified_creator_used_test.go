package opa

import (
	"context"
	"testing"

	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/results"
	"github.com/stretchr/testify/require"
)

func TestGitHubActionFromUnverifiedCreatorUsed(t *testing.T) {
	ctx := context.Background()
	o, err := NewOpa(ctx, models.DefaultConfig())
	require.NoError(t, err)

	cases := []struct {
		uses     string
		findings int
	}{
		{"astral-sh/setup-uv@bec219d24cd3e171d82865faccec33120bb574f4", 0},
		{"astral-sh/setup-uv@v10", 0},
		{"astral-sh/ruff-action@v1", 0},
		{"unverified-publisher/setup-uv@v10", 1},
		{"astral-sh-unverified/setup-uv@v10", 1},
	}

	for _, source := range []string{"workflow", "composite"} {
		for _, tc := range cases {
			t.Run(source+"/"+tc.uses, func(t *testing.T) {
				step := map[string]interface{}{
					"uses":  tc.uses,
					"lines": map[string]interface{}{"uses": 5},
				}
				pkg := map[string]interface{}{
					"purl":              "pkg:github/example/project",
					"package_namespace": "example",
					"source_git_repo":   "https://github.com/example/project",
					"source_git_ref":    "main",
				}
				if source == "workflow" {
					pkg["github_actions_workflows"] = []interface{}{map[string]interface{}{
						"path":   ".github/workflows/ci.yml",
						"events": []interface{}{map[string]interface{}{"name": "push"}},
						"jobs": []interface{}{map[string]interface{}{
							"id": "build", "steps": []interface{}{step},
						}},
					}}
				} else {
					pkg["github_actions_metadata"] = []interface{}{map[string]interface{}{
						"path": "action.yml",
						"runs": map[string]interface{}{
							"using": "composite", "steps": []interface{}{step},
						},
					}}
				}
				input := map[string]interface{}{"packages": []interface{}{pkg}}
				var findings []results.Finding
				err := o.Eval(ctx, "data.rules.github_action_from_unverified_creator_used.results", input, &findings)
				require.NoError(t, err)
				require.Len(t, findings, tc.findings)
				if tc.findings > 0 {
					require.Equal(t, tc.uses, findings[0].Meta.Details)
				}
			})
		}
	}
}
