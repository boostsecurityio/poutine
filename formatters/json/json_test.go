package json

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/boostsecurityio/poutine/results"
	"github.com/stretchr/testify/require"
)

func TestRuleDataSurvivesJSONExport(t *testing.T) {
	ctx := context.Background()
	engine, err := opa.NewOpa(ctx, &models.Config{})
	require.NoError(t, err)

	// Exercise the stock findings query and typed decoding before formatting.
	var report results.FindingsResult
	err = engine.Eval(ctx, `data.poutine.queries.findings.result with data.rules as {
		"example": {
			"rule": {"id": "example", "level": "warning"},
			"results": [{
				"rule_id": "example", "purl": "pkg:github/example/repo",
				"meta": {"path": "workflow.yml", "job": "build", "step": 2,
					"data": {"evidence_refs": ["job:build"],
						"context": {"permissions": null, "matches": [], "enabled": true}}}
			}]
		}
	}`, nil, &report)
	require.NoError(t, err)
	require.Len(t, report.Findings, 1)
	require.Equal(t, "2", report.Findings[0].Meta.Step)
	want := `{"evidence_refs":["job:build"],"context":{"permissions":null,"matches":[],"enabled":true}}`
	require.JSONEq(t, want, string(report.Findings[0].Meta.Data))

	packages := []*models.PackageInsights{{FindingsResults: report}}
	for _, withPath := range []bool{false, true} {
		name := "standard"
		if withPath {
			name = "with_path"
		}
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			formatter := NewFormat(engine, "json", &output)
			if withPath {
				err = formatter.FormatWithPath(ctx, packages, nil)
			} else {
				err = formatter.Format(ctx, packages)
			}
			require.NoError(t, err)
			var exported results.FindingsResult
			require.NoError(t, json.Unmarshal(output.Bytes(), &exported))
			require.Len(t, exported.Findings, 1)
			require.JSONEq(t, want, string(exported.Findings[0].Meta.Data))
		})
	}
}

func TestLegacyMetadataOmitsData(t *testing.T) {
	encoded, err := json.Marshal(results.FindingMeta{Job: "build"})
	require.NoError(t, err)
	require.JSONEq(t, `{"job":"build"}`, string(encoded))
}
