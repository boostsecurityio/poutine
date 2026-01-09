package sarif

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/results"
	"github.com/stretchr/testify/require"
)

func TestSarifFormat(t *testing.T) {
	// Create a test package with findings
	pkg := &models.PackageInsights{
		Purl:               "pkg:github/test/repo@1.0.0",
		SourceGitRepo:      "test/repo",
		SourceGitCommitSha: "abc123",
		SourceGitRef:       "main",
		SourceScmType:      "github",
		FindingsResults: results.FindingsResult{
			Findings: []results.Finding{
				{
					RuleId: "test_rule",
					Purl:   "pkg:github/test/repo@1.0.0",
					Meta: results.FindingMeta{
						Path: ".github/workflows/test.yml",
						Line: 10,
					},
				},
			},
			Rules: map[string]results.Rule{
				"test_rule": {
					Id:          "test_rule",
					Title:       "Test Rule",
					Description: "This is a test rule",
					Level:       "warning",
				},
			},
		},
	}

	var buf bytes.Buffer
	formatter := NewFormat(&buf, "1.0.0")
	err := formatter.Format(context.Background(), []*models.PackageInsights{pkg})
	require.NoError(t, err)

	// Parse the generated SARIF
	var sarifOutput map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &sarifOutput)
	require.NoError(t, err)

	// Validate the structure
	runs, ok := sarifOutput["runs"].([]interface{})
	require.True(t, ok, "runs should be an array")
	require.Len(t, runs, 1)

	run, ok := runs[0].(map[string]interface{})
	require.True(t, ok)

	// Check tool.driver.supportedTaxonomies
	tool, ok := run["tool"].(map[string]interface{})
	require.True(t, ok)
	driver, ok := tool["driver"].(map[string]interface{})
	require.True(t, ok)

	supportedTaxonomies, ok := driver["supportedTaxonomies"].([]interface{})
	require.True(t, ok, "supportedTaxonomies should be an array")
	require.Len(t, supportedTaxonomies, 1)

	taxonomy, ok := supportedTaxonomies[0].(map[string]interface{})
	require.True(t, ok)

	// Validate that index is an integer (not null)
	index, exists := taxonomy["index"]
	require.True(t, exists, "index field should exist")
	require.NotNil(t, index, "index should not be null")
	indexFloat, ok := index.(float64)
	require.True(t, ok, "index should be a number")
	require.InDelta(t, float64(0), indexFloat, 0.0001, "index should be 0 for the first taxonomy")

	// Validate that guid is either a string or omitted (not null)
	if guid, exists := taxonomy["guid"]; exists {
		require.NotNil(t, guid, "guid should not be null if present")
	}

	// Check taxonomies array
	taxonomies, ok := run["taxonomies"].([]interface{})
	require.True(t, ok, "taxonomies should be an array")
	require.Len(t, taxonomies, 1)

	taxonomyItem, ok := taxonomies[0].(map[string]interface{})
	require.True(t, ok)

	// Validate that rules is an array (not null)
	rulesField, exists := taxonomyItem["rules"]
	require.True(t, exists, "rules field should exist in taxonomy")
	require.NotNil(t, rulesField, "rules should not be null")
	_, ok = rulesField.([]interface{})
	require.True(t, ok, "rules should be an array")
}

func TestIsValidGitURL(t *testing.T) {
	tests := []struct {
		name    string
		gitURL  string
		isValid bool
	}{
		{
			name:    "Valid HTTPS Git URL",
			gitURL:  "https://github.com/user/repo.git",
			isValid: true,
		},
		{
			name:    "Valid SSH Git URL",
			gitURL:  "ssh://git@bitbucket.org/user/repo.git",
			isValid: true,
		},
		{
			name:    "Valid Git URL without .git",
			gitURL:  "https://gitlab.com/user/repo",
			isValid: true,
		},
		{
			name:    "Invalid Git URL - missing scheme",
			gitURL:  "github.com/user/repo.git",
			isValid: false,
		},
		{
			name:    "Invalid Git URL - empty",
			gitURL:  "",
			isValid: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := IsValidGitURL(tt.gitURL)
			require.Equal(t, tt.isValid, isValid)
		})
	}
}

// TestSarifFormatIssue384 validates that the fix for issue #384 works correctly.
// This test uses the exact workflow YAML from the issue report to ensure
// the SARIF output would be accepted by GitHub's CodeQL upload action.
func TestSarifFormatIssue384(t *testing.T) {
	// Create a test package with a finding in the workflow from issue #384
	pkg := &models.PackageInsights{
		Purl:               "pkg:github/coveo/test-repo@1.0.0",
		SourceGitRepo:      "coveo/test-repo",
		SourceGitCommitSha: "fcd6c2d5b2c2d8366e13b7415780831017e0ecae",
		SourceGitRef:       "refs/pull/482/merge",
		SourceScmType:      "github",
		FindingsResults: results.FindingsResult{
			Findings: []results.Finding{
				{
					RuleId: "unsafe_checkout",
					Purl:   "pkg:github/coveo/test-repo@1.0.0",
					Meta: results.FindingMeta{
						Path: "testdata/.github/workflows/issue-384.yml",
						Line: 29,
						Job:  "poutine",
						Step: "3",
					},
				},
			},
			Rules: map[string]results.Rule{
				"unsafe_checkout": {
					Id:          "unsafe_checkout",
					Title:       "Unsafe Checkout",
					Description: "Potential code injection via untrusted checkout",
					Level:       "warning",
				},
			},
		},
	}

	var buf bytes.Buffer
	formatter := NewFormat(&buf, "1.0.0")
	err := formatter.Format(context.Background(), []*models.PackageInsights{pkg})
	require.NoError(t, err)

	// Parse the generated SARIF
	var sarifOutput map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &sarifOutput)
	require.NoError(t, err)

	// Validate critical fields that caused issue #384
	runs, ok := sarifOutput["runs"].([]interface{})
	require.True(t, ok, "runs should be an array")
	require.Len(t, runs, 1)

	run, ok := runs[0].(map[string]interface{})
	require.True(t, ok)

	// Verify supportedTaxonomies structure
	tool, ok := run["tool"].(map[string]interface{})
	require.True(t, ok)
	driver, ok := tool["driver"].(map[string]interface{})
	require.True(t, ok)

	supportedTaxonomies, ok := driver["supportedTaxonomies"].([]interface{})
	require.True(t, ok, "supportedTaxonomies should be an array")
	require.Len(t, supportedTaxonomies, 1)

	taxonomy, ok := supportedTaxonomies[0].(map[string]interface{})
	require.True(t, ok)

	// Issue #384: index must be an integer, not null
	index, exists := taxonomy["index"]
	require.True(t, exists, "index field should exist")
	require.NotNil(t, index, "index should not be null (issue #384)")
	indexFloat, ok := index.(float64)
	require.True(t, ok, "index should be a number (issue #384)")
	require.InDelta(t, float64(0), indexFloat, 0.0001, "index should be 0")

	// Issue #384: guid must be a string, not null
	guid, exists := taxonomy["guid"]
	require.True(t, exists, "guid field should exist")
	require.NotNil(t, guid, "guid should not be null (issue #384)")
	guidStr, ok := guid.(string)
	require.True(t, ok, "guid should be a string (issue #384)")
	require.NotEmpty(t, guidStr, "guid should not be empty")

	// Verify taxonomies structure
	taxonomies, ok := run["taxonomies"].([]interface{})
	require.True(t, ok, "taxonomies should be an array")
	require.Len(t, taxonomies, 1)

	taxonomyItem, ok := taxonomies[0].(map[string]interface{})
	require.True(t, ok)

	// Issue #384: rules must be an array, not null
	rulesField, exists := taxonomyItem["rules"]
	require.True(t, exists, "rules field should exist in taxonomy")
	require.NotNil(t, rulesField, "rules should not be null (issue #384)")
	rulesArray, ok := rulesField.([]interface{})
	require.True(t, ok, "rules should be an array (issue #384)")
	require.NotNil(t, rulesArray, "rules array should not be nil")
}
