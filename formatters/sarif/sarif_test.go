package sarif

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/boostsecurityio/poutine/results"
	. "github.com/boostsecurityio/poutine/scanner"
	"github.com/stretchr/testify/require"
)

// TestSarifFormatBuildDependencyFindings validates that findings keyed by a
// build dependency purl are included in the SARIF output. This exercises
// the formatter's BuildDependencies lookup path.
func TestSarifFormatBuildDependencyFindings(t *testing.T) {
	actionPurl := "pkg:githubactions/unverified-owner/some-action"
	pkgPurl := "pkg:github/test/repo@main"
	pkg := &models.PackageInsights{
		Purl:              pkgPurl,
		SourceGitRepo:     "test/repo",
		SourceGitRef:      "main",
		SourceScmType:     "github",
		BuildDependencies: []string{actionPurl + "@v1.0"},
		FindingsResults: results.FindingsResult{
			Findings: []results.Finding{
				{
					RuleId: "github_action_from_unverified_creator_used",
					// Finding keyed by the build dependency purl (version stripped
					// by the rego rule). This tests the BuildDependencies lookup.
					Purl: actionPurl,
					Meta: results.FindingMeta{
						Path:    ".github/workflows/ci.yml",
						Line:    5,
						Job:     "build",
						Step:    "2",
						Details: "unverified-owner/some-action@v1.0",
					},
				},
			},
			Rules: map[string]results.Rule{
				"github_action_from_unverified_creator_used": {
					Id:          "github_action_from_unverified_creator_used",
					Title:       "Github Action from Unverified Creator used",
					Description: "Usage of GitHub Actions from unverified creators was detected.",
					Level:       "note",
				},
			},
		},
	}

	var buf bytes.Buffer
	formatter := NewFormat(&buf, "1.0.0")
	err := formatter.Format(context.Background(), []*models.PackageInsights{pkg})
	require.NoError(t, err)

	var sarifOutput map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &sarifOutput)
	require.NoError(t, err)

	runs, ok := sarifOutput["runs"].([]interface{})
	require.True(t, ok)
	require.Len(t, runs, 1)

	run, ok := runs[0].(map[string]interface{})
	require.True(t, ok)

	sarifResults, ok := run["results"].([]interface{})
	require.True(t, ok, "results should be present in the SARIF run")
	require.Len(t, sarifResults, 1, "build dependency finding should appear in SARIF output")

	result, ok := sarifResults[0].(map[string]interface{})
	require.True(t, ok)

	// Verify fingerprint exists
	partialFingerprints, ok := result["partialFingerprints"].(map[string]interface{})
	require.True(t, ok, "partialFingerprints should be present")
	_, exists := partialFingerprints["poutineFingerprint"]
	require.True(t, exists, "poutineFingerprint should be present")
	require.Equal(t, "github_action_from_unverified_creator_used", result["ruleId"])

	locations, ok := result["locations"].([]interface{})
	require.True(t, ok, "locations should be present")
	require.Len(t, locations, 1)

	location, ok := locations[0].(map[string]interface{})
	require.True(t, ok)

	physicalLocation, ok := location["physicalLocation"].(map[string]interface{})
	require.True(t, ok)

	artifactLocation, ok := physicalLocation["artifactLocation"].(map[string]interface{})
	require.True(t, ok)
	uri, ok := artifactLocation["uri"].(string)
	require.True(t, ok, "uri should be a string")
	require.Equal(t, ".github/workflows/ci.yml", uri, "uri should be the workflow file path")

	region, ok := physicalLocation["region"].(map[string]interface{})
	require.True(t, ok)
	startLine, ok := region["startLine"].(float64)
	require.True(t, ok, "startLine should be a number")
	require.InDelta(t, float64(5), startLine, 0.0001, "startLine should match the finding line")
}

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
// This test scans the actual workflow YAML from the issue report to ensure
// the SARIF output would be accepted by GitHub's CodeQL upload action.
func TestSarifFormatIssue384(t *testing.T) {
	// Scan the testdata directory containing the workflow from issue #384
	scanner := NewInventoryScanner("testdata")
	pkg := &models.PackageInsights{
		Purl:          "pkg:github/coveo/test-repo",
		SourceGitRepo: "coveo/test-repo",
		SourceGitRef:  "refs/pull/482/merge",
		SourceScmType: "github",
	}
	err := scanner.Run(pkg)
	require.NoError(t, err)

	// Verify the workflow was found
	require.NotEmpty(t, pkg.GithubActionsWorkflows, "should have found the issue-384 workflow")

	// Find the issue-384 workflow
	var foundWorkflow bool
	for _, wf := range pkg.GithubActionsWorkflows {
		if wf.Path == ".github/workflows/issue-384.yml" {
			foundWorkflow = true
			break
		}
	}
	require.True(t, foundWorkflow, "should have found issue-384.yml workflow")

	// Analyze with OPA to generate findings (using a basic config)
	opaInstance, err := opa.NewOpa(context.Background(), &models.Config{
		Include: []models.ConfigInclude{},
	})
	require.NoError(t, err)

	inventory := NewInventory(opaInstance, nil, "", "")
	scannedPkg, err := inventory.ScanPackage(context.Background(), *pkg, "testdata")
	require.NoError(t, err)

	// Generate SARIF output
	var buf bytes.Buffer
	formatter := NewFormat(&buf, "1.0.0")
	err = formatter.Format(context.Background(), []*models.PackageInsights{scannedPkg})
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
