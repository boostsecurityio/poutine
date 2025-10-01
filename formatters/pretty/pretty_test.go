package pretty

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/results"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormat(t *testing.T) {
	tests := []struct {
		name     string
		packages []*models.PackageInsights
		expected []string // strings that should be present in output
	}{
		{
			name: "no findings",
			packages: []*models.PackageInsights{
				{
					FindingsResults: results.FindingsResult{
						Findings: []results.Finding{},
						Rules:    map[string]results.Rule{},
					},
				},
			},
			expected: []string{
				"Summary of findings:",
			},
		},
		{
			name: "single finding",
			packages: []*models.PackageInsights{
				{
					FindingsResults: results.FindingsResult{
						Findings: []results.Finding{
							{
								RuleId: "test-rule-1",
								Purl:   "pkg:github/test/repo@v1.0.0",
								Meta: results.FindingMeta{
									Path: "test.yml",
									Line: 42,
								},
							},
						},
						Rules: map[string]results.Rule{
							"test-rule-1": {
								Id:          "test-rule-1",
								Title:       "Test Rule",
								Level:       "warning",
								Description: "This is a test rule",
							},
						},
					},
				},
			},
			expected: []string{
				"Rule: Test Rule",
				"Severity: warning",
				"Description: This is a test rule",
				"Documentation: https://boostsecurityio.github.io/poutine/rules/test-rule-1",
				"REPOSITORY", "DETAILS", "URL", // table headers
				"test/repo",
				"test.yml",
				"Summary of findings:",
				"test-rule-1", "Test Rule", "1", "Failed",
			},
		},
		{
			name: "multiple findings same rule",
			packages: []*models.PackageInsights{
				{
					FindingsResults: results.FindingsResult{
						Findings: []results.Finding{
							{
								RuleId: "test-rule-1",
								Purl:   "pkg:github/test/repo1@v1.0.0",
								Meta: results.FindingMeta{
									Path: "test1.yml",
									Line: 10,
								},
							},
							{
								RuleId: "test-rule-1",
								Purl:   "pkg:github/test/repo2@v2.0.0",
								Meta: results.FindingMeta{
									Path: "test2.yml",
									Line: 20,
								},
							},
						},
						Rules: map[string]results.Rule{
							"test-rule-1": {
								Id:          "test-rule-1",
								Title:       "Test Rule",
								Level:       "error",
								Description: "This is a test rule",
							},
						},
					},
				},
			},
			expected: []string{
				"Rule: Test Rule",
				"Severity: error",
				"test/repo1",
				"test1.yml",
				"test/repo2",
				"test2.yml",
				"test-rule-1", "Test Rule", "2", "Failed",
			},
		},
		{
			name: "multiple rules",
			packages: []*models.PackageInsights{
				{
					FindingsResults: results.FindingsResult{
						Findings: []results.Finding{
							{
								RuleId: "rule-a",
								Purl:   "pkg:github/test/repo@v1.0.0",
								Meta:   results.FindingMeta{Path: "test.yml"},
							},
							{
								RuleId: "rule-b",
								Purl:   "pkg:github/test/repo@v1.0.0",
								Meta:   results.FindingMeta{Job: "test-job"},
							},
						},
						Rules: map[string]results.Rule{
							"rule-a": {
								Id:          "rule-a",
								Title:       "Rule A",
								Level:       "info",
								Description: "First rule",
							},
							"rule-b": {
								Id:          "rule-b",
								Title:       "Rule B",
								Level:       "warning",
								Description: "Second rule",
							},
						},
					},
				},
			},
			expected: []string{
				"Rule: Rule A",
				"Severity: info",
				"Rule: Rule B",
				"Severity: warning",
				"Job: test-job",
				"rule-a", "Rule A", "1", "Failed",
				"rule-b", "Rule B", "1", "Failed",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format := &Format{}

			// Capture output by temporarily redirecting stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			err := format.Format(context.Background(), tt.packages)
			require.NoError(t, err)

			w.Close()
			os.Stdout = oldStdout

			output := make([]byte, 1024*1024) // 1MB buffer should be enough
			n, _ := r.Read(output)
			outputStr := string(output[:n])

			// Check that all expected strings are present
			for _, expected := range tt.expected {
				assert.Contains(t, outputStr, expected, "Expected output to contain: %s", expected)
			}

			// Basic structure checks
			if len(tt.packages) > 0 && len(tt.packages[0].FindingsResults.Findings) > 0 {
				// Should contain table structure indicators (Unicode box drawing characters)
				assert.Contains(t, outputStr, "┌", "Output should contain table borders")
				assert.Contains(t, outputStr, "│", "Output should contain table separators")
			}
		})
	}
}

func TestFormatWithPath(t *testing.T) {
	packages := []*models.PackageInsights{
		{
			FindingsResults: results.FindingsResult{
				Findings: []results.Finding{
					{
						RuleId: "test-rule-1",
						Purl:   "pkg:github/test/repo@v1.0.0",
						Meta: results.FindingMeta{
							Path: "workflow1.yml",
						},
					},
				},
				Rules: map[string]results.Rule{
					"test-rule-1": {
						Id:          "test-rule-1",
						Title:       "Test Rule",
						Level:       "warning",
						Description: "Test description",
					},
				},
			},
		},
	}

	pathAssociations := map[string][]*models.RepoInfo{
		"workflow1": {
			{
				RepoName: "test/repo",
				Purl:     "pkg:github/test/repo@v1.0.0",
				BranchInfos: []models.BranchInfo{
					{
						BranchName: "main",
						FilePath:   []string{"workflow1.yml"},
					},
				},
			},
		},
	}

	format := &Format{}

	// Capture output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := format.FormatWithPath(context.Background(), packages, pathAssociations)
	require.NoError(t, err)

	w.Close()
	os.Stdout = oldStdout

	output := make([]byte, 1024*1024)
	n, _ := r.Read(output)
	outputStr := string(output[:n])

	// Check expected content
	expectedStrings := []string{
		"WORKFLOW SHA", "RULE", "LOCATION", "URL", // table headers
		"workflow1",
		"test-rule-1",
		"test/repo/main",
		"Summary of findings:",
		"test-rule-1", "Test Rule", "1", "Failed",
	}

	for _, expected := range expectedStrings {
		assert.Contains(t, outputStr, expected, "Expected output to contain: %s", expected)
	}

	// Table structure checks (Unicode box drawing characters)
	assert.Contains(t, outputStr, "┌", "Output should contain table borders")
	assert.Contains(t, outputStr, "│", "Output should contain table separators")
}

func TestSummaryTableRendering(t *testing.T) {
	// Test that the summary table renders with proper column widths and formatting
	packages := []*models.PackageInsights{
		{
			FindingsResults: results.FindingsResult{
				Findings: []results.Finding{
					{
						RuleId: "very-long-rule-name-that-should-test-column-width-handling",
						Purl:   "pkg:github/test/repo@v1.0.0",
						Meta:   results.FindingMeta{Path: "test.yml"},
					},
				},
				Rules: map[string]results.Rule{
					"very-long-rule-name-that-should-test-column-width-handling": {
						Id:          "very-long-rule-name-that-should-test-column-width-handling",
						Title:       "Very Long Rule Title That Should Test Column Width Handling And Word Wrapping Behavior",
						Level:       "error",
						Description: "A very long description that should test how the table handles long text content",
					},
				},
			},
		},
	}

	format := &Format{}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := format.Format(context.Background(), packages)
	require.NoError(t, err)

	w.Close()
	os.Stdout = oldStdout

	output := make([]byte, 1024*1024)
	n, _ := r.Read(output)
	outputStr := string(output[:n])

	// Check that long content is handled properly
	assert.Contains(t, outputStr, "very-long-rule-name-that-should-test-column-width-handling")
	assert.Contains(t, outputStr, "Very Long Rule Title")

	// Verify table structure is maintained despite long content
	lines := strings.Split(outputStr, "\n")
	var summaryTableFound bool
	for _, line := range lines {
		if strings.Contains(line, "Summary of findings:") {
			summaryTableFound = true
			break
		}
	}
	assert.True(t, summaryTableFound, "Summary table should be present")
}
