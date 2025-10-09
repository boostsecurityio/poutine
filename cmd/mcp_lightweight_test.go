package cmd

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/boostsecurityio/poutine/results"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLightweightMCPResponse tests that the MCP server responses are lightweight
// and don't include heavy fields like github_actions_workflows
func TestLightweightMCPResponse(t *testing.T) {
	ctx := context.Background()

	analyzer, err := createTestAnalyzer(ctx)
	require.NoError(t, err)

	t.Run("analyze_manifest returns lightweight response", func(t *testing.T) {
		request := NewCallToolRequest("analyze_manifest", map[string]interface{}{
			"content": `name: Test Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4`,
			"manifest_type": "github-actions",
		})

		result, err := handleAnalyzeManifest(ctx, request, analyzer)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.False(t, result.IsError)

		contentText := extractTextFromContent(t, result.Content[0])

		// Verify it doesn't contain heavy fields
		assert.NotContains(t, contentText, "github_actions_workflows")
		assert.NotContains(t, contentText, "github_actions_metadata")
		assert.NotContains(t, contentText, "azure_pipelines")
		assert.NotContains(t, contentText, "gitlabci_configs")
		assert.NotContains(t, contentText, "package_dependencies")
		assert.NotContains(t, contentText, "build_dependencies")

		// Verify it contains the essential fields
		assert.Contains(t, contentText, "findings")
		assert.Contains(t, contentText, "rules")

		// Parse and verify structure
		var response map[string]interface{}
		err = json.Unmarshal([]byte(contentText), &response)
		require.NoError(t, err)

		// Should only have findings and rules
		expectedFields := map[string]bool{
			"findings": true,
			"rules":    true,
		}

		for key := range response {
			_, expected := expectedFields[key]
			assert.True(t, expected, "Unexpected field '%s' in lightweight response", key)
		}
	})
}

// TestMCPResponseStructure verifies the new mcpAnalysisResponse structure
func TestMCPResponseStructure(t *testing.T) {
	// Create a sample response to verify JSON marshaling
	response := mcpAnalysisResponse{
		Findings:   []results.Finding{},
		Rules:      map[string]results.Rule{},
		Purl:       "pkg:github/owner/repo@main",
		Repository: "owner/repo",
		ScmType:    "github",
		GitRef:     "main",
		CommitSha:  "abc123",
		LastCommit: "2023-01-01T00:00:00Z",
	}

	data, err := json.Marshal(response)
	require.NoError(t, err)

	jsonStr := string(data)

	// Verify lightweight structure
	assert.Contains(t, jsonStr, "\"findings\":")
	assert.Contains(t, jsonStr, "\"rules\":")
	assert.Contains(t, jsonStr, "\"purl\":")
	assert.Contains(t, jsonStr, "\"repository\":")
	assert.Contains(t, jsonStr, "\"scm_type\":")
	assert.Contains(t, jsonStr, "\"git_ref\":")
	assert.Contains(t, jsonStr, "\"commit_sha\":")
	assert.Contains(t, jsonStr, "\"last_commit\":")

	// Verify it doesn't contain heavy fields
	assert.NotContains(t, jsonStr, "github_actions_workflows")
	assert.NotContains(t, jsonStr, "package_dependencies")
	assert.NotContains(t, jsonStr, "org_id")
	assert.NotContains(t, jsonStr, "repo_size")
	assert.NotContains(t, jsonStr, "forks_count")
	assert.NotContains(t, jsonStr, "stars_count")
}

// TestMCPResponseOmitsEmptyFields verifies that empty optional fields are omitted
func TestMCPResponseOmitsEmptyFields(t *testing.T) {
	response := mcpAnalysisResponse{
		Findings: []results.Finding{},
		Rules:    map[string]results.Rule{},
		// Leave repository metadata fields empty
	}

	data, err := json.Marshal(response)
	require.NoError(t, err)

	jsonStr := string(data)

	// These fields should be omitted when empty due to omitempty tag
	assert.NotContains(t, jsonStr, "\"purl\":")
	assert.NotContains(t, jsonStr, "\"repository\":")
	assert.NotContains(t, jsonStr, "\"scm_type\":")
	assert.NotContains(t, jsonStr, "\"git_ref\":")
	assert.NotContains(t, jsonStr, "\"commit_sha\":")
	assert.NotContains(t, jsonStr, "\"last_commit\":")

	// These required fields should always be present
	assert.Contains(t, jsonStr, "\"findings\":")
	assert.Contains(t, jsonStr, "\"rules\":")
}

// TestMCPResponseSizeReduction demonstrates the size reduction benefit
func TestMCPResponseSizeReduction(t *testing.T) {
	// This test documents the reduction in response size
	// by comparing what the old response would have contained vs new response

	lightweightResponse := mcpAnalysisResponse{
		Findings:   []results.Finding{},
		Rules:      map[string]results.Rule{},
		Purl:       "pkg:github/test/repo@main",
		Repository: "test/repo",
		ScmType:    "github",
		GitRef:     "main",
		CommitSha:  "abc123",
		LastCommit: "2023-01-01T00:00:00Z",
	}

	lightweightData, err := json.Marshal(lightweightResponse)
	require.NoError(t, err)

	t.Logf("Lightweight response size: %d bytes", len(lightweightData))
	t.Logf("Lightweight response: %s", string(lightweightData))

	// The lightweight response should be significantly smaller than a full PackageInsights response
	// which would include many more fields like workflows, dependencies, repo stats, etc.
	assert.Less(t, len(lightweightData), 1000, "Lightweight response should be under 1KB for empty findings")
}
