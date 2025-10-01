package cmd

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/boostsecurityio/poutine/results"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func NewCallToolRequest(name string, args map[string]interface{}) mcp.CallToolRequest {
	return mcp.CallToolRequest{
		Request: mcp.Request{
			Method: "tools/call",
		},
		Params: mcp.CallToolParams{
			Name:      name,
			Arguments: args,
		},
	}
}

func TestHandleAnalyzeManifestBasic(t *testing.T) {
	ctx := context.Background()

	t.Run("valid github actions manifest", func(t *testing.T) {
		request := NewCallToolRequest("analyze_manifest", map[string]interface{}{
			"content": `name: Test Workflow
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run tests
        run: echo "Running tests"`,
			"manifest_type": "github-actions",
		})

		result, err := handleAnalyzeManifest(ctx, request)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.False(t, result.IsError)

		// Extract the JSON content
		require.Len(t, result.Content, 1)

		// Use reflection or type assertion to get the text content
		contentText := extractTextFromContent(t, result.Content[0])
		require.NotEmpty(t, contentText)

		var insights struct {
			Findings []results.Finding       `json:"findings"`
			Rules    map[string]results.Rule `json:"rules"`
		}
		err = json.Unmarshal([]byte(contentText), &insights)
		require.NoError(t, err)

		assert.Greater(t, len(insights.Rules), 0, "Should return rules")
		assert.Empty(t, insights.Findings, "Should return empty findings array")
	})

	t.Run("missing content parameter", func(t *testing.T) {
		request := NewCallToolRequest("analyze_manifest", map[string]interface{}{
			"manifest_type": "github-actions",
			// missing content
		})

		result, err := handleAnalyzeManifest(ctx, request)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.IsError)

		contentText := extractTextFromContent(t, result.Content[0])
		assert.Contains(t, contentText, "content parameter is required")
	})

	t.Run("vulnerable github actions workflow", func(t *testing.T) {
		request := NewCallToolRequest("analyze_manifest", map[string]interface{}{
			"content": `name: Vulnerable Workflow
on: pull_request_target

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - name: Vulnerable command  
        run: |
          curl -fsSL https://example.com/script.sh | bash
          echo "${{ github.event.pull_request.title }}" | bash`,
			"manifest_type": "github-actions",
		})

		result, err := handleAnalyzeManifest(ctx, request)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.False(t, result.IsError)

		contentText := extractTextFromContent(t, result.Content[0])
		require.NotEmpty(t, contentText)

		// Parse the combined response structure that includes separate findings and rules
		var response struct {
			Findings []results.Finding       `json:"findings"`
			Rules    map[string]results.Rule `json:"rules"`
		}
		err = json.Unmarshal([]byte(contentText), &response)
		require.NoError(t, err)

		// Should detect vulnerabilities
		assert.Len(t, response.Findings, 3, "Should detect security vulnerabilities")
		assert.Greater(t, len(response.Rules), 0)
	})

}

func TestHandleAnalyzeManifestDifferentTypes(t *testing.T) {
	ctx := context.Background()

	t.Run("gitlab ci manifest", func(t *testing.T) {
		request := NewCallToolRequest("analyze_manifest", map[string]interface{}{
			"content": `stages:
  - build
  - test

build_job:
  stage: build
  script:
    - echo "Building"

test_job:
  stage: test
  script:
    - echo "Testing"`,
			"manifest_type": "gitlab-ci",
		})

		result, err := handleAnalyzeManifest(ctx, request)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.False(t, result.IsError)

		contentText := extractTextFromContent(t, result.Content[0])
		var insights struct {
			Findings []results.Finding       `json:"findings"`
			Rules    map[string]results.Rule `json:"rules"`
		}
		err = json.Unmarshal([]byte(contentText), &insights)
		require.NoError(t, err)

		assert.Greater(t, len(insights.Rules), 0)
		assert.Len(t, insights.Findings, 0, "Should parse GitLab CI config")
	})

	t.Run("azure pipelines manifest", func(t *testing.T) {
		request := NewCallToolRequest("analyze_manifest", map[string]interface{}{
			"content": `trigger:
  - main

pool:
  vmImage: ubuntu-latest

steps:
  - task: UseDotNet@2
    inputs:
      version: '6.0.x'
  - script: dotnet build`,
			"manifest_type": "azure-pipelines",
		})

		result, err := handleAnalyzeManifest(ctx, request)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.False(t, result.IsError)

		contentText := extractTextFromContent(t, result.Content[0])
		var insights struct {
			Findings []results.Finding       `json:"findings"`
			Rules    map[string]results.Rule `json:"rules"`
		}
		err = json.Unmarshal([]byte(contentText), &insights)
		require.NoError(t, err)

		assert.Greater(t, len(insights.Rules), 0)
		assert.Len(t, insights.Findings, 0, "Should parse Azure Pipeline")
	})
}

// Helper function to extract text content from mcp.Content
func extractTextFromContent(t *testing.T, content mcp.Content) string {
	contentJSON, err := json.Marshal(content)
	require.NoError(t, err)

	var contentMap map[string]interface{}
	err = json.Unmarshal(contentJSON, &contentMap)
	require.NoError(t, err)

	if text, ok := contentMap["text"].(string); ok {
		return text
	}

	t.Fatalf("Could not extract text from content: %+v", contentMap)
	return ""
}

// TestHandleAnalyzeManifestEndToEnd tests the complete workflow
func TestHandleAnalyzeManifestEndToEnd(t *testing.T) {
	ctx := context.Background()

	// Test a realistic scenario
	request := NewCallToolRequest("analyze_manifest", map[string]interface{}{
		"content": `
on: pull_request_target
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout untrusted code
      uses: actions/checkout@v4
      with:
        repository: ${{ github.event.pull_request.head.repo.full_name }}
        ref: ${{ github.event.pull_request.head.sha }}
    - name: Install dependencies
      run: npm install
    - name: Run linting script
      id: lint
      env:
        LINTING_TOOL_API_KEY: ${{ secrets.LINTING_TOOL_API_KEY }}
      run: |
        echo "results<<EOF" >> "${GITHUB_OUTPUT}"
        echo "$(npm run lint)" >> "${GITHUB_OUTPUT}"
        echo "EOF" >> "${GITHUB_OUTPUT}"
    - name: Output linting results to Pull Request
      uses: actions/github-script@v7
      with:
        script: |
          github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: "👋 Thanks for your contribution.\nHere are the linting results:\n${{ steps.lint.outputs.results }}"
          })`,
		"manifest_type": "github-actions",
	})

	result, err := handleAnalyzeManifest(ctx, request)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsError)

	contentText := extractTextFromContent(t, result.Content[0])
	require.NotEmpty(t, contentText)

	var insights struct {
		Findings []results.Finding       `json:"findings"`
		Rules    map[string]results.Rule `json:"rules"`
	}
	err = json.Unmarshal([]byte(contentText), &insights)
	require.NoError(t, err)

	assert.Len(t, insights.Findings, 3, "Found findings")

	t.Logf("Successfully analyzed manifest with %d findings", len(insights.Findings))
}
