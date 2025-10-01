package analyze

import (
	"context"
	"strings"
	"testing"

	"github.com/boostsecurityio/poutine/formatters/noop"
	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestOpa creates an OPA client for testing
func newTestOpa(ctx context.Context) (*opa.Opa, error) {
	config := models.DefaultConfig()
	opaClient, err := opa.NewOpa(ctx, config)
	if err != nil {
		return nil, err
	}
	return opaClient, nil
}

func TestAnalyzeManifestDirectly(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		content        string
		manifestType   string
		expectedType   string
		validateResult func(t *testing.T, insights *models.PackageInsights)
	}{
		{
			name: "valid github actions workflow",
			content: `name: Test Workflow
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run tests
        run: echo "Running tests"`,
			manifestType: "github-actions",
			expectedType: "github-actions",
			validateResult: func(t *testing.T, insights *models.PackageInsights) {
				assert.Equal(t, "manifest", insights.SourceScmType)
				assert.Contains(t, insights.Purl, "pkg:generic/github-actions-workflow")
				assert.Equal(t, "YAML", insights.PrimaryLanguage)
				assert.Equal(t, 1, len(insights.GithubActionsWorkflows), "Should detect GitHub Actions workflow")
			},
		},
		{
			name: "valid gitlab ci config",
			content: `stages:
  - build
  - test

variables:
  DOCKER_DRIVER: overlay2

build_job:
  stage: build
  script:
    - echo "Building application"

test_job:
  stage: test
  script:
    - echo "Running tests"`,
			manifestType: "gitlab-ci",
			expectedType: "gitlab-ci",
			validateResult: func(t *testing.T, insights *models.PackageInsights) {
				assert.Equal(t, "manifest", insights.SourceScmType)
				assert.Contains(t, insights.Purl, "pkg:generic/gitlab-ci-config")
				assert.Equal(t, 1, len(insights.GitlabciConfigs), "Should detect GitLab CI config")
			},
		},
		{
			name: "vulnerable github actions workflow",
			content: `name: Vulnerable Workflow
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
			manifestType: "github-actions",
			expectedType: "github-actions",
			validateResult: func(t *testing.T, insights *models.PackageInsights) {
				assert.Contains(t, insights.Purl, "pkg:generic/github-actions-workflow")
				assert.Equal(t, 1, len(insights.GithubActionsWorkflows), "Should detect workflow")

				workflow := insights.GithubActionsWorkflows[0]
				assert.Equal(t, "Vulnerable Workflow", workflow.Name)

				assert.Equal(t, len(insights.FindingsResults.Findings), 3, "May have security findings for vulnerable workflow")
			},
		},
		{
			name: "azure pipelines config",
			content: `trigger:
  - main

pool:
  vmImage: ubuntu-latest

steps:
  - task: UseDotNet@2
    displayName: 'Install .NET'
    inputs:
      version: '6.0.x'

  - script: dotnet build
    displayName: 'Build application'`,
			manifestType: "azure-pipelines",
			expectedType: "azure-pipelines",
			validateResult: func(t *testing.T, insights *models.PackageInsights) {
				assert.Contains(t, insights.Purl, "pkg:generic/azure-pipelines-config")
				assert.Len(t, insights.AzurePipelines, 1, "Should detect Azure Pipeline")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opaClient, err := newTestOpa(ctx)
			require.NoError(t, err, "Failed to create OPA client")

			formatter := &noop.Format{}
			analyzer := NewAnalyzer(nil, nil, formatter, models.DefaultConfig(), opaClient)

			manifestReader := strings.NewReader(tt.content)
			result, err := analyzer.AnalyzeManifest(ctx, manifestReader, tt.manifestType)

			require.NoError(t, err, "AnalyzeManifest should not return an error")
			require.NotNil(t, result, "Result should not be nil")

			if tt.validateResult != nil {
				tt.validateResult(t, result)
			}
		})
	}
}

func TestAnalyzeManifestErrorHandling(t *testing.T) {
	ctx := context.Background()

	opaClient, err := newTestOpa(ctx)
	require.NoError(t, err)

	formatter := &noop.Format{}
	analyzer := NewAnalyzer(nil, nil, formatter, models.DefaultConfig(), opaClient)

	t.Run("empty content", func(t *testing.T) {
		manifestReader := strings.NewReader("")
		result, err := analyzer.AnalyzeManifest(ctx, manifestReader, "github-actions")

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "manifest", result.SourceScmType)
	})

	t.Run("invalid yaml", func(t *testing.T) {
		invalidYaml := `name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: "Unclosed quote
        run: echo "test"`

		manifestReader := strings.NewReader(invalidYaml)
		result, err := analyzer.AnalyzeManifest(ctx, manifestReader, "github-actions")

		require.NoError(t, err)
		require.NotNil(t, result)
	})
}
