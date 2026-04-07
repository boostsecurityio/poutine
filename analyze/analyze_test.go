package analyze

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
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
		return nil, fmt.Errorf("failed to create opa client: %w", err)
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
				assert.Len(t, insights.GithubActionsWorkflows, 1, "Should detect GitHub Actions workflow")
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
				assert.Len(t, insights.GitlabciConfigs, 1, "Should detect GitLab CI config")
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
				assert.Len(t, insights.GithubActionsWorkflows, 1, "Should detect workflow")

				workflow := insights.GithubActionsWorkflows[0]
				assert.Equal(t, "Vulnerable Workflow", workflow.Name)

				assert.Len(t, insights.FindingsResults.Findings, 3, "May have security findings for vulnerable workflow")
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

// mockObserver records observer events for testing.
type mockObserver struct {
	mu     sync.Mutex
	events []string
}

func (m *mockObserver) OnDiscoveryCompleted(org string, totalCount int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, fmt.Sprintf("discovery_completed:%s:%d", org, totalCount))
}
func (m *mockObserver) OnRepoStarted(repo string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, "repo_started:"+repo)
}
func (m *mockObserver) OnRepoCompleted(repo string, _ *models.PackageInsights) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, "repo_completed:"+repo)
}
func (m *mockObserver) OnRepoError(repo string, _ error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, "repo_error:"+repo)
}
func (m *mockObserver) OnRepoSkipped(repo string, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, fmt.Sprintf("repo_skipped:%s:%s", repo, reason))
}
func (m *mockObserver) OnFinalizeStarted(total int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, fmt.Sprintf("finalize_started:%d", total))
}
func (m *mockObserver) OnFinalizeCompleted() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, "finalize_completed")
}

func TestProgressObserverNilSafe(t *testing.T) {
	ctx := context.Background()
	opaClient, err := newTestOpa(ctx)
	require.NoError(t, err)

	// Observer is nil — should not panic
	analyzer := NewAnalyzer(nil, nil, &noop.Format{}, models.DefaultConfig(), opaClient)
	assert.Nil(t, analyzer.Observer)

	// AnalyzeManifest doesn't use observer, but this ensures nil Observer doesn't crash
	_, err = analyzer.AnalyzeManifest(ctx, strings.NewReader("on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4"), "github-actions")
	require.NoError(t, err)
}

func TestProgressObserverInterface(t *testing.T) {
	obs := &mockObserver{}

	// Verify the interface is implemented
	var _ ProgressObserver = obs
	var _ ProgressObserver = &noopObserver{}
	var _ ProgressObserver = &ProgressBarObserver{}

	// Test mock records events
	obs.OnDiscoveryCompleted("test-org", 10)
	obs.OnRepoStarted("test-org/repo1")
	obs.OnRepoCompleted("test-org/repo1", nil)
	obs.OnRepoSkipped("test-org/repo2", "fork")
	obs.OnRepoError("test-org/repo3", errors.New("clone failed"))
	obs.OnFinalizeStarted(1)
	obs.OnFinalizeCompleted()

	assert.Equal(t, []string{
		"discovery_completed:test-org:10",
		"repo_started:test-org/repo1",
		"repo_completed:test-org/repo1",
		"repo_skipped:test-org/repo2:fork",
		"repo_error:test-org/repo3",
		"finalize_started:1",
		"finalize_completed",
	}, obs.events)
}

func TestProgressObserverConcurrency(t *testing.T) {
	// Exercise the concurrent methods on both observer implementations
	// to verify no data races. Run with: go test -race
	observers := []ProgressObserver{
		&mockObserver{},
		NewProgressBarObserver(true),
	}

	for _, obs := range observers {
		obs.OnDiscoveryCompleted("org", 100)

		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				repo := fmt.Sprintf("org/repo-%d", n)
				obs.OnRepoStarted(repo)
				if n%5 == 0 {
					obs.OnRepoError(repo, errors.New("error"))
				} else {
					obs.OnRepoCompleted(repo, nil)
				}
			}(i)
		}
		wg.Wait()

		obs.OnFinalizeStarted(40)
		obs.OnFinalizeCompleted()
	}
}
