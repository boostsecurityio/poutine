package scanner

import (
	"context"
	"testing"

	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGithubWorkflows(t *testing.T) {
	s := NewInventoryScanner("testdata")
	pkgInsights := &models.PackageInsights{}
	err := s.Run(pkgInsights)
	workflows := pkgInsights.GithubActionsWorkflows

	assert.Nil(t, err)

	paths := []string{}
	for _, workflow := range workflows {
		paths = append(paths, workflow.Path)
	}
	assert.ElementsMatch(t, paths, []string{
		".github/workflows/debug_enabled_valid.yml",
		".github/workflows/valid.yml",
		".github/workflows/matrix.yml",
		".github/workflows/reusable.yml",
		".github/workflows/secrets.yaml",
		".github/workflows/workflow_run_valid.yml",
		".github/workflows/workflow_run_reusable.yml",
		".github/workflows/allowed_pr_runner.yml",
		".github/workflows/anchors_env.yml",
		".github/workflows/anchors_job.yml",
		".github/workflows/anchors_multiple.yml",
	})
}

func TestGithubWorkflowsNotFound(t *testing.T) {
	s := NewInventoryScanner("testdata/.github")
	pkgInsights := &models.PackageInsights{}
	err := s.Run(pkgInsights)
	workflows := pkgInsights.GithubActionsWorkflows

	assert.Nil(t, err)
	assert.Equal(t, 0, len(workflows))
}

func TestGithubActionsMetadata(t *testing.T) {
	s := NewInventoryScanner("testdata")
	pkgInsights := &models.PackageInsights{}
	err := s.Run(pkgInsights)

	metadata := pkgInsights.GithubActionsMetadata

	assert.Nil(t, err)

	assert.Equal(t, 2, len(metadata))
	assert.Equal(t, "action.yml", metadata[0].Path)
	assert.Equal(t, "docker", metadata[0].Runs.Using)
	assert.Equal(t, "docker://alpine:latest", metadata[0].Runs.Image)
}

func TestRun(t *testing.T) {
	workdir := "testdata"

	o, _ := opa.NewOpa(context.TODO(), &models.Config{
		Include: []models.ConfigInclude{},
	})

	pkgInsights := &models.PackageInsights{}
	pkgInsights.Purl = "pkg:github/org/owner"

	i := NewInventory(o, nil, "github", "")

	scannedPackage, err := i.ScanPackage(context.TODO(), *pkgInsights, workdir)
	assert.NoError(t, err)

	assert.Contains(t, scannedPackage.BuildDependencies, "pkg:githubactions/actions/checkout@v4")
	assert.Contains(t, scannedPackage.PackageDependencies, "pkg:githubactions/actions/github-script@main")
	assert.Contains(t, scannedPackage.PackageDependencies, "pkg:docker/alpine%3Alatest")
	assert.Equal(t, 3, len(scannedPackage.GitlabciConfigs))
}

func TestGithubWorkflowsWithAnchors(t *testing.T) {
	s := NewInventoryScanner("testdata")
	pkgInsights := &models.PackageInsights{}
	err := s.Run(pkgInsights)
	require.NoError(t, err)

	workflows := pkgInsights.GithubActionsWorkflows

	// Find and validate the anchor workflows
	var envWorkflow, jobWorkflow, multipleWorkflow *models.GithubActionsWorkflow
	for i := range workflows {
		switch workflows[i].Path {
		case ".github/workflows/anchors_env.yml":
			envWorkflow = &workflows[i]
		case ".github/workflows/anchors_job.yml":
			jobWorkflow = &workflows[i]
		case ".github/workflows/anchors_multiple.yml":
			multipleWorkflow = &workflows[i]
		}
	}

	// Verify anchors_env.yml parsed correctly
	assert.NotNil(t, envWorkflow, "anchors_env.yml should be found")
	assert.Equal(t, "Anchors - Environment Variables", envWorkflow.Name)
	assert.Len(t, envWorkflow.Jobs, 2)

	// Both jobs should have the same environment variables (anchor was reused)
	job1 := envWorkflow.Jobs[0]
	job2 := envWorkflow.Jobs[1]
	assert.Len(t, job1.Env, 2)
	assert.Len(t, job2.Env, 2)
	assert.Contains(t, job1.Env, models.GithubActionsEnv{Name: "NODE_ENV", Value: "production"})
	assert.Contains(t, job2.Env, models.GithubActionsEnv{Name: "NODE_ENV", Value: "production"})

	// Verify anchors_job.yml parsed correctly
	assert.NotNil(t, jobWorkflow, "anchors_job.yml should be found")
	assert.Equal(t, "Anchors - Complete Job", jobWorkflow.Name)
	assert.Len(t, jobWorkflow.Jobs, 2)

	// Both jobs should be identical (complete job anchor reused)
	testJob := jobWorkflow.Jobs[0]
	altTestJob := jobWorkflow.Jobs[1]
	assert.Equal(t, "test", testJob.ID)
	assert.Equal(t, "alt-test", altTestJob.ID)
	assert.Equal(t, testJob.RunsOn, altTestJob.RunsOn)
	assert.Equal(t, testJob.Env, altTestJob.Env)
	assert.Len(t, testJob.Steps, 3)
	assert.Len(t, altTestJob.Steps, 3)
	assert.Equal(t, "actions/checkout@v5", testJob.Steps[0].Uses)
	assert.Equal(t, "actions/checkout@v5", altTestJob.Steps[0].Uses)

	// Verify anchors_multiple.yml parsed correctly
	assert.NotNil(t, multipleWorkflow, "anchors_multiple.yml should be found")
	assert.Equal(t, "Anchors - Multiple References", multipleWorkflow.Name)
	assert.Len(t, multipleWorkflow.Jobs, 3)

	// All three jobs should use the same runner and container (multiple anchors reused)
	for i := 0; i < 3; i++ {
		assert.Equal(t, models.GithubActionsJobRunsOn{"ubuntu-latest"}, multipleWorkflow.Jobs[i].RunsOn)
		assert.Equal(t, "node:18", multipleWorkflow.Jobs[i].Container.Image)
	}
}

func TestPipelineAsCodeTekton(t *testing.T) {
	s := NewInventoryScanner("testdata")
	pkgInsights := &models.PackageInsights{}
	err := s.Run(pkgInsights)
	assert.NoError(t, err)

	pipelines := pkgInsights.PipelineAsCodeTekton

	assert.Len(t, pipelines, 1)
	expectedAnnotations := map[string]string{
		"pipelinesascode.tekton.dev/on-event":         "[push, pull_request]",
		"pipelinesascode.tekton.dev/on-target-branch": "[*]",
		"pipelinesascode.tekton.dev/task":             "[git-clone]",
	}
	expectedPipeline := models.PipelineAsCodeTekton{
		ApiVersion: "tekton.dev/v1beta1",
		Kind:       "PipelineRun",
		Metadata: struct {
			Name        string            `json:"name"`
			Annotations map[string]string `json:"annotations"`
		}{
			Name:        "linters",
			Annotations: expectedAnnotations,
		},
		Spec: models.PipelineRunSpec{
			PipelineSpec: &models.PipelineSpec{
				Tasks: []models.PipelineTask{
					{
						Name: "fetchit",
					},
					{
						Name: "vale",
						TaskSpec: &models.TaskSpec{
							Steps: []models.Step{
								{
									Name:   "vale-lint",
									Script: "vale docs/content --minAlertLevel=error --output=line\n",
									Lines:  map[string]int{"script": 43, "start": 40},
								},
							},
						},
					},
				},
			},
		},
	}
	assert.Equal(t, expectedPipeline.Metadata, pipelines[0].Metadata)
	assert.Equal(t, expectedPipeline.Spec.PipelineSpec.Tasks[1].TaskSpec.Steps[0], pipelines[0].Spec.PipelineSpec.Tasks[1].TaskSpec.Steps[0])
}
