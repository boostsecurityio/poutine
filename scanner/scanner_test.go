package scanner

import (
	"context"
	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGithubWorkflows(t *testing.T) {
	s := NewScanner("testdata")
	o, _ := opa.NewOpa()
	err := s.Run(context.TODO(), o)
	workflows := s.Package.GithubActionsWorkflows

	assert.Nil(t, err)

	paths := []string{}
	for _, workflow := range workflows {
		paths = append(paths, workflow.Path)
	}
	assert.ElementsMatch(t, paths, []string{
		".github/workflows/debug_enabled_valid.yml",
		".github/workflows/valid.yml",
		".github/workflows/reusable.yml",
		".github/workflows/secrets.yaml",
		".github/workflows/workflow_run_valid.yml",
		".github/workflows/workflow_run_reusable.yml",
		".github/workflows/allowed_pr_runner.yml",
	})
}

func TestGithubWorkflowsNotFound(t *testing.T) {
	s := NewScanner("testdata/.github")
	o, _ := opa.NewOpa()
	err := s.Run(context.TODO(), o)
	workflows := s.Package.GithubActionsWorkflows

	assert.Nil(t, err)
	assert.Equal(t, 0, len(workflows))
}

func TestGithubActionsMetadata(t *testing.T) {
	s := NewScanner("testdata")
	o, _ := opa.NewOpa()
	err := s.Run(context.TODO(), o)

	metadata := s.Package.GithubActionsMetadata

	assert.Nil(t, err)

	assert.Equal(t, 2, len(metadata))
	assert.Equal(t, "action.yml", metadata[0].Path)
	assert.Equal(t, "docker", metadata[0].Runs.Using)
	assert.Equal(t, "docker://alpine:latest", metadata[0].Runs.Image)
}

func TestRun(t *testing.T) {
	s := NewScanner("testdata")
	o, _ := opa.NewOpa()
	s.Package.Purl = "pkg:github/org/owner"

	err := s.Run(context.TODO(), o)

	assert.Nil(t, err)

	assert.Contains(t, s.Package.BuildDependencies, "pkg:githubactions/actions/checkout@v4")
	assert.Contains(t, s.Package.PackageDependencies, "pkg:githubactions/actions/github-script@main")
	assert.Contains(t, s.Package.PackageDependencies, "pkg:docker/alpine%3Alatest")
	assert.Equal(t, 3, len(s.Package.GitlabciConfigs))
}

func TestPipelineAsCodeTekton(t *testing.T) {
	s := NewScanner("testdata")
	o, _ := opa.NewOpa()
	err := s.Run(context.TODO(), o)
	assert.NoError(t, err)

	pipelines := s.Package.PipelineAsCodeTekton

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
