package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestGithubActionsDeclaredWorkingDirectories(t *testing.T) {
	subject := `
on: push
defaults:
  run:
    working-directory: ./workflow/
jobs:
  build:
    defaults:
      run:
        working-directory: '${{ matrix.directory }}'
    steps:
      - run: pwd
      - run: pwd
        working-directory: ""
      - run: pwd
        working-directory: ../step/
      - uses: actions/checkout@v4
  other:
    steps:
      - run: pwd
`
	var workflow GithubActionsWorkflow
	require.NoError(t, yaml.Unmarshal([]byte(subject), &workflow))
	require.NotNil(t, workflow.Defaults)
	require.NotNil(t, workflow.Defaults.Run)
	require.NotNil(t, workflow.Defaults.Run.WorkingDirectory)
	assert.Equal(t, "./workflow/", *workflow.Defaults.Run.WorkingDirectory)
	require.Len(t, workflow.Jobs, 2)
	job := workflow.Jobs[0]
	require.NotNil(t, job.Defaults)
	require.NotNil(t, job.Defaults.Run)
	require.NotNil(t, job.Defaults.Run.WorkingDirectory)
	assert.Equal(t, "${{ matrix.directory }}", *job.Defaults.Run.WorkingDirectory)
	require.Len(t, job.Steps, 4)
	assert.Nil(t, job.Steps[0].WorkingDirectory)
	require.NotNil(t, job.Steps[1].WorkingDirectory)
	assert.Empty(t, *job.Steps[1].WorkingDirectory)
	require.NotNil(t, job.Steps[2].WorkingDirectory)
	assert.Equal(t, "../step/", *job.Steps[2].WorkingDirectory)
	assert.Nil(t, job.Steps[3].WorkingDirectory)
	assert.Nil(t, workflow.Jobs[1].Defaults)
	assert.Nil(t, workflow.Jobs[1].Steps[0].WorkingDirectory)

	data, err := json.Marshal(workflow)
	require.NoError(t, err)
	var exposed struct {
		Defaults map[string]any `json:"defaults"`
		Jobs     []struct {
			Defaults map[string]any   `json:"defaults"`
			Steps    []map[string]any `json:"steps"`
		} `json:"jobs"`
	}
	require.NoError(t, json.Unmarshal(data, &exposed))
	assert.Equal(t, map[string]any{
		"run": map[string]any{"working_directory": "./workflow/"},
	}, exposed.Defaults)
	build := exposed.Jobs[0]
	assert.Equal(t, map[string]any{
		"run": map[string]any{"working_directory": "${{ matrix.directory }}"},
	}, build.Defaults)
	steps := build.Steps
	assert.NotContains(t, steps[0], "working_directory")
	assert.Contains(t, steps[1], "working_directory")
	assert.Equal(t, "", steps[1]["working_directory"])
	assert.Nil(t, exposed.Jobs[1].Defaults)
	assert.NotContains(t, string(data), "effective_working_directory")

	var restored GithubActionsWorkflow
	require.NoError(t, json.Unmarshal(data, &restored))
	assert.Equal(t, workflow, restored)
}

func TestGithubActionsDefaultsWorkingDirectoryPresence(t *testing.T) {
	tests := []struct {
		name string
		run  string
		want string
	}{
		{name: "absent", run: "{}", want: `{}`},
		{name: "null", run: "{working-directory: null}", want: `{}`},
		{name: "empty", run: `{working-directory: ""}`, want: `{"working_directory":""}`},
		{name: "literal", run: `{working-directory: 'C:\work\'}`, want: `{"working_directory":"C:\\work\\"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var defaults GithubActionsDefaults
			require.NoError(t, yaml.Unmarshal([]byte("run: "+tt.run), &defaults))
			require.NotNil(t, defaults.Run)
			data, err := json.Marshal(defaults.Run)
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(data))
		})
	}
}

func TestGithubActionsMalformedDefaults(t *testing.T) {
	for _, defaults := range []string{
		`unexpected-string`,
		`[]`,
		`{run: unexpected-string}`,
		`{run: []}`,
		`{run: {working-directory: [one, two]}}`,
		`{run: {working-directory: {path: scripts}}}`,
	} {
		t.Run(defaults, func(t *testing.T) {
			subject := "on: push\ndefaults: " + defaults + "\njobs:\n" +
				"  build:\n    defaults: " + defaults + "\n    steps:\n      - run: pwd\n"
			var workflow GithubActionsWorkflow
			require.Error(t, yaml.Unmarshal([]byte(subject), &workflow))

			subject = "on: push\njobs:\n  invalid:\n    defaults: " + defaults +
				"\n    steps: [{run: pwd}]\n  valid:\n    steps: [{run: kept}]\n"
			workflow = GithubActionsWorkflow{}
			require.NoError(t, yaml.Unmarshal([]byte(subject), &workflow))
			require.Len(t, workflow.Jobs, 1)
			assert.Equal(t, "valid", workflow.Jobs[0].ID)
			require.Len(t, workflow.Jobs[0].Steps, 1)
			assert.Equal(t, "kept", workflow.Jobs[0].Steps[0].Run)
		})
	}
}

func TestGithubActionsDefaultsYAMLMerge(t *testing.T) {
	subject := `
on: push
defaults: &defaults
  run:
    working-directory: scripts/
jobs:
  build:
    defaults:
      <<: *defaults
    steps:
      - run: pwd
`
	var workflow GithubActionsWorkflow
	require.NoError(t, yaml.Unmarshal([]byte(subject), &workflow))
	require.Len(t, workflow.Jobs, 1)
	require.NotNil(t, workflow.Jobs[0].Defaults)
	require.NotNil(t, workflow.Jobs[0].Defaults.Run)
	require.NotNil(t, workflow.Jobs[0].Defaults.Run.WorkingDirectory)
	assert.Equal(t, "scripts/", *workflow.Jobs[0].Defaults.Run.WorkingDirectory)
	assert.Nil(t, workflow.Jobs[0].Steps[0].WorkingDirectory)
}
