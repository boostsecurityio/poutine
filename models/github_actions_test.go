package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestGithubActionsWorkflowJobs(t *testing.T) {
	tests := []struct {
		Name     string
		Input    string
		Expected GithubActionsJob
		// Error is only for genuinely malformed YAML (lexer/syntax errors).
		Error bool
		// Dropped means the parser leniently skips the whole job (or all jobs),
		// yielding zero jobs without returning an error.
		Dropped bool
	}{
		{
			Name:    "empty",
			Input:   `[]`,
			Dropped: true,
		},
		{
			Name:  "empty job",
			Input: `build: {}`,
			Expected: GithubActionsJob{
				ID: "build",
			},
		},
		{
			Name:  "env as scalar",
			Input: `build: {env: "${{ fromJSON(inputs.env) }}"}`,
			Expected: GithubActionsJob{
				ID: "build",
				Env: []GithubActionsEnv{
					{
						Value: "${{ fromJSON(inputs.env) }}",
					},
				},
			},
		},
		{
			Name:  "runs-on list",
			Input: `build: {runs-on: [ubuntu-latest]}`,
			Expected: GithubActionsJob{
				ID:     "build",
				RunsOn: []string{"ubuntu-latest"},
				Lines:  map[string]int{"start": 1, "runs_on": 1},
			},
		},
		{
			Name:  "runs-on objects",
			Input: `build: {runs-on: { group: runner-group, labels: [runner-label] }}`,
			Expected: GithubActionsJob{
				ID:     "build",
				RunsOn: []string{"group:runner-group", "label:runner-label"},
				Lines:  map[string]int{"start": 1, "runs_on": 1},
			},
		},
		{
			Name:  "runs-on with labels",
			Input: `build: {runs-on: { labels: runner-label }}`,
			Expected: GithubActionsJob{
				ID:     "build",
				RunsOn: []string{"label:runner-label"},
				Lines:  map[string]int{"start": 1, "runs_on": 1},
			},
		},
		{
			// Lenient: a sequence containing a non-string entry can't populate
			// labels, so runs-on ends up empty but the job is still parsed.
			Name:  "runs-on with empty labels",
			Input: `build: {runs-on: { labels: [ {} ] }}`,
			Expected: GithubActionsJob{
				ID:    "build",
				Lines: map[string]int{"start": 1, "runs_on": 1},
			},
		},
		{
			Name:  "runs-on with empty string labels",
			Input: `build: {runs-on: { labels: [ "" ] }}`,
			Expected: GithubActionsJob{
				ID:    "build",
				Lines: map[string]int{"start": 1, "runs_on": 1},
			},
		},
		{
			Name:  "runs-on with empty string group",
			Input: `build: {runs-on: { group: [ "" ] }}`,
			Expected: GithubActionsJob{
				ID:    "build",
				Lines: map[string]int{"start": 1, "runs_on": 1},
			},
		},
		{
			Name:  "runs-on with empty object",
			Input: `build: {runs-on: [ {}]}`,
			Expected: GithubActionsJob{
				ID:    "build",
				Lines: map[string]int{"start": 1, "runs_on": 1},
			},
		},
		{
			// A job whose body is a sequence can't decode into a job struct, so
			// it is skipped entirely rather than aborting the whole workflow.
			Name:    "empty build",
			Input:   `build: []`,
			Dropped: true,
		},
		{
			// Unknown permission scalar leaves permissions empty; job survives.
			Name:  "invalid permissions",
			Input: `build: {permissions: foobar}`,
			Expected: GithubActionsJob{
				ID: "build",
			},
		},
		{
			Name:  "invalid permissions list",
			Input: `build: {permissions: [foobar]}`,
			Expected: GithubActionsJob{
				ID: "build",
			},
		},
		{
			Name:  "invalid env",
			Input: `build: {env: foobar}`,
			Expected: GithubActionsJob{
				ID: "build",
			},
		},
		{
			// The malformed step is dropped; the job is still parsed.
			Name:  "invalid steps",
			Input: `build: {steps: [foobar]}`,
			Expected: GithubActionsJob{
				ID: "build",
			},
		},
		{
			Name:  "invalid secrets",
			Input: `build: {secrets: []}`,
			Expected: GithubActionsJob{
				ID: "build",
			},
		},
		{
			// `[]]` is a YAML syntax error, surfaced by the lexer regardless of
			// our lenient node handling.
			Name:  "invalid outputs",
			Input: `build: {outputs: []]}`,
			Error: true,
		},
		{
			Name:  "container as scalar",
			Input: `build: {container: ubuntu:latest}`,
			Expected: GithubActionsJob{
				ID: "build",
				Container: GithubActionsJobContainer{
					Image: "ubuntu:latest",
				},
			},
		},
		{
			Name:  "container as object",
			Input: `build: {container: {image: ubuntu:latest}}`,
			Expected: GithubActionsJob{
				ID: "build",
				Container: GithubActionsJobContainer{
					Image: "ubuntu:latest",
				},
			},
		},
		{
			// Container that can't decode is left empty; job survives.
			Name:  "invalid container empty list",
			Input: `build: {container: []}`,
			Expected: GithubActionsJob{
				ID: "build",
			},
		},
		{
			Name:  "valid permissions object",
			Input: `build: {permissions: {contents: read}}`,
			Expected: GithubActionsJob{
				ID: "build",
				Permissions: []GithubActionsPermission{
					{
						Scope:      "contents",
						Permission: "read",
					},
				},
			},
		},
		{
			Name:  "environment as scalar",
			Input: `build: {environment: public}`,
			Expected: GithubActionsJob{
				ID: "build",
				Environment: []GithubActionsJobEnvironment{
					{
						Name: "public",
					},
				},
			},
		},
		{
			Name:  "environment as object",
			Input: `build: {environment: {name: dev, url: example.com}}`,
			Expected: GithubActionsJob{
				ID: "build",
				Environment: []GithubActionsJobEnvironment{
					{
						Name: "dev",
						Url:  "example.com",
					},
				},
			},
		},
		{
			// Environment that can't decode is left empty; job survives.
			Name:  "invalid empty environment",
			Input: `build: {environment: []}`,
			Expected: GithubActionsJob{
				ID: "build",
			},
		},
		{
			Name:  "single dimension matrix",
			Input: `example_matrix: { strategy: { matrix: { version: [10, 12, 14] } } }`,
			Expected: GithubActionsJob{
				ID: "example_matrix",
				Strategy: GithubActionsStrategy{
					Matrix: map[string]StringList{
						"version": {"10", "12", "14"},
					},
				},
			},
		},
		{
			Name:  "multi dimension matrix",
			Input: `example_matrix: { strategy: { matrix: { os: [ubuntu-22.04, ubuntu-20.04], version: [10, 12, 14] } }, runs-on: '${{ matrix.os }}' }`,
			Expected: GithubActionsJob{
				ID:     "example_matrix",
				RunsOn: []string{"${{ matrix.os }}"},
				Strategy: GithubActionsStrategy{
					Matrix: map[string]StringList{
						"os":      {"ubuntu-22.04", "ubuntu-20.04"},
						"version": {"10", "12", "14"},
					},
				},
				Lines: map[string]int{"runs_on": 1, "start": 1},
			},
		},
		{
			Name:  "multi dimension matrix list of objects",
			Input: `example_matrix: { strategy: { matrix: { os: [ubuntu-latest, macos-latest], node: [ { version: 14 }, { version: 20, env: NODE_OPTIONS=--openssl-legacy-provider } ] } } }`,
			Expected: GithubActionsJob{
				ID: "example_matrix",
				Strategy: GithubActionsStrategy{
					Matrix: map[string]StringList{
						"os": {
							"ubuntu-latest",
							"macos-latest",
						},
						"node": {
							`{"version":14}`,
							`{"env":"NODE_OPTIONS=--openssl-legacy-provider","version":20}`,
						},
					},
				},
			},
		},
		{
			Name:  "matrix with expression value",
			Input: `example_matrix: { strategy: { matrix: "${{ fromJSON(needs.config.outputs.matrix) }}" } }`,
			Expected: GithubActionsJob{
				ID: "example_matrix",
			},
		},
		{
			Name:  "matrix with scalar dimension skipped",
			Input: `example_matrix: { strategy: { matrix: { rust: stable, os: [ubuntu-latest, macos-latest] } } }`,
			Expected: GithubActionsJob{
				ID: "example_matrix",
				Strategy: GithubActionsStrategy{
					Matrix: map[string]StringList{
						"os": {"ubuntu-latest", "macos-latest"},
					},
				},
			},
		},
		{
			Name:  "matrix with include and exclude skipped",
			Input: `example_matrix: { strategy: { matrix: { os: [ubuntu-latest], include: [{ os: windows-latest, experimental: true }], exclude: [{ os: macos-latest }] } } }`,
			Expected: GithubActionsJob{
				ID: "example_matrix",
				Strategy: GithubActionsStrategy{
					Matrix: map[string]StringList{
						"os": {"ubuntu-latest"},
					},
				},
			},
		},
		{
			Name:  "matrix with nested sequences skipped",
			Input: "example_matrix:\n  strategy:\n    matrix:\n      target:\n        - [a, b]\n        - [c, d]\n      os: [ubuntu-latest]",
			Expected: GithubActionsJob{
				ID: "example_matrix",
				Strategy: GithubActionsStrategy{
					Matrix: map[string]StringList{
						"target": nil,
						"os":     {"ubuntu-latest"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			var jobs GithubActionsJobs
			err := yaml.Unmarshal([]byte(tt.Input), &jobs)

			if tt.Error {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.Dropped {
				require.Empty(t, jobs)
				return
			}
			require.Len(t, jobs, 1)

			got := jobs[0]
			tt.Expected.Line = 1
			if tt.Expected.Lines == nil {
				tt.Expected.Lines = map[string]int{"start": tt.Expected.Line}
			}
			assert.Equal(t, tt.Expected, got)
		})
	}
}

func TestGithubActionsWorkflowEvents(t *testing.T) {
	cases := []struct {
		Input    string
		Expected GithubActionsEvents
		Error    bool
	}{
		{
			Input: `push`,
			Expected: GithubActionsEvents{
				{Name: "push"},
			},
		},
		{
			Input: `[push, pull_request]`,
			Expected: GithubActionsEvents{
				{Name: "push"},
				{Name: "pull_request"},
			},
		},
		{
			Input: `push: {branches: main}`,
			Expected: GithubActionsEvents{
				{
					Name:     "push",
					Branches: []string{"main"},
				},
			},
		},
		{
			// branches as a mapping can't populate the list; left empty.
			Input: `push: {branches: {}}`,
			Expected: GithubActionsEvents{
				{Name: "push"},
			},
		},
		{
			Input: `push: {branches: [main]}`,
			Expected: GithubActionsEvents{
				{
					Name:     "push",
					Branches: []string{"main"},
				},
			},
		},
		{
			Input: `schedule: [cron: "s1", cron: "s2"]`,
			Expected: GithubActionsEvents{
				{
					Name: "schedule",
					Cron: []string{"s1", "s2"},
				},
			},
		},
		{
			// cron entries without a `cron` key are skipped individually.
			Input: `schedule: [error: "s1"]`,
			Expected: GithubActionsEvents{
				{Name: "schedule"},
			},
		},
		{
			// A scalar schedule can't decode into cron objects; the event is
			// skipped, leaving no events (but no error).
			Input:    `schedule: "* * * *"`,
			Expected: GithubActionsEvents{},
		},
		{
			Input: `workflow_run: {workflows: ["w1"], types: [requested]}`,
			Expected: GithubActionsEvents{
				{
					Name:      "workflow_run",
					Workflows: []string{"w1"},
					Types:     []string{"requested"},
				},
			},
		},
		{
			Input: `workflow_call: { inputs: [], }`,
			Expected: GithubActionsEvents{
				{Name: "workflow_call"},
			},
		},
		{
			// The malformed input is skipped; the event survives.
			Input: `workflow_call: { inputs: {name: []}, }`,
			Expected: GithubActionsEvents{
				{Name: "workflow_call"},
			},
		},
		{
			Input: `workflow_call: { outputs: [], }`,
			Expected: GithubActionsEvents{
				{Name: "workflow_call"},
			},
		},
		{
			Input: `workflow_call: { outputs: { name: asdf }, }`,
			Expected: GithubActionsEvents{
				{
					Name: "workflow_call",
					Outputs: []GithubActionsOutput{
						{
							Name:  "name",
							Value: "asdf",
						},
					},
				},
			},
		},
		{
			// The malformed output is skipped; the event survives.
			Input: `workflow_call: { outputs: { name: { name: {} } }, }`,
			Expected: GithubActionsEvents{
				{Name: "workflow_call"},
			},
		},
		{
			Input: `workflow_call: {
                      inputs: {previousSteps: {type: string, required: true}},
                      outputs: {build: {description: build_id, value: "${{ jobs.build.outputs.build }}" }},
                      secrets: {BOARD_TOKEN: {required: true}}
                    }`,
			Expected: GithubActionsEvents{
				{
					Name: "workflow_call",
					Inputs: []GithubActionsInput{
						{
							Name:     "previousSteps",
							Type:     "string",
							Required: true,
						},
					},
					Outputs: []GithubActionsOutput{
						{
							Name:        "build",
							Description: "build_id",
							Value:       "${{ jobs.build.outputs.build }}",
						},
					},
					Secrets: []GithubActionsInput{
						{
							Name:     "BOARD_TOKEN",
							Required: true,
						},
					},
				},
			},
		},
	}

	for _, c := range cases {
		var events GithubActionsEvents
		err := yaml.Unmarshal([]byte(c.Input), &events)
		if c.Error {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, c.Expected, events)
		}
	}
}

func TestGithubActionsWorkflow(t *testing.T) {
	subject := `
name: CI
on:
  push:
    branches:
    - main
    tags:
    - v*
  workflow_call:
    inputs:
      previousSteps:
        type: string
        required: true
    outputs:
      build:
        description: build_id
        value: ${{ jobs.build.outputs.build }}
    secrets:
      BOARD_TOKEN:
        required: true
  schedule:
    - cron: '0 0 * * 0'
    - cron: '0 0 * * 1'
  workflow_run:
    workflows: ["Build"]
    types: [requested]
    branches:
      - 'releases/**'

permissions: write-all

jobs:
  build:
    name: Build job
    runs-on: [ubuntu-latest, windows-latest]
    if: ${{ github.actor == 'bot' }}
    needs: other
    permissions:
      contents: read
    outputs:
      build: ${{ steps.checkout.outputs.build }}
    steps:
    - name: Checkout
      id: checkout
      uses: actions/checkout@v2
      shell: powershell
      run: git pull
      working-directory: /tmp
      with:
        ref: ${{ github.head_ref }}
        script: "console.log(1)"
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  noperms:
    runs-on: ubuntu-latest
    permissions: read-all
    uses: octo-org/example-repo/.github/workflows/reusable-workflow.yml@main
    with:
      config-path: .github/labeler.yml
    secrets: inherit
    container: alpine:latest

  secrets:
    runs-on: ubuntu-latest
    container:
      image: alpine:latest
    steps: []
    secrets:
      token: ${{ secrets.GITHUB_TOKEN }}}
`
	var workflow GithubActionsWorkflow

	err := yaml.Unmarshal([]byte(subject), &workflow)

	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, "CI", workflow.Name)

	assert.Equal(t, "push", workflow.Events[0].Name)
	assert.Equal(t, "main", workflow.Events[0].Branches[0])
	assert.Equal(t, "v*", workflow.Events[0].Tags[0])

	assert.Equal(t, "workflow_call", workflow.Events[1].Name)
	assert.Equal(t, "string", workflow.Events[1].Inputs[0].Type)
	assert.Equal(t, StringBool(true), workflow.Events[1].Inputs[0].Required)
	assert.Equal(t, "build", workflow.Events[1].Outputs[0].Name)
	assert.Equal(t, "build_id", workflow.Events[1].Outputs[0].Description)
	assert.Equal(t, "${{ jobs.build.outputs.build }}", workflow.Events[1].Outputs[0].Value)
	assert.Equal(t, "BOARD_TOKEN", workflow.Events[1].Secrets[0].Name)
	assert.Equal(t, StringBool(true), workflow.Events[1].Secrets[0].Required)

	assert.Equal(t, "schedule", workflow.Events[2].Name)
	assert.Equal(t, "0 0 * * 0", workflow.Events[2].Cron[0])
	assert.Equal(t, "0 0 * * 1", workflow.Events[2].Cron[1])

	assert.Equal(t, "workflow_run", workflow.Events[3].Name)
	assert.Equal(t, "requested", workflow.Events[3].Types[0])
	assert.Equal(t, "releases/**", workflow.Events[3].Branches[0])
	assert.Equal(t, "Build", workflow.Events[3].Workflows[0])

	assert.Equal(t, "build", workflow.Jobs[0].ID)
	assert.Equal(t, 33, workflow.Jobs[0].Lines["start"])
	assert.Equal(t, "Build job", workflow.Jobs[0].Name)
	assert.Equal(t, "ubuntu-latest", workflow.Jobs[0].RunsOn[0])
	assert.Equal(t, "windows-latest", workflow.Jobs[0].RunsOn[1])
	assert.Equal(t, "${{ github.actor == 'bot' }}", workflow.Jobs[0].If)
	assert.Equal(t, "other", workflow.Jobs[0].Needs[0])

	// write-all is normalized to all scopes
	assert.Contains(t, workflow.Permissions, GithubActionsPermission{Scope: "metadata", Permission: "write"})
	assert.Contains(t, workflow.Permissions, GithubActionsPermission{Scope: "contents", Permission: "write"})
	assert.Contains(t, workflow.Permissions, GithubActionsPermission{Scope: "attestations", Permission: "write"})

	assert.Equal(t, "build", workflow.Jobs[0].Outputs[0].Name)
	assert.Equal(t, "${{ steps.checkout.outputs.build }}", workflow.Jobs[0].Outputs[0].Value)
	assert.Equal(t, "checkout", workflow.Jobs[0].Steps[0].ID)
	assert.Equal(t, 43, workflow.Jobs[0].Steps[0].Line)
	assert.Equal(t, "Checkout", workflow.Jobs[0].Steps[0].Name)
	assert.Equal(t, "actions/checkout@v2", workflow.Jobs[0].Steps[0].Uses)
	assert.Equal(t, "actions/checkout", workflow.Jobs[0].Steps[0].Action)
	assert.Equal(t, "powershell", workflow.Jobs[0].Steps[0].Shell)
	assert.Equal(t, "git pull", workflow.Jobs[0].Steps[0].Run)
	assert.Equal(t, "/tmp", workflow.Jobs[0].Steps[0].WorkingDirectory)
	assert.Equal(t, "ref", workflow.Jobs[0].Steps[0].With[0].Name)
	assert.Equal(t, 50, workflow.Jobs[0].Steps[0].Lines["with_ref"])
	assert.Equal(t, "${{ github.head_ref }}", workflow.Jobs[0].Steps[0].With[0].Value)
	assert.Equal(t, "${{ github.head_ref }}", workflow.Jobs[0].Steps[0].WithRef)
	assert.Equal(t, "script", workflow.Jobs[0].Steps[0].With[1].Name)
	assert.Equal(t, 51, workflow.Jobs[0].Steps[0].Lines["with_script"])
	assert.Equal(t, "console.log(1)", workflow.Jobs[0].Steps[0].With[1].Value)
	assert.Equal(t, "console.log(1)", workflow.Jobs[0].Steps[0].WithScript)
	assert.Equal(t, "GITHUB_TOKEN", workflow.Jobs[0].Steps[0].Env[0].Name)
	assert.Equal(t, "${{ secrets.GITHUB_TOKEN }}", workflow.Jobs[0].Steps[0].Env[0].Value)
	assert.Equal(t, "noperms", workflow.Jobs[1].ID)
	assert.Equal(t, "alpine:latest", workflow.Jobs[1].Container.Image)
	assert.Equal(t, "ubuntu-latest", workflow.Jobs[1].RunsOn[0])
	assert.Contains(t, workflow.Jobs[1].Permissions, GithubActionsPermission{Scope: "metadata", Permission: "read"})
	assert.Contains(t, workflow.Jobs[1].Permissions, GithubActionsPermission{Scope: "contents", Permission: "read"})

	assert.Equal(t, "octo-org/example-repo/.github/workflows/reusable-workflow.yml@main", workflow.Jobs[1].Uses)
	assert.Equal(t, "config-path", workflow.Jobs[1].With[0].Name)
	assert.Equal(t, ".github/labeler.yml", workflow.Jobs[1].With[0].Value)
	assert.Equal(t, "*ALL", workflow.Jobs[1].Secrets[0].Name)

	assert.Equal(t, "alpine:latest", workflow.Jobs[2].Container.Image)
}

// TestGithubActionsWorkflowLenientResilience verifies that locally-malformed
// sub-nodes are skipped without aborting the whole-file parse. Previously any
// one of these constructs caused yaml.Unmarshal to error, which made the
// scanner silently drop the entire workflow (a false-negative / scan-evasion
// risk). The workflow must still be valid and retain all of its well-formed
// content.
func TestGithubActionsWorkflowLenientResilience(t *testing.T) {
	subject := `
name: CI
on:
  push:
    branches: {}            # wrong shape, ignored
  schedule:
    - cron: ""              # empty cron, skipped individually
    - cron: "0 0 * * 0"     # kept
jobs:
  good:
    runs-on: ubuntu-latest
    permissions: not-a-real-value   # invalid scalar -> empty perms, job kept
    steps:
      - uses: actions/checkout@v4
      - foobar                       # malformed step -> dropped
      - run: make build
  broken: []                         # whole job can't decode -> dropped
`
	var wf GithubActionsWorkflow
	err := yaml.Unmarshal([]byte(subject), &wf)

	// The file as a whole must still parse and be considered valid for scanning.
	require.NoError(t, err)
	assert.True(t, wf.IsValid(), "workflow should remain valid despite malformed sub-nodes")

	// Events: push survives (with empty branches) and schedule keeps only the
	// well-formed cron entry.
	require.Len(t, wf.Events, 2)
	assert.Equal(t, "push", wf.Events[0].Name)
	assert.Empty(t, wf.Events[0].Branches)
	assert.Equal(t, "schedule", wf.Events[1].Name)
	assert.Equal(t, []string{"0 0 * * 0"}, []string(wf.Events[1].Cron))

	// The undecodable `broken` job is dropped; the good job is retained.
	require.Len(t, wf.Jobs, 1)
	good := wf.Jobs[0]
	assert.Equal(t, "good", good.ID)
	assert.Equal(t, GithubActionsJobRunsOn{"ubuntu-latest"}, good.RunsOn)
	assert.Empty(t, good.Permissions, "invalid permission scalar should yield empty permissions, not drop the job")

	// The malformed step is dropped but the surrounding steps survive.
	require.Len(t, good.Steps, 2)
	assert.Equal(t, "actions/checkout@v4", good.Steps[0].Uses)
	assert.Equal(t, "make build", good.Steps[1].Run)
}

// TestGithubActionsParallelStepsFlattened verifies that `parallel:` step blocks
// are flattened inline so their nested run/uses sinks remain visible to rules.
func TestGithubActionsParallelStepsFlattened(t *testing.T) {
	input := `build:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v6
    - parallel:
        - name: Build frontend
          run: npm run build:frontend
        - name: Build backend
          run: npm run build:backend
    - name: Run tests
      run: npm test
`
	var jobs GithubActionsJobs
	require.NoError(t, yaml.Unmarshal([]byte(input), &jobs))
	require.Len(t, jobs, 1)

	steps := jobs[0].Steps
	require.Len(t, steps, 4)
	assert.Equal(t, "actions/checkout@v6", steps[0].Uses)
	assert.Equal(t, "npm run build:frontend", steps[1].Run)
	assert.Equal(t, "npm run build:backend", steps[2].Run)
	assert.Equal(t, "npm test", steps[3].Run)
	// Each flattened child keeps its own line number.
	assert.Equal(t, 6, steps[1].Line)
	assert.Equal(t, 8, steps[2].Line)

	// Steps outside the parallel block are not tagged.
	assert.False(t, steps[0].Parallel)
	assert.False(t, steps[3].Parallel)
	// Parallel children carry the flag.
	assert.True(t, steps[1].Parallel)
	assert.True(t, steps[2].Parallel)

	// The flag is present in the JSON handed to rego.
	blob, err := json.Marshal(steps[1])
	require.NoError(t, err)
	assert.Contains(t, string(blob), `"parallel":true`)
	// Non-parallel steps omit it entirely.
	blob, err = json.Marshal(steps[0])
	require.NoError(t, err)
	assert.NotContains(t, string(blob), "parallel")

	t.Run("nested parallel all tagged", func(t *testing.T) {
		nested := `build:
  steps:
    - parallel:
        - parallel:
            - run: a
            - run: b
        - run: c
`
		var jobs GithubActionsJobs
		require.NoError(t, yaml.Unmarshal([]byte(nested), &jobs))
		steps := jobs[0].Steps
		require.Len(t, steps, 3)
		assert.Equal(t, []string{"a", "b", "c"}, []string{steps[0].Run, steps[1].Run, steps[2].Run})
		for _, s := range steps {
			assert.True(t, s.Parallel)
		}
	})
}

func TestGithubActionMetadata(t *testing.T) {
	var actionMetadata GithubActionsMetadata
	subject := `name: "My GitHub Action"
author: "John Doe"
description: "Analyze git sha"

inputs:
  git_sha:
    required: true
    type: string

outputs:
  response:
    description: "Response from the command executed"

runs:
  using: "composite"
  steps:
  - uses: actions/checkout@v2
    id: checkout
    with:
      ref: koi
`
	err := yaml.Unmarshal([]byte(subject), &actionMetadata)

	assert.Nil(t, err)

	assert.Equal(t, "My GitHub Action", actionMetadata.Name)
	assert.Equal(t, "John Doe", actionMetadata.Author)
	assert.Equal(t, "Analyze git sha", actionMetadata.Description)
	assert.Equal(t, "git_sha", actionMetadata.Inputs[0].Name)
	assert.Equal(t, StringBool(true), actionMetadata.Inputs[0].Required)
	assert.Equal(t, "string", actionMetadata.Inputs[0].Type)
	assert.Equal(t, "response", actionMetadata.Outputs[0].Name)
	assert.Equal(t, "Response from the command executed", actionMetadata.Outputs[0].Description)
	assert.Equal(t, "composite", actionMetadata.Runs.Using)
	assert.Equal(t, "actions/checkout@v2", actionMetadata.Runs.Steps[0].Uses)
	assert.Equal(t, "checkout", actionMetadata.Runs.Steps[0].ID)
	assert.Equal(t, "ref", actionMetadata.Runs.Steps[0].With[0].Name)
	assert.Equal(t, "koi", actionMetadata.Runs.Steps[0].With[0].Value)
	assert.Equal(t, 17, actionMetadata.Runs.Steps[0].Lines["uses"])
}

// TestGithubActionsWorkflowWithAnchors tests YAML 1.2 anchor support
// GitHub Actions now supports YAML anchors as of 2025-09-18
// https://github.blog/changelog/2025-09-18-actions-yaml-anchors-and-non-public-workflow-templates/
func TestGithubActionsWorkflowWithAnchors(t *testing.T) {
	t.Run("simple anchor and alias", func(t *testing.T) {
		workflow := `
name: CI
on: push

jobs:
  build: &build_template
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

  test:
    <<: *build_template
    steps:
      - uses: actions/checkout@v4
      - run: npm test
`
		var wf GithubActionsWorkflow
		err := yaml.Unmarshal([]byte(workflow), &wf)
		require.NoError(t, err)
		assert.Equal(t, "CI", wf.Name)
		assert.Len(t, wf.Jobs, 2)

		// Verify the first job (with anchor definition)
		assert.Equal(t, "build", wf.Jobs[0].ID)
		assert.Equal(t, GithubActionsJobRunsOn{"ubuntu-latest"}, wf.Jobs[0].RunsOn)
		assert.Len(t, wf.Jobs[0].Steps, 1)
		assert.Equal(t, "actions/checkout@v4", wf.Jobs[0].Steps[0].Uses)

		// Verify the second job inherited runs-on from the anchor
		assert.Equal(t, "test", wf.Jobs[1].ID)
		assert.Equal(t, GithubActionsJobRunsOn{"ubuntu-latest"}, wf.Jobs[1].RunsOn)
		assert.Len(t, wf.Jobs[1].Steps, 2)
		assert.Equal(t, "actions/checkout@v4", wf.Jobs[1].Steps[0].Uses)
		assert.Equal(t, "npm test", wf.Jobs[1].Steps[1].Run)
	})

	t.Run("anchor for environment configuration", func(t *testing.T) {
		workflow := `
name: Deploy
on: push

jobs:
  deploy-staging:
    runs-on: ubuntu-latest
    environment: &env_config
      name: staging
      url: https://staging.example.com
    steps:
      - run: echo "deploying"

  deploy-prod:
    runs-on: ubuntu-latest
    environment:
      <<: *env_config
      name: production
      url: https://prod.example.com
    steps:
      - run: echo "deploying"
`
		var wf GithubActionsWorkflow
		err := yaml.Unmarshal([]byte(workflow), &wf)
		require.NoError(t, err)
		assert.Len(t, wf.Jobs, 2)
		assert.Equal(t, "staging", wf.Jobs[0].Environment[0].Name)
		assert.Equal(t, "https://staging.example.com", wf.Jobs[0].Environment[0].Url)
		assert.Equal(t, "production", wf.Jobs[1].Environment[0].Name)
		assert.Equal(t, "https://prod.example.com", wf.Jobs[1].Environment[0].Url)
	})

	t.Run("anchor for steps configuration", func(t *testing.T) {
		workflow := `
name: Test
on: push

jobs:
  test-node-14:
    runs-on: ubuntu-latest
    steps: &test_steps
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '14'
      - run: npm test

  test-node-16:
    runs-on: ubuntu-latest
    steps: *test_steps
`
		var wf GithubActionsWorkflow
		err := yaml.Unmarshal([]byte(workflow), &wf)
		require.NoError(t, err)
		assert.Len(t, wf.Jobs, 2)

		// Verify both jobs have the same steps from the anchor
		assert.Len(t, wf.Jobs[0].Steps, 3)
		assert.Equal(t, "actions/checkout@v4", wf.Jobs[0].Steps[0].Uses)
		assert.Equal(t, "actions/setup-node@v4", wf.Jobs[0].Steps[1].Uses)
		assert.Equal(t, "npm test", wf.Jobs[0].Steps[2].Run)

		// Verify the second job uses the anchor and has identical steps
		assert.Len(t, wf.Jobs[1].Steps, 3)
		assert.Equal(t, "actions/checkout@v4", wf.Jobs[1].Steps[0].Uses)
		assert.Equal(t, "actions/setup-node@v4", wf.Jobs[1].Steps[1].Uses)
		assert.Equal(t, "npm test", wf.Jobs[1].Steps[2].Run)
	})

	t.Run("anchor for permissions", func(t *testing.T) {
		workflow := `
name: Security
on: push

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions: &security_perms
      contents: read
      security-events: write
    steps:
      - run: echo "scanning"

  report:
    runs-on: ubuntu-latest
    permissions: *security_perms
    steps:
      - run: echo "reporting"
`
		var wf GithubActionsWorkflow
		err := yaml.Unmarshal([]byte(workflow), &wf)
		require.NoError(t, err)
		assert.Len(t, wf.Jobs, 2)
		assert.Len(t, wf.Jobs[0].Permissions, 2)
		assert.Contains(t, wf.Jobs[0].Permissions, GithubActionsPermission{Scope: "contents", Permission: "read"})
		assert.Contains(t, wf.Jobs[0].Permissions, GithubActionsPermission{Scope: "security-events", Permission: "write"})
		assert.Equal(t, wf.Jobs[0].Permissions, wf.Jobs[1].Permissions)
	})

	t.Run("multiple anchors in same workflow", func(t *testing.T) {
		workflow := `
name: Multi
on: push

jobs:
  job1:
    runs-on: &runner ubuntu-latest
    container: &container_image alpine:latest
    steps:
      - run: echo "test"

  job2:
    runs-on: *runner
    container: *container_image
    steps:
      - run: echo "test2"
`
		var wf GithubActionsWorkflow
		err := yaml.Unmarshal([]byte(workflow), &wf)
		require.NoError(t, err)
		assert.Len(t, wf.Jobs, 2)
		assert.Equal(t, GithubActionsJobRunsOn{"ubuntu-latest"}, wf.Jobs[0].RunsOn)
		assert.Equal(t, GithubActionsJobRunsOn{"ubuntu-latest"}, wf.Jobs[1].RunsOn)
		assert.Equal(t, "alpine:latest", wf.Jobs[0].Container.Image)
		assert.Equal(t, "alpine:latest", wf.Jobs[1].Container.Image)
	})

	t.Run("anchor for env variables", func(t *testing.T) {
		workflow := `
name: Env Test
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    env: &common_env
      NODE_ENV: production
      CI: true
    steps:
      - run: echo "build"

  test:
    runs-on: ubuntu-latest
    env: *common_env
    steps:
      - run: echo "test"
`
		var wf GithubActionsWorkflow
		err := yaml.Unmarshal([]byte(workflow), &wf)
		require.NoError(t, err)
		assert.Len(t, wf.Jobs, 2)

		// Verify the first job has the anchor env vars
		assert.Len(t, wf.Jobs[0].Env, 2)
		assert.Contains(t, wf.Jobs[0].Env, GithubActionsEnv{Name: "NODE_ENV", Value: "production"})
		assert.Contains(t, wf.Jobs[0].Env, GithubActionsEnv{Name: "CI", Value: "true"})

		// Verify the second job reuses the same env vars via alias
		assert.Len(t, wf.Jobs[1].Env, 2)
		assert.Contains(t, wf.Jobs[1].Env, GithubActionsEnv{Name: "NODE_ENV", Value: "production"})
		assert.Contains(t, wf.Jobs[1].Env, GithubActionsEnv{Name: "CI", Value: "true"})
	})

	t.Run("complex nested anchor with merge keys", func(t *testing.T) {
		workflow := `
name: Complex
on: push

jobs:
  base: &base_job
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4

  extended:
    <<: *base_job
    permissions:
      contents: write
      issues: write
    steps:
      - uses: actions/checkout@v4
      - run: npm build
`
		var wf GithubActionsWorkflow
		err := yaml.Unmarshal([]byte(workflow), &wf)
		require.NoError(t, err)
		assert.Len(t, wf.Jobs, 2)

		// Verify the base job
		assert.Equal(t, "base", wf.Jobs[0].ID)
		assert.Equal(t, GithubActionsJobRunsOn{"ubuntu-latest"}, wf.Jobs[0].RunsOn)
		assert.Len(t, wf.Jobs[0].Permissions, 1)
		assert.Contains(t, wf.Jobs[0].Permissions, GithubActionsPermission{Scope: "contents", Permission: "read"})
		assert.Len(t, wf.Jobs[0].Steps, 1)

		// Verify the extended job inherited runs-on but overrode permissions
		assert.Equal(t, "extended", wf.Jobs[1].ID)
		assert.Equal(t, GithubActionsJobRunsOn{"ubuntu-latest"}, wf.Jobs[1].RunsOn)
		assert.Len(t, wf.Jobs[1].Permissions, 2)
		assert.Contains(t, wf.Jobs[1].Permissions, GithubActionsPermission{Scope: "contents", Permission: "write"})
		assert.Contains(t, wf.Jobs[1].Permissions, GithubActionsPermission{Scope: "issues", Permission: "write"})
		assert.Len(t, wf.Jobs[1].Steps, 2)
	})
}
