package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestGithubActionsDeclaredCacheMode(t *testing.T) {
	tests := []struct {
		name string
		give string
		want *string
	}{
		{name: "absent"},
		{name: "null", give: "cache-mode: null"},
		{name: "empty", give: `cache-mode: ""`, want: stringPointer("")},
		{name: "read", give: "cache-mode: read", want: stringPointer("read")},
		{name: "write", give: "cache-mode: write", want: stringPointer("write")},
		{name: "write-only", give: "cache-mode: write-only", want: stringPointer("write-only")},
		{name: "none", give: "cache-mode: none", want: stringPointer("none")},
		{name: "unknown", give: "cache-mode: future-mode", want: stringPointer("future-mode")},
		{
			name: "expression",
			give: "cache-mode: '${{ inputs.mode }}'",
			want: stringPointer("${{ inputs.mode }}"),
		},
		{name: "boolean", give: "cache-mode: false", want: stringPointer("false")},
		{name: "number", give: "cache-mode: 123", want: stringPointer("123")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject := "on: push\n" + tt.give + "\njobs:\n  build:\n    " +
				tt.give + "\n    steps:\n      - run: pwd\n"
			workflow := GithubActionsWorkflow{Path: ".github/workflows/build.yml"}
			require.NoError(t, yaml.Unmarshal([]byte(subject), &workflow))
			assert.True(t, workflow.IsValid())
			assert.Equal(t, ".github/workflows/build.yml", workflow.Path)
			assert.Equal(t, tt.want, workflow.CacheMode)
			require.Len(t, workflow.Jobs, 1)
			job := workflow.Jobs[0]
			assert.Equal(t, "build", job.ID)
			assert.Equal(t, tt.want, job.CacheMode)
			require.Len(t, job.Steps, 1)
			assert.Equal(t, "pwd", job.Steps[0].Run)

			for _, model := range []any{workflow, job} {
				data, err := json.Marshal(model)
				require.NoError(t, err)
				var exposed map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(data, &exposed))
				if tt.want == nil {
					assert.NotContains(t, exposed, "cache_mode")
				} else {
					require.Contains(t, exposed, "cache_mode")
					var mode string
					require.NoError(t, json.Unmarshal(exposed["cache_mode"], &mode))
					assert.Equal(t, *tt.want, mode)
				}
				assert.NotContains(t, exposed, "cache-mode")
				assert.NotContains(t, exposed, "effective_cache_mode")
			}

			data, err := json.Marshal(workflow)
			require.NoError(t, err)
			var restored GithubActionsWorkflow
			require.NoError(t, json.Unmarshal(data, &restored))
			assert.Equal(t, workflow, restored)
		})
	}
}

func TestGithubActionsMalformedCacheMode(t *testing.T) {
	for _, mode := range []string{"[read, write]", "{mode: read}"} {
		t.Run(mode, func(t *testing.T) {
			var workflow GithubActionsWorkflow
			subject := "on: push\ncache-mode: " + mode +
				"\njobs: {build: {steps: [{run: pwd}]}}\n"
			require.Error(t, yaml.Unmarshal([]byte(subject), &workflow))

			subject = "on: push\njobs:\n  invalid:\n    cache-mode: " + mode +
				"\n    steps: [{run: pwd}]\n  valid:\n    steps: [{run: kept}]\n"
			workflow = GithubActionsWorkflow{}
			require.NoError(t, yaml.Unmarshal([]byte(subject), &workflow))
			require.Len(t, workflow.Jobs, 1)
			assert.Equal(t, "valid", workflow.Jobs[0].ID)
			assert.Equal(t, "kept", workflow.Jobs[0].Steps[0].Run)
		})
	}
}

func TestGithubActionsCacheModeDoesNotInherit(t *testing.T) {
	subject := `
on: push
cache-mode: read
jobs:
  declared:
    cache-mode: write-only
    steps:
      - run: pwd
  absent:
    steps:
      - run: pwd
`
	var workflow GithubActionsWorkflow
	require.NoError(t, yaml.Unmarshal([]byte(subject), &workflow))
	assert.Equal(t, stringPointer("read"), workflow.CacheMode)
	require.Len(t, workflow.Jobs, 2)
	assert.Equal(t, stringPointer("write-only"), workflow.Jobs[0].CacheMode)
	assert.Nil(t, workflow.Jobs[1].CacheMode)
}

func TestGithubActionsCacheModeYAMLAliases(t *testing.T) {
	subject := `
on: push
cache-mode: &mode read
template: &template
  cache-mode: write-only
jobs:
  alias:
    cache-mode: *mode
    steps:
      - run: pwd
  merged:
    <<: *template
    steps:
      - run: pwd
  override:
    <<: *template
    cache-mode: none
    steps:
      - run: pwd
`
	var workflow GithubActionsWorkflow
	require.NoError(t, yaml.Unmarshal([]byte(subject), &workflow))
	require.Len(t, workflow.Jobs, 3)
	assert.Equal(t, stringPointer("read"), workflow.Jobs[0].CacheMode)
	assert.Equal(t, stringPointer("write-only"), workflow.Jobs[1].CacheMode)
	assert.Equal(t, stringPointer("none"), workflow.Jobs[2].CacheMode)
}

func stringPointer(value string) *string {
	return &value
}
