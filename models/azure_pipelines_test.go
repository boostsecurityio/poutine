package models

import (
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
	"testing"
)

func TestAzurePipeline(t *testing.T) {
	lines := map[string]int{"bash": 1, "start": 1}
	cases := []struct {
		input    string
		expected AzurePipeline
		error    bool
	}{
		{
			input: `steps: [bash: asdf]`,
			expected: AzurePipeline{
				Stages: []AzureStage{
					{
						Jobs: []AzureJob{
							{
								Steps: []AzureStep{
									{
										Bash:  "asdf",
										Lines: lines,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			input: `stages: [{stage: build, jobs: [{job: test, steps: [bash: asdf]}]}]`,
			expected: AzurePipeline{
				Stages: []AzureStage{
					{
						Stage: "build",
						Jobs: []AzureJob{
							{
								Job: "test",
								Steps: []AzureStep{
									{
										Bash:  "asdf",
										Lines: lines,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			input: `jobs: [{job: test, steps: [bash: asdf]}]`,
			expected: AzurePipeline{
				Stages: []AzureStage{
					{
						Jobs: []AzureJob{
							{
								Job: "test",
								Steps: []AzureStep{
									{
										Bash:  "asdf",
										Lines: lines,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for i, c := range cases {
		var result AzurePipeline
		err := yaml.Unmarshal([]byte(c.input), &result)
		if c.error {
			assert.NotNil(t, err, i)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, c.expected, result, i)
		}
	}
}

func TestAzurePr(t *testing.T) {
	cases := []struct {
		input    string
		expected AzurePr
		error    bool
	}{
		{
			input: `asdf`,
			error: true,
		},
		{
			input: `none`,
			expected: AzurePr{
				Disabled: true,
				Drafts:   true,
			},
		},
		{
			input: `[main, dev]`,
			expected: AzurePr{
				Branches: &AzureIncludeExclude{
					Include: StringList{"main", "dev"},
				},
				Drafts: true,
			},
		},
		{
			input: `{branches: {include: [main, dev]}}`,
			expected: AzurePr{
				Branches: &AzureIncludeExclude{
					Include: StringList{"main", "dev"},
				},
				Drafts: true,
			},
		},
		{
			input: `{drafts: false, branches: {include: [main, dev]}}`,
			expected: AzurePr{
				Branches: &AzureIncludeExclude{
					Include: StringList{"main", "dev"},
				},
			},
		},
	}

	for i, c := range cases {
		var result AzurePr
		err := yaml.Unmarshal([]byte(c.input), &result)
		if c.error {
			assert.NotNil(t, err, i)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, c.expected, result, i)
		}
	}
}
