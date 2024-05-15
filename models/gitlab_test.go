package models

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGitlabciConfig(t *testing.T) {
	subject := `
spec:
  inputs:
    environment:
    job-stage:
      default: build
      options:
        - build
        - deploy

---

image: docker:19.03.10

services:
  - docker:dind

include:
- https://example.com/.gitlab-ci.yml # remote
- ./.gitlab/build.yml # local
- local: path/to/template.yml
  inputs:
    key: value
- project: my-group/my-project
  ref: main
  file: /templates/.gitlab-ci-template.yml

.vars:
  variables:
    URL: http://my-url.internal
    SCRIPT: echo 123

variables:
  REPOSITORY_URL: example.com
  FULL:
    value: 123
    expand: true
    description: full description
    options: [option1]
  REF: !reference [.vars, variables, URL]

default:
  before_script:
  - apk add curl

stages:
  - build
  - deploy

build:
  stage: build
  inherit: true
  script:
    - docker build -t $REPOSITORY_URL:latest .
    - !reference [.vars, variables, SCRIPT]
  only:
    - main

deploy:
  stage: deploy
  inherit: [REPOSITORY_URL]
  script:
    - echo $REPOSITORY_URL:$IMAGE_TAG
  after_script:
    - aws ecs update-service ...
  only:
    - main
`

	config, err := ParseGitlabciConfig([]byte(subject))
	assert.Nil(t, err)

	assert.Equal(t, 2, len(config.Spec.Inputs))

	assert.Equal(t, 2, len(config.Spec.Inputs))
	assert.Equal(t, "environment", config.Spec.Inputs[0].Name)
	assert.Equal(t, "job-stage", config.Spec.Inputs[1].Name)
	assert.Equal(t, "build", config.Spec.Inputs[1].Default)
	assert.Equal(t, 2, len(config.Spec.Inputs[1].Options))
	assert.Equal(t, "build", config.Spec.Inputs[1].Options[0])
	assert.Equal(t, "deploy", config.Spec.Inputs[1].Options[1])

	assert.Equal(t, "docker:19.03.10", config.Default.Image.Name)
	assert.Equal(t, "REPOSITORY_URL", config.Variables[0].Name)
	assert.Equal(t, "example.com", config.Variables[0].Value)
	assert.Equal(t, false, config.Variables[0].Expand)
	assert.Equal(t, "FULL", config.Variables[1].Name)
	assert.Equal(t, "123", config.Variables[1].Value)
	assert.Equal(t, true, config.Variables[1].Expand)
	assert.Equal(t, "full description", config.Variables[1].Description)
	assert.Equal(t, []string{"option1"}, config.Variables[1].Options)
	assert.Equal(t, "REF", config.Variables[2].Name)
	assert.Equal(t, "!reference [.vars, variables, URL]\n", config.Variables[2].Value)

	assert.Equal(t, 1, len(config.Default.BeforeScript))
	assert.Equal(t, "apk add curl", string(config.Default.BeforeScript[0].Run))

	assert.Equal(t, "build", config.Stages[0])
	assert.Equal(t, "deploy", config.Stages[1])

	assert.Equal(t, 4, len(config.Jobs))
	assert.Equal(t, ".vars", config.Jobs[0].Name)
	assert.Equal(t, true, config.Jobs[0].Hidden)
	assert.Equal(t, 2, len(config.Jobs[0].Variables))
	assert.Equal(t, "URL", config.Jobs[0].Variables[0].Name)
	assert.Equal(t, "http://my-url.internal", config.Jobs[0].Variables[0].Value)

	assert.Equal(t, config.Default, config.Jobs[1])
	assert.Equal(t, 42, config.Default.Line)

	assert.Equal(t, "build", config.Jobs[2].Name)
	assert.Equal(t, "true", config.Jobs[2].Inherit[0])
	assert.Equal(t, 2, len(config.Jobs[2].Script))
	assert.Equal(t, "docker build -t $REPOSITORY_URL:latest .", string(config.Jobs[2].Script[0].Run))
	assert.Equal(t, "!reference [.vars, variables, SCRIPT]\n", string(config.Jobs[2].Script[1].Run))

	assert.Equal(t, "deploy", config.Jobs[3].Name)
	assert.Equal(t, "REPOSITORY_URL", config.Jobs[3].Inherit[0])
	assert.Equal(t, 1, len(config.Jobs[3].Script))
	assert.Equal(t, "echo $REPOSITORY_URL:$IMAGE_TAG", string(config.Jobs[3].Script[0].Run))
	assert.Equal(t, 1, len(config.Jobs[3].AfterScript))
	assert.Equal(t, "aws ecs update-service ...", string(config.Jobs[3].AfterScript[0].Run))

	assert.Equal(t, "https://example.com/.gitlab-ci.yml", config.Include[0].Remote)
	assert.Equal(t, "./.gitlab/build.yml", config.Include[1].Local)
	assert.Equal(t, "path/to/template.yml", config.Include[2].Local)
	assert.Equal(t, "key", config.Include[2].Inputs[0].Name)
	assert.Equal(t, "value", config.Include[2].Inputs[0].Value)

	assert.Equal(t, "my-group/my-project", config.Include[3].Project)
	assert.Equal(t, "main", config.Include[3].Ref)
	assert.Equal(t, "/templates/.gitlab-ci-template.yml", config.Include[3].File[0])
}

func TestGitlabIncludes(t *testing.T) {
	subjects := []struct {
		config   string
		expected GitlabciIncludeItems
	}{
		{
			config: `include: https://example.com`,
			expected: []GitlabciIncludeItem{
				{Remote: "https://example.com"},
			},
		},
		{
			config: `include: local.yml`,
			expected: []GitlabciIncludeItem{
				{Local: "local.yml"},
			},
		},
		{
			config: `include: [https://example.com]`,
			expected: []GitlabciIncludeItem{
				{Remote: "https://example.com"},
			},
		},
		{
			config: `include: [local.yml]`,
			expected: []GitlabciIncludeItem{
				{Local: "local.yml"},
			},
		},
		{
			config: `include: [{local: local.yml}]`,
			expected: []GitlabciIncludeItem{
				{Local: "local.yml"},
			},
		},
		{
			config: `include: [{remote: http://example.com}]`,
			expected: []GitlabciIncludeItem{
				{Remote: "http://example.com"},
			},
		},
		{
			config: `include: [{template: Auto-DevOps.gitlab-ci.yml}]`,
			expected: []GitlabciIncludeItem{
				{Template: "Auto-DevOps.gitlab-ci.yml"},
			},
		},
		{
			config: `include: [{project: my-group/my-project, ref: main, file: /templates/.gitlab-ci-template.yml}]`,
			expected: []GitlabciIncludeItem{
				{
					Project: "my-group/my-project",
					Ref:     "main",
					File:    []string{"/templates/.gitlab-ci-template.yml"},
				},
			},
		},
		{
			config:   `{}`,
			expected: nil,
		},
	}

	for _, subject := range subjects {
		config, err := ParseGitlabciConfig([]byte(subject.config))
		assert.Nil(t, err)
		assert.Equal(t, subject.expected, config.Include)
	}
}
