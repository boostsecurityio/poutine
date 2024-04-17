package opa

import (
	"context"
	"github.com/open-policy-agent/opa/ast"

	"github.com/stretchr/testify/assert"
	"testing"
)

func noOpaErrors(t *testing.T, err error) {
	if err == nil {
		return
	}

	if regoErrors, ok := err.(*ast.Errors); ok {
		for _, e := range *regoErrors {
			t.Errorf("ast error: %v", e)

		}
	}

	panic(err)
}

func TestOpaBuiltins(t *testing.T) {
	cases := []struct {
		builtin  string
		input    string
		expected string
	}{
		{
			builtin:  "purl.parse_github_actions",
			input:    "actions/checkout@v4",
			expected: "pkg:githubactions/actions/checkout@v4",
		},
		{
			builtin:  "purl.parse_docker_image",
			input:    "alpine:latest",
			expected: "pkg:docker/alpine%3Alatest",
		},
	}

	opa, err := NewOpa()
	noOpaErrors(t, err)

	for _, c := range cases {
		var result interface{}
		err := opa.Eval(context.TODO(), c.builtin+"(\""+c.input+"\")", nil, &result)
		noOpaErrors(t, err)

		assert.Equal(t, c.expected, result)
	}
}

func TestSemverConstraintCheck(t *testing.T) {
	cases := []struct {
		constraint string
		version    string
		expected   bool
	}{
		{
			constraint: ">=1.0.0",
			version:    "1.0.0",
			expected:   true,
		},
		{
			constraint: ">=4.0.0,<4.4.1",
			version:    "4",
			expected:   true,
		},
		{
			constraint: ">=4.0.0,<4.4.1",
			version:    "3",
			expected:   false,
		},
	}

	opa, err := NewOpa()
	noOpaErrors(t, err)

	for _, c := range cases {
		var result interface{}
		err := opa.Eval(context.TODO(), "semver.constraint_check(\""+c.constraint+"\", \""+c.version+"\")", nil, &result)
		noOpaErrors(t, err)

		assert.Equal(t, c.expected, result)
	}
}

func TestJobUsesSelfHostedRunner(t *testing.T) {
	// based on https://github.com/actions/runner-images/
	cases := map[string]bool{
		"ubuntu-latest":       false,
		"ubuntu-22.04":        false,
		"ubuntu-20.04":        false,
		"macos-latest-large":  false,
		"macos-14-large":      false,
		"macos-latest":        false,
		"macos-14":            false,
		"macos-latest-xlarge": false,
		"macos-14-xlarge":     false,
		"macos-13":            false,
		"macos-13-large":      false,
		"macos-13-xlarge":     false,
		"macos-12":            false,
		"macos-12-large":      false,
		"macos-11":            false,
		"windows-latest":      false,
		"windows-2022":        false,
		"windows-2019":        false,
		"self-hosted":         true,
		"random-name":         true,
	}

	opa, err := NewOpa()
	noOpaErrors(t, err)

	for runner, expected := range cases {
		var result bool
		input := map[string]interface{}{
			"runs_on": []string{runner},
		}

		err = opa.Eval(
			context.TODO(),
			`utils.job_uses_self_hosted_runner(input)`,
			input,
			&result,
		)

		noOpaErrors(t, err)
		assert.Equal(t, expected, result, "runner: "+runner)
	}
}
