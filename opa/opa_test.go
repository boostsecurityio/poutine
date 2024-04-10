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
