package opa

import (
	"context"
	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/results"
	"github.com/open-policy-agent/opa/ast"

	"fmt"
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
			input:    `"actions/checkout@v4","",""`,
			expected: "pkg:githubactions/actions/checkout@v4",
		},
		{
			builtin:  "purl.parse_docker_image",
			input:    `"alpine:latest"`,
			expected: "pkg:docker/alpine%3Alatest",
		},
	}

	opa, err := NewOpa(context.TODO(), &models.Config{
		Include: []models.ConfigInclude{},
	})
	noOpaErrors(t, err)

	for _, c := range cases {
		var result interface{}
		query := fmt.Sprintf(`%s(%s)`, c.builtin, c.input)
		err := opa.Eval(context.TODO(), query, nil, &result)
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
			constraint: "<=3.11.13",
			version:    "3.11.13",
			expected:   true,
		},
		{
			constraint: "<=3.11.13",
			version:    "3.11.14",
			expected:   false,
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

	opa, err := NewOpa(context.TODO(), &models.Config{
		Include: []models.ConfigInclude{},
	})
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

	opa, err := NewOpa(context.TODO(), &models.Config{
		Include: []models.ConfigInclude{},
	})
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

func TestWithConfig(t *testing.T) {
	o, err := NewOpa(context.TODO(), &models.Config{
		Include: []models.ConfigInclude{},
	})
	noOpaErrors(t, err)
	ctx := context.TODO()

	err = o.WithConfig(ctx, &models.Config{
		Skip: []models.ConfigSkip{
			{
				Path: []string{"action.yaml"},
			},
		},
		Include: []models.ConfigInclude{
			{
				Path: []string{"testdata/config"},
			},
		},
	})
	assert.NoError(t, err)

	var result []string
	err = o.Eval(ctx, "[data.config.skip[_].path[_], data.config.include[_].path[_]]", nil, &result)

	noOpaErrors(t, err)
	assert.Equal(t, "action.yaml", result[0])
	assert.Equal(t, "testdata/config", result[1])
	assert.Equal(t, "testdata/config", o.LoadPaths[0])
}

func TestCapabilities(t *testing.T) {
	capabilities, err := Capabilities()
	assert.NoError(t, err)
	assert.NotNil(t, capabilities)

	for _, b := range capabilities.Builtins {
		switch b.Name {
		case "http.send",
			"opa.runtime",
			"net.lookup_ip_addr",
			"rego.parse_module",
			"trace":
			t.Errorf("unexpected opa capabilities builtin: %v", b.Name)
		}
	}
}

func TestRulesMetadataLevel(t *testing.T) {
	opa, err := NewOpa(context.TODO(), &models.Config{
		Include: []models.ConfigInclude{},
	})
	noOpaErrors(t, err)

	query := `{rule_id: rule.level |
	  rule := data.rules[rule_id].rule;
	  not input[rule.level]
	}`

	var result map[string]string
	err = opa.Eval(context.TODO(), query, map[string]interface{}{
		"note":    true,
		"warning": true,
		"error":   true,
		"none":    true,
	}, &result)
	noOpaErrors(t, err)

	assert.Empty(t, result, fmt.Sprintf("rules with invalid levels: %v", result))
}

func TestWithRulesConfig(t *testing.T) {
	o, err := NewOpa(context.TODO(), &models.Config{
		Include: []models.ConfigInclude{},
	})
	noOpaErrors(t, err)
	ctx := context.TODO()

	var rule *results.Rule
	err = o.Eval(ctx, "data.rules.pr_runs_on_self_hosted.rule", nil, &rule)
	noOpaErrors(t, err)
	assert.Equal(t, []interface{}{}, rule.Config["allowed_runners"].Default)
	assert.Equal(t, []interface{}{}, rule.Config["allowed_runners"].Value)

	err = o.WithConfig(ctx, &models.Config{
		RulesConfig: map[string]map[string]interface{}{
			"pr_runs_on_self_hosted": {
				"allowed_runners": []string{"self-hosted"},
			},
		},
	})
	assert.NoError(t, err)

	err = o.Eval(ctx, "data.rules.pr_runs_on_self_hosted.rule", nil, &rule)
	noOpaErrors(t, err)
	assert.Equal(t, []interface{}{}, rule.Config["allowed_runners"].Default)
	assert.Equal(t, []interface{}{"self-hosted"}, rule.Config["allowed_runners"].Value)
}
