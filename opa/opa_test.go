package opa

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/results"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/embedded
var testEmbeddedRules embed.FS

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
			expected: "pkg:docker/alpine@latest",
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
		"ubuntu-slim":         false,
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

func TestCheckoutForkPRGuard(t *testing.T) {
	o, err := NewOpa(context.TODO(), &models.Config{
		Include: []models.ConfigInclude{},
	})
	require.NoError(t, err)

	tests := []struct {
		name  string
		input map[string]interface{}
		want  bool
	}{
		{
			name: "fixed release on pull request target",
			input: checkoutGuardInput(
				[]map[string]interface{}{{"name": "pull_request_target"}},
				"actions/checkout@v4",
				nil,
				nil,
			),
			want: true,
		},
		{
			name: "fixed commit on pull request target",
			input: checkoutGuardInput(
				[]map[string]interface{}{{"name": "pull_request_target"}},
				"actions/checkout@f548e57e544e1ff5a4c46bf1e1b8685f8e4a348a",
				nil,
				nil,
			),
			want: true,
		},
		{
			name: "vulnerable commit",
			input: checkoutGuardInput(
				[]map[string]interface{}{{"name": "pull_request_target"}},
				"actions/checkout@1e31de5234b9f8995739874a8ce0492dc87873e2",
				nil,
				nil,
			),
		},
		{
			name: "vulnerable version ref",
			input: checkoutGuardInput(
				[]map[string]interface{}{{"name": "pull_request_target"}},
				"actions/checkout@v4.3.1",
				nil,
				nil,
			),
		},
		{
			name: "unlisted version below fixed floor",
			input: checkoutGuardInput(
				[]map[string]interface{}{{"name": "pull_request_target"}},
				"actions/checkout@v4.3.2",
				nil,
				nil,
			),
		},
		{
			name: "major minor below fixed floor",
			input: checkoutGuardInput(
				[]map[string]interface{}{{"name": "pull_request_target"}},
				"actions/checkout@v4.3",
				nil,
				nil,
			),
		},
		{
			name: "major minor at fixed floor",
			input: checkoutGuardInput(
				[]map[string]interface{}{{"name": "pull_request_target"}},
				"actions/checkout@v4.4",
				nil,
				nil,
			),
			want: true,
		},
		{
			name: "prerelease below fixed floor",
			input: checkoutGuardInput(
				[]map[string]interface{}{{"name": "pull_request_target"}},
				"actions/checkout@v2.8.0-rc.1",
				nil,
				nil,
			),
		},
		{
			name: "build metadata at fixed floor",
			input: checkoutGuardInput(
				[]map[string]interface{}{{"name": "pull_request_target"}},
				"actions/checkout@v2.8.0+build.1",
				nil,
				nil,
			),
			want: true,
		},
		{
			name: "v1 prerelease",
			input: checkoutGuardInput(
				[]map[string]interface{}{{"name": "pull_request_target"}},
				"actions/checkout@v1.2.3-alpha.1",
				nil,
				nil,
			),
		},
		{
			name: "numeric prerelease follows Rego semver",
			input: checkoutGuardInput(
				[]map[string]interface{}{{"name": "pull_request_target"}},
				"actions/checkout@v2.8.0-01",
				nil,
				nil,
			),
		},
		{
			name: "invalid empty prerelease identifier",
			input: checkoutGuardInput(
				[]map[string]interface{}{{"name": "pull_request_target"}},
				"actions/checkout@v2.8.0-alpha..1",
				nil,
				nil,
			),
			want: true,
		},
		{
			name: "vulnerable v1 major ref",
			input: checkoutGuardInput(
				[]map[string]interface{}{{"name": "pull_request_target"}},
				"actions/checkout@v1",
				nil,
				nil,
			),
		},
		{
			name: "unknown version ref",
			input: checkoutGuardInput(
				[]map[string]interface{}{{"name": "pull_request_target"}},
				"actions/checkout@v8",
				nil,
				nil,
			),
			want: true,
		},
		{
			name: "future semantic version ref",
			input: checkoutGuardInput(
				[]map[string]interface{}{{"name": "pull_request_target"}},
				"actions/checkout@v8.0.0",
				nil,
				nil,
			),
			want: true,
		},
		{
			name: "branch ref",
			input: checkoutGuardInput(
				[]map[string]interface{}{{"name": "pull_request_target"}},
				"actions/checkout@feature-branch",
				nil,
				nil,
			),
			want: true,
		},
		{
			name: "unsafe checkout opt out",
			input: checkoutGuardInput(
				[]map[string]interface{}{{"name": "pull_request_target"}},
				"actions/checkout@v4",
				[]map[string]interface{}{{"name": "allow-unsafe-pr-checkout", "value": "true"}},
				nil,
			),
		},
		{
			name: "unguarded event",
			input: checkoutGuardInput(
				[]map[string]interface{}{{"name": "pull_request_target"}, {"name": "issue_comment"}},
				"actions/checkout@v4",
				nil,
				nil,
			),
		},
		{
			name: "pull request workflow run",
			input: checkoutGuardInput(
				[]map[string]interface{}{{"name": "workflow_run", "workflows": []string{"PR checks"}}},
				"actions/checkout@v4",
				nil,
				[]map[string]interface{}{{
					"github_actions_workflows": []map[string]interface{}{{
						"name":   "PR checks",
						"events": []map[string]interface{}{{"name": "pull_request"}},
					}},
				}},
			),
			want: true,
		},
		{
			name: "non pull request workflow run",
			input: checkoutGuardInput(
				[]map[string]interface{}{{"name": "workflow_run", "workflows": []string{"Issue checks"}}},
				"actions/checkout@v4",
				nil,
				[]map[string]interface{}{{
					"github_actions_workflows": []map[string]interface{}{{
						"name":   "Issue checks",
						"events": []map[string]interface{}{{"name": "issue_comment"}},
					}},
				}},
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got bool
			err := o.Eval(
				context.TODO(),
				`count([true | utils.checkout_fork_pr_guard_blocks_step(input.workflow, input.step, {"issues", "issue_comment", "workflow_call"})]) > 0`,
				tt.input,
				&got,
			)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func checkoutGuardInput(events []map[string]interface{}, uses string, with, packages []map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"workflow": map[string]interface{}{"events": events},
		"step": map[string]interface{}{
			"uses":     uses,
			"with_ref": "${{ github.event.pull_request.head.sha }}",
			"with":     with,
		},
		"packages": packages,
	}
}

func TestCheckoutGuardData(t *testing.T) {
	o, err := NewOpa(context.TODO(), &models.Config{
		Include: []models.ConfigInclude{},
	})
	require.NoError(t, err)

	var vulnerableSHAs []string
	err = o.Eval(
		context.TODO(),
		`sort([sha | sha := data.poutine.checkout_guard_data.vulnerable_commit_shas[_]])`,
		nil,
		&vulnerableSHAs,
	)
	require.NoError(t, err)
	assert.Len(t, vulnerableSHAs, 223)
	digest := sha256.Sum256([]byte(strings.Join(vulnerableSHAs, "\n")))
	assert.Equal(
		t,
		"017930673376b24e4bff0fa4bd8fd9c4c196da4b6cd5eb193b421032b43598c1",
		hex.EncodeToString(digest[:]),
	)

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

func TestNewOpaWithEmbeddedRules(t *testing.T) {
	ctx := context.TODO()

	// Test NewOpaWithEmbeddedRules constructor
	opa, err := NewOpaWithEmbeddedRules(ctx, &models.Config{
		Include: []models.ConfigInclude{},
	}, testEmbeddedRules)
	noOpaErrors(t, err)
	assert.NotNil(t, opa)

	// Verify that the custom rule was loaded and can be evaluated
	var customRule map[string]interface{}
	err = opa.Eval(ctx, "data.custom.rule", nil, &customRule)
	noOpaErrors(t, err)
	assert.Equal(t, "Custom Test Rule", customRule["title"])
	assert.Equal(t, "warning", customRule["level"])

	// Test that the custom rule logic works
	var results []map[string]interface{}
	input := map[string]interface{}{
		"test_value": "test data",
	}
	err = opa.Eval(ctx, "data.custom.results", input, &results)
	noOpaErrors(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "Custom rule executed successfully", results[0]["message"])
	assert.Equal(t, "test data", results[0]["details"])

	// Verify built-in Poutine rules are still loaded
	var builtinRule interface{}
	err = opa.Eval(ctx, "data.rules.pr_runs_on_self_hosted.rule", nil, &builtinRule)
	noOpaErrors(t, err)
	assert.NotNil(t, builtinRule)
}

func TestEmbeddedRulesWithSkipAndAllowed(t *testing.T) {
	ctx := context.TODO()

	// Test that skip rules work with embedded custom rules
	opa, err := NewOpaWithEmbeddedRules(ctx, &models.Config{
		Include: []models.ConfigInclude{},
	}, testEmbeddedRules)
	noOpaErrors(t, err)

	// Verify both rules are loaded initially
	var customRule map[string]interface{}
	err = opa.Eval(ctx, "data.custom.rule", nil, &customRule)
	noOpaErrors(t, err)
	assert.Equal(t, "Custom Test Rule", customRule["title"])

	var skippableRule map[string]interface{}
	err = opa.Eval(ctx, "data.custom.rules.skippable_rule", nil, &skippableRule)
	noOpaErrors(t, err)
	assert.NotNil(t, skippableRule)
	assert.Equal(t, "Skippable Test Rule", skippableRule["title"])

	// Now recompile with skip rule
	err = opa.Compile(ctx, []string{"skippable_rule"}, []string{})
	noOpaErrors(t, err)

	// The non-skipped rule should still be available
	err = opa.Eval(ctx, "data.custom.rule", nil, &customRule)
	noOpaErrors(t, err)
	assert.Equal(t, "Custom Test Rule", customRule["title"])

	// The skipped rule should not be available
	err = opa.Eval(ctx, "data.custom.rules.skippable_rule", nil, &skippableRule)
	assert.Error(t, err)
}
