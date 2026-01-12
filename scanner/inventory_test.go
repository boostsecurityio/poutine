package scanner

import (
	"context"
	"testing"

	"github.com/boostsecurityio/poutine/results"

	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/stretchr/testify/assert"
)

func TestPurls(t *testing.T) {
	o, _ := opa.NewOpa(context.TODO(), &models.Config{
		Include: []models.ConfigInclude{},
	})
	i := NewInventory(o, nil, "", "")
	pkg := &models.PackageInsights{
		Purl:          "pkg:github/org/owner",
		SourceGitRepo: "org/owner",
		SourceGitRef:  "main",
	}
	_ = pkg.NormalizePurl()
	scannedPackage, err := i.ScanPackage(context.Background(), *pkg, "testdata")
	assert.NoError(t, err)

	purls := []string{
		"pkg:docker/node%3Alatest",
		"pkg:githubactions/hashicorp/vault-action@v3",
		"pkg:githubactions/actions/checkout@main",
		"pkg:githubactions/kartverket/github-workflows@main#.github/workflows/run-terraform.yml",
		"pkg:githubactions/kartverket/github-workflows@v2.2#.github/workflows/run-terraform.yml",
		"pkg:githubactions/kartverket/github-workflows@v2.7.1#.github/workflows/run-terraform.yml",
		"pkg:docker/alpine%3Alatest",
		"pkg:githubactions/actions/github-script@main",
		"pkg:githubactions/actions/setup-node@v4",
		"pkg:githubactions/hashicorp/vault-action@v2.1.0",
		"pkg:githubactions/actions/checkout@v4",
		"pkg:docker/ruby%3A3.2",
		"pkg:docker/postgres%3A15",
		"pkg:gitlabci/include/template?file_name=Auto-DevOps.gitlab-ci.yml",
		"pkg:gitlabci/include/project?file_name=%2Ftemplates%2F.gitlab-ci-template.yml&project=my-group%2Fmy-project&ref=main",
		"pkg:gitlabci/include/remote?download_url=https%3A%2F%2Fexample.com%2F.gitlab-ci.yml",
		"pkg:gitlabci/include/component?project=my-org%2Fsecurity-components%2Fsecret-detection&ref=1.0&repository_url=gitlab.example.com",
		"pkg:githubactions/org/repo@main",
		"pkg:docker/debian%3Avuln",
		"pkg:githubactions/bridgecrewio/checkov-action@main",
		"pkg:githubactions/org/repo@main#.github/workflows/Reusable.yml",
		"pkg:azurepipelinestask/DownloadPipelineArtifact@2",
		"pkg:azurepipelinestask/Cache@2",
		"pkg:githubactions/org/owner@main#.github/workflows/ci.yml",
		"pkg:githubactions/actions/checkout@v5",
		"pkg:docker/node%3A18",
		"pkg:githubactions/some/action@v1",
	}
	assert.ElementsMatch(t, i.Purls(*scannedPackage), purls)
	assert.Len(t, scannedPackage.BuildDependencies, 23)
	assert.Equal(t, 4, len(scannedPackage.PackageDependencies))
}

func TestFindings(t *testing.T) {
	o, _ := opa.NewOpa(context.TODO(), &models.Config{
		Include: []models.ConfigInclude{},
	})
	i := NewInventory(o, nil, "gitlab", "")
	purl := "pkg:github/org/owner"
	pkg := &models.PackageInsights{
		Purl:          purl,
		SourceGitRepo: "org/owner",
		SourceGitRef:  "main",
	}
	_ = pkg.NormalizePurl()

	scannedPackage, err := i.ScanPackage(context.Background(), *pkg, "testdata")
	assert.NoError(t, err)

	analysisResults := scannedPackage.FindingsResults

	rule_ids := []string{}
	for _, r := range analysisResults.Rules {
		rule_ids = append(rule_ids, r.Id)
	}

	assert.ElementsMatch(t, rule_ids, []string{
		"default_permissions_on_risky_events",
		"if_always_true",
		"known_vulnerability_in_build_component",
		"pr_runs_on_self_hosted",
		"known_vulnerability_in_build_platform",
		"unpinnable_action",
		"untrusted_checkout_exec",
		"injection",
		"github_action_from_unverified_creator_used",
		"debug_enabled",
		"job_all_secrets",
		"unverified_script_exec",
		"confused_deputy_auto_merge",
	})

	findings := []results.Finding{
		{
			RuleId: "debug_enabled",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:          ".github/workflows/debug_enabled_valid.yml",
				Details:       "ACTIONS_RUNNER_DEBUG",
				EventTriggers: []string{"push"},
			},
		},
		{
			RuleId: "debug_enabled",
			Purl:   purl,
			Meta: results.FindingMeta{
				Job:           "build",
				Path:          ".github/workflows/debug_enabled_valid.yml",
				Line:          9,
				Details:       "ACTIONS_STEP_DEBUG",
				EventTriggers: []string{"push"},
			},
		},
		{
			RuleId: "debug_enabled",
			Purl:   purl,
			Meta: results.FindingMeta{
				Job:           "build",
				Path:          ".github/workflows/debug_enabled_valid.yml",
				Step:          "0",
				Line:          14,
				Details:       "ACTIONS_STEP_DEBUG",
				EventTriggers: []string{"push"},
			},
		},
		{
			RuleId: "injection",
			Purl:   purl,
			Meta: results.FindingMeta{
				Job:               "build",
				Path:              ".github/workflows/valid.yml",
				Step:              "1",
				Line:              20,
				Details:           "Sources: github.head_ref",
				InjectionSources:  []string{"github.head_ref"},
				EventTriggers:     []string{"push", "pull_request_target"},
				ReferencedSecrets: []string{},
			},
		},
		{
			RuleId: "injection",
			Purl:   purl,
			Meta: results.FindingMeta{
				Job:               "build",
				Path:              ".github/workflows/valid.yml",
				Step:              "7",
				Line:              46,
				Details:           "Sources: github.event.workflow_run.head_branch",
				InjectionSources:  []string{"github.event.workflow_run.head_branch"},
				EventTriggers:     []string{"push", "pull_request_target"},
				ReferencedSecrets: []string{},
			},
		},
		{
			RuleId: "known_vulnerability_in_build_component",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:    "composite/action.yml",
				OsvId:   "GHSA-4mgv-m5cm-f9h7",
				Step:    "2",
				Line:    13,
				Details: "Package: hashicorp/vault-action",
			},
		},
		{
			RuleId: "known_vulnerability_in_build_component",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:          ".github/workflows/valid.yml",
				Job:           "build",
				Step:          "5",
				OsvId:         "GHSA-f9qj-7gh3-mhj4",
				Line:          39,
				Details:       "Package: kartverket/github-workflows/.github/workflows/run-terraform.yml",
				EventTriggers: []string{"push", "pull_request_target"},
			},
		},
		{
			RuleId: "known_vulnerability_in_build_component",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:          ".github/workflows/valid.yml",
				Job:           "build",
				Step:          "6",
				OsvId:         "GHSA-f9qj-7gh3-mhj4",
				Line:          43,
				Details:       "Package: kartverket/github-workflows/.github/workflows/run-terraform.yml",
				EventTriggers: []string{"push", "pull_request_target"},
			},
		},
		{
			RuleId: "untrusted_checkout_exec",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:              ".github/workflows/valid.yml",
				Job:               "build",
				Line:              30,
				Details:           "Detected usage of `npm`",
				LOTPTool:          "npm",
				EventTriggers:     []string{"push", "pull_request_target"},
				ReferencedSecrets: []string{},
			},
		},
		{
			RuleId: "untrusted_checkout_exec",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:              ".github/workflows/valid.yml",
				Job:               "build",
				Line:              56,
				Details:           "Detected usage the GitHub Action `bridgecrewio/checkov-action`",
				LOTPAction:        "bridgecrewio/checkov-action",
				EventTriggers:     []string{"push", "pull_request_target"},
				ReferencedSecrets: []string{},
			},
		},
		{
			RuleId: "untrusted_checkout_exec",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:              ".github/workflows/valid.yml",
				Job:               "build",
				Line:              60,
				Details:           "Detected usage of `pre-commit`",
				LOTPTool:          "pre-commit",
				EventTriggers:     []string{"push", "pull_request_target"},
				ReferencedSecrets: []string{},
			},
		},
		{
			RuleId: "untrusted_checkout_exec",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:              ".github/workflows/valid.yml",
				Job:               "build",
				Line:              75,
				Details:           "Detected usage of `bash`",
				LOTPTool:          "bash",
				EventTriggers:     []string{"push", "pull_request_target"},
				ReferencedSecrets: []string{},
			},
		},
		{
			RuleId: "untrusted_checkout_exec",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:              ".github/workflows/valid.yml",
				Job:               "build",
				Line:              80,
				Details:           "Detected usage of `bash`",
				LOTPTool:          "bash",
				EventTriggers:     []string{"push", "pull_request_target"},
				ReferencedSecrets: []string{},
			},
		},
		{
			RuleId: "untrusted_checkout_exec",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:              ".github/workflows/workflow_run_valid.yml",
				Job:               "pr",
				Line:              13,
				Details:           "Detected usage of `npm`",
				LOTPTool:          "npm",
				EventTriggers:     []string{"workflow_run"},
				ReferencedSecrets: []string{},
			},
		},
		{
			RuleId: "default_permissions_on_risky_events",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:          ".github/workflows/valid.yml",
				EventTriggers: []string{"push", "pull_request_target"},
			},
		},
		{
			RuleId: "unpinnable_action",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path: "action.yml",
			},
		},
		{
			RuleId: "unpinnable_action",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path: "composite/action.yml",
			},
		},
		{
			RuleId: "pr_runs_on_self_hosted",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:          ".github/workflows/valid.yml",
				Job:           "build",
				Line:          9,
				Details:       "runs-on: self-hosted",
				EventTriggers: []string{"push", "pull_request_target"},
			},
		},
		{
			RuleId: "pr_runs_on_self_hosted",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:          ".github/workflows/allowed_pr_runner.yml",
				Job:           "group",
				Line:          18,
				Details:       "runs-on: group:prdeploy",
				EventTriggers: []string{"pull_request"},
			},
		},
		{
			RuleId: "pr_runs_on_self_hosted",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:          ".github/workflows/allowed_pr_runner.yml",
				Job:           "labels",
				Line:          24,
				Details:       "runs-on: label:linux",
				EventTriggers: []string{"pull_request"},
			},
		},
		{
			RuleId: "github_action_from_unverified_creator_used",
			Purl:   "pkg:githubactions/kartverket/github-workflows",
			Meta: results.FindingMeta{
				Details: "Used in 1 repo(s)",
			},
		},
		{
			RuleId: "injection",
			Purl:   purl,
			Meta: results.FindingMeta{
				Job:               "build",
				Path:              ".github/workflows/valid.yml",
				Step:              "8",
				Line:              50,
				Details:           "Sources: github.event.client_payload.foo",
				InjectionSources:  []string{"github.event.client_payload.foo"},
				EventTriggers:     []string{"push", "pull_request_target"},
				ReferencedSecrets: []string{},
			},
		},
		{
			RuleId: "injection",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:             ".gitlab-ci.yml",
				Job:              "default.before_script[0]",
				Details:          "Sources: inputs.gem_name",
				InjectionSources: []string{"inputs.gem_name"},
				Line:             48,
			},
		},
		{
			RuleId: "debug_enabled",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:    ".gitlab-ci.yml",
				Details: "CI_DEBUG_SERVICES CI_DEBUG_TRACE",
			},
		},
		{
			RuleId: "job_all_secrets",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:          ".github/workflows/secrets.yaml",
				Line:          4,
				Job:           "matrix",
				EventTriggers: []string{"pull_request"},
			},
		},
		{
			RuleId: "job_all_secrets",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:          ".github/workflows/secrets.yaml",
				Line:          16,
				Job:           "json",
				EventTriggers: []string{"pull_request"},
			},
		},
		{
			RuleId: "if_always_true",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path: "composite/action.yml",
				Line: 17,
				Step: "3",
			},
		},
		{
			RuleId: "unverified_script_exec",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:          ".github/workflows/valid.yml",
				Line:          70,
				Job:           "build",
				Step:          "12",
				Details:       "Command: curl https://example.com | bash",
				EventTriggers: []string{"push", "pull_request_target"},
			},
		},
		{
			RuleId: "unverified_script_exec",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:          ".github/workflows/valid.yml",
				Line:          75,
				Job:           "build",
				Step:          "13",
				Details:       "Command: curl https://raw.githubusercontent.com/org/repo/main/install.sh | bash",
				EventTriggers: []string{"push", "pull_request_target"},
			},
		},
		{
			RuleId: "unverified_script_exec",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:    "azure-pipelines-1.yml",
				Line:    8,
				Step:    "2",
				Details: "Command: curl $(URL) | bash",
			},
		},
		{
			RuleId: "injection",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:             ".azure-pipelines.yml",
				Line:             14,
				Job:              "build",
				Step:             "1",
				Details:          "Sources: Build.SourceBranch",
				InjectionSources: []string{"Build.SourceBranch"},
			},
		},
		{
			RuleId: "debug_enabled",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:    ".azure-pipelines.yml",
				Line:    0,
				Job:     "",
				Step:    "1",
				Details: "system.debug",
			},
		},
		{
			RuleId: "untrusted_checkout_exec",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:     "azure-pipelines-2.yml",
				Line:     13,
				Job:      "",
				Step:     "1",
				Details:  "Detected usage of `bash`",
				LOTPTool: "bash",
			},
		},
		{
			RuleId: "untrusted_checkout_exec",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:     "azure-pipelines-2.yml",
				Line:     14,
				Job:      "",
				Step:     "2",
				Details:  "Detected usage of `npm`",
				LOTPTool: "npm",
			},
		},
		{
			RuleId: "untrusted_checkout_exec",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:     "azure-pipelines-4.yml",
				Line:     10,
				Job:      "",
				Step:     "1",
				Details:  "Detected usage of `bash`",
				LOTPTool: "bash",
			},
		},
		{
			RuleId: "untrusted_checkout_exec",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:     "azure-pipelines-4.yml",
				Line:     11,
				Job:      "",
				Step:     "2",
				Details:  "Detected usage of `npm`",
				LOTPTool: "npm",
			},
		},
		{
			RuleId: "untrusted_checkout_exec",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:     ".tekton/pipeline-as-code-tekton.yml",
				Line:     43,
				Job:      "vale",
				Step:     "0",
				Details:  "Detected usage of `vale`",
				LOTPTool: "vale",
			},
		},
		{
			RuleId: "injection",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:             ".tekton/pipeline-as-code-tekton.yml",
				Line:             45,
				Job:              "vale",
				Step:             "1",
				Details:          "Sources: body.pull_request.body",
				InjectionSources: []string{"body.pull_request.body"},
			},
		},
		{
			RuleId: "injection",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:              ".github/workflows/anchors_with_vulnerability.yml",
				Line:              15,
				Job:               "base_job",
				Step:              "1",
				Details:           "Sources: github.head_ref",
				InjectionSources:  []string{"github.head_ref"},
				EventTriggers:     []string{"pull_request_target", "push"},
				ReferencedSecrets: []string{},
			},
		},
		{
			RuleId: "injection",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:              ".github/workflows/anchors_with_vulnerability.yml",
				Line:              15,
				Job:               "test_job",
				Step:              "1",
				Details:           "Sources: github.head_ref",
				InjectionSources:  []string{"github.head_ref"},
				EventTriggers:     []string{"pull_request_target", "push"},
				ReferencedSecrets: []string{},
			},
		},
		{
			RuleId: "default_permissions_on_risky_events",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:          ".github/workflows/anchors_with_vulnerability.yml",
				EventTriggers: []string{"pull_request_target", "push"},
			},
		},
		// test_new_fields.yml findings
		{
			RuleId: "injection",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:              ".github/workflows/test_new_fields.yml",
				Line:              14,
				Job:               "vulnerable_injection",
				Step:              "1",
				Details:           "Sources: github.event.issue.title",
				InjectionSources:  []string{"github.event.issue.title"},
				EventTriggers:     []string{"pull_request_target"},
				ReferencedSecrets: []string{},
			},
		},
		{
			RuleId: "github_action_from_unverified_creator_used",
			Purl:   "pkg:githubactions/some/action",
			Meta: results.FindingMeta{
				Details: "Used in 1 repo(s)",
			},
		},
		{
			RuleId: "untrusted_checkout_exec",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:              ".github/workflows/test_new_fields.yml",
				Line:              29,
				Job:               "vulnerable_checkout",
				Details:           "Detected usage of `npm`",
				LOTPTool:          "npm",
				EventTriggers:     []string{"pull_request_target"},
				ReferencedSecrets: []string{"API_KEY", "DATABASE_PASSWORD", "DEPLOY_TOKEN", "ENABLE_BUILD"},
			},
		},
		{
			RuleId: "default_permissions_on_risky_events",
			Purl:   purl,
			Meta: results.FindingMeta{
				Path:          ".github/workflows/test_new_fields.yml",
				EventTriggers: []string{"pull_request_target"},
			},
		},
	}

	assert.Equal(t, len(findings), len(analysisResults.Findings))
	assert.ElementsMatch(t, findings, analysisResults.Findings)
}

func TestSkipRule(t *testing.T) {
	o, _ := opa.NewOpa(context.TODO(), &models.Config{
		Include: []models.ConfigInclude{},
	})
	i := NewInventory(o, nil, "", "")
	ctx := context.TODO()
	purl := "pkg:github/org/owner"
	rule_id := "known_vulnerability_in_build_component"
	pkg := &models.PackageInsights{
		Purl:          purl,
		SourceGitRepo: "org/owner",
		SourceGitRef:  "main",
	}
	_ = pkg.NormalizePurl()

	updatedPkg, err := i.ScanPackage(ctx, *pkg, "testdata")
	assert.NoError(t, err)

	analysisResults := updatedPkg.FindingsResults

	rule_ids := []string{}
	for _, r := range analysisResults.Findings {
		rule_ids = append(rule_ids, r.RuleId)
	}

	assert.Contains(t, rule_ids, rule_id)

	err = o.WithConfig(ctx, &models.Config{
		Skip: []models.ConfigSkip{
			{
				Rule: []string{rule_id},
			},
		},
	})
	assert.NoError(t, err)

	secondUpdatedPkg, err := i.ScanPackage(context.Background(), *pkg, "testdata")
	assert.NoError(t, err)

	analysisResults = secondUpdatedPkg.FindingsResults

	rule_ids = []string{}
	for _, r := range analysisResults.Findings {
		rule_ids = append(rule_ids, r.RuleId)
	}

	assert.NotContains(t, rule_ids, rule_id)
}

func TestRulesConfig(t *testing.T) {
	o, _ := opa.NewOpa(context.TODO(), &models.Config{
		Include: []models.ConfigInclude{},
	})
	i := NewInventory(o, nil, "", "")
	ctx := context.TODO()
	purl := "pkg:github/org/owner"
	rule_id := "pr_runs_on_self_hosted"
	path := ".github/workflows/allowed_pr_runner.yml"
	pkg := &models.PackageInsights{
		Purl:          purl,
		SourceGitRepo: "org/owner",
		SourceGitRef:  "main",
	}
	_ = pkg.NormalizePurl()

	scannedPackage, err := i.ScanPackage(ctx, *pkg, "testdata")
	assert.NoError(t, err)

	labels := []string{}
	for _, f := range scannedPackage.FindingsResults.Findings {
		if f.RuleId == rule_id && f.Meta.Path == path {
			labels = append(labels, f.Meta.Details)
		}
	}
	assert.ElementsMatch(t, labels, []string{"runs-on: label:linux", "runs-on: group:prdeploy"})

	err = o.WithConfig(ctx, &models.Config{
		RulesConfig: map[string]map[string]interface{}{
			rule_id: {
				"allowed_runners": []string{"label:linux", "group:prdeploy"},
			},
		},
	})
	assert.NoError(t, err)

	reScannedPackage, err := i.ScanPackage(ctx, *pkg, "testdata")
	assert.NoError(t, err)

	labels = []string{}
	for _, f := range reScannedPackage.FindingsResults.Findings {
		if f.RuleId == rule_id && f.Meta.Path == path {
			labels = append(labels, f.Meta.Details)
		}
	}
	assert.Empty(t, labels)
}

func TestStructuredFindingFields(t *testing.T) {
	o, _ := opa.NewOpa(context.TODO(), &models.Config{
		Include: []models.ConfigInclude{},
	})
	i := NewInventory(o, nil, "", "")
	ctx := context.TODO()
	purl := "pkg:github/org/owner"
	pkg := &models.PackageInsights{
		Purl:          purl,
		SourceGitRepo: "org/owner",
		SourceGitRef:  "main",
	}
	_ = pkg.NormalizePurl()

	scannedPackage, err := i.ScanPackage(ctx, *pkg, "testdata")
	assert.NoError(t, err)

	// Test injection_sources field - find the specific injection finding
	var injectionFinding *results.Finding
	for idx, f := range scannedPackage.FindingsResults.Findings {
		if f.RuleId == "injection" && f.Meta.Path == ".github/workflows/test_new_fields.yml" {
			injectionFinding = &scannedPackage.FindingsResults.Findings[idx]
			break
		}
	}
	assert.NotNil(t, injectionFinding, "Expected to find injection finding for test_new_fields.yml")
	if injectionFinding != nil {
		assert.NotEmpty(t, injectionFinding.Meta.InjectionSources, "InjectionSources should be populated")
		assert.Contains(t, injectionFinding.Meta.InjectionSources, "github.event.issue.title")
	}

	// Test lotp_tool and referenced_secrets fields
	var lotpFinding *results.Finding
	for idx, f := range scannedPackage.FindingsResults.Findings {
		if f.RuleId == "untrusted_checkout_exec" && f.Meta.Path == ".github/workflows/test_new_fields.yml" {
			lotpFinding = &scannedPackage.FindingsResults.Findings[idx]
			break
		}
	}
	assert.NotNil(t, lotpFinding, "Expected to find untrusted_checkout_exec finding for test_new_fields.yml")
	if lotpFinding != nil {
		assert.Equal(t, "npm", lotpFinding.Meta.LOTPTool, "LOTPTool should be 'npm'")
		assert.Contains(t, lotpFinding.Meta.ReferencedSecrets, "API_KEY")
		assert.Contains(t, lotpFinding.Meta.ReferencedSecrets, "DATABASE_PASSWORD")
		assert.Contains(t, lotpFinding.Meta.ReferencedSecrets, "DEPLOY_TOKEN")
		assert.Contains(t, lotpFinding.Meta.ReferencedSecrets, "ENABLE_BUILD")
		assert.NotContains(t, lotpFinding.Meta.ReferencedSecrets, "GITHUB_TOKEN", "GITHUB_TOKEN should be excluded")
	}
}
