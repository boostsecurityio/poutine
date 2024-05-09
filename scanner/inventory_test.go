package scanner

import (
	"context"
	"testing"

	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/stretchr/testify/assert"
)

func TestPurls(t *testing.T) {
	o, _ := opa.NewOpa()
	i := NewInventory(o, nil)
	pkg := &models.PackageInsights{
		Purl: "pkg:github/org/owner",
	}
	_ = pkg.NormalizePurl()
	err := i.AddPackage(context.Background(), pkg, "testdata")

	assert.Nil(t, err)

	purls := []string{
		"pkg:docker/node%3Alatest",
		"pkg:githubactions/hashicorp/vault-action@v3",
		"pkg:githubactions/actions/checkout@main",
		"pkg:githubactions/kartverket/github-workflows@main#.github/workflows/run-terraform.yml",
		"pkg:githubactions/kartverket/github-workflows@v2.2#.github/workflows/run-terraform.yml",
		"pkg:githubactions/kartverket/github-workflows@v2.7.1#.github/workflows/run-terraform.yml",
		"pkg:docker/alpine%3Alatest",
		"pkg:githubactions/actions/github-script@main",
		"pkg:githubactions/hashicorp/vault-action@v2.1.0",
		"pkg:githubactions/actions/checkout@v4",
		"pkg:docker/ruby%3A3.2",
		"pkg:docker/postgres%3A15",
		"pkg:gitlabci/include/template?file_name=Auto-DevOps.gitlab-ci.yml",
		"pkg:gitlabci/include/project?file_name=%2Ftemplates%2F.gitlab-ci-template.yml&project=my-group%2Fmy-project&ref=main",
		"pkg:gitlabci/include/remote?download_url=https%3A%2F%2Fexample.com%2F.gitlab-ci.yml",
		"pkg:gitlabci/include/component?project=my-org%2Fsecurity-components%2Fsecret-detection&ref=1.0&repository_url=gitlab.example.com",
		// "pkg:gitlabci/include/local?file_name=%2F.local-ci-template.yml",
		// "pkg:gitlabci/include/local?file_name=.gitlab-ci.yml",
		"pkg:githubactions/org/repo@main",
		"pkg:docker/debian%3Avuln",
		"pkg:githubactions/bridgecrewio/checkov-action@main",
		"pkg:githubactions/org/repo@main#.github/workflows/Reusable.yml",
	}
	assert.ElementsMatch(t, i.Purls(), purls)
	assert.Equal(t, 1, len(i.Packages))
	assert.Equal(t, 16, len(i.Packages[0].BuildDependencies))
	assert.Equal(t, 4, len(i.Packages[0].PackageDependencies))
}

func TestFindings(t *testing.T) {
	o, _ := opa.NewOpa()
	i := NewInventory(o, nil)
	purl := "pkg:github/org/owner"
	pkg := &models.PackageInsights{
		Purl: purl,
	}
	_ = pkg.NormalizePurl()

	err := i.AddPackage(context.Background(), pkg, "testdata")
	assert.Nil(t, err)

	results, err := i.Findings(context.Background())
	assert.Nil(t, err)

	rule_ids := []string{}
	for _, r := range results.Rules {
		rule_ids = append(rule_ids, r.Id)
	}

	assert.ElementsMatch(t, rule_ids, []string{
		"default_permissions_on_risky_events",
		"if_always_true",
		"known_vulnerability",
		"pr_runs_on_self_hosted",
		"unpinnable_action",
		"untrusted_checkout_exec",
		"injection",
		"github_action_from_unverified_creator_used",
		"debug_enabled",
		"job_all_secrets",
	})

	findings := []opa.Finding{
		{
			RuleId: "injection",
			Purl:   purl,
			Meta: opa.FindingMeta{
				Job:     "build",
				Path:    ".github/workflows/valid.yml",
				Step:    "1",
				Line:    20,
				Details: "Sources: github.head_ref",
			},
		},
		{
			RuleId: "injection",
			Purl:   purl,
			Meta: opa.FindingMeta{
				Job:     "build",
				Path:    ".github/workflows/valid.yml",
				Step:    "7",
				Line:    46,
				Details: "Sources: github.event.workflow_run.head_branch",
			},
		},
		{
			RuleId: "known_vulnerability",
			Purl:   purl,
			Meta: opa.FindingMeta{
				Path:    "composite/action.yml",
				OsvId:   "GHSA-4mgv-m5cm-f9h7",
				Step:    "2",
				Line:    13,
				Details: "Package: hashicorp/vault-action",
			},
		},
		{
			RuleId: "known_vulnerability",
			Purl:   purl,
			Meta: opa.FindingMeta{
				Path:    ".github/workflows/valid.yml",
				Job:     "build",
				Step:    "5",
				OsvId:   "GHSA-f9qj-7gh3-mhj4",
				Line:    39,
				Details: "Package: kartverket/github-workflows/.github/workflows/run-terraform.yml",
			},
		},
		{
			RuleId: "known_vulnerability",
			Purl:   purl,
			Meta: opa.FindingMeta{
				Path:    ".github/workflows/valid.yml",
				Job:     "build",
				Step:    "6",
				OsvId:   "GHSA-f9qj-7gh3-mhj4",
				Line:    43,
				Details: "Package: kartverket/github-workflows/.github/workflows/run-terraform.yml",
			},
		},
		{
			RuleId: "untrusted_checkout_exec",
			Purl:   purl,
			Meta: opa.FindingMeta{
				Path:    ".github/workflows/valid.yml",
				Line:    30,
				Details: "Detected usage of `npm`",
			},
		},
		{
			RuleId: "untrusted_checkout_exec",
			Purl:   purl,
			Meta: opa.FindingMeta{
				Path:    ".github/workflows/valid.yml",
				Line:    56,
				Details: "Detected usage the GitHub Action `bridgecrewio/checkov-action`",
			},
		},
		{
			RuleId: "untrusted_checkout_exec",
			Purl:   purl,
			Meta: opa.FindingMeta{
				Path:    ".github/workflows/valid.yml",
				Line:    60,
				Details: "Detected usage of `pre-commit`",
			},
		},
		{
			RuleId: "untrusted_checkout_exec",
			Purl:   purl,
			Meta: opa.FindingMeta{
				Path:    ".github/workflows/workflow_run_valid.yml",
				Line:    13,
				Details: "Detected usage of `npm`",
			},
		},
		{
			RuleId: "default_permissions_on_risky_events",
			Purl:   purl,
			Meta: opa.FindingMeta{
				Path: ".github/workflows/valid.yml",
			},
		},
		{
			RuleId: "unpinnable_action",
			Purl:   purl,
			Meta: opa.FindingMeta{
				Path: "action.yml",
			},
		},
		{
			RuleId: "unpinnable_action",
			Purl:   purl,
			Meta: opa.FindingMeta{
				Path: "composite/action.yml",
			},
		},
		{
			RuleId: "pr_runs_on_self_hosted",
			Purl:   purl,
			Meta: opa.FindingMeta{
				Path:    ".github/workflows/valid.yml",
				Job:     "build",
				Line:    9,
				Details: "runs-on: self-hosted"},
		},
		{
			RuleId: "github_action_from_unverified_creator_used",
			Purl:   "pkg:githubactions/kartverket/github-workflows",
			Meta: opa.FindingMeta{
				Details: "Used in 1 repo(s)",
			},
		},
		{
			RuleId: "injection",
			Purl:   purl,
			Meta: opa.FindingMeta{
				Job:     "build",
				Path:    ".github/workflows/valid.yml",
				Step:    "8",
				Line:    50,
				Details: "Sources: github.event.client_payload.foo",
			},
		},
		{
			RuleId: "injection",
			Purl:   purl,
			Meta: opa.FindingMeta{
				Path:    ".gitlab-ci.yml",
				Job:     "default.before_script[0]",
				Details: "Sources: inputs.gem_name",
				Line:    48,
			},
		},
		{
			RuleId: "debug_enabled",
			Purl:   purl,
			Meta: opa.FindingMeta{
				Path:    ".gitlab-ci.yml",
				Details: "CI_DEBUG_SERVICES CI_DEBUG_TRACE",
			},
		},
		{
			RuleId: "job_all_secrets",
			Purl:   purl,
			Meta: opa.FindingMeta{
				Path: ".github/workflows/secrets.yaml",
				Line: 4,
				Job:  "matrix",
			},
		},
		{
			RuleId: "job_all_secrets",
			Purl:   purl,
			Meta: opa.FindingMeta{
				Path: ".github/workflows/secrets.yaml",
				Line: 16,
				Job:  "json",
			},
		},
		{
			RuleId: "if_always_true",
			Purl:   purl,
			Meta: opa.FindingMeta{
				Path: "composite/action.yml",
				Line: 17,
				Step: "3",
			},
		},
	}

	assert.Equal(t, len(findings), len(results.Findings))
	assert.ElementsMatch(t, findings, results.Findings)
}

func TestSkipRule(t *testing.T) {
	o, _ := opa.NewOpa()
	i := NewInventory(o, nil)
	ctx := context.TODO()
	purl := "pkg:github/org/owner"
	rule_id := "known_vulnerability"
	pkg := &models.PackageInsights{
		Purl: purl,
	}
	_ = pkg.NormalizePurl()

	err := i.AddPackage(ctx, pkg, "testdata")
	assert.Nil(t, err)

	results, err := i.Findings(context.Background())
	assert.Nil(t, err)

	rule_ids := []string{}
	for _, r := range results.Findings {
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

	results, err = i.Findings(context.Background())
	assert.Nil(t, err)

	rule_ids = []string{}
	for _, r := range results.Findings {
		rule_ids = append(rule_ids, r.RuleId)
	}

	assert.NotContains(t, rule_ids, rule_id)
}
