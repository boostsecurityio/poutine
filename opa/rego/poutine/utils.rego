package poutine.utils

import data.external.checkout_unsafe
import rego.v1

unpinned_github_action(purl) if {
	startswith(purl, "pkg:githubactions/")
	contains(purl, "@")
	not regex.match("@[a-f0-9]{40}", purl)
}

unpinned_docker(purl) if {
	startswith(purl, "pkg:docker/")
	not regex.match("@sha256:[a-f0-9]{64}", purl)
}

unpinned_purl(purl) if {
	unpinned_github_action(purl)
} else if {
	unpinned_docker(purl)
}

find_pr_checkouts(workflow) := xs if {
	xs := (({{"job_idx": j, "step_idx": i, "workflow": workflow} |
		s := workflow.jobs[j].steps[i]
		startswith(s.uses, "actions/checkout@")
		contains(s.with_ref, "${{")
	} | {{"job_idx": j, "step_idx": i, "workflow": workflow} |
		s := workflow.jobs[j].steps[i]
		regex.match("gh pr checkout ", s.run)
	}) | {{"job_idx": j, "step_idx": i, "workflow": workflow} |
		# raw git fetch of a PR ref (pull/N/head|merge, refs/pull/...) — still in scope per
		# GitHub's "What's not changing" note; never neutralized by the checkout safe default.
		s := workflow.jobs[j].steps[i]
		regex.match(`git fetch\b.*\bpull/.*/(head|merge)\b`, s.run)
	}) | {{"job_idx": j, "step_idx": i, "workflow": workflow} |
		# raw git checkout/switch of an untrusted head ref.
		s := workflow.jobs[j].steps[i]
		regex.match(`git (checkout|switch)\b.*(github\.event\.(pull_request|issue|workflow_run)|\bhead\.sha\b|\bhead\.ref\b|\bhead_sha\b)`, s.run)
	}
}

# checkout_is_action is true when a find_pr_checkouts member is an `actions/checkout@…` step
# (vs a `gh`/`git` run-block). Only action checkouts can be neutralized by the safe default;
# run-block vectors always fire.
checkout_is_action(checkout) if {
	step := checkout.workflow.jobs[checkout.job_idx].steps[checkout.step_idx]
	startswith(step.uses, "actions/checkout@")
}

# checkout_guard_protects is true when an actions/checkout step is on a fixed version (the
# safe default refuses unsafe fork-PR checkouts) AND allow-unsafe-pr-checkout is not enabled.
checkout_guard_protects(step, scan_date) if {
	startswith(step.uses, "actions/checkout@")
	ref := substring(step.uses, count("actions/checkout@"), -1)
	_checkout_ref_safe(ref, scan_date)
	_allow_unsafe_is_default(step)
}

# allow-unsafe-pr-checkout is at its safe default when absent or set to anything the runner
# does not treat as true. A `${{ … }}` expression is treated as possibly-true (not default).
_allow_unsafe_is_default(step) if not step.with_allow_unsafe_pr_checkout

_allow_unsafe_is_default(step) if {
	v := step.with_allow_unsafe_pr_checkout
	not contains(v, "${{")
	lower(trim_space(v)) != "true"
}

# _checkout_ref_safe: a 40-hex SHA is safe iff NOT in the frozen vulnerable set (default-allow);
# a tag/branch is safe only if explicitly recognized as a fixed line (default-deny).
_checkout_ref_safe(ref, _) if {
	regex.match("^[a-fA-F0-9]{40}$", ref)
	not checkout_unsafe.vulnerable_shas[lower(ref)]
}

_checkout_ref_safe(ref, scan_date) if {
	not regex.match("^[a-fA-F0-9]{40}$", ref)
	_ref_tag_safe(ref, scan_date)
}

_ref_tag_safe(ref, _) if _ref_major(ref) >= 7 # v7, v7.x, v7.x.x, v8…

_ref_tag_safe("main", _) := true # tip of main carries the fix

_ref_tag_safe(ref, scan_date) if {
	ref in {"v4", "v5", "v6"} # floating major tags auto-update on the backport date
	scan_date >= checkout_unsafe.backport_floor_date
}

_ref_tag_safe(ref, scan_date) if {
	ref in {"releases/v4", "releases/v5", "releases/v6"}
	scan_date >= checkout_unsafe.backport_floor_date
}

# v1/v2/v3 (+ their tags) and pinned v4.x.x/v5.x.x/v6.x.x: no clause → not safe → fire.
# (Add a semver.constraint_check clause for the v4/v5/v6 backport floor versions once known,
# behind a strict ^v\d+\.\d+\.\d+$ guard so a malformed tag cannot error eval.)

# _ref_major is the integer major for a tag like v7 / v7.1 / v7.1.2; undefined otherwise.
_ref_major(ref) := to_number(matches[0][1]) if {
	matches := regex.find_all_string_submatch_n(`^v([0-9]+)(\.[0-9]+){0,2}$`, ref, 1)
	count(matches) == 1
}

workflow_steps_after(options) := steps if {
	steps := {{"step": s, "job_idx": options.job_idx, "step_idx": k} |
		s := options.workflow.jobs[options.job_idx].steps[k]
		k > options.step_idx
	}
}

filter_workflow_events(workflow, only) if {
	workflow.events[_].name == only[_]
}

job_uses_self_hosted_runner(job) if {
	run_on := job.runs_on[_]
	not contains(run_on, "$") # skip expressions
	not regex.match(
		"(?i)^((ubuntu-(([0-9]{2})\\.04|latest(-(4|8|16)-cores)?|slim)|macos-([0-9]{2}|latest)(-x?large)?|windows-(20[0-9]{2}|latest(-8-cores)?)|(buildjet|warp)-[a-z0-9-]+))$",
		run_on,
	)
} else := false

empty(xs) if {
	xs == null
} else if {
	count(xs) == 0
}

workflow_run_parents(pkg, workflow) := parents if {
	parent_names = {name |
		event := workflow.events[_]
		event.name == "workflow_run"
		name := event.workflows[_]
	}
	parents := {parent |
		parent := pkg.github_actions_workflows[_]
		glob.match(parent_names[_], ["/"], parent.name)
	}
}

to_set(xs) := xs if {
	is_set(xs)
} else := {v | v := xs[_]} if {
	is_array(xs)
} else := {xs}

########################################################################
# lotp_target resolution
########################################################################

lotp_static_targets := {
	"ant": "build.xml",
	"bundler": "Gemfile",
	"cargo": "Cargo.toml",
	"checkov": ".checkov.yml",
	"docker": "Dockerfile",
	"eslint": "eslint.config.js",
	"golangci-lint": ".golangci.yml",
	"gomplate": ".gomplate.yaml",
	"goreleaser": ".goreleaser.yaml",
	"gradle": "build.gradle",
	"make": "Makefile",
	"maven": "pom.xml",
	"mkdocs": "mkdocs.yml",
	"msbuild": "Directory.Build.props",
	"mypy": "mypy.ini",
	"npm": "package.json",
	"phpstan": "phpstan.neon",
	"pip": "requirements.txt",
	"pre-commit": ".pre-commit-config.yaml",
	"rake": "Rakefile",
	"rubocop": ".rubocop.yml",
	"sonar-scanner": "sonar-project.properties",
	"stylelint": ".stylelintrc.js",
	"terraform": "main.tf",
	"tflint": ".tflint.hcl",
	"tofu": "main.tf",
	"vale": ".vale.ini",
	"webpack": "webpack.config.js",
	"yarn": "package.json",
}

lotp_dynamic_target_patterns := {
	"bash": `(\S+\.sh)\b`,
	"powershell": `(\S+\.ps1)\b`,
	"python": `python3?\s+(\S+\.py)\b`,
	"chmod": `chmod\s+\S+\s+(\S+)`,
}

resolve_lotp_targets(cmd, run_content) := [lotp_static_targets[cmd]] if {
	lotp_static_targets[cmd]
} else := targets if {
	pattern := lotp_dynamic_target_patterns[cmd]
	matches := regex.find_all_string_submatch_n(pattern, run_content, -1)
	unique := {trim_left(m[1], "./") | m := matches[_]; not contains(m[1], "://")}
	count(unique) > 0
	targets := sort(unique)
}

########################################################################
# job order utils
########################################################################

job_steps_after(options) := steps if {
	steps := {{"step": s, "step_idx": k} |
		s := options.job.steps[k]
		k > options.step_idx
	}
}

job_steps_before(options) := steps if {
	steps := {{"step": s, "step_idx": k} |
		s := options.job.steps[k]
		k < options.step_idx
	}
}

########################################################################
# find_first_uses_in_job
########################################################################

find_first_uses_in_job(job, uses) := xs if {
	xs := {{"job": job, "step_idx": i} |
		s := job.steps[i]
		startswith(s.uses, sprintf("%v@", [uses[_]]))
	}
}

########################################################################
# extract_referenced_secrets
# Extracts all secrets.* references from GitHub Actions expressions (${{ }})
# Excludes GITHUB_TOKEN. Handles dot and bracket notation.
########################################################################

# Dot notation: ${{ secrets.FOO }} or ${{ format(secrets.FOO) }}
_secrets_dot_notation(str) := {m[1] |
	matches := regex.find_all_string_submatch_n("\\$\\{\\{[^}]*?secrets\\.([a-zA-Z_][a-zA-Z0-9_]*)", str, -1)
	m := matches[_]
	m[1] != "GITHUB_TOKEN"
}

# Bracket notation with single quotes: ${{ secrets['FOO'] }}
_secrets_bracket_single(str) := {m[1] |
	matches := regex.find_all_string_submatch_n("\\$\\{\\{[^}]*?secrets\\['([a-zA-Z_][a-zA-Z0-9_]*)'\\]", str, -1)
	m := matches[_]
	m[1] != "GITHUB_TOKEN"
}

# Bracket notation with double quotes: ${{ secrets["FOO"] }}
# Also handles JSON-escaped quotes: secrets[\"FOO\"] (after json.marshal)
_secrets_bracket_double(str) := {m[1] |
	matches := regex.find_all_string_submatch_n("\\$\\{\\{[^}]*?secrets\\[\\\\?\"([a-zA-Z_][a-zA-Z0-9_]*)\\\\?\"\\]", str, -1)
	m := matches[_]
	m[1] != "GITHUB_TOKEN"
}

extract_referenced_secrets(str) := sort(secrets) if {
	secrets := (_secrets_dot_notation(str) | _secrets_bracket_single(str)) | _secrets_bracket_double(str)
}

# Extract secrets from a job by marshaling to JSON and searching
job_referenced_secrets(job) := secrets if {
	job_json := json.marshal(job)
	secrets := extract_referenced_secrets(job_json)
}
