package poutine.utils

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
	xs := {{"job_idx": j, "step_idx": i, "workflow": workflow} |
		s := workflow.jobs[j].steps[i]
		startswith(s.uses, "actions/checkout@")
		contains(s.with_ref, "${{")
	} | {{"job_idx": j, "step_idx": i, "workflow": workflow} |
		s := workflow.jobs[j].steps[i]
		regex.match("gh pr checkout ", s.run)
	}
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

workflow_run_parents(pkg, workflow) = parents if {
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

to_set(xs) = xs if {
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
	secrets := _secrets_dot_notation(str) | _secrets_bracket_single(str) | _secrets_bracket_double(str)
}

# Extract secrets from a job by marshaling to JSON and searching
job_referenced_secrets(job) := secrets if {
	job_json := json.marshal(job)
	secrets := extract_referenced_secrets(job_json)
}

########################################################################
# actions/checkout pull_request_target / workflow_run safety default
#
# https://github.blog/changelog/2026-06-18-safer-pull_request_target-defaults-for-github-actions-checkout/
#
# The guard shipped in v7 and was backported to supported v2-v6 releases. It
# refuses fork pull request code in `pull_request_target` and selected
# `workflow_run` workflows unless `allow-unsafe-pr-checkout: true` is set.
########################################################################

checkout_fork_pr_guard_blocks_step(workflow, step, non_blocked_events) if {
	_checkout_has_pr_safe_default(step.uses)
	not _checkout_allows_unsafe_pr_checkout(step)
	_checkout_targets_fork_pr_head(step)
	_workflow_has_event_in(workflow, {"pull_request_target", "workflow_run"})
	not _workflow_has_event_in(workflow, non_blocked_events)
	not _workflow_run_from_unsafe_upstream(workflow)
}

_workflow_run_from_unsafe_upstream(workflow) if {
	some event in workflow.events
	event.name == "workflow_run"
	not _workflow_run_event_safe(event)
}

_workflow_run_event_safe(event) if {
	count(event.workflows) > 0
	every upstream in event.workflows {
		_upstream_is_pull_request_only(upstream)
	}
}

_upstream_is_pull_request_only(name) if {
	some pkg in input.packages
	some workflow in pkg.github_actions_workflows
	workflow.name == name
	count(workflow.events) > 0
	every event in workflow.events {
		startswith(event.name, "pull_request")
	}
}

# A ref is fixed unless it is a vulnerable commit SHA or a semantic version
# below the fixed floor for its release line. Moving major tags from v2 onward
# and branch-like refs are assumed to track guarded code.
_checkout_has_pr_safe_default(uses) if {
	ref := _checkout_ref(uses)
	not regex.match(`^[0-9A-Fa-f]{40}$`, ref)
	not _checkout_version_ref_is_vulnerable(ref)
}

_checkout_has_pr_safe_default(uses) if {
	ref := _checkout_ref(uses)
	regex.match(`^[0-9A-Fa-f]{40}$`, ref)
	sha := lower(ref)
	not sha in data.poutine.checkout_guard_data.vulnerable_commit_shas
}

_checkout_guard_fixed_version_floors := {
	"2": "2.8.0",
	"3": "3.7.0",
	"4": "4.4.0",
	"5": "5.1.0",
	"6": "6.1.0",
}

_checkout_version_ref_is_vulnerable("v1")

_checkout_version_ref_is_vulnerable(ref) if {
	version := _checkout_semver(ref)
	major := split(version, ".")[0]
	major == "1"
}

_checkout_version_ref_is_vulnerable(ref) if {
	version := _checkout_semver(ref)
	major := split(version, ".")[0]
	fixed_floor := _checkout_guard_fixed_version_floors[major]
	semver.compare(version, fixed_floor) < 0
}

_checkout_semver(ref) := sprintf("%s.0", [trim_prefix(ref, "v")]) if {
	regex.match(`^v[0-9]+\.[0-9]+$`, ref)
	semver.is_valid(sprintf("%s.0", [trim_prefix(ref, "v")]))
}

_checkout_semver(ref) := version if {
	regex.match(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`, ref)
	version := trim_prefix(ref, "v")
	semver.is_valid(version)
}

_checkout_ref(uses) := ref if {
	matches := regex.find_all_string_submatch_n(`(?i)^actions/checkout@(.+)$`, uses, 1)
	count(matches) == 1
	ref := matches[0][1]
}

_checkout_allows_unsafe_pr_checkout(step) if {
	some w in step["with"]
	w.name == "allow-unsafe-pr-checkout"
	lower(trim_space(w.value)) == "true"
}

_checkout_allows_unsafe_pr_checkout(step) if {
	some w in step["with"]
	w.name == "allow-unsafe-pr-checkout"
	contains(w.value, "${{")
}

_checkout_targets_fork_pr_head(step) if {
	some w in step["with"]
	w.name == "repository"
	regex.match(`(?i)github\.event\.(pull_request\.head\.repo|workflow_run\.head_repository)`, w.value)
}

_checkout_targets_fork_pr_head(step) if {
	regex.match(`(?i)^refs/pull/.+/(head|merge)$`, step.with_ref)
}

_checkout_targets_fork_pr_head(step) if {
	regex.match(
		`(?i)github\.event\.(pull_request\.head\.sha|pull_request\.merge_commit_sha|workflow_run\.head_sha|workflow_run\.head_commit\.id)`,
		step.with_ref,
	)
}

_workflow_has_event_in(workflow, names) if {
	some event in workflow.events
	event.name in names
}
