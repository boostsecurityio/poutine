# METADATA
# title: CI Runner Debug Enabled
# description: |-
#   The workflow is configured to increase the verbosity of the runner.
#   This can potentially expose sensitive information.
# related_resources:
# - https://docs.gitlab.com/ee/ci/variables/index.html#enable-debug-logging
# - https://docs.gitlab.com/ee/ci/variables/index.html#mask-a-cicd-variable
# custom:
#   level: note
package rules.debug_enabled

import data.poutine
import rego.v1

rule := poutine.rule(rego.metadata.chain())

_gitlab_debug_vars := {"CI_DEBUG_TRACE", "CI_DEBUG_SERVICES"}

results contains poutine.finding(rule, pkg_purl, {
	"path": config_path,
	"details": concat(" ", sort(vars)),
}) if {
	vars := _gitlab_debug_enabled[[pkg_purl, config_path]]
}

_gitlab_debug_enabled[[pkg.purl, config.path]] contains var.name if {
	pkg := input.packages[_]
	config := pkg.gitlabci_configs[_]
	var := config.variables[_]

	var.name in _gitlab_debug_vars
	lower(var.value) == "true"
}

_gitlab_debug_enabled[[pkg.purl, config.path]] contains var.name if {
	pkg := input.packages[_]
	config := pkg.gitlabci_configs[_]
	var := config.jobs[_].variables[_]

	var.name in _gitlab_debug_vars
	lower(var.value) == "true"
}

_github_actions_debug_env_vars := {"ACTIONS_STEP_DEBUG", "ACTIONS_RUNNER_DEBUG"}

is_debug_enabled(var) if {
	var.name in _github_actions_debug_env_vars
	lower(var.value) == "true"
}

results contains poutine.finding(rule, pkg.purl, {
	"path": workflow.path,
	"details": var.name,
	"event_triggers": [event | event := workflow.events[i].name],
}) if {
	pkg := input.packages[_]
	workflow := pkg.github_actions_workflows[_]
	var := workflow.env[_]
	is_debug_enabled(var)
}

results contains poutine.finding(rule, pkg.purl, {
	"path": workflow.path,
	"job": job.id,
	"details": var.name,
	"line": job.lines.start,
	"event_triggers": [event | event := workflow.events[i].name],
}) if {
	pkg := input.packages[_]
	workflow := pkg.github_actions_workflows[_]
	job := workflow.jobs[_]
	var := job.env[_]
	is_debug_enabled(var)
}

results contains poutine.finding(rule, pkg.purl, {
	"path": workflow.path,
	"job": job.id,
	"step": step_id,
	"details": var.name,
	"line": step.lines.start,
	"event_triggers": [event | event := workflow.events[i].name],
}) if {
	pkg := input.packages[_]
	workflow := pkg.github_actions_workflows[_]
	job := workflow.jobs[_]
	step := job.steps[step_id]
	var := step.env[_]
	is_debug_enabled(var)
}

results contains poutine.finding(rule, pkg.purl, {
	"path": pipeline.path,
	"job": "",
	"step": "1",
	"details": key,
	"line": 0,
}) if {
	pkg := input.packages[_]
	pipeline := pkg.azure_pipelines[_]
	pipeline.variables.map[key]
	key == "system.debug"
	pipeline.variables.map[key] == "true"
}
