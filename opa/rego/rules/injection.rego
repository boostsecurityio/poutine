# METADATA
# title: Injection with Arbitrary External Contributor Input
# description: |-
#   The pipeline contains an injection into bash or JavaScript with an expression
#   that can contain user input. Prefer placing the expression in an environment variable
#   instead of interpolating it directly into a script.
# related_resources:
# - https://securitylab.github.com/research/github-actions-preventing-pwn-requests/
# custom:
#   level: warning
package rules.injection

import data.poutine
import rego.v1

rule := poutine.rule(rego.metadata.chain())

# GitHub Actions
patterns.github contains "\\$\\{\\{\\s*(github\\.head_ref|github\\.event\\.workflow_run\\.(head_branch|head_repository\\.description|head_repository\\.owner\\.email|pull_requests[^}]+?(head\\.ref|head\\.repo\\.name))|github\\.event\\.(issue\\.title|issue\\.body|pull_request\\.title|pull_request\\.body|comment\\.body|review\\.body|review_comment\\.body|pages\\.[^}]+?\\.page_name|head_commit\\.message|head_commit\\.author\\.email|head_commit\\.author\\.name|commits[^}]+?\\.author\\.email|commits[^}]+?\\.author\\.name|pull_request\\.head\\.ref|pull_request\\.head\\.label|pull_request\\.head\\.repo\\.default_branch|(inputs|client_payload)[^}]+?))\\s*\\}\\}"

gh_injections(str) = {expr |
	match := regex.find_n(patterns.github[_], str, -1)[_]
	expr := regex.find_all_string_submatch_n("\\$\\{\\{\\s*([^}]+?)\\s*\\}\\}", match, 1)[0][1]
}

gh_step_injections(step) = [gh_injections(step.with_script), step.lines.with_script] if {
	startswith(step.uses, "actions/github-script@")
} else = [gh_injections(step.run), step.lines.run]

results contains poutine.finding(rule, pkg.purl, {
	"path": workflow.path,
	"line": line,
	"job": job.id,
	"step": i,
	"details": sprintf("Sources: %s", [concat(" ", exprs)]),
	"event_triggers": [event | event := workflow.events[j].name],
}) if {
	pkg = input.packages[_]
	workflow = pkg.github_actions_workflows[_]
	job := workflow.jobs[_]
	step := job.steps[i]
	[exprs, line] := gh_step_injections(step)
	count(exprs) > 0
}

results contains poutine.finding(rule, pkg.purl, {
	"path": action.path,
	"line": line,
	"step": i,
	"details": sprintf("Sources: %s", [concat(" ", exprs)]),
	"event_triggers": [event | event := action.events[j].name],
}) if {
	pkg = input.packages[_]
	action := pkg.github_actions_metadata[_]
	step := action.runs.steps[i]
	action.runs.using == "composite"
	[exprs, line] := gh_step_injections(step)
	count(exprs) > 0
}

# Gitlab
patterns.gitlab contains "\\$\\[\\[\\s*?[^\\]]*?(inputs\\.[a-zA-Z0-9_-]+)[^\\]]*?expand_vars[^\\]]*?\\s*?\\]\\]"

gl_injections(str) = {expr |
	expr := regex.find_all_string_submatch_n(patterns.gitlab[_], str, -1)[_][1]
}

results contains poutine.finding(rule, pkg.purl, {
	"path": config.path,
	"job": sprintf("%s.%s[%d]", [job.name, attr, i]),
	"details": sprintf("Sources: %s", [concat(" ", exprs)]),
	"line": job[attr][i].line,
}) if {
	pkg = input.packages[_]
	config := pkg.gitlabci_configs[_]
	job := config.jobs[_]
	attr in {"before_script", "after_script", "script"}
	script := job[attr][i].run
	exprs := gl_injections(script)
	count(exprs) > 0
}

# Azure Pipelines
patterns.azure contains `\$\((Build\.(SourceBranchName|SourceBranch|SourceVersionMessage)|System\.PullRequest\.SourceBranch)\)`

azure_injections(str) = {expr |
	match := regex.find_n(patterns.azure[_], str, -1)[_]
	expr := regex.find_all_string_submatch_n(`\$\(([^\)]+)\)`, match, 1)[0][1]
}

results contains poutine.finding(rule, pkg.purl, {
	"path": pipeline.path,
	"job": job.job,
	"step": step_id,
	"line": step.lines[attr],
	"details": sprintf("Sources: %s", [concat(" ", exprs)]),
}) if {
	some attr in {"script", "powershell", "pwsh", "bash"}
	pkg := input.packages[_]
	pipeline := pkg.azure_pipelines[_]
	job := pipeline.stages[_].jobs[_]
	step := job.steps[step_id]
	exprs := azure_injections(step[attr])
	count(exprs) > 0
}

patterns.pipeline_as_code_tekton contains "\\{\\{\\s*(body\\.pull_request\\.(title|user\\.email|body)|source_branch)\\s*\\}\\}"

pipeline_as_code_tekton_injections(str) = {expr |
	match := regex.find_n(patterns.pipeline_as_code_tekton[_], str, -1)[_]
	expr := regex.find_all_string_submatch_n("\\{\\{\\s*([^}]+?)\\s*\\}\\}", match, 1)[0][1]
}

results contains poutine.finding(rule, pkg.purl, {
	"path": pipeline.path,
	"job": task.name,
	"step": step_idx,
	"line": step.lines.start,
	"details": sprintf("Sources: %s", [concat(" ", exprs)]),
}) if {
	pkg := input.packages[_]
	pipeline := pkg.pipeline_as_code_tekton[_]
	contains(pipeline.api_version, "tekton.dev")
	pipeline.kind == "PipelineRun"
	contains(pipeline.metadata.annotations["pipelinesascode.tekton.dev/on-event"], "pull_request")
	task := pipeline.spec.pipeline_spec.tasks[_]
	step := task.task_spec.steps[step_idx]

	exprs := pipeline_as_code_tekton_injections(step.script)
	count(exprs) > 0
}
