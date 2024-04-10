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

gh_step_injections(step) = gh_injections(step.with_script) if {
	startswith(step.uses, "actions/github-script@")
} else = gh_injections(step.run)

results contains poutine.finding(rule, pkg.purl, {
	"path": workflow.path,
	"line": step.line,
	"job": job.id,
	"step": i,
	"details": sprintf("Sources: %s", [concat(" ", exprs)]),
}) if {
	pkg = input.packages[_]
	workflow = pkg.github_actions_workflows[_]
	job := workflow.jobs[_]
	step := job.steps[i]
	exprs := gh_step_injections(step)
	count(exprs) > 0
}

results contains poutine.finding(rule, pkg.purl, {
	"path": action.path,
	"line": step.line,
	"step": i,
	"details": sprintf("Sources: %s", [concat(" ", exprs)]),
}) if {
	pkg = input.packages[_]
	action := pkg.github_actions_metadata[_]
	step := action.runs.steps[i]
	action.runs.using == "composite"
	exprs := gh_step_injections(step)
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
