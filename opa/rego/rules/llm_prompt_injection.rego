# METADATA
# title: LLM Prompt Injection with untrusted user input
# description: |-
#   The pipeline contains an AI prompt injection into bash or JavaScript with an expression
#   that can contain user input. Prefer placing the expression in an environment variable
#   instead of interpolating it directly into a script.
# custom:
#   level: warning
package rules.llm_prompt_injection

import data.poutine
import data.poutine.utils
import rego.v1

rule := poutine.rule(rego.metadata.chain())

github.events contains event if some event in {
	"pull_request_target",
	"issues",
	"issue_comment",
	"workflow_call",
}

github.workflow_run.parent.events contains event if some event in {
	"pull_request_target",
	"pull_request",
	"issues",
	"issue_comment",
}

ai_agent_github_actions[action] = {
    "codex": {"openai/codex-action"},
    "claude": {"anthropics/claude-code-action", "anthropics/claude-code-base-action"},
    "gemini": {"google-github-actions/run-gemini-cli"},
    "ollama": {"pydantic/ollama-action"},
}[action]


results contains poutine.finding(rule, pkg_purl, {
	"path": workflow_path,
	"line": step.lines.uses,
	"details": sprintf("Detected usage the GitHub Action `%s`", [step.action]),
	"event_triggers": workflow_events,
}) if {
	[pkg_purl, workflow_path, workflow_events, step] := _steps_after_untrusted_invocation[_]
	regex.match(
		sprintf("([^a-z]|^)(%v)@", [concat("|", ai_agent_github_actions[_])]),
		step.uses,
	)
}


results contains poutine.finding(rule, pkg_purl, {
	"path": workflow_path,
	"line": step.lines.uses,
	"details": sprintf("Detected usage of a Local GitHub Action at path: `%s`", [step.action]),
	"event_triggers": workflow_events,
}) if {
	[pkg_purl, workflow_path, workflow_events, step] := _steps_after_untrusted_invocation[_]
	regex.match(
		`^\./`,
		step.action,
	)
}

_steps_after_untrusted_invocation contains [pkg.purl, workflow.path, events, s] if {
	pkg := input.packages[_]
	workflow := pkg.github_actions_workflows[_]

	utils.filter_workflow_events(workflow, github.events)

	events := [event | event := workflow.events[i].name]
	s := workflow.jobs[_].steps[_]
#	pr_checkout := utils.find_pr_checkouts(workflow)[_]
#	s := utils.workflow_steps_after(workflow)[_]
}

_steps_after_untrusted_invocation contains [pkg_purl, workflow.path, events, s] if {
	[pkg_purl, workflow] := _workflows_runs_from_pr[_]

	events := [event | event := workflow.events[i].name]
	s := workflow[_].jobs[_].steps[_]
#	pr_checkout := utils.find_pr_checkouts(workflow)[_]
#	s := utils.workflow_steps_after(workflow)[_]
}

_workflows_runs_from_pr contains [pkg.purl, workflow] if {
	pkg := input.packages[_]
	workflow := pkg.github_actions_workflows[_]
	parent := utils.workflow_run_parents(pkg, workflow)[_]

	utils.filter_workflow_events(parent, github.workflow_run.parent.events)
}
