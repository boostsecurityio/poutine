# METADATA
# title: Arbitrary Code Execution from Untrusted Code Changes
# description: |-
#   The workflow appears to checkout untrusted code from a fork
#   and uses a command that is known to allow code execution.
# custom:
#   level: error
package rules.untrusted_checkout_exec

import data.poutine
import data.poutine.utils
import rego.v1

rule := poutine.rule(rego.metadata.chain())

github.events contains event if some event in {
	"pull_request_target",
	"issue_comment",
	"workflow_call",
}

github.workflow_run.parent.events contains event if some event in {
	"pull_request_target",
	"pull_request",
}

build_github_actions[action] = {
	"pre-commit/action": "pre-commit",
	"oxsecurity/megalinter": "megalinter",
	"bridgecrewio/checkov-action": "checkov",
	"ruby/setup-ruby": "bundler",
}[action]

build_commands[cmd] = {
	"npm": {"npm install", "npm run ", "yarn ", "npm ci(\\b|$)"},
	"make": {"make "},
	"terraform": {"terraform plan", "terraform apply"},
	"gomplate": {"gomplate "},
	"pre-commit": {"pre-commit run", "pre-commit install"},
	"go generate": {"go generate"},
	"msbuild": {"msbuild "},
	"maven": {"mvn ", "./mvnw "},
	"gradle": {"gradle ", "./gradlew "},
	"bundler": {"bundle install", "bundle exec "},
	"ant": {"^ant "},
	"mkdocs": {"mkdocs build"},
}[cmd]

results contains poutine.finding(rule, pkg_purl, {
	"path": workflow_path,
	"line": step.lines.run,
	"details": sprintf("Detected usage of `%s`", [cmd]),
}) if {
	[pkg_purl, workflow_path, step] := _steps_after_untrusted_checkout[_]
	regex.match(
		sprintf("([^a-z]|^)(%v)", [concat("|", build_commands[cmd])]),
		step.run,
	)
}

results contains poutine.finding(rule, pkg_purl, {
	"path": workflow_path,
	"line": step.lines.uses,
	"details": sprintf("Detected usage the GitHub Action `%s`", [step.action]),
}) if {
	[pkg_purl, workflow_path, step] := _steps_after_untrusted_checkout[_]
	build_github_actions[step.action]
}

_steps_after_untrusted_checkout contains [pkg.purl, workflow.path, s.step] if {
	pkg := input.packages[_]
	workflow := pkg.github_actions_workflows[_]

	utils.filter_workflow_events(workflow, github.events)

	pr_checkout := utils.find_pr_checkouts(workflow)[_]
	s := utils.workflow_steps_after(pr_checkout)[_]
}

_steps_after_untrusted_checkout contains [pkg_purl, workflow.path, s.step] if {
	[pkg_purl, workflow] := _workflows_runs_from_pr[_]

	pr_checkout := utils.find_pr_checkouts(workflow)[_]
	s := utils.workflow_steps_after(pr_checkout)[_]
}

_workflows_runs_from_pr contains [pkg.purl, workflow] if {
	pkg := input.packages[_]
	workflow := pkg.github_actions_workflows[_]
	parent := utils.workflow_run_parents(pkg, workflow)[_]

	utils.filter_workflow_events(parent, github.workflow_run.parent.events)
}

# Azure Devops

results contains poutine.finding(rule, pkg_purl, {
	"path": pipeline_path,
	"job": job,
	"step": s.step_idx,
	"line": s.step.lines[attr],
	"details": sprintf("Detected usage of `%s`", [cmd]),
}) if {
	[pkg_purl, pipeline_path, s, job] := _steps_after_untrusted_checkout_ado[_]
	regex.match(
		sprintf("([^a-z]|^)(%v)", [concat("|", build_commands[cmd])]),
		s.step[attr],
	)
}

_steps_after_untrusted_checkout_ado contains [pkg.purl, pipeline.path, s, job] if {
	pkg := input.packages[_]
	pipeline := pkg.azure_pipelines[_]
	pipeline.pr.disabled == false
	stage := pipeline.stages[_]

	checkout := find_ado_checkout(stage)[_]
	s := steps_after(checkout)[_]
	job := stage.jobs[s.job_idx].job
}

steps_after(checkout) := steps if {
	steps := {{"step": s, "job_idx": checkout.job_idx, "step_idx": k} |
		s := checkout.stage.jobs[checkout.job_idx].steps[k]
		k > checkout.step_idx
	}
}

find_ado_checkout(stage) := xs if {
	xs := {{"job_idx": j, "step_idx": i, "stage": stage} |
		s := stage.jobs[j].steps[i]
		s[step_attr]
		step_attr == "checkout"
		s[step_attr] == "self"
	}
}
