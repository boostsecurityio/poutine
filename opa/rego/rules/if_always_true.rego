# METADATA
# title: If condition always evaluates to true
# description: |-
#   GitHub Actions expressions used in if condition of jobs or steps
#   must not contain extra characters or spaces.
#   Otherwise, the condition is always true.
# custom:
#   level: error
package rules.if_always_true

import data.poutine
import rego.v1

rule := poutine.rule(rego.metadata.chain())

results contains poutine.finding(rule, pkg.purl, meta) if {
	pkg := input.packages[_]
	meta := if_conditions[pkg.purl][_]
}

always_true(cond) if {
	contains(cond, "${{")
	not startswith(cond, "${{")
} else if {
	contains(cond, "${{")
	not endswith(cond, "}}")
} else if {
	contains(cond, "${{")
	count(split(cond, "${{")) > 2
}

if_conditions[pkg.purl] contains {
	"path": workflow.path,
	"line": object.get(job.lines, "if", 0),
	"job": job.id,
	"event_triggers": [event | event := workflow.events[j].name],
} if {
	pkg := input.packages[_]
	workflow = pkg.github_actions_workflows[_]
	job := workflow.jobs[_]
	cond := object.get(job, "if", "")

	always_true(cond)
}

if_conditions[pkg.purl] contains {
	"path": workflow.path,
	"line": object.get(step.lines, "if", 0),
	"job": job.id,
	"step": step_id,
	"event_triggers": [event | event := workflow.events[j].name],
} if {
	pkg := input.packages[_]
	workflow = pkg.github_actions_workflows[_]
	job := workflow.jobs[_]
	step := job.steps[step_id]
	cond := object.get(step, "if", "")

	always_true(cond)
}

if_conditions[pkg.purl] contains {
	"path": action.path,
	"line": object.get(step.lines, "if", 0),
	"step": step_id,
} if {
	pkg := input.packages[_]
	action = pkg.github_actions_metadata[_]
	step := action.runs.steps[step_id]
	cond := object.get(step, "if", "")

	always_true(cond)
}
