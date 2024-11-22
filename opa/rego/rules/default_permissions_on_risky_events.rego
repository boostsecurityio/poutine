# METADATA
# title: Default permissions used on risky events
# description: |-
#   The workflow and some of its jobs do not explicitely define permissions
#   and the workflow triggers on events that are typically used to run builds from forks.
#   Because no permissions is set, the workflow inherits the default permissions
#   configured on the repository or the organization.
# custom:
#   level: warning
package rules.default_permissions_on_risky_events

import data.poutine
import data.poutine.utils
import rego.v1

rule := poutine.rule(rego.metadata.chain())

github.events contains event if some event in {
	"pull_request_target",
	"issue_comment",
}

results contains poutine.finding(rule, pkg.purl, {
	"path": workflow.path,
	"event_triggers": [event | event := workflow.events[j].name],
}) if {
	pkg := input.packages[_]
	workflow = pkg.github_actions_workflows[_]
	job := workflow.jobs[_]

	utils.filter_workflow_events(workflow, github.events)

	utils.empty(workflow.permissions)
	utils.empty(job.permissions)
}

results contains poutine.finding(rule, pkg.purl, {
	"path": workflow.path,
	"event_triggers": [event | event := workflow.events[j].name],
}) if {
	pkg := input.packages[_]
	workflow = pkg.github_actions_workflows[_]
	job := workflow.jobs[_]

	utils.filter_workflow_events(workflow, github.events)

	not workflow.permissions
	not job.permissions
}
