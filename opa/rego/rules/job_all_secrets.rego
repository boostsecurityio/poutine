# METADATA
# title: Workflow job exposes all secrets
# description: |-
#   The GitHub Actions Runner attempts to keep in memory only the secrets
#   that are necessary to execute a workflow job.
#   If a job converts the secrets object to JSON or accesses it using an expression,
#   all secrets will be retained in memory for the duration of the job.
# custom:
#   level: warning
package rules.job_all_secrets

import data.poutine
import rego.v1

rule := poutine.rule(rego.metadata.chain())

results contains poutine.finding(rule, pkg.purl, {
	"path": workflow.path,
	"job": job.id,
	"line": job.lines.start,
	"event_triggers": [event | event := workflow.events[i].name],
}) if {
	pkg := input.packages[_]
	workflow := pkg.github_actions_workflows[_]
	job := workflow.jobs[_]

	regex.match("\\$\\{\\{\\s*(secrets\\[|toJSON\\(secrets\\))", json.marshal(job))
}
