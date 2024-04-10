# METADATA
# title: Pull Request Runs on Self-Hosted GitHub Actions Runner
# description: |-
#   This job runs on a self-hosted GitHub Actions runner in a workflow 
#   that is triggered by a pull request event.
# custom:
#   level: warning
package rules.pr_runs_on_self_hosted

import data.poutine
import data.poutine.utils
import rego.v1

rule := poutine.rule(rego.metadata.chain())

results contains poutine.finding(rule, pkg.purl, {
	"path": workflow.path,
	"job": job.id,
	"line": job.line,
	"details": sprintf("runs-on: %s", [concat(", ", job.runs_on)]),
}) if {
	pkg := input.packages[_]
	workflow = pkg.github_actions_workflows[_]
	job := workflow.jobs[_]

	utils.filter_workflow_events(workflow, {
		"pull_request",
		"pull_request_review",
		"pull_request_review_comment",
		"pull_request_target",
	})

	utils.job_uses_self_hosted_runner(job)
}
