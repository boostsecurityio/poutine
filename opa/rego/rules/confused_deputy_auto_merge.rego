# METADATA
# title: Confused Deputy Auto-Merge
# description: |-
#      Confused Deputy for GitHub Actions is a situation where a GitHub event attribute (ex. github.actor) is used to check the last interaction of a certain event. This allows an attacker abuse an event triggered by a Bot (ex. @dependabot recreate) and trigger as a side effect other privileged workflows, which may for instance automatically merge unapproved changes.
# custom:
#   level: error
package rules.confused_deputy_auto_merge

import data.poutine
import data.poutine.utils
import rego.v1

merge_commands[cmd] = {
    "gh pr merge": `gh\s+pr\s+merge`,
    "gh pr review": `gh\s+pr\s+review`
}[cmd]

merge_github_actions = {
    "ad-m/github-push-action",
    "ahmadnassri/action-dependabot-auto-merge",
    "ana06/automatic-pull-request-review",
    "endbug/add-and-commit",
    "hmarr/auto-approve-action",
    "peter-evans/create-pull-request",
    "stefanzweifel/git-auto-commit-action"
}

actor_bots = {
    "dependabot": `dependabot\[bot\]`,
    "dependabot-preview": `dependabot-preview\[bot\]`,
    "renovate": `renovate\[bot\]`,
    "github-actions": `github-actions\[bot\]`
}

uses_fix_deputy_confusion = {
    "dependabot/fetch-metadata",
    "fastify/github-action-merge-dependabot",
    "actions-cool/check-user-permission"
}

regex_actor_bot = `(github\.(actor|triggering_actor)\s*==\s*\'%v\'|contains\(\s*fromJSON\(.*%v.*\)\s*,\s*github\.(actor|triggering_actor)\s*\))` # Unit test: https://regex101.com/r/tjnx0o/1

rule := poutine.rule(rego.metadata.chain())

github.events contains event if some event in {
	"pull_request_target",
	"workflow_run"
}

# Case with if in job
results contains poutine.finding(rule, pkg_purl, {
    "path": workflow_path,
    "line": line,
    "details": sprintf("Detected usage of `%s` with actor `%s`", [cmd, bot]),
}) if {
    [pkg_purl, workflow_path, job, step, cmd, line] := _merge_commands_run[_]
    regex.match(
        sprintf(regex_actor_bot, [actor_bots[bot], actor_bots[bot]]),
        job["if"]
    )
}

# Case with if in step
results contains poutine.finding(rule, pkg_purl, {
    "path": workflow_path,
    "line": line,
    "details": sprintf("Detected usage of `%s` with actor `%s`", [cmd, bot]),
}) if {
    [pkg_purl, workflow_path, _, step, cmd, line] := _merge_commands_run[_]
    regex.match(
        sprintf(regex_actor_bot, [actor_bots[bot], actor_bots[bot]]),
        step["if"]
    )
}

# Case with merge command
_merge_commands_run contains [pkg_purl, workflow_path, job, step, cmd, step.lines.run] if {
    [pkg_purl, workflow_path, job, step] := _remove_steps_after_fetch_metadata[_]
    regex.match(
        merge_commands[cmd],
        step.run
    )
}

# Case with github actions
_merge_commands_run contains [pkg_purl, workflow_path, job, step, merge_github_action, step.line] if {
    [pkg_purl, workflow_path, job, step] := _remove_steps_after_fetch_metadata[_]
    merge_github_action := merge_github_actions[_]
    regex.match(
        merge_github_action,
        step.action
    )
}

# Case without metadata-fetch
_remove_steps_after_fetch_metadata contains [pkg.purl, workflow.path, job, s_step] if {
    pkg := input.packages[_]
    workflow := pkg.github_actions_workflows[_]
    job := workflow.jobs[_]
    relevant_steps := utils.find_first_uses_in_job(job, uses_fix_deputy_confusion)
    count(relevant_steps) = 0
    s_step = job.steps[_]
}

# Case with metadata-fetch which fix deputy confusion problem for future steps
_remove_steps_after_fetch_metadata contains [pkg.purl, workflow.path, job, s.step] if {
    pkg := input.packages[_]
    workflow := pkg.github_actions_workflows[_]
    job := workflow.jobs[_]
    relevant_steps := utils.find_first_uses_in_job(job, uses_fix_deputy_confusion)
    count(relevant_steps) > 0
    s := utils.job_steps_before(relevant_steps[_])[_]
}