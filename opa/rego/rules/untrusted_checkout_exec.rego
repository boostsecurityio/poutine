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

build_github_actions[action] := {
	"bundler": {"ruby/setup-ruby"},
	"cargo": {"actions-rs/cargo"},
	"checkov": {"bridgecrewio/checkov-action"},
	"docker": {"docker/build-push-action", "docker/setup-buildx-action"},
	"eslint": {"reviewdog/action-eslint", "stefanoeb/eslint-action", "tj-actions/eslint-changed-files", "sibiraj-s/action-eslint", "tinovyatkin/action-eslint", "bradennapier/eslint-plus-action", "CatChen/eslint-suggestion-action", "iCrawl/action-eslint", "ninosaurus/eslint-check"},
	"golangci-lint": {"golangci/golangci-lint-action"},
	"goreleaser": {"goreleaser/goreleaser-action"},
	"gradle": {"gradle/gradle-build-action"},
	"maven": {"qcastel/github-actions-maven-release", "samuelmeuli/action-maven-publish", "LucaFeger/action-maven-cli"},
	"megalinter": {"oxsecurity/megalinter"},
	"mkdocs": {"mhausenblas/mkdocs-deploy-gh-pages", "athackst/mkdocs-simple-plugin"},
	"msbuild": {"MVS-Telecom/publish-nuget"},
	"mypy": {"ricardochaves/python-lint", "jpetrucciani/mypy-check", "sunnysid3up/python-linter", "tsuyoshicho/action-mypy"},
	"npm": {"actions/setup-node", "JS-DevTools/npm-publish"},
	"phpstan": {"php-actions/phpstan"},
	"pip": {"brettcannon/pip-secure-install", "BSFishy/pip-action"},
	"pre-commit": {"pre-commit/action"},
	"python": {"hynek/build-and-inspect-python-package"},
	"rake": {"magefile/mage-action"},
	"rubocop": {"reviewdog/action-rubocop", "andrewmcodes-archive/rubocop-linter-action", "gimenete/rubocop-action", "r7kamura/rubocop-todo-corrector"},
	"sonar-scanner": {"sonarsource/sonarqube-scan-action"},
	"stylelint": {"actions-hub/stylelint"},
	"terraform": {"OP5dev/TF-via-PR", "dflook/terraform-plan", "dflook/terraform-apply"},
	"tflint": {"reviewdog/action-tflint", "devops-infra/action-tflint"},
	"tofu": {"dflook/tofu-plan", "dflook/tofu-apply"},
	"vale": {"gaurav-nelson/github-action-vale-lint", "errata-ai/vale-action"},
}[action]

build_commands[cmd] := {
	"ant": {"^ant "},
	"bash": {"\\S+\\.sh\\b"},
	"bundler": {"bundle install", "bundle exec "},
	"cargo": {"cargo build", "cargo run", "cargo test", "cargo bench"},
	"checkov": {"checkov "},
	"chmod": {"^\\s*chmod\\s+(?:.*\\+x.*|\\b(?:[0-7]{2}[1357]|[0-7][0-7]{2}[1357])\\b)"}, # Unit test: https://regex101.com/r/tt7qzw/1
	"docker": {"docker build"}, # docker build need to also be run to have significant impact.
	"eslint": {"eslint "},
	"go generate": {"go generate"},
	"gomplate": {"gomplate "},
	"goreleaser": {"goreleaser build", "goreleaser release"},
	"gradle": {"gradle ", "./gradlew ", "./gradlew.bat "}, # https://docs.gradle.org/current/userguide/gradle_wrapper_basics.html
	"make": {"make "},
	"maven": {"mvn ", "./mvnw ", "./mvnw.bat", "./mvnw.cmd", "./mvnw.sh "}, # https://maven.apache.org/wrapper/
	"mkdocs": {"mkdocs build"},
	"msbuild": {"msbuild "},
	"mypy": {"mypy "},
	"npm": {"npm diff", "npm restart", "npm (rum|urn|run(-script)?)", "npm start", "npm stop", "npm t(e?st)?", "npm ver(si|is)on", "npm (install|add|i|in|ins|inst|insta|instal|inst|isnta|isntal|isntall)", "npm ci(\\b|$)"},
	"phpstan": {"phpstan "},
	"pip": {"pip install", "pipenv install", "pipenv run "},
	"powershell": {"\\S+\\.ps1\\b"},
	"pre-commit": {"pre-commit run", "pre-commit install"},
	"python": {"^\\s*python(3)?\\s+\\S+\\.py\\b"}, # Unit test: https://regex101.com/r/tuap3y/1
	"rake": {"rails db:create", "rails assets:precompile", "^rake "},
	"rubocop": {"rubocop"},
	"sonar-scanner": {"sonar-scanner"},
	"stylelint": {"stylelint "},
	"tar": {"tar (-?x-?P-?f|-?P-?x-?f|-?x -P -f|-?P -x -f) "}, # Unit test: https://regex101.com/r/pX85P8/1
	"terraform": {"terraform plan", "terraform apply"},
	"tflint": {"tflint"},
	"tofu": {"tofu plan", "tofu apply"},
	"trivy": {"trivy "},
	"unzip": {"unzip .*-:"},
	"vale": {"vale "},
	"webpack": {"webpack"},
	"yarn": {"yarn "},
}[cmd]

results contains poutine.finding(rule, pkg_purl, object.union(
	{
		"path": workflow_path,
		"line": step.lines.run,
		"job": job_id,
		"lotp_tool": cmd,
		"_job": job_obj,
		"details": sprintf("Detected usage of `%s`", [cmd]),
		"event_triggers": workflow_events,
	},
	_lotp_targets_meta(cmd, step.run),
)) if {
	[pkg_purl, workflow_path, workflow_events, step, job_id, job_obj] := _steps_after_untrusted_checkout[_]
	regex.match(
		sprintf("([^a-z]|^)(%v)", [concat("|", build_commands[cmd])]),
		step.run,
	)
}

results contains poutine.finding(rule, pkg_purl, {
	"path": workflow_path,
	"line": step.lines.uses,
	"job": job_id,
	"lotp_action": step.action,
	"_job": job_obj,
	"details": sprintf("Detected usage the GitHub Action `%s`", [step.action]),
	"event_triggers": workflow_events,
}) if {
	[pkg_purl, workflow_path, workflow_events, step, job_id, job_obj] := _steps_after_untrusted_checkout[_]
	regex.match(
		sprintf("([^a-z]|^)(%v)@", [concat("|", build_github_actions[_])]),
		step.uses,
	)
}

results contains poutine.finding(rule, pkg_purl, {
	"path": workflow_path,
	"line": step.lines.uses,
	"job": job_id,
	"lotp_action": step.action,
	"_job": job_obj,
	"details": sprintf("Detected usage of a Local GitHub Action at path: `%s`", [step.action]),
	"event_triggers": workflow_events,
}) if {
	[pkg_purl, workflow_path, workflow_events, step, job_id, job_obj] := _steps_after_untrusted_checkout[_]
	regex.match(
		`^\./`,
		step.action,
	)
}

_lotp_targets_meta(cmd, content) := {"lotp_targets": targets} if {
	targets := utils.resolve_lotp_targets(cmd, content)
} else := {}

# Scan time (RFC3339 UTC), injected by the scanner; absent => far past => fail-safe (fires).
scan_date := object.get(input, "scan_time", "0001-01-01T00:00:00Z")

# Events for which actions/checkout's safe default actually refuses the unsafe fork-PR
# checkout. The guard does nothing for issue_comment / issues / workflow_call / plain
# pull_request, so a finding under those keeps firing even on a fixed checkout version.
_direct_guarded_events := {"pull_request_target"}

_parent_guarded_events := {"pull_request_target", "pull_request"}

# A direct-event finding is neutralized when the checkout is guard-protected AND every flagged
# trigger event is one the guard covers.
_neutralized_direct(workflow, checkout) if {
	utils.checkout_guard_protects(workflow.jobs[checkout.job_idx].steps[checkout.step_idx], scan_date)
	flagged := {e | some i; e := workflow.events[i].name; e in github.events}
	count(flagged) > 0
	every e in flagged { e in _direct_guarded_events }
}

# A workflow_run finding is neutralized when the checkout is guard-protected AND every matched
# parent (triggering) event is a pull_request* event the guard covers.
_neutralized_parent(checkout, parent_events) if {
	utils.checkout_guard_protects(checkout.workflow.jobs[checkout.job_idx].steps[checkout.step_idx], scan_date)
	count(parent_events) > 0
	every e in parent_events { e in _parent_guarded_events }
}

# Steps to scan for dangerous build commands after a checkout. actions/checkout puts the build
# in a later step; gh/git run-block checkouts usually fetch+build in one script, so include the
# checkout step itself for those.
_steps_to_scan(checkout) := utils.workflow_steps_after(checkout) | _run_block_self_step(checkout)

_run_block_self_step(checkout) := {{"step": step, "job_idx": checkout.job_idx, "step_idx": checkout.step_idx}} if {
	not utils.checkout_is_action(checkout)
	step := checkout.workflow.jobs[checkout.job_idx].steps[checkout.step_idx]
} else := set()

_steps_after_untrusted_checkout contains [pkg.purl, workflow.path, events, s.step, workflow.jobs[s.job_idx].id, workflow.jobs[s.job_idx]] if {
	pkg := input.packages[_]
	workflow := pkg.github_actions_workflows[_]

	utils.filter_workflow_events(workflow, github.events)

	events := [event | event := workflow.events[i].name]
	pr_checkout := utils.find_pr_checkouts(workflow)[_]
	not _neutralized_direct(workflow, pr_checkout)
	s := _steps_to_scan(pr_checkout)[_]
}

_steps_after_untrusted_checkout contains [pkg_purl, workflow.path, events, s.step, workflow.jobs[s.job_idx].id, workflow.jobs[s.job_idx]] if {
	[pkg_purl, workflow, parent_events] := _workflows_runs_from_pr[_]

	events := [event | event := workflow.events[i].name]
	pr_checkout := utils.find_pr_checkouts(workflow)[_]
	not _neutralized_parent(pr_checkout, parent_events)
	s := _steps_to_scan(pr_checkout)[_]
}

_workflows_runs_from_pr contains [pkg.purl, workflow, parent_events] if {
	pkg := input.packages[_]
	workflow := pkg.github_actions_workflows[_]
	parent := utils.workflow_run_parents(pkg, workflow)[_]

	utils.filter_workflow_events(parent, github.workflow_run.parent.events)
	parent_events := {e | some i; e := parent.events[i].name; e in github.workflow_run.parent.events}
}

# Azure Devops

results contains poutine.finding(rule, pkg_purl, object.union(
	{
		"path": pipeline_path,
		"job": job,
		"step": s.step_idx,
		"line": s.step.lines[attr],
		"lotp_tool": cmd,
		"details": sprintf("Detected usage of `%s`", [cmd]),
	},
	_lotp_targets_meta(cmd, s.step[attr]),
)) if {
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

# Pipeline As Code Tekton

results contains poutine.finding(rule, pkg.purl, object.union(
	{
		"path": pipeline.path,
		"job": task.name,
		"step": step_idx,
		"line": step.lines.script,
		"lotp_tool": cmd,
		"details": sprintf("Detected usage of `%s`", [cmd]),
	},
	_lotp_targets_meta(cmd, step.script),
)) if {
	pkg := input.packages[_]
	pipeline := pkg.pipeline_as_code_tekton[_]
	contains(pipeline.api_version, "tekton.dev")
	pipeline.kind == "PipelineRun"
	contains(pipeline.metadata.annotations["pipelinesascode.tekton.dev/on-event"], "pull_request")
	contains(pipeline.metadata.annotations["pipelinesascode.tekton.dev/task"], "git-clone")
	task := pipeline.spec.pipeline_spec.tasks[_]
	step := task.task_spec.steps[step_idx]
	regex.match(
		sprintf("([^a-z]|^)(%v)", [concat("|", build_commands[cmd])]),
		step.script,
	)
}
