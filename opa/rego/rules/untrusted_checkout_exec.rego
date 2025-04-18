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

build_github_actions[action] = {
	"bundler":{"ruby/setup-ruby"},
	"cargo":{"actions-rs/cargo"},
	"checkov":{"bridgecrewio/checkov-action"},
	"docker":{"docker/build-push-action", "docker/setup-buildx-action"},
	"eslint":{"reviewdog/action-eslint", "stefanoeb/eslint-action", "tj-actions/eslint-changed-files", "sibiraj-s/action-eslint", "tinovyatkin/action-eslint", "bradennapier/eslint-plus-action", "CatChen/eslint-suggestion-action", "iCrawl/action-eslint", "ninosaurus/eslint-check"},
	"golangci-lint":{"golangci/golangci-lint-action"},
	"goreleaser": {"goreleaser/goreleaser-action"},
	"gradle": {"gradle/gradle-build-action"},
	"maven": {"qcastel/github-actions-maven-release", "samuelmeuli/action-maven-publish", "LucaFeger/action-maven-cli"},
	"megalinter":{"oxsecurity/megalinter"},
	"mkdocs": {"mhausenblas/mkdocs-deploy-gh-pages", "athackst/mkdocs-simple-plugin"},
	"msbuild": {"MVS-Telecom/publish-nuget"},
	"mypy": {"ricardochaves/python-lint", "jpetrucciani/mypy-check", "sunnysid3up/python-linter", "tsuyoshicho/action-mypy"},
	"npm": {"actions/setup-node","JS-DevTools/npm-publish"},
	"phpstan":{"php-actions/phpstan"},
	"pip": {"brettcannon/pip-secure-install", "BSFishy/pip-action"},
	"pre-commit": {"dbt-checkpoint/dbt-checkpoint", "pre-commit/action", "pre-commit-ci/lite-action", "browniebroke/pre-commit-autoupdate-action", "cloudposse/github-action-pre-commit"},
	"pre-commit":{"pre-commit/action"},
	"python": {"hynek/build-and-inspect-python-package"},
	"rake": {"magefile/mage-action"},
	"rubocop": {"reviewdog/action-rubocop", "andrewmcodes-archive/rubocop-linter-action", "gimenete/rubocop-action", "r7kamura/rubocop-todo-corrector"},
	"sonar-scanner": {"sonarsource/sonarqube-scan-action"},
	"stylelint":{"actions-hub/stylelint"},
	"terraform": {"OP5dev/TF-via-PR", "dflook/terraform-plan", "dflook/terraform-apply"},
	"tflint": {"reviewdog/action-tflint", "devops-infra/action-tflint"},
	"tofu": {"dflook/tofu-plan", "dflook/tofu-apply"},
	"vale": {"gaurav-nelson/github-action-vale-lint", "errata-ai/vale-action"},
}[action]

build_commands[cmd] = {
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
	"gradle": {"gradle ", "./gradlew ", "./gradlew.bat "}, 	# https://docs.gradle.org/current/userguide/gradle_wrapper_basics.html
	"make": {"make "},
	"maven": {"mvn ", "./mvnw ", "./mvnw.bat", "./mvnw.cmd", "./mvnw.sh "}, # https://maven.apache.org/wrapper/
	"mkdocs": {"mkdocs build"},
	"msbuild": {"msbuild "},
	"mypy": {"mypy "},
	"npm": {"npm diff", "npm restart", "npm (rum|urn|run(-script)?)", "npm start", "npm stop", "npm t(e?st)?", "npm ver(si|is)on","npm (install|add|i|in|ins|inst|insta|instal|inst|isnta|isntal|isntall)", "npm ci(\\b|$)"},
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

results contains poutine.finding(rule, pkg_purl, {
	"path": workflow_path,
	"line": step.lines.run,
	"details": sprintf("Detected usage of `%s`", [cmd]),
	"event_triggers": workflow_events,
}) if {
	[pkg_purl, workflow_path, workflow_events, step] := _steps_after_untrusted_checkout[_]
	regex.match(
		sprintf("([^a-z]|^)(%v)", [concat("|", build_commands[cmd])]),
		step.run,
	)
}

results contains poutine.finding(rule, pkg_purl, {
	"path": workflow_path,
	"line": step.lines.uses,
	"details": sprintf("Detected usage the GitHub Action `%s`", [step.action]),
	"event_triggers": workflow_events,
}) if {
	[pkg_purl, workflow_path, workflow_events, step] := _steps_after_untrusted_checkout[_]
	regex.match(
		sprintf("([^a-z]|^)(%v)@", [concat("|", build_github_actions[_])]),
		step.uses,
	)
}


results contains poutine.finding(rule, pkg_purl, {
	"path": workflow_path,
	"line": step.lines.uses,
	"details": sprintf("Detected usage of a Local GitHub Action at path: `%s`", [step.action]),
	"event_triggers": workflow_events,
}) if {
	[pkg_purl, workflow_path, workflow_events, step] := _steps_after_untrusted_checkout[_]
	regex.match(
		`^\./`,
		step.action,
	)
}

_steps_after_untrusted_checkout contains [pkg.purl, workflow.path, events, s.step] if {
	pkg := input.packages[_]
	workflow := pkg.github_actions_workflows[_]

	utils.filter_workflow_events(workflow, github.events)

	events := [event | event := workflow.events[i].name]
	pr_checkout := utils.find_pr_checkouts(workflow)[_]
	s := utils.workflow_steps_after(pr_checkout)[_]
}

_steps_after_untrusted_checkout contains [pkg_purl, workflow.path, events, s.step] if {
	[pkg_purl, workflow] := _workflows_runs_from_pr[_]

	events := [event | event := workflow.events[i].name]
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

# Pipeline As Code Tekton

results contains poutine.finding(rule, pkg.purl, {
	"path": pipeline.path,
	"job": task.name,
	"step": step_idx,
	"line": step.lines.script,
	"details": sprintf("Detected usage of `%s`", [cmd]),
}) if {
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
