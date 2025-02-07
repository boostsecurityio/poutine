# METADATA
# title: Unverified Script Execution
# description: |-
#   The pipeline executes a script or binary fetched from a remote
#   server without verifying its integrity.
# custom:
#   level: note
package rules.unverified_script_exec

import data.poutine
import rego.v1

rule := poutine.rule(rego.metadata.chain())

patterns.shell contains sprintf("(%s)", [concat("|", [
	`(bash|source) <\(curl [^\)\n]+?\)`,
	`(curl|wget|iwr)[^\n]{0,256}(\|(|.*?[^a-z])((ba)?sh|python|php|node|iex|perl)|chmod ([aug]?\+x|[75]))`,
	`iex[^\n]{0,512}\.DownloadString\([^\)]+?\)`,
	`deno (run|install) (-A|--allow-all)[^\n]{0,128}https://[^\s]{0,128}`,
])])

patterns.safe contains sprintf("(%s)", [concat("|", [
	`https://raw\.githubusercontent\.com/[^/]+/[^/]+/[a-f0-9]{40}/`,
	`https://github\.com/[^/]+/[^/]+/raw/[a-f0-9]{40}/`,
])])

results contains poutine.finding(rule, pkg_purl, _scripts[pkg_purl][_])

_unverified_scripts(script) = [sprintf("Command: %s", [match]) |
	match := regex.find_n(patterns.shell[_], script, -1)[_]
	not _is_safe(match)
]

_is_safe(match) = regex.match(patterns.safe[_], match)

_scripts[pkg.purl] contains {
	"path": workflow.path,
	"step": step_id,
	"job": job.id,
	"line": step.lines.run,
	"details": details,
	"event_triggers": [event | event := workflow.events[j].name],
} if {
	pkg := input.packages[_]
	workflow := pkg.github_actions_workflows[_]
	job := workflow.jobs[_]
	step := job.steps[step_id]
	details := _unverified_scripts(step.run)[_]
}

_scripts[pkg.purl] contains {
	"path": action.path,
	"step": step_id,
	"line": step.lines.run,
	"details": details,
} if {
	pkg := input.packages[_]
	action := pkg.github_actions_metadata[_]
	step := action.runs.steps[step_id]
	details := _unverified_scripts(step.run)[_]
}

_scripts[pkg.purl] contains {
	"path": config.path,
	"line": script.line,
	"job": job.name,
	"details": details,
} if {
	some attr in {"before_script", "after_script", "script"}
	pkg := input.packages[_]
	config := pkg.gitlabci_configs[_]
	job := array.concat(config.jobs, [config["default"]])[_]
	script := job[attr][_]
	details := _unverified_scripts(script.run)[_]
}

_scripts[pkg.purl] contains {
	"path": pipeline.path,
	"job": job.job,
	"step": step_id,
	"line": step.lines[attr],
	"details": details,
} if {
	some attr in {"script", "powershell", "pwsh", "bash"}
	pkg := input.packages[_]
	pipeline := pkg.azure_pipelines[_]
	job := pipeline.stages[_].jobs[_]
	step := job.steps[step_id]
	details := _unverified_scripts(step[attr])[_]
}
