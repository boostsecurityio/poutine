# METADATA
# title: CI Runner Debug Enabled
# description: |-
#   The workflow is configured to increase the verbosity of the runner.
#   This can potentially expose sensitive information.
# related_resources:
# - https://docs.gitlab.com/ee/ci/variables/index.html#enable-debug-logging
# - https://docs.gitlab.com/ee/ci/variables/index.html#mask-a-cicd-variable
# custom:
#   level: note
package rules.debug_enabled

import data.poutine
import rego.v1

rule := poutine.rule(rego.metadata.chain())

results contains poutine.finding(rule, pkg_purl, {
	"path": config_path,
	"details": concat(" ", sort(vars)),
}) if {
	vars := _debug_enabled[[pkg_purl, config_path]]
}

_gitlab_debug_vars := {"CI_DEBUG_TRACE", "CI_DEBUG_SERVICES"}

_debug_enabled[[pkg.purl, config.path]] contains var.name if {
	pkg := input.packages[_]
	config := pkg.gitlabci_configs[_]
	var := config.variables[_]

	var.name in _gitlab_debug_vars
	lower(var.value) == "true"
}

_debug_enabled[[pkg.purl, config.path]] contains var.name if {
	pkg := input.packages[_]
	config := pkg.gitlabci_configs[_]
	var := config.jobs[_].variables[_]

	var.name in _gitlab_debug_vars
	lower(var.value) == "true"
}
