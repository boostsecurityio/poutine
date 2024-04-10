# METADATA
# title: Unpinnable CI component used
# description: |-
#   Pinning this GitHub Action is likely ineffective 
#   as it depends on other mutable supply chain components.
# custom:
#   level: note
package rules.unpinnable_action

import data.external.reputation
import data.poutine
import data.poutine.utils
import rego.v1

rule := poutine.rule(rego.metadata.chain())

results contains poutine.finding(rule, pkg.purl, {
	"path": action.path,
	"dependencies": purls,
}) if {
	pkg := input.packages[_]
	action := pkg.github_actions_metadata[_]
	purls := data.poutine.inventory.package_dependencies with input.packages as [{"github_actions_metadata": [action]}]

	unpinned_purls := [p |
		p := purls[_]
		utils.unpinned_purl(p)
	]

	unpinnable_purls := [p |
		p := purls[_]
		reputation.by_purl[p].attributes.unpinnable
	]

	count(unpinnable_purls) + count(unpinned_purls) > 0
}
