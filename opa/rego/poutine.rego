package poutine

import rego.v1

rule(chain) = {
	"id": rule_id,
	"title": meta.title,
	"description": meta.description,
	"level": meta.custom.level,
	"refs": object.get(meta, "related_resources", []),
} if {
	module := chain[1]
	module.path[0] == "rules"
	rule_id := module.path[1]
	meta := object.union(
		{
			"title": rule_id,
			"description": "",
			"related_resources": [],
			"custom": {"level": "note"},
		},
		module.annotations,
	)
}

finding(rule, pkg_purl, meta) = {
	"rule_id": rule.id,
	"purl": pkg_purl,
	"meta": meta,
}
