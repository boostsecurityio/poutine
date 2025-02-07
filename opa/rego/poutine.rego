package poutine

import rego.v1

rule(chain) = {
	"id": rule_id,
	"title": meta.title,
	"description": meta.description,
	"level": meta.custom.level,
	"refs": object.get(meta, "related_resources", []),
	"config": _rule_config(rule_id, meta),
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

_rule_config(rule_id, meta) = object.union(rule_config, config_values) if {
	rule_config := {key: value |
		param := meta.custom.config[key]
		value := object.union({"value": object.get(param, "default", null)}, param)
	}
	config_values := {key: {"value": value} |
		value := data.config.rules_config[rule_id][key]
	}
}
