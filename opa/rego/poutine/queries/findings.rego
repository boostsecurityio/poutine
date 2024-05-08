package poutine.queries.findings

import data.rules
import rego.v1

rules_by_id[id] = rules[id].rule

skip(f) if {
	s := data.config.skip[_]
	o := object.union(
		{
			"purl": f.purl,
			"rule": f.rule_id,
			"level": rules_by_id[rule_id].level,
		},
		object.filter(f.meta, {"osv_id", "job", "path"}),
	)

	count(s) > 0
	[attr | s[attr]; not o[attr] in s[attr]] == []
}

skip(f) if {
	data.poutine.config.skip with input as {
		"finding": f,
		"packages": input.packages,
	}
}

findings contains finding if {
	finding := rules[rule_id].results[_]

	not skip(finding)
}

result = {
	"findings": findings,
	"rules": rules_by_id,
}
