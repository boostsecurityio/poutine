package poutine.queries.findings

import data.rules

rules_by_id[id] = rules[id].rule

result = {
	"findings": [f | f := rules[rule_id].results[_]],
	"rules": rules_by_id,
}
