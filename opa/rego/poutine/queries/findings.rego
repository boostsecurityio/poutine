package poutine.queries.findings

import data.rules
import rego.v1

rules_by_id[id] = rules[id].rule

_purl_match(finding_purl, skip_purl) if {
	finding_purl == skip_purl
}

# Prefix match with structural purl boundary: ensures that e.g.
# "pkg:githubactions/foo/bar" matches "pkg:githubactions/foo/bar@v1"
# (boundary is @) but not "pkg:githubactions/foo/bar-baz@v1".
_purl_match(finding_purl, skip_purl) if {
	startswith(finding_purl, skip_purl)
	rest := substring(finding_purl, count(skip_purl), -1)
	regex.match("^[@#]", rest)
}

# No purl constraint in skip rule: purl matches by default.
_skip_purl(_, s) if {
	not s.purl
}

_skip_purl(o, s) if {
	skip_purl := s.purl[_]
	_purl_match(o.purl, skip_purl)
}

skip(f) if {
	s := data.config.skip[_]
	o := object.union(
		{
			"purl": f.purl,
			"rule": f.rule_id,
			"level": rules_by_id[rule_id].level,
		},
		object.filter(f.meta, {"osv_id", "job", "path", "purl"}),
	)

	count(s) > 0
	[attr | s[attr]; attr != "purl"; not o[attr] in s[attr]] == []
	_skip_purl(o, s)
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
