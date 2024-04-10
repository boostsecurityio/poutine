package external.reputation

import rego.v1

by_purl[pkg.purl] = pkg if {
	pkg := input.reputation.packages[_]
}
