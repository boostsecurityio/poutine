package poutine.config

import rego.v1

skip if {
	startswith(finding.meta.path, "scanner/testdata")
}
