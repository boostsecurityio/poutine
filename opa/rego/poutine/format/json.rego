package poutine.format.json

import rego.v1

dependencies[pkg.purl] contains dep if {
	pkg := input.packages[_]
	dep := array.concat(pkg.build_dependencies, pkg.package_dependencies)[_]
}

packages[pkg.purl] = {
	"dependencies": object.get(dependencies, pkg.purl, []),
	"commit_sha": pkg.source_git_commit_sha,
	"ref": pkg.source_git_ref,
} if {
	pkg := input.packages[_]
}

result := json.marshal({
	"rules": input.results.rules,
	"findings": input.results.findings,
	"packages": packages,
})
