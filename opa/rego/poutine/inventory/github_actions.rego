package poutine.inventory

import rego.v1

import data.poutine.utils

build_dependencies contains dep if {
	pkg := input.packages[_]
	step := pkg.github_actions_workflows[_].jobs[_].steps[_]
	dep := purl.parse_github_actions(step.uses, pkg.source_git_repo, pkg.source_git_ref)
}

build_dependencies contains dep if {
	pkg := input.packages[_]
	job := pkg.github_actions_workflows[_].jobs[_]
	image := job.container.image
	not contains(image, "$")
	dep := purl.parse_docker_image(image)
}

build_dependencies contains dep if {
	pkg := input.packages[_]
	job := pkg.github_actions_workflows[_].jobs[_]
	uses := job.uses
	not utils.empty(uses)
	dep := purl.parse_github_actions(uses, pkg.source_git_repo, pkg.source_git_ref)
}

package_dependencies contains dep if {
	pkg := input.packages[_]
	step := pkg.github_actions_metadata[_].runs.steps[_]
	dep := purl.parse_github_actions(step.uses, pkg.source_git_repo, pkg.source_git_ref)
}

package_dependencies contains dep if {
	pkg := input.packages[_]
	runs := pkg.github_actions_metadata[_].runs

	runs.using == "docker"
	startswith(runs.image, "docker://")
	dep := purl.parse_github_actions(runs.image, pkg.source_git_repo, pkg.source_git_ref)
}
