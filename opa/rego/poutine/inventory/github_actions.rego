package poutine.inventory

import future.keywords.contains

build_dependencies contains dep {
	pkg := input.packages[_]
	step := pkg.github_actions_workflows[_].jobs[_].steps[_]

	dep := purl.parse_github_actions(step.uses)
}

build_dependencies contains dep {
	pkg := input.packages[_]
	job := pkg.github_actions_workflows[_].jobs[_]
	image := job.container.image
	not contains(image, "$")
	dep := purl.parse_docker_image(image)
}

package_dependencies contains dep {
	pkg := input.packages[_]
	step := pkg.github_actions_metadata[_].runs.steps[_]

	dep := purl.parse_github_actions(step.uses)
}

package_dependencies contains dep {
	pkg := input.packages[_]
	runs := pkg.github_actions_metadata[_].runs

	runs.using == "docker"
	startswith(runs.image, "docker://")

	dep := purl.parse_github_actions(runs.image)
}
