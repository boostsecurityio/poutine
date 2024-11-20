package poutine.inventory

import rego.v1

build_dependencies contains dep if {
	pkg := input.packages[_]
	pipeline := pkg.azure_pipelines[_]
	stage := pipeline.stages[_]
	job := stage.jobs[_]
	step := job.steps[_]

	not contains(step.task, "$")
	dep := sprintf("pkg:azurepipelinestask/%s", [step.task])
}
