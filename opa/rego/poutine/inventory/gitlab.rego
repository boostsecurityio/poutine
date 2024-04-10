package poutine.inventory

import rego.v1

build_dependencies contains dep if {
	pkg := input.packages[_]
	config := pkg.gitlabci_configs[_]
	job := config.jobs[_]
	image := job.image.name
	not contains(image, "$")

	dep := purl.parse_docker_image(image)
}

build_dependencies contains dep if {
	pkg := input.packages[_]
	config := pkg.gitlabci_configs[_]
	job := config.jobs[_]
	image := job.services[_].name
	not contains(image, "$")

	dep := purl.parse_docker_image(image)
}

build_dependencies contains dep if {
	pkg := input.packages[_]
	config := pkg.gitlabci_configs[_]
	include := config.include[_]
	ref := object.get(include, "ref", "HEAD")
	file := include.file[_]
	not contains(ref, "$")
	not contains(include.project, "$")
	not contains(file, "$")

	dep := sprintf("pkg:gitlabci/include/project?%s", [urlquery.encode_object({
		"file_name": file,
		"project": include.project,
		"ref": ref,
	})])
}

build_dependencies contains dep if {
	pkg := input.packages[_]
	config := pkg.gitlabci_configs[_]
	include := config.include[_]
	url := include.remote
	not contains(url, "$")

	dep := sprintf("pkg:gitlabci/include/remote?download_url=%s", [urlquery.encode(url)])
}

build_dependencies contains dep if {
	pkg := input.packages[_]
	config := pkg.gitlabci_configs[_]
	include := config.include[_]
	path := include.template
	not contains(path, "$")

	dep := sprintf("pkg:gitlabci/include/template?file_name=%s", [urlquery.encode(trim_left(path, "/"))])
}

build_dependencies contains dep if {
	pkg := input.packages[_]
	config := pkg.gitlabci_configs[_]
	include := config.include[_]
	component = include.component
	not contains(component, "$")

	match := regex.find_all_string_submatch_n("([^/]+)/(.*)", component, 1)[0]
	repository_url = match[1]
	parts = split(match[2], "@")
	project := parts[0]
	ref := parts[1]

	dep := sprintf("pkg:gitlabci/include/component?%s", [urlquery.encode_object({
		"project": project,
		"ref": ref,
		"repository_url": repository_url,
	})])
}
