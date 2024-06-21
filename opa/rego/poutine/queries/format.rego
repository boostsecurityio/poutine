package poutine.queries.format

import rego.v1

default output := ""

output = data.poutine.format[input.format].result

formats contains format if data.poutine.format[format]

formats contains input.builtin_formats[_]

errors contains error if {
	not input.format in formats
	error := sprintf("format %s not found in the available formats: %s", [
		input.format,
		concat(", ", formats),
	])
}

result = {
	"output": output,
	"error": concat(", ", errors),
}
