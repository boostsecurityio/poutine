package custom

# METADATA
# title: Custom Test Rule
# description: A custom rule for testing embedded rules functionality
# custom:
#   level: warning

rule := {
	"title": "Custom Test Rule",
	"description": "This is a custom embedded rule for testing",
	"level": "warning",
}

results contains {
	"message": "Custom rule executed successfully",
	"details": input.test_value,
} if {
	input.test_value != ""
}
