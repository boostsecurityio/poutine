Run code quality checks on the current branch:

1. Format all Go code: `make fmt`
2. Run branch-scoped linting (only lint changes vs main): `make lint-branch`
3. Run all tests: `make test`

If linting or tests fail, fix the issues before proceeding. Report a summary of what passed and what failed.
