---
name: quality
description: Run code formatting and linting after writing or modifying Go code. Use this after making code changes to ensure quality standards are met.
allowed-tools: Bash(make fmt:*), Bash(make lint-branch:*), Bash(make test:*)
---

Run code quality checks on the current branch:

1. Format all Go code: `make fmt`
2. Run branch-scoped linting (only changes vs main): `make lint-branch`
3. Run all tests: `make test`

Fix any issues found before proceeding. Report a summary of what passed and what failed.
