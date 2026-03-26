---
name: update-vulndb
description: Update the embedded build platform vulnerability database from the CVE Project's cvelistV5 repository.
disable-model-invocation: true
allowed-tools: Bash(make update-vulndb:*), Bash(make test:*)
---

Update the embedded build platform vulnerability database:

1. Run the database update: `make update-vulndb`
2. Verify the updated database compiles correctly: `make test`
3. Report how many CVEs were added or updated compared to the previous version

Note: This clones the CVE repository (sparse checkout) and processes CVE JSON files for GitHub Actions and GitLab CI vulnerabilities. The output is written to `opa/rego/external/build_platform.rego`.
