---
name: snapshot
description: Run snapshot regression tests after changes to OPA rules, scanners, analyzers, or formatters to detect output regressions.
allowed-tools: Bash(make snapshot:*), Bash(make update-snapshots:*)
paths: opa/**, scanner/**, analyze/**, formatters/**
---

Run the snapshot regression tests to validate analysis output hasn't changed:

1. Run snapshot tests: `make snapshot`
2. If tests fail, examine the diff carefully:
   - If the change is **expected** (new rule, modified output format, updated OPA policy), update the snapshots: `make update-snapshots`
   - If the change is **unexpected**, investigate what caused the regression and fix the root cause
3. After updating snapshots, re-run `make snapshot` to confirm they pass
4. Report which snapshots changed and why

Note: Requires GH_TOKEN environment variable to be set.
