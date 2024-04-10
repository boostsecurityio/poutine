---
title: "If condition always evaluates to true"
slug: if_always_true
url: /rules/if_always_true/
rule: if_always_true
severity: error
---

## Description

GitHub Actions expressions used in if condition of jobs or steps
must not contain extra characters or spaces.
Otherwise, the condition is always evaluated to `true`. 

This can lead to logic bugs and possibly expose parts of the workflow only meant to be executed in secure contexts.

## Remediation

#### Recommended
```yaml
name: Conditionally process PR

on:
  pull_request_target:
    types: [opened, synchronize, reopened]

jobs:
  process-pr:
    runs-on: ubuntu-latest
    steps:
      - name: Auto-format markdown files
        if: github.actor == 'torvalds' || github.actor == 'dependabot[bot]'
        uses: messypoutine/actionable/.github/actions/auto-format@0108c4ec935a308435e665a0e9c2d1bf91e25685 # v1.0.0
```

#### Anti-Pattern
```yaml
name: Conditionally process PR

on:
  pull_request_target:
    types: [opened, synchronize, reopened]

jobs:
  process-pr:
    runs-on: ubuntu-latest
    steps:
      - name: Auto-format markdown files
        if: |
          ${{ 
              github.actor == 'torvalds' || 
              github.actor == 'dependabot[bot]'
          }}
        uses: messypoutine/actionable/.github/actions/auto-format@0108c4ec935a308435e665a0e9c2d1bf91e25685 # v1.0.0
```


## See Also
- [Expression Always True Github Issue](https://github.com/actions/runner/issues/1173)
- [About expressions](https://docs.github.com/en/actions/learn-github-actions/expressions#about-expressions)
- [jobs<job_id>.if](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idif)