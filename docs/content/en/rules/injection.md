---
title: "Injection with Arbitrary External Contributor Input"
slug: injection
url: /rules/injection/
rule: injection
severity: warning
---

## Description

The pipeline contains an injection into bash or JavaScript with an expression that can contain user input. Prefer placing the expression in an environment variable instead of interpolating it directly into a script.

## Remediation

### GitHub Actions

#### Recommended

```yaml
on:
  pull_request_target:
    branches: [main]
    types: [opened, synchronize]

permissions: {}

jobs:
  lint:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - name: Validate pull request title and body
        uses: actions/github-script@v60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        with:
          script: |
            const { PR_TITLE } = process.env
            github.rest.issues.createComment({
                issue_number: context.issue.number,
                owner: context.repo.owner,
                repo: context.repo.repo,
                body: `Your title (${PR_TITLE}) must match our expected format ("BUG: Fix this now!!!").`
            })
```

#### Anti-Pattern

```yaml
# (1) Triggers on `pull_request_target`, no scoping to protected branch, no scoping to selected events
on: pull_request_target

permissions: write-all # (2) Unnecessary permissions

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - name: Debug
        run: |
          # (3) Bash injection
          echo "Title: ${{ github.event.pull_request.title }}"
          echo "Body: ${{ github.event.pull_request.body }}"
      - name: Validate pull request title and body
        uses: actions/github-script@v7 # (4) Missing pinning
        with:
          script: |
            // (5) JavaScript injection
            github.rest.issues.createComment({
                issue_number: context.issue.number,
                owner: context.repo.owner,
                repo: context.repo.repo,
                body: "Your title (${{ github.event.pull_request.title}}) must match the expected format."
            })
```

## Remediation

### Pipeline as Code Tekton

#### Anti-Pattern
```yaml
apiVersion: tekton.dev/v1beta1
kind: PipelineRun
metadata:
  name: linters
  annotations:
    pipelinesascode.tekton.dev/on-event: "[push, pull_request]"
    pipelinesascode.tekton.dev/on-target-branch: "[*]"
    pipelinesascode.tekton.dev/task: "[git-clone]"
spec:
  params:
    - name: repo_url
      value: "{{repo_url}}"
    - name: revision
      value: "{{revision}}"
  pipelineSpec:
    params:
      - name: repo_url
      - name: revision
    tasks:
      - name: fetchit
        displayName: "Fetch git repository"
        params:
          - name: url
            value: $(params.repo_url)
          - name: revision
            value: $(params.revision)
        taskRef:
          name: git-clone
        workspaces:
          - name: output
            workspace: source
      - name: vale
        displayName: "Spelling and Grammar"
        runAfter:
          - fetchit
        taskSpec:
          workspaces:
            - name: source
          steps:
            - name: execute
              image: some.registry/some-image
              script: |
                binary {{body.pull_request.body}}
        workspaces:
          - name: source
            workspace: source
    workspaces:
      - name: source
  workspaces:
    - name: source
      volumeClaimTemplate:
        spec:
          accessModes:
            - ReadWriteOnce
          resources:
            requests:
              storage: 5Gi
```

## See Also
- [Understanding the risk of script injections](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections)
- [Good practices for mitigating script injection attacks](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#good-practices-for-mitigating-script-injection-attacks)
