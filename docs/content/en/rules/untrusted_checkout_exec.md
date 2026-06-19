---
title: "Arbitrary Code Execution from Untrusted Code Changes"
slug: untrusted_checkout_exec
url: /rules/untrusted_checkout_exec/
rule: untrusted_checkout_exec
severity: error
---

## Description

The workflow appears to checkout untrusted code from a fork and uses a command that is known to allow code execution. 

Using workflows with `pull_request_target` has the added benefit (as opposed to `pull_request`) of allowing access to secrets even in forked repositories. There can be good reasons to do so if you need to use API Keys to talk to some external services or want to interact with the GitHub API with `write` permissions. However, this comes at the cost of paying extra attention to the tools you use in your workflow.

So-called "Living Off The Pipeline" tools are common development tools (typically CLIs), commonly used in CI/CD pipelines that have lesser-known RCE-By-Design features ("foot guns") that can be abused to execute arbitrary code. These tools are often used to automate tasks such as compiling, testing, packaging, linting or scanning. The gotcha comes from the fact that many of those tools will consume unutrusted input from files on disk and when you checkout untrusted code from a fork, you are effectively allowing the attacker to control the input to those tools.

## `actions/checkout` safe default (`allow-unsafe-pr-checkout`)

As of `actions/checkout@v7.0.0` (and backported to `v4`/`v5`/`v6` on 2026-07-16), `actions/checkout` **refuses to fetch untrusted fork pull request code** unless the step explicitly sets `allow-unsafe-pr-checkout: true`. When that protection is in effect, the untrusted code never lands on disk, so the code-execution premise of this rule no longer holds.

poutine accounts for this and **suppresses this finding** for an `actions/checkout@<ref>` step only when **all** of the following hold:

- the pinned version enforces the safe default — `v7`+ tags, `main`, a commit SHA that is not in the frozen pre-fix set, or `v4`/`v5`/`v6` (floating tag / `releases/v4..6` branch) once the backport date has passed; **and**
- `allow-unsafe-pr-checkout` is not enabled (absent, or any value other than the literal `true`; a `${{ … }}` expression is treated as possibly-`true` and does **not** suppress); **and**
- the triggering event is one the guard actually covers — `pull_request_target`, or a `workflow_run` whose triggering event is `pull_request`/`pull_request_target`.

The finding still fires when any of those is not met, in particular:

- old or SHA-pinned vulnerable versions (`v1`/`v2`/`v3`, pre-backport `v4`/`v5`/`v6`, or a SHA in the frozen pre-fix set), or `allow-unsafe-pr-checkout: true`;
- events the guard does **not** cover — `issues`, `issue_comment`, `workflow_call`, and `workflow_run` triggered by those;
- untrusted checkout performed via `gh pr checkout` or raw `git` (e.g. `git fetch … pull/<n>/head` then `git checkout`) in a `run:` block — these are explicitly out of scope of GitHub's change and remain exploitable.

The version/SHA resolution is fully offline (it works with `analyze_local`), using an embedded, frozen set of pre-fix `actions/checkout` commit SHAs. The scan instant used for the date gate can be pinned via the `POUTINE_SCAN_TIME` environment variable (RFC3339) for reproducible scans.

## Remediation

### GitHub Actions

#### Recommended

##### Using labels

Make it mandatory to label the PR with a specific label before the workflow runs. This way, you can ensure that only PRs that are labeled with the specific label are allowed to run the workflow.

Adding a label to a pull request can only be performed by users with write access to the repository. This means that the attacker would need to have write access to the repository to add the label to the pull request.

IMPORTANT NOTE: The hypotethical `npm run lint` command used here, assumes that it will process files in the `untrusted` directory. If your actual tool is not designed to process files in a specific directory, you should consider using a different approach to prevent code execution.

The following example not only checks for the label, but is also coded defensively to run trusted linting scripts, despite needing access to secrets.

```yaml
on:
  pull_request_target:
    branches: [main]
    types: [labeled]
permissions: {}
jobs:
  lint:
    runs-on: ubuntu-latest
    if: github.event.label.name == 'safe-to-run'
    permissions:
      contents: read
      pull-requests: write
    steps:
    - name: Checkout trusted code from protected branch
      uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
      with:
        ref: main
        persist-credentials: false
        path: trusted
    - name: Install trusted dependencies
      working-directory: trusted
      run: npm ci

    - name: Checkout untrusted code
      uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
      with:
        repository: ${{ github.event.pull_request.head.repo.full_name }}
        ref: ${{ github.event.pull_request.head.sha }}
        persist-credentials: false
        path: untrusted
    - name: Run linting script on untrusted code
      id: untrusted-code-lint
      working-directory: trusted
      env:
        LINTING_TOOL_API_KEY: ${{ secrets.LINTING_TOOL_API_KEY }}
      run: |
        RAND_DELIMITER="$(openssl rand -hex 16)" # 128-bit random delimiter token
        echo "tainted<<${RAND_DELIMITER}" >> "${GITHUB_OUTPUT}"
        echo "$(npm run lint --ignore-scripts $GITHUB_WORKSPACE/untrusted/)" >> "${GITHUB_OUTPUT}"
        echo "${RAND_DELIMITER}" >> "${GITHUB_OUTPUT}"
    - name: Output linting results to Pull Request
      uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1
      env:
        UNTRUSTED_CODE_TAINTED_LINT_RESULTS: ${{ steps.untrusted-code-lint.outputs.tainted }}
      with:
        script: |
          const { UNTRUSTED_CODE_TAINTED_LINT_RESULTS } = process.env
          github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `👋 Thanks for your contribution.\nHere are the linting results:\n${UNTRUSTED_CODE_TAINTED_LINT_RESULTS}`
          })
```

##### Using environments

You should limit the number of simple Actions secrets and prefer the use environments to store secrets to restrict the execution of the workflow to specific environments. This way, you can ensure that only PRs that are targeting the specific environment are allowed to run the workflow. And you can configure the environment to be protected and require approval before the workflow runs.

IMPORTANT NOTE: The hypotethical `npm run lint` command used here, assumes that it will process files in the `untrusted` directory. If your actual tool is not designed to process files in a specific directory, you should consider using a different approach to prevent code execution.

The following example is very similar to the previous, but uses environments and stores the `LINTING_TOOL_API_KEY` in the environment.

```yaml
on:
  pull_request_target:
    branches: [main]
    types: [opened, synchronize]
permissions: {}
jobs:
  lint:
    runs-on: ubuntu-latest
    environment: untrusted-pull-request-from-forks
    permissions:
      contents: read
      pull-requests: write
    steps:
    - name: Checkout trusted code from protected branch
      uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
      with:
        ref: main
        persist-credentials: false
        path: trusted
    - name: Install trusted dependencies
      working-directory: trusted
      run: npm ci

    - name: Checkout untrusted code
      uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
      with:
        repository: ${{ github.event.pull_request.head.repo.full_name }}
        ref: ${{ github.event.pull_request.head.sha }}
        persist-credentials: false
        path: untrusted
    - name: Run linting script on untrusted code
      id: untrusted-code-lint
      working-directory: trusted
      env:
        LINTING_TOOL_API_KEY: ${{ secrets.LINTING_TOOL_API_KEY }}
      run: |
        RAND_DELIMITER="$(openssl rand -hex 16)" # 128-bit random delimiter token
        echo "tainted<<${RAND_DELIMITER}" >> "${GITHUB_OUTPUT}"
        echo "$(npm run lint --ignore-scripts $GITHUB_WORKSPACE/untrusted/)" >> "${GITHUB_OUTPUT}"
        echo "${RAND_DELIMITER}" >> "${GITHUB_OUTPUT}"
    - name: Output linting results to Pull Request
      uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1
      env:
        UNTRUSTED_CODE_TAINTED_LINT_RESULTS: ${{ steps.untrusted-code-lint.outputs.tainted }}
      with:
        script: |
          const { UNTRUSTED_CODE_TAINTED_LINT_RESULTS } = process.env
          github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `👋 Thanks for your contribution.\nHere are the linting results:\n${UNTRUSTED_CODE_TAINTED_LINT_RESULTS}`
          })
```

#### Anti-Pattern

This example contains several things that could be improved to make the workflow more secure.

```yaml
# (1) Triggers on `pull_request_target`, no scoping to protected branch, no scoping to selected events
on: pull_request_target

# (2) Using default permissions for automatic token

jobs:
  lint:
    runs-on: ubuntu-latest
    # (3) Runs unconditionnally (no label, no environment)
    steps:
    - name: Checkout untrusted code
      uses: actions/checkout@v4 # (4) Missing pinning
      with:
        repository: ${{ github.event.pull_request.head.repo.full_name }}
        ref: ${{ github.event.pull_request.head.sha }}
        # (5) Persisting credentials is not necessary - Though this is not a panacea, credentials can still be dumped from memory
        # (6) Checking untrusted code in default workspace path - In this scenario, it's good to explicitely define the path with untrusted code
    - name: Install dependencies
      run: npm install # (7) Should use `npm ci` instead, this will allow attack to install any package
    - name: Run linting script
      id: lint
      env:
        LINTING_TOOL_API_KEY: ${{ secrets.LINTING_TOOL_API_KEY }}
      run: |
        echo "results<<EOF" >> "${GITHUB_OUTPUT}" # (8) Untrusted output could output more that just `results` because EOF delimiter is known to the attacker
        echo "$(npm run lint)" >> "${GITHUB_OUTPUT}" # (9) RCE-by-design (npm will consume untrusted `package.json` and execute arbitrary code)
        echo "EOF" >> "${GITHUB_OUTPUT}"
    - name: Output linting results to Pull Request
      uses: actions/github-script@v7 # (10) Missing pinning
      with:
        script: |
          github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `👋 Thanks for your contribution.\nHere are the linting results:\n${{ steps.lint.outputs.results }}` // (11) Second-order Injection
          })
```

### Azure DevOps

#### Caveat
False positives are likely given that static analysis of solely the pipeline file is not enough to confirm exploitability

#### Recommended
##### Azure DevOps Settings
Organization Setting:
![img.png](img.png)

Avoid activating the following settings to prevent issues:
![img_1.png](img_1.png)

### Pipeline As Code Tekton

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
      - name: npm
        displayName: "NPM Install"
        runAfter:
          - fetchit
        taskSpec:
          workspaces:
            - name: source
          steps:
            - name: npm-install
              image: node:16
              workingDir: $(workspaces.source.path)
              script: |
                npm install
...

```



## See Also
- [Keeping your GitHub Actions and workflows secure Part 1: Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [Erosion of Trust: Unmasking Supply Chain Vulnerabilities in the Terraform Registry](https://boostsecurity.io/blog/erosion-of-trust-unmasking-supply-chain-vulnerabilities-in-the-terraform-registry)
- [The tale of a Supply Chain near-miss incident](https://boostsecurity.io/blog/the-tale-of-a-supply-chain-near-miss-incident)
- [Living Off The Pipeline](https://boostsecurityio.github.io/lotp/)
- https://learn.microsoft.com/en-us/azure/devops/pipelines/repos/github?view=azure-devops&tabs=yaml#important-security-considerations
- https://learn.microsoft.com/en-us/azure/devops/pipelines/security/misc?view=azure-devops#dont-provide-secrets-to-fork-builds
