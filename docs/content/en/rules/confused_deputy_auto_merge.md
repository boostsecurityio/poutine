---
title: "Confused Deputy Auto-Merge"
slug: confused_deputy_auto_merge
url: /rules/confused_deputy_auto_merge/
rule: confused_deputy_auto_merge
severity: error
---

## Description

The workflow appears to be vulnerable to a "Confused Deputy" attack when processing Pull Requests, typically from bots like Dependabot. This vulnerability occurs when a workflow triggered by an event like `pull_request_target` automatically trusts an actor (e.g., `github.actor == 'dependabot[bot]'`) to perform privileged actions, such as merging a Pull Request. An attacker can exploit this by tricking the trusted bot (the "confused deputy") into triggering the workflow on a Pull Request from a fork containing malicious changes. The workflow then mistakenly executes the privileged action (e.g., auto-merging the malicious code) because it only checks the identity of the bot that triggered the event, not guaranteeing the origin of the code changes within the Pull Request.

## Remediation

The core principle for remediation is to ensure that any automated action, especially merging, is based on a reliable verification of the content and origin of the Pull Request, rather than solely on the actor triggering the workflow event.

### GitHub Actions

#### Recommended

Instead of directly using `github.actor` to authorize merge operations in a `pull_request_target` workflow, use specialized GitHub Actions designed to securely handle dependency update PRs or verify the true initiator of the changes. These actions often inspect the PR metadata or commit history to confirm that the changes are genuinely from the trusted bot and not manipulated by an attacker.

For Dependabot auto-merges, consider using actions like:
- `dependabot/fetch-metadata`: This action helps you reliably determine metadata about a Dependabot PR, including whether it has been edited by a user. You can then use this information in subsequent steps to make a safer merge decision.
- `fastify/github-action-merge-dependabot`: This action is specifically designed to securely auto-merge Dependabot pull requests.
- `actions-cool/check-user-permission`: This action can be used to verify permissions of the user who created the pull request or initiated the changes, rather than just the `github.actor` of the current workflow run.

```yaml
name: Auto-Merge Dependabot PRs

on:
  pull_request_target:
    types:
    - opened
    - reopened
    - synchronize

jobs:
  dependabot:
    runs-on: ubuntu-latest
    if: ${{ !github.event.pull_request.head.repo.fork && github.event.pull_request.user.login == 'dependabot[bot]' }}
    steps:
    - name: Auto-merge the PR
      run: gh pr merge --auto --squash ${{ github.event.pull_request.html_url }}
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

#### Anti-Pattern

This example demonstrates a common anti-pattern where a workflow triggered on `pull_request_target` relies solely on `github.actor` to identify a bot (like Dependabot) and then proceeds to automatically merge the Pull Request.

```yaml
name: Auto-Merge Dependabot PRs

on:
  pull_request_target:
    types:
    - opened
    - reopened
    - synchronize

jobs:
  dependabot:
    runs-on: ubuntu-latest
    if: ${{ github.actor == 'dependabot[bot]' }}
    steps:
    - name: Auto-merge the PR
      run: gh pr merge --auto --squash ${{ github.event.pull_request.html_url }}
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## See Also
- [Weaponizing Dependabot: Pwn Request at its finest](https://boostsecurity.io/blog/weaponizing-dependabot-pwn-request-at-its-finest)
- [GitHub Actions Exploitation: Dependabot](https://www.synacktiv.com/en/publications/github-actions-exploitation-dependabot)
- [Dependabot Confusion: Gaining Access to Private GitHub Repositories using Dependabot](https://giraffesecurity.dev/posts/dependabot-confusion/)
