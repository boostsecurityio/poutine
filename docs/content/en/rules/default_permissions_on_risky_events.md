---
title: "Default permissions used on risky events"
slug: default_permissions_on_risky_events
url: /rules/default_permissions_on_risky_events/
rule: default_permissions_on_risky_events
severity: warning
---

## Description

If a GitHub Actions workflow does not declare permissions for its job, it inherits the default permissions configured in the GitHub Actions settings of the repository. For organizations created before February 2023, which is the case for a large number of important OSS projects and corporations, [the default permissions used to grant read-write access to the repository](https://github.blog/changelog/2023-02-02-github-actions-updating-the-default-github_token-permissions-to-read-only/) and even new repositories will inherit the permissions of the old, insecure defaults from the organization.

Workflows that trigger on events often related to pull requests from forks (`pull_request_target`, `issue_comment`) should ensure all jobs run with the minimum required permissions. This helps to ensure the workflow does not inadvertently expose a privileged token to untrusted code regardless of the default permissions set in the repository.

## Remediation

In the affected worfklows, ensure that permissions are explicitely declared at the workflow level or at each job level.

The default workflow permissions can be configured to have no permissions to ensure that all jobs declare their permissions.
```
on:
  pull_request_target:
    branches: [main]
    types: [opened, synchronized]

permissions: {} # Change the default job permissions to none

jobs:
  pr-read:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
    - uses: actions/checkout@v4
```


When using workflow level permissions, ensure that the permissions are set to the minimum required for the workflow to function correctly. Increase the permissions only if necessary on a per-job basis.
```
on:
  pull_request_target:
    branches: [main]
    types: [opened, synchronized]

permissions:
  contents: read

jobs:
  pr-read:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
  issues-write:
    runs-on: ubuntu-latest
    permissions:
      issues: write
    steps:
    - uses: org/create-issue-action@v2
```

### Anti-Pattern

```
on: pull_request_target

jobs:
  build-pr:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
      with:
        ref: ${{ github.event.pull_request.head.ref }}
    - run: make
```

## See Also

- [GitHub Actions: Assigning permissions to jobs](https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs)
- [GitHub Actions: Setting the permissions of the `GITHUB_TOKEN` for your repository](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#setting-the-permissions-of-the-github_token-for-your-repository)
