---
title: "Pull Request Runs on Self-Hosted GitHub Actions Runner"
slug: pr_runs_on_self_hosted
url: /rules/pr_runs_on_self_hosted/
rule: pr_runs_on_self_hosted
severity: warning
---

## Description

This job runs on a self-hosted GitHub Actions runner in a workflow that is triggered by a `pull_request` event (or other Pull Request related events). Using self-hosted runners in **Public repositories**, especially when processing events for `pull_request` events is considered highly risky as it allows external threats to **run arbitrary code** on that self-hosted runner compute instance. 

While the ["Maximum access for pull requests from public forked repositories"](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token) is `read`, meaning that secrets (either repo-level or organization-level) are not exposed immediately accessible to the pull request workflow, the attacker can still directly run arbitrary code, without leveraging any vulnerability. Then, if they can perform privilege escalation (most runners allow `sudo`), they may exfiltrate sensitive information from the runner, especially if the runner does not properly reset its state between jobs.

This risk occurs **as soon as** your GitHub Organization sets the GitHub Actions Runners configuration to allow self-hosted runners to be used in public repositories. You don't even need to have a workflow that explicitly uses a self-hosted runner in a public repository, the mere fact that the configuration allows it is enough to allow the attacker to exploit it. 

At the moment, `poutine` looks for evidence of workflows explicitely using self-hosted runners, but we plan on improving this detection to also include the configuration of the GitHub Organization.

## Remediation

### GitHub Actions

#### Recommended

Set GitHub Organization **Runners** configuration to **Disabled**.

If you decide to allow and use self-hosted runners in public repositories, make sure to follow the [hardening guidelines](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#hardening-for-self-hosted-runners), knowing that is it critical to ensure that the runner is properly isolated from the rest of your infrastructure and state is cleared between jobs.

#### Anti-Pattern

Having a GitHub Organization **Runners** configuration set to **All repositories** or to select some public repositories comes with the added responsbility of configuring your self-hosted runners pool in a way that is safe.

## See Also
- [Self-hosted runner security](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security)
- [Hardening for self-hosted runners](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#hardening-for-self-hosted-runners)
- [Playing with fire - How we executed a critical supply chain attack on pytorch](https://johnstawinski.com/2024/01/11/playing-with-fire-how-we-executed-a-critical-supply-chain-attack-on-pytorch/)
- [TensorFlow Supply Chain Compromise via Self-Hosted Runner Attack](https://www.praetorian.com/blog/tensorflow-supply-chain-compromise-via-self-hosted-runner-attack/)
- [Gato - Github Attack TOOlkit](https://github.com/praetorian-inc/gato)