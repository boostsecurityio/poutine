---
title: "Github Action from Unverified Creator used"
slug: github_action_from_unverified_creator_used
url: /rules/github_action_from_unverified_creator_used/
rule: github_action_from_unverified_creator_used
severity: note
---

## Description

Usage of the following GitHub Actions repositories was detected in workflows
or composite actions, but their owner is not a verified creator.

## Remediation

In the workflow file, replace the action with a verified creator's action if possible. Verified creators can be found in the GitHub Marketplace.

Even if the action is published by a Verified Creator, it should not imply that the action is secure or still maintained. A popular action (with many stars and/or downloads) neither implies that it is safe.

Running `poutine` against the org / repo where the action is published can help you in your own risk analysis.

## See Also
- [Actions published by Verified Creators on the GitHub Actions Marketplace](https://github.com/marketplace?query=sort%3Apopularity-desc&type=actions&verification=verified_creator)
- [About badges in GitHub Marketplace](https://docs.github.com/en/actions/creating-actions/publishing-actions-in-github-marketplace#about-badges-in-github-marketplace)