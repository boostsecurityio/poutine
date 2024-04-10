---
title: "Job uses all secrets"
slug: job_all_secrets
url: /rules/job_all_secrets/
rule: job_all_secrets
severity: warning
---

## Description

A GitHub Actions job was found to have access to all secrets. This may be unnecessary and expose sensitive information to the job.

This can occur when the `secrets` object is serialized to JSON. For example:
```yaml
env:
  ALL_SECRETS: ${{ toJSON(secrets) }}
```

Accessing the `secrets` object using a dynamic key will also expose all secrets to the job. For example:
```yaml
strategy:
  matrix:
    env: [PROD, DEV]
env:
  GH_TOKEN: ${{ secrets[format('GH_PAT_%s', matrix.env)] }}
```

In this example, both secrets `GH_PAT_DEV` and `GH_PAT_PROD` are made available in each job as the GitHub Actions runner is unable to determine the secrets the job requires. As a result, all repository and organization secrets are retained in memory and may be accessed by the job.

## Remediation

Avoid using `${{ toJSON(secrets) }}` or `${{ secrets[...] }}` and only reference individual secrets that are required for the job.

To avoid dynamic key access, consider using GitHub Actions environments to restrict the secrets available to the job. This way, the secrets can share the same name, but have different values based on the environment the job uses. Additionally, GitHub Actions environments can benefit from deployment protections rules to further restrict the access to its secrets. The previous matrix workflow can be rewritten as follows:

```yaml
build:
  runs-on: ubuntu-latest
  strategy:
    matrix:
      env: [PROD, DEV]
  environment: ${{ matrix.env }}
  env:
    GH_TOKEN: ${{ secrets.GH_PAT }}
```

## See Also
- [GitHub Actions: Using environments for jobs](https://docs.github.com/en/actions/using-jobs/using-environments-for-jobs)
- [GitHub Actions: Deployment protection rules](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment#deployment-protection-rules)
- [Leaking Secrets From GitHub Actions: Reading Files And Environment Variables, Intercepting Network/Process Communication, Dumping Memory](https://karimrahal.com/2023/01/05/github-actions-leaking-secrets/)
