---
title: "CI Debug Enabled"
slug: debug_enabled
url: /rules/debug_enabled/
rule: debug_enabled
severity: note
---

## Description

The workflow is configured to increase the verbosity of the runner. This can
potentially expose sensitive information.

## Remediation

### Gitlab CI

In the workflow file, remove the `CI_DEBUG_TRACE` or `CI_DEBUG_SERVICES` variable in the `job` definition or set to false.

#### Recommended
```yaml
job_name:
  variables:
    CI_DEBUG_TRACE: "false" # Or, better, simply omit those variables as they default to `false` anyway.
    CI_DEBUG_SERVICES: "false"
```

#### Anti-Pattern
```yaml
job_name:
  variables:
    CI_DEBUG_TRACE: "true"
    CI_DEBUG_SERVICES: "true"
```

## See Also
 - https://docs.gitlab.com/ee/ci/variables/index.html#enable-debug-logging
 - https://docs.gitlab.com/ee/ci/variables/index.html#mask-a-cicd-variable