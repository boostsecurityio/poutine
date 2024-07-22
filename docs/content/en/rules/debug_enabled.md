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

### GitHub Actions

In the workflow file, remove the `ACTIONS_RUNNER_DEBUG` or `ACTIONS_STEP_DEBUG` environment variables. This may also be enabled by setting a secret or variable, so the fact that `poutine` does not detect those variables, does not guarantee it is not enabled otherwise.

#### Recommended
```yaml
on:
  push:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - id: 1
        run: echo Hello
```

#### Anti-Pattern
```yaml
on:
  push:

env:
  ACTIONS_RUNNER_DEBUG: true

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - id: 1
        env:
          ACTIONS_STEP_DEBUG: true
        run: echo Hello
```


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
### Azure DevOps

In the pipeline file, remove the `system.debug` variable in the `variables` definition or set to false.

#### Recommended
```yaml
variables:
  system.debug: 'false' # Or, better, simply omit this variable as they default to `false` anyway.
```

#### Anti-Pattern
```yaml
variables:
  system.debug: 'true'
```

## See Also
 - https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/enabling-debug-logging
 - https://docs.gitlab.com/ee/ci/variables/index.html#enable-debug-logging
 - https://docs.gitlab.com/ee/ci/variables/index.html#mask-a-cicd-variable
 - https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops&tabs=yaml#systemdebug
