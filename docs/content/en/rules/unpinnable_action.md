---
title: "Unpinnable CI component used"
slug: unpinnable_action
url: /rules/unpinnable_action/
rule: unpinnable_action
severity: note
---

## Description

The rule identifies CI components that are unpinnable (often seen in the context of "composite" GitHub Actions), because they depend on mutable supply chain components. Pinning using a cryptographic hash or signature is considered a Best Practice to ensure that a specific version of a component is used, which can help in making builds more reproducible and trustworthy. However, if a component, such as a GitHub Action, is architected in a way that depends on other components, which can be compromised, pinning it does not effectively mitigate the risks associated with mutable supply chain components.

It is critical to keep in mind that the same logic applies to the dependencies of the dependencies. You must validate that those transitive dependencies are also pinned! Even if those components are pinned, they might dynamically load other components at runtime (like with `curl | bash`) or have an `injection` vulnerability. Pinning is NOT a silver bullet, but it is step in the right direction.

## Remediation

### GitHub Actions

Unfortunately, there is no easy way to mitigate the risks associated with unpinnable GitHub Actions, since this a risk inherited from the way the action you are using is designed. 

You can do one of the following:
- Find an alternative action that is pinnable
- You can fork the action and pin the downstream components yourself
- You can file a bug report with the maintainer of the action to request that they make it pinnable

#### Composite Actions

##### Recommended pattern

`action.yml`
```yaml
runs:
  using: composite
  steps:
    - uses: someorg/some-action@8de4be516879302afce542ac80a6a43ced807759 # v3.1.2
      with:
        some-input: some-value
```

##### Anti-Pattern

`action.yml`
```yaml
runs:
  using: composite
  steps:
    - uses: someorg/some-action@v3
      with:
        some-input: some-value
```

#### Docker-based Actions (remote image)

##### Recommended pattern

`action.yml`
```yaml
runs:
  using: docker
  image: docker://ghcr.io/some-org/some-docker@sha256:8de4be516879302afce542ac80a6a43ced807759 # v6.3.1
```

##### Anti-Pattern

`action.yml`
```yaml
runs:
  using: docker
  image: docker://ghcr.io/some-org/some-docker:v6.3.1
```

#### Docker-based Actions (Dockerfile)

##### Recommended pattern

`action.yml`
```yaml
runs:
  using: docker
  image: Dockerfile
```

`Dockerfile`
```yaml
FROM: ghcr.io/some-org/some-docker@sha256:8de4be516879302afce542ac80a6a43ced807759 # v6.3.1
```

##### Anti-Pattern

`action.yml`
```yaml
runs:
  using: docker
  image: Dockerfile
```

`Dockerfile`
```yaml
FROM: ghcr.io/some-org/some-docker:v6.3.1
```

## See Also

- [Unpinnable Actions: How Malicious Code Can Sneak into Your GitHub Actions Workflows](https://www.paloaltonetworks.com/blog/prisma-cloud/unpinnable-actions-github-security/)
- [Pinning Dependencies to a Specific Hash](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)