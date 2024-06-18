---
title: "Unverified Script Execution"
slug: unverified_script_exec
url: /rules/unverified_script_exec/
rule: unverified_script_exec
severity: note
---

## Description

The pipeline executes a script or binary fetched from a remote server without verifying its integrity. This pattern commonly appears in the form `curl $URL | bash` (referred as _curl pipe bash_) where a remote script is downloaded and executed in a subsequent command. Other commands may be used in place of `curl` to download the script, such as `wget` or `Invoke-WebRequest`, as well as other interpreters than `bash` such as `python`, `powershell`, `php`, etc.

Piping `curl` into `bash` is a common way to quickly get started with a software on a development machine. Although this is convenient and generally safe to do when the script is sourced from a trusted domain, the likelihood of downloading a compromised script increases when the frequency of execution is higher, such as in a CI pipeline. For production build environments, executing remote scripts leave little to no control and visibility over the code that is being executed. This obscures the provenance of build dependencies and tamper with the build environment in unpredictable ways.

## Remediation

### Anti-Pattern

```sh
curl https://git.io/get_helm.sh | bash
curl -Lo ./kind https://kind.sigs.k8s.io/dl/latest/kind-linux-amd64 && chmod +x ./kind
bash <(curl -s https://codecov.io/bash)
deno run --allow-all https://raw.githubusercontent.com/org/repo/main/ci.ts
iex ((New-Object System.Net.WebClient).DownloadString("https://get.pulumi.com/install.ps1"))
iwr -useb get.scoop.sh | iex
```

### Prefer Using a Package Manager

If the script is meant to install software, consider installing it through a package manager operating system of the pipeline (`apt`, `apk`, `brew`, `rpm`, etc.).
The CI provider's plugin ecosystem (GitHub Actions, Gitlab CI/CD components) may already have a plugin that can install the software in a more robust way. Otherwise, consider using the software in a container image.

### Download the Script From a Public Repository

Installation scripts that are hosted on a custom domain add unnecessary risks when sourcing the script. Often the custom domain simply redirects to a file hosted on a public repository.

Using a `HEAD` request with `curl` can be used to reveal the redirection URL:
```sh
$ curl -I https://get.rvm.io/ | grep -i location
Location: https://raw.githubusercontent.com/rvm/rvm/master/binscripts/rvm-installer
```

Installation scripts that are hosted in a public repository benefit from publicly auditable events and a version control system that provides transparency on the script's history of changes. It also allows consumers of the script to download the file from a specific commit, providing an additional integrity measure that ensures the script does not change unexpectedly.

Instead of downloading a script from a mutable reference, such as a branch or tag:
```sh
curl -f https://raw.githubusercontent.com/anchore/grype/main/install.sh | bash
```

Resolve the mutable reference to a commit SHA using `git ls-remote`:
```sh
git ls-remote https://github.com/anchore/grype main
239741f535c59d6e1b9faee61f64ebcf4361d2c5        refs/heads/main
```

Then, in a CI workflow, replace `main` with the commit SHA to execute the script from an immutable reference:
```sh
curl -f https://raw.githubusercontent.com/anchore/grype/239741f535c59d6e1b9faee61f64ebcf4361d2c5/install.sh | bash
```

### Use `curl --fail`

Remote servers can sometimes fail to properly serve a request and could return a response that is not the expected content. For example, in case of an intermittent server error, an HTML page may be returned instead of a bash script. Piping HTML into `bash` may have unintended consequences. By using curl's `--fail` option, it ensures the command does not output the response when the request fails, thus reducing the risk of executing unexpected content.

```sh
$ curl https://example.com/foo.sh | bash
bash: line 1: syntax error near unexpected token `newline'
bash: line 1: `<?xml version="1.0" encoding="iso-8859-1"?>'

$ curl --fail https://example.com/foo.sh | bash
curl: (22) The requested URL returned error: 500
```

### Enforce Integrity With Checksum Verification

To ensure the content of the script does not change after it is included in a CI workflow, a checksum can be computed and verified before executing the script. This approach is best when used with remote scripts that are known to be immutable. Otherwise, the checksums will need to be updated each time the remote script changes.

First, compute the digest of the script:
```sh
$ curl https://raw.githubusercontent.com/anchore/grype/239741f535c59d6e1b9faee61f64ebcf4361d2c5/install.sh | sha256sum
a8c6d3c0f110f7243bb379f9baf46b382a1b7704221a0d4591b810fe741176e3  -
```

Then, in a CI pipeline, the script should first be downloaded to file and then only be executed if the checksum matches the value computed earlier:
```sh
curl -fo install.sh https://raw.githubusercontent.com/anchore/grype/239741f535c59d6e1b9faee61f64ebcf4361d2c5/install.sh
echo "a8c6d3c0f110f7243bb379f9baf46b382a1b7704221a0d4591b810fe741176e3  install.sh" | sha256sum -c \
  && bash install.sh
```
