![build](https://github.com/boostsecurityio/poutine/actions/workflows/build_test.yml/badge.svg)
![CodeQL](https://github.com/boostsecurityio/poutine/actions/workflows/codeql.yml/badge.svg)
[![Go Reference](https://pkg.go.dev/badge/github.com/boostsecurityio/poutine/v4.svg)](https://pkg.go.dev/github.com/boostsecurityio/poutine)
[![Go Report Card](https://goreportcard.com/badge/github.com/boostsecurityio/poutine)](https://goreportcard.com/report/github.com/boostsecurityio/poutine)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)

# `poutine`

Created by [BoostSecurity.io](https://boostsecurity.io), `poutine` is a security scanner that detects misconfigurations and vulnerabilities in the build pipelines of a repository. It supports parsing CI workflows from GitHub Actions and Gitlab CI/CD. When given an access token with read-level access, `poutine` can analyze all the repositories of an organization to quickly gain insights into the security posture of the organization's software supply chain.

<table>
<td>

![Finding raised by poutine about "Arbitrary Code Execution from Untrusted Code Changes"](https://github.com/boostsecurityio/poutine/assets/172889/ca031a4f-afd8-4e3f-9e66-a2502bd0379b)

</td>
</table>

See the [documentation](docs/content/en/rules) for a list of rules currently supported by `poutine`.

## Why `poutine`?

In French, the word "poutine", when not referring to the [dish](https://en.wikipedia.org/wiki/Poutine), can be used to mean "messy". Inspired by the complexity and intertwined dependencies of modern open-source projects, `poutine` reflects both a nod to our Montreal roots and the often messy, complex nature of securing software supply chains. 

## Getting Started

### Installation

To install `poutine`, download the latest release from the [releases page](https://github.com/boostsecurityio/poutine/releases) and add the binary to your $PATH. 

<!-- TODO: cosign verify instructions? -->

#### Homebrew
``` bash
brew install boostsecurityio/tap/poutine
```

#### Docker
``` bash
docker run -e GH_TOKEN ghcr.io/boostsecurityio/poutine:latest
```

#### GitHub Actions
```yaml
...
jobs:
  poutine:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
    - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
#################################################################################################
    - name: poutine - GitHub Actions SAST
      uses: boostsecurityio/poutine-action@main # We recommend to use a tagged version and pin it
#################################################################################################
    - name: Upload poutine SARIF file
      uses: github/codeql-action/upload-sarif@4355270be187e1b672a7a1c7c7bae5afdc1ab94a # v3.24.10
      with:
        sarif_file: results.sarif
```

### Usage
``` bash
poutine [options] [command] [arguments]
```

#### Analyze a local repository

``` bash
poutine analyze_local .
```

#### Analyze a remote GitHub repository

```bash
poutine -token "$GH_TOKEN" analyze_repo org/repo
```

#### Analyze all repositories in a GitHub organization

```bash
poutine -token "$GH_TOKEN" analyze_org org
```


#### Analyze all projects in a self-hosted Gitlab instance

``` bash
poutine -token "$GL_TOKEN" -scm gitlab -scm-base-uri https://gitlab.example.com analyze_org my-org/project
```

### Configuration Options

``` 
-token          SCM access token (required for the commands analyze_repo, analyze_org) (env: GH_TOKEN)
-format         Output format (default: pretty, json, sarif)
-scm            SCM platform (default: github, gitlab)
-scm-base-uri   Base URI of the self-hosted SCM instance
-threads        Number of threads to use (default: 2)
-verbose        Enable debug logging
```

## Building from source

Building `poutine` requires Go 1.22.

```bash
git clone https://github.com/boostsecurityio/poutine.git
cd poutine
make build
```

## See Also 

For examples of vulnerabilities in GitHub Actions workflows, you can explore the [Messy poutine GitHub organization](https://github.com/messypoutine). It showcases real-world vulnerabilities from open-source projects readily exploitable for educational purposes. 

To get started with some hints, try using `poutine` to analyze the `messypoutine` organization:
``` bash
poutine -token `gh auth token` analyze_org messypoutine 
```

You may submit the flags you find in a [private vulnerability disclosure](https://github.com/messypoutine/.github/security/advisories/new).

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.
