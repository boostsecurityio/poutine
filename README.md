[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/8787/badge)](https://www.bestpractices.dev/projects/8787)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/boostsecurityio/poutine/badge)](https://securityscorecards.dev/viewer/?uri=github.com/boostsecurityio/poutine)
![build](https://github.com/boostsecurityio/poutine/actions/workflows/build_test.yml/badge.svg)
![CodeQL](https://github.com/boostsecurityio/poutine/actions/workflows/codeql.yml/badge.svg)
[![Go Reference](https://pkg.go.dev/badge/github.com/boostsecurityio/poutine/v4.svg)](https://pkg.go.dev/github.com/boostsecurityio/poutine)
[![Go Report Card](https://goreportcard.com/badge/github.com/boostsecurityio/poutine)](https://goreportcard.com/report/github.com/boostsecurityio/poutine)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)

[![View site - GH Pages](https://img.shields.io/badge/View_site-GH_Pages-2ea44f?style=for-the-badge)](https://boostsecurityio.github.io/poutine/)

# `messypoutine`

Created by [BoostSecurity.io](https://boostsecurity.io), `poutine` is a security scanner that detects misconfigurations and vulnerabilities in the build pipelines of a repository. It supports parsing CI workflows from GitHub Actions and Gitlab CI/CD. When given an access token with read-level access, `poutine` can analyze all the repositories of an organization to quickly gain insights into the security posture of the organization's software supply chain.

<table>
<td>

![Finding raised by poutine about "Arbitrary Code Execution from Untrusted Code Changes"](https://github.com/boostsecurityio/poutine/assets/172889/ca031a4f-afd8-4e3f-9e66-a2502bd0379b)

</td>
</table>

See the [documentation](docs/content/en/rules) for a list of rules currently supported by `poutine`.

## Why `poutine`?

In French, the word "poutine", when not referring to the [dish](https://en.wikipedia.org/wiki/Poutine), can be used to mean "messy". Inspired by the complexity and intertwined dependencies of modern open-source projects, `poutine` reflects both a nod to our Montreal roots and the often messy, complex nature of securing software supply chains.

## Supported Platforms

- GitHub Actions
- Gitlab Pipelines
- Azure DevOps
- Pipelines As Code Tekton

## Getting Started

### Installation

To install `poutine`, download the latest release from the [releases page](https://github.com/boostsecurityio/poutine/releases) and add the binary to your $PATH. 

<!-- TODO: cosign verify instructions? -->

#### Homebrew
``` bash
brew install poutine
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
poutine [command] [arguments] [options]
```

#### Analyze a local repository

``` bash
poutine analyze_local .
```

#### Analyze a remote GitHub repository

```bash
poutine analyze_repo org/repo --token "$GH_TOKEN"
```

#### Analyze all repositories in a GitHub organization

```bash
poutine analyze_org org --token "$GH_TOKEN"
```


#### Analyze all projects in a self-hosted Gitlab instance

``` bash
poutine analyze_org my-org/project --token "$GL_TOKEN" --scm gitlab --scm-base-url https://gitlab.example.com
```

### Configuration Options

```
--token          SCM access token (required for the commands analyze_repo, analyze_org) (env: GH_TOKEN)
--format         Output format (default: pretty, json, sarif)
--ignore-forks   Ignore forked repositories in the organization(analyze_org)
--scm            SCM platform (default: github, gitlab)
--scm-base-url   Base URI of the self-hosted SCM instance
--threads        Number of threads to use (default: 2)
--config         Path to the configuration file (default: .poutine.yml)
--skip           Add rules to the skip list for the current run (can be specified multiple times)
--verbose        Enable debug logging
```

See [.poutine.sample.yml](.poutine.sample.yml) for an example configuration file.

### Custom Rules

`poutine` supports custom Rego rules to extend its security scanning capabilities. You can write your own rules and include them at runtime.

#### Configuration

Create a `.poutine.yml` configuration file in your current working directory, or use a custom path with the `--config` flag:

```bash
poutine analyze_local . --config my-config.yml
```

In your configuration file, specify the path(s) to your custom rules using the `include` directive:

```yaml
include:
  - path: ./custom_rules
  - path: ./github_actions
```

#### Writing Custom Rules

Custom Rego rules must:
1. Be saved as `*.rego` files in the included directory
2. Follow the package naming convention: `package rules.<rule_name>`
3. Define a `rule` variable with metadata
4. Define a `results` set containing findings

**Example custom rule:**

```rego
package rules.custom_injection

import data.poutine
import rego.v1

# METADATA
# title: Custom Injection Detection
# description: Detects potential injection vulnerabilities in workflows
# custom:
#   level: warning

rule := poutine.rule(rego.metadata.chain())

# Define pattern to detect (properly escaped for Rego)
patterns.github contains `\\$\\{\\{[^\\}]+\\}\\}`

results contains poutine.finding(rule, pkg.purl, {
  "path": workflow.path,
  "line": step.lines.run,
  "job": job.id,
  "step": i,
  "details": "Potential injection found in step",
}) if {
  pkg := input.packages[_]
  workflow := pkg.github_actions_workflows[_]
  job := workflow.jobs[_]
  step := job.steps[i]
  step.run  # Ensure step has a run command
  regex.match(patterns.github[_], step.run)
}
```

**Key points:**
- Use `import data.poutine` and `import rego.v1` for modern Rego syntax and poutine utilities
- Use `rule := poutine.rule(rego.metadata.chain())` to extract metadata from METADATA comments
- The `package` name determines the rule identifier (e.g., `package rules.custom_injection` → rule ID: `custom_injection`)
- Add METADATA comments to describe the rule with `title`, `description`, and `level`
- Set the severity `level` to `note`, `warning`, or `error`
- Use `poutine.finding(rule, pkg.purl, {...})` to create findings that match the poutine schema
- The `results` set should contain findings with fields like `path`, `line`, `job`, `step`, `details`

For more examples, see:
- [poutine-rules repository](https://github.com/boost-rnd/poutine-rules) - External rule examples
- Built-in rules in [opa/rego/rules/](./opa/rego/rules/) directory
- [.poutine.sample.yml](.poutine.sample.yml) - Configuration examples

### Acknowledging Findings

`poutine` supports skipping (acknowledging) specific findings that are not relevant in your context. This can be useful when:
- A finding is a false positive
- The security concern has been addressed through other means (e.g., hardened self-hosted runners)
- You've accepted the risk for a particular finding

To acknowledge findings, you can either:
1. Add a `skip` section to your `.poutine.yml` configuration file
2. Use the `--skip` command-line flag (e.g., `--skip rule_name`) for one-time skipping

#### Configuration File

Add a `skip` section to your `.poutine.yml` configuration file. Each skip rule can filter findings by:
- `job`: Filter by job name
- `level`: Filter by severity level (note, warning, error)
- `path`: Filter by workflow file path
- `rule`: Filter by rule name
- `purl`: Filter by package URL
- `osv_id`: Filter by OSV ID

Example configuration:

```yaml
skip:
  # Skip all note-level findings
  - level: note

  # Skip findings in a specific workflow
  - path: .github/workflows/safe.yml

  # Skip a specific rule everywhere
  - rule: unpinnable_action

  # Skip a rule for specific workflows
  - rule: pr_runs_on_self_hosted
    path:
      - .github/workflows/pr.yml
      - .github/workflows/deploy.yml

  # Skip findings for specific packages
  - rule: github_action_from_unverified_creator_used
    purl:
      - pkg:githubactions/dorny/paths-filter
```

For more examples, see [.poutine.sample.yml](.poutine.sample.yml).

#### Command Line

You can also skip rules on the command line using the `--skip` flag. Note that the command-line flag only supports skipping rules by name globally and does not support the granular filtering options (job, path, level, etc.) available in the configuration file.

```bash
# Skip a single rule globally
poutine analyze_repo org/repo --skip unpinnable_action

# Skip multiple rules globally
poutine analyze_repo org/repo --skip unpinnable_action --skip pr_runs_on_self_hosted
```

This is useful for one-time analysis or when you want to temporarily ignore specific rules without modifying your configuration file. For more granular control (e.g., skipping a rule only in specific workflows), use the configuration file instead.

## AI Coding Assistant Integration (MCP)

`poutine` can be integrated with AI coding assistants like Claude Code, Gemini, etc. through the Model Context Protocol (MCP). This allows AI assistants to analyze repositories and validate CI/CD pipelines directly from your development environment.

For detailed setup instructions for your specific AI coding tool, see the [MCP Integration Guide](MCP_INTEGRATION.md).

## Building from source

Building `poutine` requires Go 1.25+.

```bash
git clone https://github.com/boostsecurityio/poutine.git
cd poutine
make build
```

## Development
### Updating Build Platform CVE Database
```bash
go test -tags build_platform_vuln_database ./...
opa fmt -w opa/rego/external/build_platform.rego
```

## See Also 

For examples of vulnerabilities in GitHub Actions workflows, you can explore the [Messy poutine GitHub organization](https://github.com/messypoutine). It showcases real-world vulnerabilities from open-source projects readily exploitable for educational purposes. 

To get started with some hints, try using `poutine` to analyze the `messypoutine` organization:
``` bash
poutine analyze_org messypoutine --token `gh auth token`
```

You may submit the flags you find in a [private vulnerability disclosure](https://github.com/messypoutine/.github/security/advisories/new).

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.
