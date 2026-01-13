---
title: "Structured Finding Metadata"
weight: 10
---

# Structured Finding Metadata

Poutine findings now include structured metadata fields that provide programmatic access to security-relevant information. These fields enable library users to build automated triage workflows, correlate findings with secrets exposure, and integrate with downstream security tooling without parsing human-readable text.

## New Finding Fields

### `injection_sources`

**Type:** `[]string`

A sorted array of the specific expression sources that are being injected into a sink (shell script, JavaScript, etc.).

**Example:**
```json
{
  "rule_id": "injection",
  "meta": {
    "details": "Sources: github.event.issue.title github.head_ref",
    "injection_sources": ["github.event.issue.title", "github.head_ref"]
  }
}
```

**Use case:** Programmatically identify which untrusted inputs are exploitable without parsing the `details` string.

---

### `lotp_tool`

**Type:** `string`

The "Living Off The Pipeline" build tool detected after an untrusted checkout. Common values include `npm`, `pip`, `make`, `bash`, `cargo`, `gradle`, etc.

**Example:**
```json
{
  "rule_id": "untrusted_checkout_exec",
  "meta": {
    "details": "Detected usage of `npm`",
    "lotp_tool": "npm"
  }
}
```

**Use case:** Filter findings by tool type, prioritize based on tool risk, or build tool-specific remediation guidance.

---

### `lotp_action`

**Type:** `string`

The GitHub Action identified as a "Living Off The Pipeline" vector (e.g., actions that execute code from the checked-out repository).

**Example:**
```json
{
  "rule_id": "untrusted_checkout_exec",
  "meta": {
    "details": "Detected usage the GitHub Action `bridgecrewio/checkov-action`",
    "lotp_action": "bridgecrewio/checkov-action"
  }
}
```

**Use case:** Track which third-party actions introduce code execution risks, build action allowlists.

---

### `referenced_secrets`

**Type:** `[]string`

A sorted array of secret names referenced in the job where the vulnerability was found. The `GITHUB_TOKEN` is excluded since it's always available.

Supports both dot notation (`secrets.MY_SECRET`) and bracket notation (`secrets['MY_SECRET']`).

**Example:**
```json
{
  "rule_id": "untrusted_checkout_exec",
  "meta": {
    "lotp_tool": "npm",
    "referenced_secrets": ["API_KEY", "DATABASE_PASSWORD", "DEPLOY_TOKEN"]
  }
}
```

**Use case:** Assess blast radius of a vulnerability - if a job with an injection vulnerability also references `PROD_DEPLOY_KEY`, the finding is more critical than one with no secrets.

---

## Usage Examples

### Prioritize by Secrets Exposure

```python
def calculate_priority(finding):
    secrets = finding.get("meta", {}).get("referenced_secrets", [])
    high_value = ["DEPLOY", "PROD", "AWS", "GCP", "AZURE", "NPM_TOKEN"]

    if any(s for s in secrets if any(h in s for h in high_value)):
        return "critical"
    elif secrets:
        return "high"
    return "medium"
```

### Filter Injection Sources

```python
def is_pr_body_injection(finding):
    sources = finding.get("meta", {}).get("injection_sources", [])
    pr_body_patterns = ["pull_request.body", "issue.body", "comment.body"]
    return any(p in s for s in sources for p in pr_body_patterns)
```

### Group by LOTP Tool

```python
from collections import defaultdict

def group_by_tool(findings):
    by_tool = defaultdict(list)
    for f in findings:
        if f["rule_id"] == "untrusted_checkout_exec":
            tool = f["meta"].get("lotp_tool") or f["meta"].get("lotp_action", "unknown")
            by_tool[tool].append(f)
    return dict(by_tool)
```

---

## Backward Compatibility

These fields are additive - the existing `details` field continues to provide human-readable descriptions. Tools parsing `details` will continue to work, but new integrations should prefer the structured fields for reliability.

**JSON behavior:**
- `injection_sources`, `lotp_tool`, `lotp_action`: Omitted when not applicable
- `referenced_secrets`: Present as `[]` (empty array) for GitHub Actions findings even when no secrets are found; omitted for other CI systems

---

## Supported Rules

| Rule | `injection_sources` | `lotp_tool` | `lotp_action` | `referenced_secrets` |
|------|---------------------|-------------|---------------|----------------------|
| `injection` (GitHub Actions) | Yes | - | - | Yes |
| `injection` (GitLab CI) | Yes | - | - | - |
| `injection` (Azure Pipelines) | Yes | - | - | - |
| `injection` (Tekton) | Yes | - | - | - |
| `untrusted_checkout_exec` (GitHub Actions) | - | Yes | Yes | Yes |
| `untrusted_checkout_exec` (Azure DevOps) | - | Yes | - | - |
| `untrusted_checkout_exec` (Tekton) | - | Yes | - | - |
