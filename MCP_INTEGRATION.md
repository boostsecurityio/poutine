# Poutine MCP Server Integration Guide

The Poutine MCP (Model Context Protocol) server allows AI coding assistants to analyze repositories and CI/CD pipelines for security vulnerabilities directly from your development environment.

## Prerequisites

1. **Install Poutine**: Follow the [installation guide](README.md) to install Poutine
2. **GitHub Authentication**: Set up GitHub CLI authentication
   ```bash
   gh auth login
   ```
3. **Set GitHub Token Environment Variable**: Before launching your AI coding assistant, export the GitHub token:
   ```bash
   export GH_TOKEN=$(gh auth token)
   ```

   The Poutine MCP server will automatically pick up the `GH_TOKEN` environment variable from your shell session.

## Setup

### Claude Code

```bash
claude mcp add poutine poutine mcp-server
```

### Gemini CLI

```bash
gemini mcp add poutine poutine mcp-server
```

### Other MCP-Compatible Clients

Add the following configuration to your MCP-compatible AI coding assistant:

```json
"mcpServers": {
  "poutine": {
    "type": "stdio",
    "command": "poutine",
    "args": [
      "mcp-server"
    ],
  }
}
```

**Note**: The Poutine MCP server will automatically pick up the `GH_TOKEN` environment variable from your shell session. Make sure you've set it (see Prerequisites) before launching your AI coding assistant.

## Available MCP Tools

Once configured, the following tools are available to your AI assistant:

### `analyze_org`
Scan all repositories in a GitHub/GitLab organization.

**Parameters:**
- `org` (required): Organization name
- `scm_provider` (optional): "github" or "gitlab" (default: "github")
- `scm_base_url` (optional): Base URL for self-hosted instances
- `threads` (optional): Number of parallel threads (default: 2)
- `ignore_forks` (optional): Skip forked repositories (default: false)

### `analyze_repo`
Scan a specific repository.

**Parameters:**
- `repo` (required): Repository name in format "org/repo"
- `scm_provider` (optional): "github" or "gitlab" (default: "github")
- `scm_base_url` (optional): Base URL for self-hosted instances
- `ref` (optional): Git branch or commit to analyze (default: "HEAD")

### `analyze_local`
Scan a local repository by file path.

**Parameters:**
- `path` (required): Local file system path to the repository

### `analyze_repo_stale_branches`
Scan repository branches for `pull_request_target` vulnerabilities.

**Parameters:**
- `repo` (required): Repository name in format "org/repo"
- `scm_provider` (optional): "github" or "gitlab" (default: "github")
- `scm_base_url` (optional): Base URL for self-hosted instances
- `threads` (optional): Number of parallel threads (default: 5)
- `expand` (optional): Expand output to full format (default: false)
- `regex` (optional): Regex pattern for workflow matching (default: "pull_request_target")

### `analyze_manifest`
Analyze CI/CD pipeline manifest content for security issues.

**Parameters:**
- `content` (required): The complete YAML manifest content
- `manifest_type` (required): Type of manifest - "github-actions", "gitlab-ci", "azure-pipelines", or "tekton"

**Note**: This tool is automatically called when AI assistants generate or modify CI/CD workflows to ensure security best practices.

## Example AI Assistant Prompts

Here are some example prompts you can use with your AI coding assistant:

**Organization-wide scan:**
```
Use Poutine to scan all repositories in the <your_org> organization
```

**Single repository analysis:**
```
Analyze the security of the repository actions/checkout
```

**Local repository scan:**
```
Scan the repository at /Users/me/projects/myapp for supply chain vulnerabilities
```

**Stale branch analysis:**
```
Check the myorg/myrepo repository for pull_request_target vulnerabilities in stale branches
```

**Workflow generation with automatic security validation:**
```
Create a GitHub Actions workflow that runs tests on pull requests
```
*(The AI will automatically use `analyze_manifest` to validate the generated workflow)*

## Additional Resources

- [Model Context Protocol Specification](https://spec.modelcontextprotocol.io/)
- [Poutine Documentation](README.md)
- [Claude Code MCP Guide](https://docs.claude.com/en/docs/claude-code/mcp)
- [Gemini CLI MCP Guide](https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md)
