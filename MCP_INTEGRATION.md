# Poutine MCP Server Integration Guide

The Poutine MCP (Model Context Protocol) server allows AI coding assistants to analyze repositories and CI/CD pipelines for security vulnerabilities directly from your development environment.

## Prerequisites

1. **Install Poutine**: Follow the [installation guide](../README.md) to install Poutine
2. **GitHub Authentication**: Set up GitHub CLI authentication
   ```bash
   gh auth login
   ```

## Setup by AI Coding Tool

### Claude Code

Claude Code natively supports MCP servers and provides a CLI tool for easy configuration.

#### Configuration

**Recommended Method - Using Claude Code CLI:**

```bash
claude mcp add poutine poutine mcp-server --env GH_TOKEN="\$(gh auth token)"
```

#### Usage

Once configured, you can use Poutine tools in Claude Code conversations:

```
Analyze the security of github.com/myorg/myrepo
```

```
Check all repositories in the myorg organization for vulnerabilities
```

```
Analyze the local repository at /path/to/my/project
```

### Gemini CLI

Google's Gemini CLI supports MCP servers for enhanced AI assistance.

#### Configuration

**Using Gemini CLI:**

```bash
# Add the Poutine MCP server
gemini mcp add poutine --command poutine --args mcp-server --env GH_TOKEN="\$(gh auth token)"
```

**Verify Configuration:**

```bash
gemini mcp list
```

#### Usage

Once configured, Poutine tools are available in your Gemini CLI sessions:

```
gemini chat "Use Poutine to analyze the security of myorg/myrepo"
```

### Generic MCP Client Setup

For any MCP-compatible client, use this configuration pattern:

```json
{
  "name": "poutine",
  "command": "poutine",
  "args": ["mcp-server"],
  "env": {
    "GH_TOKEN": "$(gh auth token)"
  }
}
```

**Note**: If your MCP client doesn't support shell command substitution (`$()`), use the wrapper script approach:

**macOS/Linux** - Create `~/.local/bin/poutine-mcp-wrapper.sh`:
```bash
#!/bin/bash
export GH_TOKEN=$(gh auth token)
exec poutine mcp-server "$@"
```

Make it executable:
```bash
chmod +x ~/.local/bin/poutine-mcp-wrapper.sh
```

Then reference the wrapper in your MCP client configuration:
```json
{
  "name": "poutine",
  "command": "/home/username/.local/bin/poutine-mcp-wrapper.sh",
  "args": []
}
```

**Windows** - Create `%USERPROFILE%\bin\poutine-mcp-wrapper.bat`:
```batch
@echo off
for /f "tokens=*" %%i in ('gh auth token') do set GH_TOKEN=%%i
poutine mcp-server %*
```

Then reference in your MCP client configuration:
```json
{
  "name": "poutine",
  "command": "C:\\Users\\username\\bin\\poutine-mcp-wrapper.bat",
  "args": []
}
```

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
Use Poutine to scan all repositories in the boostsecurityio organization
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

## Self-Hosted SCM Instances

For GitHub Enterprise or GitLab self-hosted instances:

### GitHub Enterprise

```bash
# Set the base URL for your GitHub Enterprise instance
export GITHUB_BASE_URL="https://github.enterprise.com"
```

Update your MCP configuration to include the base URL in the environment:
```json
{
  "env": {
    "GH_TOKEN": "$(gh auth token)",
    "GITHUB_BASE_URL": "https://github.enterprise.com"
  }
}
```

### GitLab Self-Hosted

```bash
# Authenticate with GitLab
gl auth login --hostname gitlab.company.com

# Set the token
export GL_TOKEN=$(gl auth token)
```

Update your MCP configuration:
```json
{
  "env": {
    "GL_TOKEN": "$(gl auth token)"
  }
}
```

When using the AI assistant, specify the SCM provider and base URL:
```
Analyze the myorg/myrepo repository on our GitLab instance at https://gitlab.company.com
```

## Troubleshooting

### Token Issues

**Problem**: "SCM access token is required" error

**Solution**: Verify your GitHub CLI authentication:
```bash
gh auth status
gh auth token  # Should output a token
```

If not authenticated:
```bash
gh auth login
```

### Permission Issues

**Problem**: "404 Not Found" or "403 Forbidden" errors

**Solution**: Ensure your GitHub token has the necessary scopes:
```bash
gh auth refresh -s read:org,repo
```

### MCP Server Not Found

**Problem**: AI assistant can't find the Poutine MCP server

**Solution**:
1. Verify Poutine is in your PATH:
   ```bash
   which poutine
   poutine --version
   ```
2. If using a wrapper script, ensure the full path is specified in the configuration
3. Check the AI assistant's logs for detailed error messages

### Wrapper Script Not Working

**Problem**: Wrapper script fails to set token

**Solution**:
1. Test the wrapper script manually:
   ```bash
   # Unix/Linux/macOS
   ~/.local/bin/poutine-mcp-wrapper.sh

   # Windows
   %USERPROFILE%\bin\poutine-mcp-wrapper.bat
   ```
2. Ensure `gh` is in your PATH
3. Check script permissions (Unix/Linux/macOS):
   ```bash
   ls -l ~/.local/bin/poutine-mcp-wrapper.sh
   # Should show: -rwxr-xr-x
   ```

## Security Best Practices

1. **Never hardcode tokens**: Always use `gh auth token` or environment variables
2. **Rotate tokens regularly**: Use short-lived tokens when possible
3. **Limit token scopes**: Only grant the minimum required permissions
4. **Use wrapper scripts**: Keeps token retrieval logic separate from configuration
5. **Review AI-generated workflows**: While `analyze_manifest` validates security, always review generated code

## Additional Resources

- [Model Context Protocol Specification](https://spec.modelcontextprotocol.io/)
- [Poutine Documentation](../README.md)
- [GitHub CLI Documentation](https://cli.github.com/manual/)
- [Claude Code MCP Guide](https://docs.anthropic.com/claude/docs/mcp)
