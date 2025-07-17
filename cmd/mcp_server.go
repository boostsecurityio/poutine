package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var mcpServerCmd = &cobra.Command{
	Use:   "mcp-server",
	Short: "Start the Poutine MCP server",
	Long: `Start the Poutine MCP server that exposes Poutine's analysis capabilities
through the Model Context Protocol (MCP). This allows AI assistants and other
tools to analyze repositories and organizations for supply chain vulnerabilities.

The server communicates via JSON-RPC over stdio and provides two main tools:
- analyze_org: Analyze all repositories in an organization
- analyze_repo: Analyze a specific repository

Parameters that must be provided for each tool call:
- org/repo: Organization or repository name
- scm_provider: SCM platform (github, gitlab) - optional, defaults to github
- scm_base_url: Base URL for self-hosted SCM - optional
- threads: Number of parallel analysis threads - optional, defaults to 2
- ignore_forks: Whether to ignore forked repositories - optional, defaults to false
- ref: Git reference to analyze for repos - optional, defaults to HEAD

The SCM access token should be provided via the --token flag or GH_TOKEN/GL_TOKEN environment variable.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		return startMCPServer(ctx)
	},
}

func startMCPServer(_ context.Context) error {
	// Set format to json for MCP output
	Format = "json"

	// Create MCP server
	s := server.NewMCPServer(
		"Poutine Security Scanner",
		"1.0.0",
		server.WithToolCapabilities(false),
		server.WithRecovery(),
	)

	// Create analyze_org tool
	analyzeOrgTool := mcp.NewTool("analyze_org",
		mcp.WithDescription("Analyze an organization's repositories for supply chain vulnerabilities"),
		mcp.WithString("org",
			mcp.Required(),
			mcp.Description("Organization name to analyze"),
		),
		mcp.WithString("scm_provider",
			mcp.Description("SCM platform (github, gitlab)"),
			mcp.Enum("github", "gitlab"),
		),
		mcp.WithString("scm_base_url",
			mcp.Description("Base URL of self-hosted SCM instance (optional)"),
		),
		mcp.WithNumber("threads",
			mcp.Description("Number of parallel threads for analysis"),
		),
		mcp.WithBoolean("ignore_forks",
			mcp.Description("Ignore forked repositories"),
		),
	)

	// Create analyze_repo tool
	analyzeRepoTool := mcp.NewTool("analyze_repo",
		mcp.WithDescription("Analyze a remote repository for supply chain vulnerabilities"),
		mcp.WithString("repo",
			mcp.Required(),
			mcp.Description("Repository name in format 'org/repo'"),
		),
		mcp.WithString("scm_provider",
			mcp.Description("SCM platform (github, gitlab)"),
			mcp.Enum("github", "gitlab"),
		),
		mcp.WithString("scm_base_url",
			mcp.Description("Base URL of self-hosted SCM instance (optional)"),
		),
		mcp.WithString("ref",
			mcp.Description("Commit or branch to analyze"),
		),
	)

	// Add tool handlers
	s.AddTool(analyzeOrgTool, handleAnalyzeOrg)
	s.AddTool(analyzeRepoTool, handleAnalyzeRepo)

	log.Info().Msg("Starting Poutine MCP server on stdio")

	// Start the server
	return server.ServeStdio(s)
}

func handleAnalyzeOrg(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	token := viper.GetString("token")
	if token == "" {
		return mcp.NewToolResultError("SCM access token is required. Please provide it via --token flag or GH_TOKEN/GL_TOKEN environment variable"), nil
	}

	org, err := request.RequireString("org")
	if err != nil {
		return mcp.NewToolResultError("org parameter is required"), nil
	}

	scmProvider := request.GetString("scm_provider", "github")
	scmBaseURLStr := request.GetString("scm_base_url", "")
	threads := int(request.GetFloat("threads", 2))
	ignoreForks := request.GetBool("ignore_forks", false)

	Token = token
	ScmProvider = scmProvider
	if scmBaseURLStr != "" {
		if err := ScmBaseURL.Set(scmBaseURLStr); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("invalid scm_base_url: %v", err)), nil
		}
	}
	config.IgnoreForks = ignoreForks

	analyzer, err := GetAnalyzer(ctx, "analyze_org")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to create analyzer: %v", err)), nil
	}

	results, err := analyzer.AnalyzeOrg(ctx, org, &threads)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to analyze org %s: %v", org, err)), nil
	}

	resultData, err := json.Marshal(results)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to marshal results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(resultData)), nil
}

func handleAnalyzeRepo(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	token := viper.GetString("token")
	if token == "" {
		return mcp.NewToolResultError("SCM access token is required. Please provide it via --token flag or GH_TOKEN/GL_TOKEN environment variable"), nil
	}

	repo, err := request.RequireString("repo")
	if err != nil {
		return mcp.NewToolResultError("repo parameter is required"), nil
	}

	scmProvider := request.GetString("scm_provider", "github")
	scmBaseURLStr := request.GetString("scm_base_url", "")
	ref := request.GetString("ref", "HEAD")

	Token = token
	ScmProvider = scmProvider
	if scmBaseURLStr != "" {
		if err := ScmBaseURL.Set(scmBaseURLStr); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("invalid scm_base_url: %v", err)), nil
		}
	}

	analyzer, err := GetAnalyzer(ctx, "analyze_repo")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to create analyzer: %v", err)), nil
	}

	results, err := analyzer.AnalyzeRepo(ctx, repo, ref)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to analyze repo %s: %v", repo, err)), nil
	}

	resultData, err := json.Marshal(results)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to marshal results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(resultData)), nil
}

func init() {
	RootCmd.AddCommand(mcpServerCmd)

	mcpServerCmd.Flags().StringVarP(&Token, "token", "t", "", "SCM access token (env: GH_TOKEN)")
}
