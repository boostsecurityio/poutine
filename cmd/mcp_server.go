package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/boostsecurityio/poutine/analyze"
	"github.com/boostsecurityio/poutine/formatters/noop"
	"github.com/boostsecurityio/poutine/results"
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

The server communicates via JSON-RPC over stdio and provides these tools:
- analyze_org: Analyze all repositories in an organization
- analyze_repo: Analyze a specific repository
- analyze_repo_stale_branches: Analyze stale branches for pull_request_target vulnerabilities
- analyze_manifest: Analyze CI/CD pipeline manifests for security issues with actionable recommendations (ideal for agents generating secure pipelines)

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
	Format = "noop"

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

	// Create analyze_repo_stale_branches tool
	analyzeStaleBranchesTool := mcp.NewTool("analyze_repo_stale_branches",
		mcp.WithDescription("Analyze a remote repository for pull_request_target vulnerabilities in stale branches"),
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
		mcp.WithNumber("threads",
			mcp.Description("Number of parallel threads for analysis"),
		),
		mcp.WithBoolean("expand",
			mcp.Description("Expand the output to the classic representation from analyze_repo"),
		),
		mcp.WithString("regex",
			mcp.Description("Regex to check if the workflow is accessible in stale branches"),
		),
	)

	analyzeManifestTool := mcp.NewTool("analyze_manifest",
		mcp.WithDescription("Analyze a CI/CD pipeline manifest for supply chain vulnerabilities and security best practices. Use this tool when generating or reviewing pipeline manifests to ensure they are secure and follow best practices. The tool identifies security issues and provides actionable recommendations for creating secure pipelines."),
		mcp.WithString("content",
			mcp.Required(),
			mcp.Description("The complete CI/CD pipeline manifest content as a string (YAML format)"),
		),
		mcp.WithString("manifest_type",
			mcp.Required(),
			mcp.Description("Type of CI/CD manifest to analyze"),
			mcp.Enum("github-actions", "gitlab-ci", "azure-pipelines", "tekton"),
		),
	)

	// Add tool handlers
	s.AddTool(analyzeOrgTool, handleAnalyzeOrg)
	s.AddTool(analyzeRepoTool, handleAnalyzeRepo)
	s.AddTool(analyzeStaleBranchesTool, handleAnalyzeStaleBranches)
	s.AddTool(analyzeManifestTool, handleAnalyzeManifest)

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

	analysisResults, err := analyzer.AnalyzeOrg(ctx, org, &threads)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to analyze org %s: %v", org, err)), nil
	}

	resultData, err := json.Marshal(analysisResults)
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

	analysisResults, err := analyzer.AnalyzeRepo(ctx, repo, ref)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to analyze repo %s: %v", repo, err)), nil
	}

	resultData, err := json.Marshal(analysisResults)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to marshal results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(resultData)), nil
}

func handleAnalyzeStaleBranches(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
	threads := int(request.GetFloat("threads", 5))
	expand := request.GetBool("expand", false)
	regexStr := request.GetString("regex", "pull_request_target")

	Token = token
	ScmProvider = scmProvider
	if scmBaseURLStr != "" {
		if err := ScmBaseURL.Set(scmBaseURLStr); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("invalid scm_base_url: %v", err)), nil
		}
	}

	// Compile the regex
	reg, err := regexp.Compile(regexStr)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("error compiling regex: %v", err)), nil
	}

	analyzer, err := GetAnalyzer(ctx, "analyze_repo_stale_branches")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to create analyzer: %v", err)), nil
	}

	analysisResults, err := analyzer.AnalyzeStaleBranches(ctx, repo, &threads, &expand, reg)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to analyze repo %s: %v", repo, err)), nil
	}

	resultData, err := json.Marshal(analysisResults)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to marshal results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(resultData)), nil
}

func handleAnalyzeManifest(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	content, err := request.RequireString("content")
	if err != nil {
		return mcp.NewToolResultError("content parameter is required"), nil
	}

	manifestType := request.GetString("manifest_type", "auto-detect")

	opaClient, err := newOpa(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create OPA client")
		return mcp.NewToolResultError(fmt.Sprintf("failed to create opa client: %v", err)), nil
	}

	analyzer := analyze.NewAnalyzer(nil, nil, &noop.Format{}, config, opaClient)

	manifestReader := strings.NewReader(content)
	analysisResults, err := analyzer.AnalyzeManifest(ctx, manifestReader, manifestType)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to analyze manifest: %v", err)), nil
	}

	combinedResponse := struct {
		Findings []results.Finding       `json:"findings"`
		Rules    map[string]results.Rule `json:"rules"`
	}{
		Findings: analysisResults.FindingsResults.Findings,
		Rules:    analysisResults.FindingsResults.Rules,
	}

	resultData, err := json.Marshal(combinedResponse)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to marshal results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(resultData)), nil
}

func init() {
	RootCmd.AddCommand(mcpServerCmd)

	mcpServerCmd.Flags().StringVarP(&Token, "token", "t", "", "SCM access token (env: GH_TOKEN)")
}
