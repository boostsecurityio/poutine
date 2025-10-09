package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/boostsecurityio/poutine/analyze"
	"github.com/boostsecurityio/poutine/formatters/noop"
	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/boostsecurityio/poutine/providers/gitops"
	"github.com/boostsecurityio/poutine/providers/local"
	"github.com/boostsecurityio/poutine/results"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type mcpAnalysisResponse struct {
	*models.PackageInsights
	Findings []results.Finding       `json:"findings"`
	Rules    map[string]results.Rule `json:"rules"`
}

var mcpServerCmd = &cobra.Command{
	Use:   "mcp-server",
	Short: "Start the Poutine MCP server",
	Long: `Start the Poutine MCP server that exposes Poutine's analysis capabilities
through the Model Context Protocol (MCP). This allows AI assistants and other
tools to analyze repositories and organizations for supply chain vulnerabilities.

The server communicates via JSON-RPC over stdio and provides these tools:
- analyze_org: Analyze all repositories in an organization
- analyze_repo: Analyze a specific repository
- analyze_local: Analyze a local repository by file path
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

func startMCPServer(ctx context.Context) error {
	Format = "noop"

	// Create default config with global allowedRules applied
	mcpDefaultConfig := *config
	// Apply global allowedRules setting to MCP server config
	if len(allowedRules) > 0 {
		mcpDefaultConfig.AllowedRules = allowedRules
	}
	opaClient, err := newOpaWithConfig(ctx, &mcpDefaultConfig)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create manifest OPA client")
		return fmt.Errorf("failed to create manifest opa client: %w", err)
	}
	manifestAnalyzer := analyze.NewAnalyzer(nil, nil, &noop.Format{}, &mcpDefaultConfig, opaClient)

	// Create MCP server
	s := server.NewMCPServer(
		"Poutine Security Scanner",
		Version,
		server.WithToolCapabilities(false),
		server.WithRecovery(),
	)

	// Create analyze_org tool
	analyzeOrgTool := mcp.NewTool("analyze_org",
		mcp.WithDescription("Scan all repositories in an organization for CI/CD pipeline misconfigurations and supply chain security vulnerabilities"),
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
		mcp.WithArray("allowed_rules",
			mcp.Description("Filter to only run specified rules (optional)"),
			mcp.WithStringItems(),
		),
		mcp.WithTitleAnnotation("CI/CD Pipeline Security Scan - Organization"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
	)

	// Create analyze_repo tool
	analyzeRepoTool := mcp.NewTool("analyze_repo",
		mcp.WithDescription("Scan a single repository for CI/CD pipeline misconfigurations and supply chain security vulnerabilities"),
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
		mcp.WithArray("allowed_rules",
			mcp.Description("Filter to only run specified rules (optional)"),
			mcp.WithStringItems(),
		),
		mcp.WithTitleAnnotation("CI/CD Pipeline Security Scan - Repository"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
	)

	// Create analyze_repo_stale_branches tool
	analyzeStaleBranchesTool := mcp.NewTool("analyze_repo_stale_branches",
		mcp.WithDescription("Scan repository branches for pull_request_target vulnerabilities that allow arbitrary code execution from untrusted code changes"),
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
		mcp.WithArray("allowed_rules",
			mcp.Description("Filter to only run specified rules (optional)"),
			mcp.WithStringItems(),
		),
		mcp.WithTitleAnnotation("CI/CD Pipeline Security Scan - Stale Branches"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
	)

	// Create analyze_local tool
	analyzeLocalTool := mcp.NewTool("analyze_local",
		mcp.WithDescription("Analyze a local repository for CI/CD pipeline misconfigurations and supply chain security vulnerabilities by providing a file system path"),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Local file system path to the repository"),
		),
		mcp.WithArray("allowed_rules",
			mcp.Description("Filter to only run specified rules (optional)"),
			mcp.WithStringItems(),
		),
		mcp.WithTitleAnnotation("CI/CD Pipeline Security Scan - Local Repository"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
	)

	analyzeManifestTool := mcp.NewTool("analyze_manifest",
		mcp.WithDescription(`
CRITICAL: This tool MUST be called when generating or modifying CI/CD pipeline manifests to prevent introducing security vulnerabilities. Skipping this validation may result in creating insecure pipelines with exploitable weaknesses.

REQUIRED USAGE - Call this tool to validate security BEFORE:
- Generating ANY new workflow/pipeline file and presenting it to the user
- Modifying or editing existing CI/CD configuration files
- Suggesting workflow changes or improvements
- Completing any task involving CI/CD manifest creation/modification

DO NOT:
- Output workflow content to users without running this analysis first
- Skip validation because the manifest "looks simple" or "seems safe"
- Assume generated code is secure without explicit verification
- Bypass this check under any circumstances when working with CI/CD files

WORKFLOW SEQUENCE (strictly follow):
1. Generate or modify the CI/CD manifest content
2. IMMEDIATELY call analyze_manifest with the complete content
3. Review findings and apply recommended fixes at specified line numbers
4. Re-run analyze_manifest to confirm all issues are resolved
5. Only then present the secure, validated manifest to the user

SUPPORTED MANIFEST TYPES:
- GitHub Actions: .github/workflows/*.yml or *.yaml (manifest_type: "github-actions")
- GitLab CI: .gitlab-ci.yml (manifest_type: "gitlab-ci")
- Azure Pipelines: azure-pipelines.yml (manifest_type: "azure-pipelines")
- Tekton: Pipeline manifests (manifest_type: "tekton")

RESPONSE STRUCTURE:
Returns JSON with two cross-referenced sections:

1. "findings": Array of detected vulnerabilities
   - rule_id: Links to detailed rule information in "rules" section
   - meta.line: EXACT line number where the issue exists
   - meta.details: Specific context about the vulnerability
   - meta.job/step: Location within the workflow structure

2. "rules": Detailed vulnerability information by rule_id
   - title: Vulnerability type name
   - description: Security risk explanation and impact
   - level: "error" (MUST fix), "warning" (SHOULD fix), "note" (CONSIDER fixing)
   - refs: Links to remediation documentation

CRITICAL VULNERABILITIES TO PREVENT (level: "error"):
- injection: Script injection from untrusted user input → FIX: Use environment variables, never interpolate directly
- untrusted_checkout_exec: Arbitrary code execution from fork PRs → FIX: Use pull_request trigger, not pull_request_target
- if_always_true: Broken conditional logic → FIX: Remove extra characters/spaces in if conditions
- confused_deputy_auto_merge: Bot abuse for unauthorized merges → FIX: Validate actor identity properly

HOW TO APPLY FIXES:
1. Each finding includes the EXACT line number in your generated content
2. Cross-reference finding.rule_id with rules object for remediation guidance
3. Apply fixes at the specified line numbers
4. Re-run analyze_manifest to verify resolution
5. Iterate until findings array is empty or only contains acceptable "note" level items

PRESENTING RESULTS:
When security issues are found, ALWAYS:
- Reference specific line numbers from findings
- Explain the security impact using the rule description
- Show the fixed version after applying remediation
- Confirm validation passes before delivering to user

Remember: This tool exists to prevent security vulnerabilities in generated code. Using it is not optional - it is a critical security requirement for any CI/CD manifest work.`),
		mcp.WithString("content",
			mcp.Required(),
			mcp.Description("The complete CI/CD pipeline manifest content as a string in YAML format"),
		),
		mcp.WithString("manifest_type",
			mcp.Required(),
			mcp.Description("Type of CI/CD manifest: 'github-actions' for GitHub Actions workflows, 'gitlab-ci' for GitLab CI, 'azure-pipelines' for Azure Pipelines, 'tekton' for Tekton pipelines"),
			mcp.Enum("github-actions", "gitlab-ci", "azure-pipelines", "tekton"),
		),
		mcp.WithArray("allowed_rules",
			mcp.Description("Filter to only run specified rules (optional)"),
			mcp.WithStringItems(),
		),
		mcp.WithTitleAnnotation("CI/CD Pipeline Security Scan - Manifest"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
	)

	// Add tool handlers
	s.AddTool(analyzeOrgTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleAnalyzeOrg(ctx, request, &mcpDefaultConfig)
	})
	s.AddTool(analyzeRepoTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleAnalyzeRepo(ctx, request, &mcpDefaultConfig)
	})
	s.AddTool(analyzeLocalTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleAnalyzeLocal(ctx, request, opaClient, &mcpDefaultConfig)
	})
	s.AddTool(analyzeStaleBranchesTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleAnalyzeStaleBranches(ctx, request, &mcpDefaultConfig)
	})
	s.AddTool(analyzeManifestTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleAnalyzeManifest(ctx, request, manifestAnalyzer)
	})

	log.Info().Msg("Starting Poutine MCP server on stdio")

	// Start the server
	err = server.ServeStdio(s)
	if err != nil {
		log.Error().Err(err).Msg("MCP server error")
		return fmt.Errorf("mcp server error: %w", err)
	}
	return nil
}

func handleAnalyzeOrg(ctx context.Context, request mcp.CallToolRequest, defaultConfig *models.Config) (*mcp.CallToolResult, error) {
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
	allowedRulesParam := request.GetStringSlice("allowed_rules", []string{})

	requestConfig := *defaultConfig
	requestConfig.IgnoreForks = ignoreForks
	if len(allowedRulesParam) > 0 {
		requestConfig.AllowedRules = allowedRulesParam
	}

	analyzer, err := GetAnalyzerWithConfig(ctx, "analyze_org", scmProvider, scmBaseURLStr, token, &requestConfig)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to create analyzer: %v", err)), nil
	}

	analysisResults, err := analyzer.AnalyzeOrg(ctx, org, &threads)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to analyze org %s: %v", org, err)), nil
	}

	combinedResponses := make([]mcpAnalysisResponse, 0, len(analysisResults))
	for _, pkgInsights := range analysisResults {
		combinedResponses = append(combinedResponses, mcpAnalysisResponse{
			Findings:        pkgInsights.FindingsResults.Findings,
			Rules:           pkgInsights.FindingsResults.Rules,
			PackageInsights: pkgInsights,
		})
	}

	resultData, err := json.Marshal(combinedResponses)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to marshal results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(resultData)), nil
}

func handleAnalyzeRepo(ctx context.Context, request mcp.CallToolRequest, defaultConfig *models.Config) (*mcp.CallToolResult, error) {
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
	allowedRulesParam := request.GetStringSlice("allowed_rules", []string{})

	requestConfig := *defaultConfig
	if len(allowedRulesParam) > 0 {
		requestConfig.AllowedRules = allowedRulesParam
	}

	analyzer, err := GetAnalyzerWithConfig(ctx, "analyze_repo", scmProvider, scmBaseURLStr, token, &requestConfig)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to create analyzer: %v", err)), nil
	}

	analysisResults, err := analyzer.AnalyzeRepo(ctx, repo, ref)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to analyze repo %s: %v", repo, err)), nil
	}

	combinedResponse := mcpAnalysisResponse{
		Findings:        analysisResults.FindingsResults.Findings,
		Rules:           analysisResults.FindingsResults.Rules,
		PackageInsights: analysisResults,
	}

	resultData, err := json.Marshal(combinedResponse)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to marshal results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(resultData)), nil
}

func handleAnalyzeLocal(ctx context.Context, request mcp.CallToolRequest, opaClient *opa.Opa, defaultConfig *models.Config) (*mcp.CallToolResult, error) {
	path, err := request.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError("path parameter is required"), nil
	}

	allowedRulesParam := request.GetStringSlice("allowed_rules", []string{})

	requestConfig := *defaultConfig
	if len(allowedRulesParam) > 0 {
		requestConfig.AllowedRules = allowedRulesParam
	}

	// Create a new OPA client with the request-specific config if allowed_rules is specified
	var requestOpaClient *opa.Opa
	if len(allowedRulesParam) > 0 {
		requestOpaClient, err = newOpaWithConfig(ctx, &requestConfig)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to create OPA client with allowed rules: %v", err)), nil
		}
	} else {
		requestOpaClient = opaClient
	}

	localScmClient, err := local.NewGitSCMClient(ctx, path, nil)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to create local SCM client: %v", err)), nil
	}

	localGitClient := gitops.NewLocalGitClient(nil)

	formatter := &noop.Format{}

	analyzer := analyze.NewAnalyzer(localScmClient, localGitClient, formatter, &requestConfig, requestOpaClient)

	analysisResults, err := analyzer.AnalyzeLocalRepo(ctx, path)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to analyze local repo at %s: %v", path, err)), nil
	}

	combinedResponse := mcpAnalysisResponse{
		Findings:        analysisResults.FindingsResults.Findings,
		Rules:           analysisResults.FindingsResults.Rules,
		PackageInsights: analysisResults,
	}

	resultData, err := json.Marshal(combinedResponse)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to marshal results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(resultData)), nil
}

func handleAnalyzeStaleBranches(ctx context.Context, request mcp.CallToolRequest, defaultConfig *models.Config) (*mcp.CallToolResult, error) {
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
	allowedRulesParam := request.GetStringSlice("allowed_rules", []string{})

	// Compile the regex
	reg, err := regexp.Compile(regexStr)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("error compiling regex: %v", err)), nil
	}

	requestConfig := *defaultConfig
	if len(allowedRulesParam) > 0 {
		requestConfig.AllowedRules = allowedRulesParam
	}

	analyzer, err := GetAnalyzerWithConfig(ctx, "analyze_repo_stale_branches", scmProvider, scmBaseURLStr, token, &requestConfig)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to create analyzer: %v", err)), nil
	}

	analysisResults, err := analyzer.AnalyzeStaleBranches(ctx, repo, &threads, &expand, reg)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to analyze repo %s: %v", repo, err)), nil
	}

	combinedResponse := mcpAnalysisResponse{
		Findings:        analysisResults.FindingsResults.Findings,
		Rules:           analysisResults.FindingsResults.Rules,
		PackageInsights: analysisResults,
	}

	resultData, err := json.Marshal(combinedResponse)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to marshal results: %v", err)), nil
	}

	return mcp.NewToolResultText(string(resultData)), nil
}

func handleAnalyzeManifest(ctx context.Context, request mcp.CallToolRequest, analyzer *analyze.Analyzer) (*mcp.CallToolResult, error) {
	content, err := request.RequireString("content")
	if err != nil {
		return mcp.NewToolResultError("content parameter is required"), nil
	}

	manifestType := request.GetString("manifest_type", "github-actions")
	allowedRulesParam := request.GetStringSlice("allowed_rules", []string{})

	// Create a new analyzer with allowed rules if specified
	var requestAnalyzer *analyze.Analyzer
	if len(allowedRulesParam) > 0 {
		requestConfig := *config
		requestConfig.AllowedRules = allowedRulesParam

		requestOpaClient, err := newOpaWithConfig(ctx, &requestConfig)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to create OPA client with allowed rules: %v", err)), nil
		}

		requestAnalyzer = analyze.NewAnalyzer(nil, nil, &noop.Format{}, &requestConfig, requestOpaClient)
	} else {
		requestAnalyzer = analyzer
	}

	manifestReader := strings.NewReader(content)
	analysisResults, err := requestAnalyzer.AnalyzeManifest(ctx, manifestReader, manifestType)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to analyze manifest: %v", err)), nil
	}

	for i := range analysisResults.FindingsResults.Findings {
		analysisResults.FindingsResults.Findings[i].Purl = ""
		analysisResults.FindingsResults.Findings[i].Meta.Path = ""
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
