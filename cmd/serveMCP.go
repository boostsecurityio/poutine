package cmd

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var serveMcpCmd = &cobra.Command{
	Use:   "serve-mcp",
	Short: "Starts the poutine MCP server",
	Long: `Starts the poutine MCP server.
Example to start the MCP server: poutine serve-mcp --token "$GH_TOKEN"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		Token = viper.GetString("token")
		ctx := cmd.Context()
		s := server.NewMCPServer("poutine", Version)
		analyzer, err := GetAnalyzer(ctx, "")
		if err != nil {
			return err
		}

		analyzeRepoTool := mcp.NewTool(
			"analyze_repo",
			mcp.WithDescription("Analyzes a remote repository for supply chain vulnerabilities."),
			mcp.WithString("github_repo", mcp.Required(), mcp.Description("The slug of the GitHub repository to analyze (i.e. org/repo).")),
			mcp.WithString("ref", mcp.Description("Defaults to 'HEAD'")),
		)

		s.AddTool(analyzeRepoTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			repo, err := request.RequireString("github_repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			ref := request.GetString("ref", "HEAD")

			packageInsights, err := analyzer.AnalyzeRepo(ctx, repo, ref)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			jsonData, err := json.Marshal(packageInsights)
			if err != nil {
				return mcp.NewToolResultError("Failed to marshal result to JSON: " + err.Error()), nil
			}
			return mcp.NewToolResultText(string(jsonData)), nil
		})

		analyzeOrgTool := mcp.NewTool(
			"analyze_org",
			mcp.WithDescription("Analyzes all repositories in an organization."),
			mcp.WithString("github_org", mcp.Required(), mcp.Description("The slug of the GitHub organization to analyze.")),
			mcp.WithString("threads", mcp.Description("Number of concurrent analyzers to run. Defaults to 4.")), // Define as string
		)

		s.AddTool(analyzeOrgTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			org, err := request.RequireString("github_org")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			threadsStr := request.GetString("threads", "4")
			threads, err := strconv.Atoi(threadsStr)
			if err != nil {
				return mcp.NewToolResultError("Invalid format for threads: must be an integer."), nil
			}
			threadsPtr := &threads

			packageInsightsSlice, err := analyzer.AnalyzeOrg(ctx, org, threadsPtr)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			jsonResult, err := json.Marshal(packageInsightsSlice)
			if err != nil {
				return mcp.NewToolResultError("Failed to marshal result to JSON: " + err.Error()), nil
			}
			return mcp.NewToolResultText(string(jsonResult)), nil
		})

		analyzeRepoStaleBranchesTool := mcp.NewTool(
			"analyze_repo_stale_branches",
			mcp.WithDescription("Analyzes a remote repository for stale branches."),
			mcp.WithString("github_repo", mcp.Required(), mcp.Description("The slug of the GitHub repository to analyze (i.e. org/repo).")), // Corrected parameter name
			mcp.WithString("regex", mcp.Description("Regex to match stale branches. Defaults to an empty string, matching all branches.")),
		)

		s.AddTool(analyzeRepoStaleBranchesTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			repo, err := request.RequireString("github_repo")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			regexStr := request.GetString("regex", "")

			var compiledRegex *regexp.Regexp
			var errRegex error
			if regexStr != "" {
				compiledRegex, errRegex = regexp.Compile(regexStr)
				if errRegex != nil {
					return mcp.NewToolResultError("Invalid regex: " + errRegex.Error()), nil
				}
			}

			packageInsights, err := analyzer.AnalyzeStaleBranches(ctx, repo, nil, nil, compiledRegex)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			jsonData, err := json.Marshal(packageInsights)
			if err != nil {
				return mcp.NewToolResultError("Failed to marshal result to JSON: " + err.Error()), nil
			}
			return mcp.NewToolResultText(string(jsonData)), nil
		})

		return server.ServeStdio(s)
	},
}

func init() {
	RootCmd.AddCommand(serveMcpCmd)

	serveMcpCmd.Flags().StringVarP(&Token, "token", "t", "", "SCM access token (env: GH_TOKEN)")

	viper.BindPFlag("token", serveMcpCmd.Flags().Lookup("token"))
	viper.BindEnv("token", "GH_TOKEN")
}
