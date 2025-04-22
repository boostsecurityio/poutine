package cmd

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var expand bool
var regex string

var analyzeRepoStaleBranches = &cobra.Command{
	Use:   "analyze_repo_stale_branches",
	Short: "Analyzes a remote repository for pull_request_target vulnerabilities in stale branches",
	Long: `Analyzes a remote repository, looping through all remote branches to find unique GitHub Actions workflows with old pull_request_target vulnerabilities, even though the default branch does not have that vulnerability anymore.
Example Scanning a remote Github Repository: poutine analyze_repo_stale_branches org/repo --token "$GH_TOKEN"`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		token = viper.GetString("token")
		ctx := cmd.Context()
		analyzer, err := GetAnalyzer(ctx, "analyze_repo_stale_branches")
		if err != nil {
			return fmt.Errorf("error getting analyzer analyze_repo_stale_branches: %w", err)
		}

		if Format == "sarif" {
			return errors.New("sarif formatter not supported for analyze_repo_stale_branches")
		}

		repo := args[0]

		reg, err := regexp.Compile(regex)
		if err != nil {
			return fmt.Errorf("error compiling regex: %w", err)
		}

		_, err = analyzer.AnalyzeStaleBranches(ctx, repo, &threads, &expand, reg)
		if err != nil {
			return fmt.Errorf("failed to analyze repo %s: %w", repo, err)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(analyzeRepoStaleBranches)

	analyzeRepoStaleBranches.Flags().StringVarP(&token, "token", "t", "", "SCM access token (env: GH_TOKEN)")
	analyzeRepoStaleBranches.Flags().IntVarP(&threads, "threads", "j", 5, "Parallelization factor for scanning stale branches")
	analyzeRepoStaleBranches.Flags().BoolVarP(&expand, "expand", "e", false, "Expand the output to the classic representation from analyze_repo")
	analyzeRepoStaleBranches.Flags().StringVarP(&regex, "regex", "r", "pull_request_target", "Regex to check if the workflow is accessible in stale branches")

	_ = viper.BindPFlag("token", analyzeRepoStaleBranches.Flags().Lookup("token"))
	_ = viper.BindEnv("token", "GH_TOKEN")
}
