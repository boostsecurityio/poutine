package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var threadsRepoStaleBranch int

// analyzeRepoCmd represents the analyzeRepo command
var analyzeRepoStaleBranch = &cobra.Command{
	Use:   "analyze_repo_stale_branch",
	Short: "Analyzes a remote repository for vulnerable stale branch",
	Long: `Analyzes a remote repository for supply chain vulnerabilities
Example Scanning a remote Github Repository: poutine analyze_repo_stale_branch org/repo --token "$GH_TOKEN"`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		token = viper.GetString("token")
		ctx := cmd.Context()
		analyzer, err := GetAnalyzer(ctx, "analyze_repo_stale_branch")
		if err != nil {
			return err
		}

		repo := args[0]

		_, err = analyzer.AnalyzeStaleBranch(ctx, repo, &threadsRepoStaleBranch)
		if err != nil {
			return fmt.Errorf("failed to analyze repo %s: %w", repo, err)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(analyzeRepoStaleBranch)

	analyzeRepoStaleBranch.Flags().StringVarP(&token, "token", "t", "", "SCM access token (env: GH_TOKEN)")
	analyzeRepoStaleBranch.Flags().IntVarP(&threadsRepoStaleBranch, "threads", "j", 5, "Parallelization factor for scanning stale branches")

	viper.BindPFlag("token", analyzeRepoStaleBranch.Flags().Lookup("token"))
	viper.BindEnv("token", "GH_TOKEN")
}
