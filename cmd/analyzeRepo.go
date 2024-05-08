package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// analyzeRepoCmd represents the analyzeRepo command
var analyzeRepoCmd = &cobra.Command{
	Use:   "analyze_repo",
	Short: "Analyzes a remote repository for supply chain vulnerabilities",
	Long: `Analyzes a remote repository for supply chain vulnerabilities
Example Scanning a remote Github Repository: poutine analyze_repo org/repo --token "$GH_TOKEN"`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		token = viper.GetString("token")
		ctx := cmd.Context()
		analyzer, err := GetAnalyzer(ctx, "analyze_repo")
		if err != nil {
			return err
		}

		repo := args[0]

		err = analyzer.AnalyzeRepo(ctx, repo)
		if err != nil {
			return fmt.Errorf("failed to analyze repo %s: %w", repo, err)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(analyzeRepoCmd)

	analyzeRepoCmd.Flags().StringVarP(&token, "token", "t", "", "SCM access token (env: GH_TOKEN)")

	viper.BindPFlag("token", analyzeOrgCmd.Flags().Lookup("token"))
	viper.BindEnv("token", "GH_TOKEN")
}
