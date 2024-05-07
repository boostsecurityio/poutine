package cmd

import (
	"fmt"
	"github.com/boostsecurityio/poutine/analyze"
	"github.com/boostsecurityio/poutine/providers/gitops"
	"github.com/boostsecurityio/poutine/providers/local"

	"github.com/spf13/cobra"
)

// analyzeLocalCmd represents the analyzeLocal command
var analyzeLocalCmd = &cobra.Command{
	Use:   "analyze_local",
	Short: "Analyzes a local repository for supply chain vulnerabilities",
	Long: `Analyzes a local repository for supply chain vulnerabilities
Example: poutine analyze_local /path/to/repo`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		repoPath := args[0]

		formatter := GetFormatter()

		localScmClient, err := local.NewGitSCMClient(ctx, repoPath, nil)
		if err != nil {
			return fmt.Errorf("failed to create local SCM client: %w", err)
		}

		localGitClient := gitops.NewLocalGitClient(nil)

		analyzer := analyze.NewAnalyzer(localScmClient, localGitClient, formatter, config)

		err = analyzer.AnalyzeLocalRepo(ctx, repoPath)
		if err != nil {
			return fmt.Errorf("failed to analyze repoPath %s: %w", repoPath, err)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(analyzeLocalCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// analyzeLocalCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// analyzeLocalCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
