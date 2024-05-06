package cmd

import (
	"fmt"
	"github.com/rs/zerolog/log"

	"github.com/spf13/cobra"
)

// analyzeRepoCmd represents the analyzeRepo command
var analyzeRepoCmd = &cobra.Command{
	Use:   "analyze_repo",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		analyzer, err := GetAnalyzer(ctx)
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

	err := analyzeRepoCmd.MarkFlagRequired("token")
	if err != nil {
		log.Err(err).Msg("token flag is required")
		return
	}

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// analyzeRepoCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// analyzeRepoCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
