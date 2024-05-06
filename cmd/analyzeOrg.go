package cmd

import (
	"fmt"
	"github.com/rs/zerolog/log"

	"github.com/spf13/cobra"
)

var token string
var threads int

// analyzeOrgCmd represents the analyzeOrg command
var analyzeOrgCmd = &cobra.Command{
	Use:   "analyze_org",
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

		org := args[0]

		err = analyzer.AnalyzeOrg(ctx, org, &threads)
		if err != nil {
			return fmt.Errorf("failed to analyze org %s: %w", org, err)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(analyzeOrgCmd)

	analyzeOrgCmd.Flags().StringVarP(&token, "token", "t", "", "SCM access token (env: GH_TOKEN)")

	analyzeOrgCmd.Flags().IntVarP(&threads, "threads", "j", 2, "Parallelization factor for scanning organizations")

	err := analyzeOrgCmd.MarkFlagRequired("token")
	if err != nil {
		log.Err(err).Msg("token flag is required")
		return
	}

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// analyzeOrgCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// analyzeOrgCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
