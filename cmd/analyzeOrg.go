package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var threads int

// analyzeOrgCmd represents the analyzeOrg command
var analyzeOrgCmd = &cobra.Command{
	Use:   "analyze_org",
	Short: "Analyzes an organization's repositories for supply chain vulnerabilities",
	Long: `Analyzes an organization's repositories for supply chain vulnerabilities
Example: poutine analyze_org org --token "$GH_TOKEN"

Analyze All Projects in a Self-Hosted Gitlab Organization: 
poutine analyze_org my-org/project --token "$GL_TOKEN" --scm gitlab --scm-base-uri https://gitlab.example.com
		
Note: This command will scan all repositories in the organization except those that are Archived.
`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		token = viper.GetString("token")
		ctx := cmd.Context()
		analyzer, err := GetAnalyzer(ctx, "analyze_org")
		if err != nil {
			return err
		}

		org := args[0]

		_, err = analyzer.AnalyzeOrg(ctx, org, &threads)
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
	analyzeOrgCmd.Flags().BoolVarP(&config.IgnoreForks, "ignore-forks", "i", false, "Ignore forked repositories in the organization")

	viper.BindPFlag("token", analyzeOrgCmd.Flags().Lookup("token"))
	viper.BindPFlag("ignoreForks", analyzeOrgCmd.Flags().Lookup("ignore-forks"))
	viper.BindEnv("token", "GH_TOKEN")
}
