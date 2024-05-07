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

	viper.BindPFlag("token", analyzeOrgCmd.Flags().Lookup("token"))
	viper.BindEnv("token", "GH_TOKEN")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// analyzeOrgCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// analyzeOrgCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
