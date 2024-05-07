package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "prints the version of poutine",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Version: %s\nCommit: %s\nBuilt At: %s\n", Version, Commit, Date)
		return
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
