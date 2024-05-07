package cmd

import (
	"context"
	"fmt"
	"github.com/boostsecurityio/poutine/analyze"
	"github.com/boostsecurityio/poutine/formatters/json"
	"github.com/boostsecurityio/poutine/formatters/pretty"
	"github.com/boostsecurityio/poutine/formatters/sarif"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/boostsecurityio/poutine/providers/gitops"
	"github.com/boostsecurityio/poutine/providers/scm"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

var Format string
var Verbose bool
var ScmProvider string
var ScmBaseURL string
var (
	Version string
	Commit  string
	Date    string
)
var token string

const (
	exitCodeErr       = 1
	exitCodeInterrupt = 2
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "poutine",
	Short: "A Supply Chain Vulnerability Scanner for Build Pipelines",
	Long: `A Supply Chain Vulnerability Scanner for Build Pipelines
By BoostSecurity.io - https://github.com/boostsecurityio/poutine `,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if Verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	output := zerolog.ConsoleWriter{Out: os.Stderr}
	output.FormatLevel = func(i interface{}) string {
		return strings.ToUpper(fmt.Sprintf("| %-6s|", i))
	}
	log.Logger = log.Output(output)

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	defer func() {
		signal.Stop(signalChan)
		cancel()
	}()

	go func() {
		select {
		case <-signalChan: // first signal, cancel context
			cancel()
			cleanup()
		case <-ctx.Done():
			return
		}
		<-signalChan // second signal, hard exit
		os.Exit(exitCodeInterrupt)
	}()

	err := rootCmd.ExecuteContext(ctx)
	if err != nil {
		log.Error().Err(err).Msg("")
		os.Exit(exitCodeErr)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	cobra.OnInitialize(initConfig)

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.poutine.yaml)")
	rootCmd.PersistentFlags().StringVarP(&Format, "format", "f", "pretty", "Output format (pretty, json, sarif)")
	rootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.PersistentFlags().StringVarP(&ScmProvider, "scm", "s", "github", "SCM platform (github, gitlab)")
	rootCmd.PersistentFlags().StringVarP(&ScmBaseURL, "scm-base-url", "b", "", "Base URI of the self-hosted SCM instance (optional)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func initConfig() {
	viper.AutomaticEnv()
}

func cleanup() {
	log.Debug().Msg("Cleaning up temp directories")
	globPattern := filepath.Join(os.TempDir(), analyze.TEMP_DIR_PREFIX)
	matches, err := filepath.Glob(globPattern)
	if err != nil {
		log.Error().Err(err).Msg("Failed to match temp folders")
	}
	for _, match := range matches {
		if err := os.RemoveAll(match); err != nil {
			log.Error().Err(err).Msgf("Failed to remove %q", match)
		}
	}
	log.Debug().Msg("Finished cleaning up temp directories")
}

func GetFormatter() analyze.Formatter {
	switch Format {
	case "pretty":
		return &pretty.Format{}
	case "json":
		opaClient, _ := opa.NewOpa()
		return json.NewFormat(opaClient, Format, os.Stdout)
	case "sarif":
		return sarif.NewFormat(os.Stdout)
	}
	return &pretty.Format{}
}

func GetAnalyzer(ctx context.Context, command string) (*analyze.Analyzer, error) {
	scmClient, err := scm.NewScmClient(ctx, ScmProvider, ScmBaseURL, token, command)
	if err != nil {
		return nil, fmt.Errorf("failed to create SCM client: %w", err)
	}

	formatter := GetFormatter()

	gitClient := gitops.NewGitClient(nil)

	analyzer := analyze.NewAnalyzer(scmClient, gitClient, formatter)
	return analyzer, nil
}
