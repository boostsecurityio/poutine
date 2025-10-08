package cmd

import (
	"context"
	"embed"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/boostsecurityio/poutine/analyze"
	"github.com/boostsecurityio/poutine/formatters/json"
	"github.com/boostsecurityio/poutine/formatters/noop"
	"github.com/boostsecurityio/poutine/formatters/pretty"
	"github.com/boostsecurityio/poutine/formatters/sarif"
	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/boostsecurityio/poutine/providers/gitops"
	"github.com/boostsecurityio/poutine/providers/scm"
	scm_domain "github.com/boostsecurityio/poutine/providers/scm/domain"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

var Format string
var Verbose bool
var ScmProvider string
var ScmBaseURL scm_domain.ScmBaseDomain
var (
	Version string
	Commit  string
	Date    string
)
var Token string
var CustomEmbeddedRules *embed.FS
var CustomEmbeddedRulesRoot string
var cfgFile string
var config *models.Config = models.DefaultConfig()
var skipRules []string
var allowedRules []string

var legacyFlags = []string{"-token", "-format", "-verbose", "-scm", "-scm-base-uri", "-threads"}

const (
	exitCodeErr       = 1
	exitCodeInterrupt = 2
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "poutine",
	Short: "A Supply Chain Vulnerability Scanner for Build Pipelines",
	Long: `A Supply Chain Vulnerability Scanner for Build Pipelines
By BoostSecurity.io - https://github.com/boostsecurityio/poutine `,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		if Verbose {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		}
		output := zerolog.ConsoleWriter{Out: os.Stderr}
		output.FormatLevel = func(i interface{}) string {
			return strings.ToUpper(fmt.Sprintf("| %-6s|", i))
		}
		log.Logger = log.Output(output)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
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

	err := RootCmd.ExecuteContext(ctx)
	if err != nil {
		log.Error().Err(err).Msg("")
		os.Exit(exitCodeErr)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	for _, arg := range os.Args {
		for _, legacyFlag := range legacyFlags {
			if arg == legacyFlag {
				fmt.Println("Error: Flags now come after the command and require '--' instead of a single '-', use poutine --help for more information.")
				os.Exit(exitCodeErr)
			}
		}
	}

	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is .poutine.yml in the current directory)")
	RootCmd.PersistentFlags().StringVarP(&Format, "format", "f", "pretty", "Output format (pretty, json, sarif)")
	RootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "Enable verbose logging")
	RootCmd.PersistentFlags().StringVarP(&ScmProvider, "scm", "s", "github", "SCM platform (github, gitlab)")
	RootCmd.PersistentFlags().VarP(&ScmBaseURL, "scm-base-url", "b", "Base URI of the self-hosted SCM instance (optional)")
	RootCmd.PersistentFlags().BoolVarP(&config.Quiet, "quiet", "q", false, "Disable progress output")
	RootCmd.PersistentFlags().StringSliceVar(&skipRules, "skip", []string{}, "Adds rules to the configured skip list for the current run (optional)")
	RootCmd.PersistentFlags().StringSliceVar(&allowedRules, "allowed-rules", []string{}, "Overwrite the configured allowedRules list for the current run (optional)")

	_ = viper.BindPFlag("quiet", RootCmd.PersistentFlags().Lookup("quiet"))
}

func initConfig() {
	viper.AutomaticEnv()
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(".")
		viper.SetConfigName(".poutine")
	}

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return
		} else {
			log.Error().Err(err).Msg("Can't read config")
			os.Exit(1)
		}
	}

	if err := viper.Unmarshal(&config); err != nil {
		log.Error().Err(err).Msg("Unable to unmarshal config")
		os.Exit(1)
	}
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

func GetFormatter(opaClient *opa.Opa) analyze.Formatter {
	switch Format {
	case "pretty":
		return &pretty.Format{}
	case "sarif":
		return sarif.NewFormat(os.Stdout, Version)
	case "noop":
		return &noop.Format{}
	}

	return json.NewFormat(opaClient, Format, os.Stdout)
}

func GetAnalyzer(ctx context.Context, command string) (*analyze.Analyzer, error) {
	scmClient, err := scm.NewScmClient(ctx, ScmProvider, ScmBaseURL.String(), Token, command)
	if err != nil {
		return nil, fmt.Errorf("failed to create SCM client: %w", err)
	}

	opaClient, err := newOpa(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create OPA client")
		return nil, err
	}

	formatter := GetFormatter(opaClient)
	gitClient := gitops.NewGitClient(nil)

	analyzer := analyze.NewAnalyzer(scmClient, gitClient, formatter, config, opaClient)
	return analyzer, nil
}

// GetAnalyzerWithConfig creates an analyzer
func GetAnalyzerWithConfig(ctx context.Context, command, scmProvider, scmBaseURL, token string, cfg *models.Config) (*analyze.Analyzer, error) {
	scmClient, err := scm.NewScmClient(ctx, scmProvider, scmBaseURL, token, command)
	if err != nil {
		return nil, fmt.Errorf("failed to create SCM client: %w", err)
	}

	opaClient, err := newOpaWithConfig(ctx, cfg)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create OPA client")
		return nil, err
	}

	formatter := GetFormatter(opaClient)
	gitClient := gitops.NewGitClient(nil)

	analyzer := analyze.NewAnalyzer(scmClient, gitClient, formatter, cfg, opaClient)
	return analyzer, nil
}

func newOpa(ctx context.Context) (*opa.Opa, error) {
	if len(skipRules) > 0 {
		config.Skip = append(config.Skip, models.ConfigSkip{Rule: skipRules})
	}
	if len(allowedRules) > 0 {
		config.AllowedRules = allowedRules
	}

	var opaClient *opa.Opa
	var err error

	if CustomEmbeddedRules != nil {
		opaClient, err = opa.NewOpaWithEmbeddedRules(ctx, config, *CustomEmbeddedRules, CustomEmbeddedRulesRoot)
	} else {
		opaClient, err = opa.NewOpa(ctx, config)
	}

	if err != nil {
		log.Error().Err(err).Msg("Failed to create OPA client")
		return nil, err
	}

	return opaClient, nil
}

// newOpaWithConfig creates an OPA client with request-scoped configuration
func newOpaWithConfig(ctx context.Context, cfg *models.Config) (*opa.Opa, error) {
	var opaClient *opa.Opa
	var err error

	if CustomEmbeddedRules != nil {
		opaClient, err = opa.NewOpaWithEmbeddedRules(ctx, cfg, *CustomEmbeddedRules, CustomEmbeddedRulesRoot)
	} else {
		opaClient, err = opa.NewOpa(ctx, cfg)
	}

	if err != nil {
		log.Error().Err(err).Msg("Failed to create OPA client")
		return nil, fmt.Errorf("failed to create OPA client: %w", err)
	}

	return opaClient, nil
}
