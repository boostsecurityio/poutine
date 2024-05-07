package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/boostsecurityio/poutine/providers/gitops"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/boostsecurityio/poutine/analyze"
	"github.com/boostsecurityio/poutine/formatters/json"
	"github.com/boostsecurityio/poutine/formatters/pretty"
	"github.com/boostsecurityio/poutine/formatters/sarif"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/boostsecurityio/poutine/providers/local"
	"github.com/boostsecurityio/poutine/providers/scm"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	exitCodeErr       = 1
	exitCodeInterrupt = 2
)

func usage() {
	fmt.Fprintf(os.Stderr, `poutine - A Supply Chain Vulnerability Scanner for Build Pipelines
By BoostSecurity.io - https://github.com/boostsecurityio/poutine

Usage:
  poutine [options] <command> [<args>]

Commands:
  analyze_org <org>
  analyze_repo <org>/<repo>
  analyze_local <path>
  version

Options:
`)

	flag.PrintDefaults()
	os.Exit(exitCodeInterrupt)
}

var (
	format      = flag.String("format", "pretty", "Output format (pretty, json, sarif)")
	token       = flag.String("token", "", "SCM access token (required for the commands analyze_org, analyze_repo) (env: GH_TOKEN)")
	scmProvider = flag.String("scm", "github", "SCM platform (github, gitlab)")
	scmBaseURL  = flag.String("scm-base-url", "", "Base URI of the self-hosted SCM instance (optional)")
	threads     = flag.Int("threads", 2, "Parallelization factor for scanning organizations")
	verbose     = flag.Bool("verbose", false, "Enable verbose logging")
	config      = flag.String("config", analyze.CONFIG_PATH, "Path to the configuration file")
	version     = "development"
	commit      = "none"
	date        = "unknown"
)

func main() {
	// Parse flags.
	flag.Usage = usage
	flag.Parse()

	// Ensure the command is correct.
	args := flag.Args()
	if len(args) < 1 {
		usage()
	}

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if *verbose {
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

	err := run(ctx, args)
	if err != nil {
		log.Error().Err(err).Msg("")
		os.Exit(exitCodeErr)
	}
}

func run(ctx context.Context, args []string) error {
	command := args[0]
	if command == "version" {
		fmt.Printf("Version: %s\nCommit: %s\nBuilt At: %s\n", version, commit, date)
		return nil
	}
	if len(args) != 2 {
		usage()
	}
	scmToken := getToken()
	scmClient, err := scm.NewScmClient(ctx, *scmProvider, *scmBaseURL, scmToken, command)
	if err != nil {
		return fmt.Errorf("failed to create SCM client: %w", err)
	}

	formatter := getFormatter()

	gitClient := gitops.NewGitClient(nil)

	analyzer := analyze.NewAnalyzer(scmClient, gitClient, formatter)
	err = analyzer.LoadConfig(*config)
	if err != nil {
		return err
	}

	switch command {
	case "analyze_org":
		return analyzeOrg(ctx, args[1], analyzer)
	case "analyze_repo":
		return analyzeRepo(ctx, args[1], analyzer)
	case "analyze_local":
		return analyzeLocal(ctx, args[1], analyzer, formatter)
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func analyzeOrg(ctx context.Context, org string, analyzer *analyze.Analyzer) error {
	if org == "" {
		return fmt.Errorf("invalid organization name %q", org)
	}

	err := analyzer.AnalyzeOrg(ctx, org, threads)
	if err != nil {
		return fmt.Errorf("failed to analyze org %s: %w", org, err)
	}

	return nil
}

func analyzeRepo(ctx context.Context, repo string, analyzer *analyze.Analyzer) error {
	err := analyzer.AnalyzeRepo(ctx, repo)
	if err != nil {
		return fmt.Errorf("failed to analyze repo %s: %w", repo, err)
	}

	return nil
}

func analyzeLocal(ctx context.Context, repoPath string, analyzer *analyze.Analyzer, formatter analyze.Formatter) error {
	localScmClient, err := local.NewGitSCMClient(ctx, repoPath, nil)
	if err != nil {
		return fmt.Errorf("failed to create local SCM client: %w", err)
	}

	localGitClient := gitops.NewLocalGitClient(nil)
	local := analyze.NewAnalyzer(localScmClient, localGitClient, formatter)
	local.Config = analyzer.Config

	err = local.AnalyzeLocalRepo(ctx, repoPath)
	if err != nil {
		return fmt.Errorf("failed to analyze repoPath %s: %w", repoPath, err)
	}
	return nil
}

func getToken() string {
	ghToken := *token
	if ghToken == "" {
		ghToken = os.Getenv("GH_TOKEN")
	}
	return ghToken
}

func getFormatter() analyze.Formatter {
	format := *format
	switch format {
	case "pretty":
		return &pretty.Format{}
	case "json":
		opaClient, _ := opa.NewOpa()
		return json.NewFormat(opaClient, format, os.Stdout)
	case "sarif":
		return sarif.NewFormat(os.Stdout)
	}
	return &pretty.Format{}
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
