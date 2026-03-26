package snapshot_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"sort"
	"testing"

	"github.com/boostsecurityio/poutine/analyze"
	jsonformatter "github.com/boostsecurityio/poutine/formatters/json"
	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/boostsecurityio/poutine/providers/gitops"
	"github.com/boostsecurityio/poutine/providers/scm"
	"github.com/boostsecurityio/poutine/results"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func setupAnalyzer(t *testing.T, command string, buf *bytes.Buffer) *analyze.Analyzer {
	t.Helper()

	token := os.Getenv("GH_TOKEN")
	if token == "" {
		t.Skip("GH_TOKEN not set, skipping snapshot test")
	}

	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	ctx := context.Background()

	scmClient, err := scm.NewScmClient(ctx, "github", "", token, command)
	require.NoError(t, err)

	config := models.DefaultConfig()
	config.Quiet = true

	opaClient, err := opa.NewOpa(ctx, config)
	require.NoError(t, err)

	formatter := jsonformatter.NewFormat(opaClient, "json", buf)
	gitClient := gitops.NewGitClient(nil)

	return analyze.NewAnalyzer(scmClient, gitClient, formatter, config, opaClient)
}

// normalizeJSON sorts findings for stable ordering and pretty-prints.
func normalizeJSON(t *testing.T, data []byte) string {
	t.Helper()

	var result results.FindingsResult
	require.NoError(t, json.Unmarshal(data, &result))

	sort.Slice(result.Findings, func(i, j int) bool {
		a, b := result.Findings[i], result.Findings[j]
		if a.RuleId != b.RuleId {
			return a.RuleId < b.RuleId
		}
		if a.Purl != b.Purl {
			return a.Purl < b.Purl
		}
		if a.Meta.Path != b.Meta.Path {
			return a.Meta.Path < b.Meta.Path
		}
		if a.Meta.Line != b.Meta.Line {
			return a.Meta.Line < b.Meta.Line
		}
		if a.Meta.Details != b.Meta.Details {
			return a.Meta.Details < b.Meta.Details
		}
		return a.Meta.Job < b.Meta.Job
	})

	normalized, err := json.MarshalIndent(result, "", "  ")
	require.NoError(t, err)
	return string(normalized)
}

func TestSnapshotAnalyzeOrg(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping snapshot test in short mode")
	}

	var buf bytes.Buffer
	analyzer := setupAnalyzer(t, "analyze_org", &buf)
	ctx := context.Background()
	threads := 2

	packages, err := analyzer.AnalyzeOrg(ctx, "messypoutine", &threads)
	require.NoError(t, err)
	require.NotEmpty(t, packages)

	buf.Reset()
	err = analyzer.Formatter.Format(ctx, packages)
	require.NoError(t, err)

	snaps.MatchJSON(t, normalizeJSON(t, buf.Bytes()))
}

func TestSnapshotAnalyzeRepo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping snapshot test in short mode")
	}

	var buf bytes.Buffer
	analyzer := setupAnalyzer(t, "analyze_repo", &buf)
	ctx := context.Background()

	pkg, err := analyzer.AnalyzeRepo(ctx, "messypoutine/gravy-overflow", "HEAD")
	require.NoError(t, err)
	require.NotNil(t, pkg)

	buf.Reset()
	err = analyzer.Formatter.Format(ctx, []*models.PackageInsights{pkg})
	require.NoError(t, err)

	snaps.MatchJSON(t, normalizeJSON(t, buf.Bytes()))
}
