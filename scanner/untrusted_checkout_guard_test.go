package scanner

import (
	"context"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain pins the scan clock for the scanner package so date-sensitive rules — namely the
// actions/checkout v4/v5/v6 backport gate in untrusted_checkout_exec — stay deterministic
// regardless of when the suite runs (it must not start failing on 2026-07-16). Tests that need
// a specific instant override inventory.now directly (see firedCheckoutKeys).
func TestMain(m *testing.M) {
	if os.Getenv("POUTINE_SCAN_TIME") == "" {
		_ = os.Setenv("POUTINE_SCAN_TIME", "2026-06-19T00:00:00Z")
	}
	os.Exit(m.Run())
}

// firedCheckoutKeys scans testdata_checkout with a pinned scan time and returns the set of
// "<path>::<job>" keys that produced an untrusted_checkout_exec finding.
func firedCheckoutKeys(t *testing.T, scanTime string) []string {
	t.Helper()
	o, err := opa.NewOpa(context.TODO(), &models.Config{Include: []models.ConfigInclude{}})
	require.NoError(t, err)

	i := NewInventory(o, nil, "github", "")
	at, err := time.Parse(time.RFC3339, scanTime)
	require.NoError(t, err)
	i.now = func() time.Time { return at }

	pkg := &models.PackageInsights{Purl: "pkg:github/org/owner", SourceGitRepo: "org/owner", SourceGitRef: "main"}
	require.NoError(t, pkg.NormalizePurl())

	scanned, err := i.ScanPackage(context.Background(), *pkg, "testdata_checkout")
	require.NoError(t, err)

	seen := map[string]bool{}
	for _, f := range scanned.FindingsResults.Findings {
		if f.RuleId == "untrusted_checkout_exec" {
			seen[f.Meta.Path+"::"+f.Meta.Job] = true
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestUntrustedCheckoutGuard(t *testing.T) {
	const wf = ".github/workflows/"

	// Date-independent expectations (true regardless of the backport date).
	alwaysFires := []string{
		wf + "prt_matrix.yml::unsafe_true", // allow-unsafe-pr-checkout: true
		wf + "prt_matrix.yml::unsafe_expr", // allow-unsafe-pr-checkout: ${{ expr }} => possibly true
		wf + "prt_matrix.yml::old_v3",      // v3 never gets the fix
		wf + "prt_matrix.yml::vuln_sha",    // SHA in the frozen vulnerable set
		wf + "multi_event.yml::build",      // issue_comment is not guard-covered
		wf + "gh_pr_checkout.yml::build",   // gh pr checkout never suppressed
		wf + "git_vectors.yml::samestep",   // git fetch pull/N/head + build in one step
		wf + "git_vectors.yml::headsha",    // git checkout of head.sha
		wf + "wr_child_comment.yml::build", // workflow_run whose parent is issue_comment
	}
	neverFires := []string{
		wf + "prt_matrix.yml::safe_v7",  // v7 fixed
		wf + "prt_matrix.yml::safe_sha", // v7.0.0 SHA, not in vulnerable set
		wf + "git_benign.yml::build",    // benign git, no PR ref
		wf + "wr_child_pr.yml::build",   // workflow_run whose parent is pull_request (covered)
	}

	t.Run("before backport date (v4/v5/v6 still vulnerable)", func(t *testing.T) {
		fired := firedCheckoutKeys(t, "2026-06-19T00:00:00Z")
		want := append(append([]string{}, alwaysFires...), wf+"prt_matrix.yml::v4_gated")
		assert.ElementsMatch(t, want, fired)
		for _, k := range neverFires {
			assert.NotContains(t, fired, k)
		}
	})

	t.Run("after backport date (v4/v5/v6 auto-updated)", func(t *testing.T) {
		fired := firedCheckoutKeys(t, "2026-08-01T00:00:00Z")
		assert.ElementsMatch(t, alwaysFires, fired) // v4_gated now suppressed
		assert.NotContains(t, fired, wf+"prt_matrix.yml::v4_gated")
	})
}
