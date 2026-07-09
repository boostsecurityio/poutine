//go:build checkout_unsafe_shas
// +build checkout_unsafe_shas

package opa

// Regenerates opa/rego/external/checkout_unsafe.rego — the frozen set of actions/checkout
// commit SHAs that LACK the safe-default fix (GitHub's allow-unsafe-pr-checkout change).
//
// Run with:
//
//	make update-checkout-shas
//	# or: go test -tags checkout_unsafe_shas -run TestPopulateCheckoutUnsafeShas -timeout 10m ./opa
//
// A SHA is SAFE iff it is (or descends from) a release-line fix commit. Today only the v7
// line is fixed (v7.0.0 = 9c091bb…); the v4/v5/v6 backports land on/after 2026-07-16 — add
// their fix-commit SHAs to fixCommits below and re-run once they are published. Because this
// is a default-ALLOW (bad) set, it is only complete/sound once every supported line is fixed:
// freeze it AFTER the backports so no vulnerable commit is created after the freeze.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	checkoutRepo      = "https://github.com/actions/checkout.git"
	checkoutRegoFile  = "rego/external/checkout_unsafe.rego"
	v7FixSHA          = "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0" // actions/checkout v7.0.0
	expectMinUniverse = 200
	expectMaxUniverse = 600
)

// fixCommits are the release-line fix commits. Any commit that is one of these or descends
// from one is SAFE (enforces the safe default). Add the v4/v5/v6 backport SHAs here once
// GitHub publishes them (on/after 2026-07-16).
var fixCommits = []string{
	v7FixSHA,
	// "<v4 backport fix SHA>",
	// "<v5 backport fix SHA>",
	// "<v6 backport fix SHA>",
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	require.NoError(t, err, "git %s", strings.Join(args, " "))
	return strings.TrimSpace(string(out))
}

func gitOK(dir string, args ...string) bool {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	return cmd.Run() == nil
}

func TestPopulateCheckoutUnsafeShas(t *testing.T) {
	tmp, err := os.MkdirTemp("", "checkout-shas")
	require.NoError(t, err)
	defer os.RemoveAll(tmp)

	// Shallow-by-blob clone of the commit graph only (no file contents needed).
	git(t, tmp, "init", "-q", "repo")
	repo := tmp + "/repo"
	git(t, repo, "remote", "add", "origin", checkoutRepo)
	git(t, repo, "fetch", "-q", "--filter=blob:none", "origin",
		"refs/heads/main:refs/remotes/origin/main",
		"refs/heads/releases/*:refs/remotes/origin/releases/*",
		"refs/tags/*:refs/tags/*",
	)

	// Sanity: v7.0.0 resolves to the documented fix commit.
	require.Equal(t, v7FixSHA, git(t, repo, "rev-parse", "v7.0.0^{commit}"),
		"v7.0.0 no longer resolves to the expected fix commit")

	// Universe = every commit reachable from main + release branches + all tags.
	listCmd := exec.Command("git", "for-each-ref", "--format=%(refname)",
		"refs/remotes/origin/main", "refs/remotes/origin/releases", "refs/tags")
	listCmd.Dir = repo
	refs, err := listCmd.Output()
	require.NoError(t, err)

	revCmd := exec.Command("git", "rev-list", "--stdin")
	revCmd.Dir = repo
	revCmd.Stdin = strings.NewReader(string(refs))
	universeOut, err := revCmd.Output()
	require.NoError(t, err)
	universe := strings.Fields(string(universeOut))
	require.GreaterOrEqual(t, len(universe), expectMinUniverse, "universe too small — partial fetch?")
	require.LessOrEqual(t, len(universe), expectMaxUniverse, "universe too large — unexpected refs?")

	// Vulnerable = not a descendant of (or equal to) any fix commit.
	var vulnerable []string
	for _, c := range universe {
		safe := false
		for _, fix := range fixCommits {
			if gitOK(repo, "merge-base", "--is-ancestor", fix, c) {
				safe = true
				break
			}
		}
		if !safe {
			vulnerable = append(vulnerable, strings.ToLower(c))
		}
	}
	sort.Strings(vulnerable)

	// Anti-gap assertions: the freeze must not silently drop or over-include.
	vulnSet := map[string]bool{}
	for _, s := range vulnerable {
		vulnSet[s] = true
	}
	assert.False(t, vulnSet[v7FixSHA], "v7.0.0 fix commit must NOT be in the vulnerable set")
	for _, tag := range []string{"v1.0.0", "v2.0.0", "v3.0.0"} {
		sha := strings.ToLower(git(t, repo, "rev-parse", tag+"^{commit}"))
		assert.True(t, vulnSet[sha], "%s (%s) must be in the vulnerable set", tag, sha)
	}
	assert.Greater(t, len(vulnerable), 100, "suspiciously few vulnerable SHAs")

	sum := sha256.Sum256([]byte(strings.Join(vulnerable, "\n")))
	t.Logf("vulnerable_shas: %d entries, universe %d, sha256 %s",
		len(vulnerable), len(universe), hex.EncodeToString(sum[:]))

	writeCheckoutUnsafeRego(t, vulnerable)
}

func writeCheckoutUnsafeRego(t *testing.T, vulnerable []string) {
	t.Helper()
	content, err := os.ReadFile(checkoutRegoFile)
	require.NoError(t, err)

	var b strings.Builder
	b.WriteString("vulnerable_shas := {\n")
	for _, s := range vulnerable {
		fmt.Fprintf(&b, "\t%q,\n", s)
	}
	b.WriteString("}")

	re := regexp.MustCompile(`(?s)vulnerable_shas := \{.*?\n}`)
	updated := re.ReplaceAllString(string(content), b.String())
	require.Contains(t, updated, "vulnerable_shas := {", "replacement anchor not found")

	require.NoError(t, os.WriteFile(checkoutRegoFile, []byte(updated), 0644))
	t.Logf("wrote %s — run `opa fmt -w %s`", checkoutRegoFile, checkoutRegoFile)
}
