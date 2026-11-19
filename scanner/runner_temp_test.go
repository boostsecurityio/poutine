package scanner

import (
	"context"
	"testing"

	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunnerTempScriptNotFlaggedAsUntrustedCheckoutExec(t *testing.T) {
	o, err := opa.NewOpa(context.TODO(), &models.Config{
		Include: []models.ConfigInclude{},
	})
	require.NoError(t, err)

	i := NewInventory(o, nil, "", "")
	pkg := &models.PackageInsights{
		Purl:          "pkg:github/org/owner",
		SourceGitRepo: "org/owner",
		SourceGitRef:  "main",
	}
	require.NoError(t, pkg.NormalizePurl())

	scannedPackage, err := i.ScanPackage(context.Background(), *pkg, "testdata")
	require.NoError(t, err)

	for _, finding := range scannedPackage.FindingsResults.Findings {
		if finding.RuleId != "untrusted_checkout_exec" {
			continue
		}
		assert.NotEqual(
			t,
			".github/workflows/runner_temp_script.yml",
			finding.Meta.Path,
			"bash scripts under RUNNER_TEMP should not be treated as checked-out workspace code",
		)
	}
}
