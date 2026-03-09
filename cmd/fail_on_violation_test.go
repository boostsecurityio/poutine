package cmd

import (
	"testing"

	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/results"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrViolationsFound(t *testing.T) {
	require.EqualError(t, ErrViolationsFound, "poutine: violations found")
	assert.Implements(t, (*error)(nil), ErrViolationsFound)
}

func TestExitCodeViolations(t *testing.T) {
	assert.Equal(t, 10, exitCodeViolations)
}

func TestFailOnViolationFlag(t *testing.T) {
	flag := RootCmd.PersistentFlags().Lookup("fail-on-violation")
	require.NotNil(t, flag, "--fail-on-violation flag should be registered")
	assert.Equal(t, "false", flag.DefValue, "--fail-on-violation should default to false")
}

func TestCheckViolations(t *testing.T) {
	pkgWithFindings := &models.PackageInsights{
		FindingsResults: results.FindingsResult{
			Findings: []results.Finding{
				{RuleId: "injection", Purl: "pkg:github/example/repo"},
			},
		},
	}
	pkgNoFindings := &models.PackageInsights{
		FindingsResults: results.FindingsResult{
			Findings: []results.Finding{},
		},
	}

	t.Run("returns nil when failOnViolation is false", func(t *testing.T) {
		failOnViolation = false
		defer func() { failOnViolation = false }()

		assert.NoError(t, checkViolations(pkgWithFindings))
	})

	t.Run("returns ErrViolationsFound when findings exist", func(t *testing.T) {
		failOnViolation = true
		defer func() { failOnViolation = false }()

		assert.ErrorIs(t, checkViolations(pkgWithFindings), ErrViolationsFound)
	})

	t.Run("returns nil when no findings", func(t *testing.T) {
		failOnViolation = true
		defer func() { failOnViolation = false }()

		assert.NoError(t, checkViolations(pkgNoFindings))
	})

	t.Run("returns nil for nil package", func(t *testing.T) {
		failOnViolation = true
		defer func() { failOnViolation = false }()

		assert.NoError(t, checkViolations(nil))
	})

	t.Run("returns nil when called with no args", func(t *testing.T) {
		failOnViolation = true
		defer func() { failOnViolation = false }()

		assert.NoError(t, checkViolations())
	})
}

func TestCheckViolationsOrg(t *testing.T) {
	pkgWithFindings := &models.PackageInsights{
		FindingsResults: results.FindingsResult{
			Findings: []results.Finding{
				{RuleId: "injection", Purl: "pkg:github/example/repo"},
			},
		},
	}
	pkgNoFindings := &models.PackageInsights{}

	t.Run("returns ErrViolationsFound when any package has findings", func(t *testing.T) {
		failOnViolation = true
		defer func() { failOnViolation = false }()

		err := checkViolations(pkgNoFindings, pkgWithFindings)
		assert.ErrorIs(t, err, ErrViolationsFound)
	})

	t.Run("returns nil when no packages have findings", func(t *testing.T) {
		failOnViolation = true
		defer func() { failOnViolation = false }()

		err := checkViolations(pkgNoFindings, pkgNoFindings)
		assert.NoError(t, err)
	})
}
