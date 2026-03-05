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
	assert.ErrorIs(t, ErrViolationsFound, ErrViolationsFound)
}

func TestExitCodeViolations(t *testing.T) {
	assert.Equal(t, 10, exitCodeViolations)
}

func TestFailOnViolationFlag(t *testing.T) {
	flag := RootCmd.PersistentFlags().Lookup("fail-on-violation")
	require.NotNil(t, flag, "--fail-on-violation flag should be registered")
	assert.Equal(t, "false", flag.DefValue, "--fail-on-violation should default to false")
}

func TestFailOnViolationLogic(t *testing.T) {
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

	t.Run("failOnViolation=false with findings returns no error", func(t *testing.T) {
		// Simulate the logic in command handlers
		fov := false
		pkg := pkgWithFindings
		var err error
		if fov && pkg != nil && len(pkg.FindingsResults.Findings) > 0 {
			err = ErrViolationsFound
		}
		assert.NoError(t, err)
	})

	t.Run("failOnViolation=true with findings returns ErrViolationsFound", func(t *testing.T) {
		fov := true
		pkg := pkgWithFindings
		var err error
		if fov && pkg != nil && len(pkg.FindingsResults.Findings) > 0 {
			err = ErrViolationsFound
		}
		assert.ErrorIs(t, err, ErrViolationsFound)
	})

	t.Run("failOnViolation=true with no findings returns no error", func(t *testing.T) {
		fov := true
		pkg := pkgNoFindings
		var err error
		if fov && pkg != nil && len(pkg.FindingsResults.Findings) > 0 {
			err = ErrViolationsFound
		}
		assert.NoError(t, err)
	})

	t.Run("failOnViolation=true with nil result returns no error", func(t *testing.T) {
		fov := true
		var pkg *models.PackageInsights
		var err error
		if fov && pkg != nil && len(pkg.FindingsResults.Findings) > 0 {
			err = ErrViolationsFound
		}
		assert.NoError(t, err)
	})
}

func TestFailOnViolationOrgLogic(t *testing.T) {
	pkgWithFindings := &models.PackageInsights{
		FindingsResults: results.FindingsResult{
			Findings: []results.Finding{
				{RuleId: "injection", Purl: "pkg:github/example/repo"},
			},
		},
	}
	pkgNoFindings := &models.PackageInsights{}

	t.Run("failOnViolation=true with findings in org returns ErrViolationsFound", func(t *testing.T) {
		fov := true
		pkgs := []*models.PackageInsights{pkgNoFindings, pkgWithFindings}
		var err error
		if fov {
			for _, pkg := range pkgs {
				if pkg != nil && len(pkg.FindingsResults.Findings) > 0 {
					err = ErrViolationsFound
					break
				}
			}
		}
		assert.ErrorIs(t, err, ErrViolationsFound)
	})

	t.Run("failOnViolation=true with no findings in org returns no error", func(t *testing.T) {
		fov := true
		pkgs := []*models.PackageInsights{pkgNoFindings, pkgNoFindings}
		var err error
		if fov {
			for _, pkg := range pkgs {
				if pkg != nil && len(pkg.FindingsResults.Findings) > 0 {
					err = ErrViolationsFound
					break
				}
			}
		}
		assert.NoError(t, err)
	})
}
