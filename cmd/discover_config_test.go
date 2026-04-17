package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// chdir switches the working directory for the duration of the test and
// restores it afterwards.
func chdir(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() {
		_ = os.Chdir(prev)
	})
}

func TestDiscoverConfigFile_NoFile(t *testing.T) {
	chdir(t, t.TempDir())
	assert.Equal(t, "", discoverConfigFile())
}

func TestDiscoverConfigFile_RootTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".poutine.yml"), []byte("allowedRules:\n  - a\n"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".github"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".github", "poutine.yml"), []byte("allowedRules:\n  - b\n"), 0o644))
	chdir(t, dir)

	assert.Equal(t, ".poutine.yml", discoverConfigFile())
}

func TestDiscoverConfigFile_GithubFallback(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".github"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".github", "poutine.yml"), []byte("allowedRules:\n  - b\n"), 0o644))
	chdir(t, dir)

	assert.Equal(t, filepath.Join(".github", "poutine.yml"), discoverConfigFile())
}

func TestDiscoverConfigFile_IgnoresDirectories(t *testing.T) {
	dir := t.TempDir()
	// .poutine.yml exists as a directory; it must be ignored.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".poutine.yml"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".github"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".github", "poutine.yaml"), []byte("allowedRules:\n  - b\n"), 0o644))
	chdir(t, dir)

	assert.Equal(t, filepath.Join(".github", "poutine.yaml"), discoverConfigFile())
}
