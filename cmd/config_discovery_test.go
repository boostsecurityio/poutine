package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindDefaultConfigFile_NoConfig(t *testing.T) {
	dir := t.TempDir()
	assert.Empty(t, findDefaultConfigFile(dir))
}

func TestFindDefaultConfigFile_RootYml(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".poutine.yml")
	require.NoError(t, os.WriteFile(path, []byte("ignoreForks: true\n"), 0o644))

	assert.Equal(t, path, findDefaultConfigFile(dir))
}

func TestFindDefaultConfigFile_RootYaml(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".poutine.yaml")
	require.NoError(t, os.WriteFile(path, []byte("ignoreForks: true\n"), 0o644))

	assert.Equal(t, path, findDefaultConfigFile(dir))
}

func TestFindDefaultConfigFile_GithubDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, ".github"), 0o755))
	path := filepath.Join(dir, ".github", "poutine.yml")
	require.NoError(t, os.WriteFile(path, []byte("ignoreForks: true\n"), 0o644))

	assert.Equal(t, path, findDefaultConfigFile(dir))
}

func TestFindDefaultConfigFile_RootTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	rootPath := filepath.Join(dir, ".poutine.yml")
	require.NoError(t, os.WriteFile(rootPath, []byte("ignoreForks: true\n"), 0o644))

	require.NoError(t, os.Mkdir(filepath.Join(dir, ".github"), 0o755))
	ghPath := filepath.Join(dir, ".github", "poutine.yml")
	require.NoError(t, os.WriteFile(ghPath, []byte("ignoreForks: false\n"), 0o644))

	assert.Equal(t, rootPath, findDefaultConfigFile(dir),
		"`.poutine.yml` at repo root must take precedence over `.github/poutine.yml`")
}

// TestFindDefaultConfigFile_IgnoresDirectoryNamedLikeConfig ensures that a
// directory (rather than a file) at a candidate path is skipped — otherwise
// a stray `.poutine.yml/` dir would be wrongly reported as the config file.
func TestFindDefaultConfigFile_IgnoresDirectoryNamedLikeConfig(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, ".poutine.yml"), 0o755))

	require.NoError(t, os.Mkdir(filepath.Join(dir, ".github"), 0o755))
	ghPath := filepath.Join(dir, ".github", "poutine.yml")
	require.NoError(t, os.WriteFile(ghPath, []byte("ignoreForks: true\n"), 0o644))

	assert.Equal(t, ghPath, findDefaultConfigFile(dir))
}
