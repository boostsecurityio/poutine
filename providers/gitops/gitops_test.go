package gitops

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/config"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/go-git/go-git/v6/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGitClient(t *testing.T) {
	client := NewGitClient(nil)
	assert.NotNil(t, client)
	assert.NotNil(t, client.repos)
}

func TestCleanup(t *testing.T) {
	client := NewGitClient(nil)

	// Manually insert a repo entry
	client.mu.Lock()
	client.repos["test-key"] = &inMemRepo{
		store: memory.NewStorage(),
	}
	client.mu.Unlock()

	// Verify it exists
	_, err := client.getRepo("test-key")
	require.NoError(t, err)

	// Clean up
	client.Cleanup("test-key")

	// Verify it's gone
	_, err = client.getRepo("test-key")
	assert.Error(t, err)
}

func TestGetRepoNotFound(t *testing.T) {
	client := NewGitClient(nil)
	_, err := client.getRepo("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no in-memory repo found")
}

func TestCommitSHA(t *testing.T) {
	client := NewGitClient(nil)
	expectedHash := plumbing.NewHash("abc123def456abc123def456abc123def456abc1")

	client.mu.Lock()
	client.repos["test"] = &inMemRepo{
		store:   memory.NewStorage(),
		headRef: expectedHash,
	}
	client.mu.Unlock()

	sha, err := client.CommitSHA("test")
	require.NoError(t, err)
	assert.Equal(t, expectedHash.String(), sha)
}

func TestLastCommitDate(t *testing.T) {
	client := NewGitClient(nil)
	store := memory.NewStorage()

	// Create a commit object in memory
	commit := &object.Commit{
		Author:    object.Signature{When: fixedTime()},
		Committer: object.Signature{When: fixedTime()},
		Message:   "test commit",
	}
	obj := store.NewEncodedObject()
	err := commit.Encode(obj)
	require.NoError(t, err)
	hash, err := store.SetEncodedObject(obj)
	require.NoError(t, err)

	client.mu.Lock()
	client.repos["test"] = &inMemRepo{
		store:   store,
		headRef: hash,
	}
	client.mu.Unlock()

	date, err := client.LastCommitDate(context.Background(), "test")
	require.NoError(t, err)
	assert.True(t, fixedTime().Equal(date), "expected %v, got %v", fixedTime(), date)
}

func TestBlobMatches(t *testing.T) {
	client := NewGitClient(nil)
	store := memory.NewStorage()

	// Create a blob object
	blobContent := []byte("1ccc2c4c-1791-4c14-ac2a-688173af4f65")
	obj := store.NewEncodedObject()
	obj.SetType(plumbing.BlobObject)
	obj.SetSize(int64(len(blobContent)))
	w, err := obj.Writer()
	require.NoError(t, err)
	_, err = w.Write(blobContent)
	require.NoError(t, err)
	err = w.Close()
	require.NoError(t, err)
	hash, err := store.SetEncodedObject(obj)
	require.NoError(t, err)

	client.mu.Lock()
	client.repos["test"] = &inMemRepo{store: store}
	client.mu.Unlock()

	tests := []struct {
		name      string
		regex     *regexp.Regexp
		wantMatch bool
	}{
		{"match found", regexp.MustCompile(`-4c14-ac2a`), true},
		{"no match", regexp.MustCompile(`-918dasd0-ac2a`), false},
		{"complex match", regexp.MustCompile(`-.*-ac2a`), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, content, err := client.BlobMatches(context.Background(), "test", hash.String(), tt.regex)
			require.NoError(t, err)
			assert.Equal(t, tt.wantMatch, match)
			assert.Equal(t, blobContent, content)
		})
	}
}

func TestListFilesEmpty(t *testing.T) {
	client := NewGitClient(nil)
	_, err := client.ListFiles("nonexistent", []string{".yml"})
	assert.Error(t, err)
}

func TestAuthForToken(t *testing.T) {
	assert.Nil(t, authForToken(""))
	auth := authForToken("mytoken")
	assert.NotNil(t, auth)
}

func TestClassifyFetchError(t *testing.T) {
	require.NoError(t, classifyFetchError(nil))

	err := classifyFetchError(ErrRepoNotReachable)
	assert.Error(t, err)
}

func TestResolveRemoteRefBareTagPrefersTag(t *testing.T) {
	remotePath, _ := createTestRemoteRepo(t)
	repo := createTestClientRepo(t, remotePath)

	resolved, err := resolveRemoteRef(repo, remotePath, "", "v2")
	require.NoError(t, err)
	assert.Equal(t, resolvedRefTag, resolved.kind)
	assert.Equal(t, "refs/tags/v2", resolved.fullRef)
	assert.Equal(t, plumbing.ReferenceName("refs/poutine/target"), resolved.localRef)
}

func TestResolveRemoteRefExplicitBranch(t *testing.T) {
	remotePath, _ := createTestRemoteRepo(t)
	repo := createTestClientRepo(t, remotePath)

	resolved, err := resolveRemoteRef(repo, remotePath, "", "refs/heads/release")
	require.NoError(t, err)
	assert.Equal(t, resolvedRefBranch, resolved.kind)
	assert.Equal(t, "refs/heads/release", resolved.fullRef)
	assert.Equal(t, plumbing.ReferenceName("refs/remotes/origin/release"), resolved.localRef)
}

func TestResolveFetchedRefToCommitPeelsAnnotatedTag(t *testing.T) {
	remotePath, refs := createTestRemoteRepo(t)
	repo, err := gogit.PlainOpen(remotePath)
	require.NoError(t, err)

	hash, err := resolveFetchedRefToCommit(repo.Storer, repo, plumbing.ReferenceName("refs/tags/v2"))
	require.NoError(t, err)
	assert.Equal(t, refs.annotatedTagCommit, hash)
}

func TestFetchResolvedRefResolvesBareAndExplicitTags(t *testing.T) {
	remotePath, refs := createTestRemoteRepo(t)
	ctx := context.Background()

	repo := createTestClientRepo(t, remotePath)
	resolved, err := resolveRemoteRef(repo, remotePath, "", "v2")
	require.NoError(t, err)
	err = fetchResolvedRef(ctx, repo, &gogit.FetchOptions{
		RemoteName: "origin",
		Depth:      1,
		Tags:       gogit.NoTags,
	}, resolved)
	require.NoError(t, err)
	sha, err := resolveFetchedRefToCommit(repo.Storer, repo, resolved.localRef)
	require.NoError(t, err)
	assert.Equal(t, refs.annotatedTagCommit, sha)

	repo = createTestClientRepo(t, remotePath)
	resolved, err = resolveRemoteRef(repo, remotePath, "", "refs/tags/v2")
	require.NoError(t, err)
	err = fetchResolvedRef(ctx, repo, &gogit.FetchOptions{
		RemoteName: "origin",
		Depth:      1,
		Tags:       gogit.NoTags,
	}, resolved)
	require.NoError(t, err)
	sha, err = resolveFetchedRefToCommit(repo.Storer, repo, resolved.localRef)
	require.NoError(t, err)
	assert.Equal(t, refs.annotatedTagCommit, sha)
}

type testRemoteRefs struct {
	annotatedTagCommit plumbing.Hash
	releaseCommit      plumbing.Hash
}

func createTestRemoteRepo(t *testing.T) (string, testRemoteRefs) {
	t.Helper()

	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	require.NoError(t, err)

	writeRepoFile(t, dir, "action.yml", "name: first\n")
	firstCommit := commitAll(t, repo, "first commit")

	writeRepoFile(t, dir, "action.yml", "name: release\n")
	releaseCommit := commitAll(t, repo, "release commit")

	err = repo.Storer.SetReference(plumbing.NewHashReference(plumbing.ReferenceName("refs/heads/release"), releaseCommit))
	require.NoError(t, err)

	_, err = repo.CreateTag("v2", firstCommit, &gogit.CreateTagOptions{
		Tagger:  &object.Signature{Name: "test", Email: "test@example.com", When: fixedTime()},
		Message: "annotated v2",
	})
	require.NoError(t, err)

	err = repo.Storer.SetReference(plumbing.NewHashReference(plumbing.ReferenceName("refs/heads/v2"), releaseCommit))
	require.NoError(t, err)

	return dir, testRemoteRefs{
		annotatedTagCommit: firstCommit,
		releaseCommit:      releaseCommit,
	}
}

func createTestClientRepo(t *testing.T, remotePath string) *gogit.Repository {
	t.Helper()

	store := memory.NewStorage()
	repo, err := gogit.Init(store, nil)
	require.NoError(t, err)
	_, err = repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{remotePath},
	})
	require.NoError(t, err)
	return repo
}

func writeRepoFile(t *testing.T, repoDir, name, content string) {
	t.Helper()
	err := os.WriteFile(filepath.Join(repoDir, name), []byte(content), 0o644)
	require.NoError(t, err)
}

func commitAll(t *testing.T, repo *gogit.Repository, message string) plumbing.Hash {
	t.Helper()

	wt, err := repo.Worktree()
	require.NoError(t, err)
	_, err = wt.Add(".")
	require.NoError(t, err)

	hash, err := wt.Commit(message, &gogit.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: fixedTime()},
	})
	require.NoError(t, err)
	return hash
}

func fixedTime() time.Time {
	return time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
}
