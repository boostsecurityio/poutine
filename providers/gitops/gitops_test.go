package gitops

import (
	"context"
	"regexp"
	"testing"
	"time"

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

func fixedTime() time.Time {
	return time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
}
