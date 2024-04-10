package gitops

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type MockGitCommand struct {
	MockRun      func(cmd string, args []string, dir string) ([]byte, error)
	MockReadFile func(path string) ([]byte, error)
}

func (m MockGitCommand) Run(ctx context.Context, cmd string, args []string, dir string) ([]byte, error) {
	return m.MockRun(cmd, args, dir)
}

func (m MockGitCommand) ReadFile(path string) ([]byte, error) {
	return m.MockReadFile(path)
}

func TestCommitSHA(t *testing.T) {
	expectedSHA := "abc123"

	mockCommand := &MockGitCommand{
		MockRun: func(cmd string, args []string, dir string) ([]byte, error) {
			// Simulate reading the SHA from a .git/refs/heads/target file
			return []byte(expectedSHA), nil
		},
	}

	client := &GitClient{Command: mockCommand}

	sha, err := client.CommitSHA("/path/to/repo")
	if err != nil {
		t.Errorf("commitSHA returned an error: %v", err)
	}
	assert.Equal(t, expectedSHA, sha, "expected SHA to be '%s', got '%s'", expectedSHA, sha)
}

func TestLastCommitDate(t *testing.T) {
	expectedDate := time.Unix(1609459200, 0)
	mockCommander := &MockGitCommand{
		MockRun: func(cmd string, args []string, dir string) ([]byte, error) {
			return []byte("1609459200"), nil
		},
	}

	client := &GitClient{Command: mockCommander}

	date, err := client.LastCommitDate(context.TODO(), "/path/to/repo")
	if err != nil {
		t.Errorf("lastCommitDate returned an error: %v", err)
	}
	if !date.Equal(expectedDate) {
		t.Errorf("Expected date '%v', got '%v'", expectedDate, date)
	}
}

func TestClone(t *testing.T) {
	clonePath := "/path/to/repo"
	url := "https://token@github.com/example/repo.git"
	credentialHelperScript := "!f() { test \"$1\" = get && echo \"password=$POUTINE_GIT_ASKPASS_TOKEN\"; }; f"
	token := "RANDOM_SECRET_TOKEN"
	ref := "main"

	var executedCommands []string
	mockCommand := &MockGitCommand{
		MockRun: func(cmd string, args []string, dir string) ([]byte, error) {
			executedCommands = append(executedCommands, fmt.Sprintf("%s %s", cmd, strings.Join(args, " ")))
			return nil, nil
		},
	}

	client := &GitClient{Command: mockCommand}

	err := client.Clone(context.TODO(), clonePath, url, token, ref)
	if err != nil {
		t.Fatalf("clone failed: %v", err)
	}

	expectedCommands := []string{
		"git init --quiet",
		"git remote add origin https://token@github.com/example/repo.git", // Assuming url variable equals "https://github.com/example/repo.git"
		"git config credential.helper " + credentialHelperScript,
		"git config submodule.recurse false",
		"git config core.sparseCheckout true",
		"git config index.sparse true",
		"git sparse-checkout init --sparse-index",
		"git sparse-checkout set **/*.yml **/*.yaml",
		"git fetch --quiet --no-tags --depth 1 --filter=blob:none origin main", // Assuming ref variable equals "main"
		"git checkout --quiet -b target FETCH_HEAD",
	}

	if len(executedCommands) != len(expectedCommands) {
		t.Fatalf("expected %d commands to be executed, got %d", len(expectedCommands), len(executedCommands))
	}

	for i, cmd := range executedCommands {
		if cmd != expectedCommands[i] {
			t.Errorf("expected command %d to be '%s', got '%s'", i, expectedCommands[i], cmd)
		}
	}
}
