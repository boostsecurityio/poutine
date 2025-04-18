package gitops

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/boostsecurityio/poutine/models"
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

func TestGitClient_BlobMatches(t *testing.T) {
	mockCommand := &MockGitCommand{
		MockRun: func(cmd string, args []string, dir string) ([]byte, error) {
			for _, arg := range args {
				cmd += " " + arg
			}

			switch cmd {
			case "git cat-file blob ba50d9b9d4567fd9cc6229af2670b5b42434b852":
				return []byte(`1ccc2c4c-1791-4c14-ac2a-688173af4f65`), nil
			}
			return nil, nil
		},
	}

	client := &GitClient{Command: mockCommand}
	ctx := context.Background()

	type Want struct {
		match  bool
		result string
		err    bool
	}

	expected := []struct {
		name    string
		blobSha string
		want    Want
		regex   *regexp.Regexp
	}{
		{
			name:    "Simple regex with match",
			blobSha: "ba50d9b9d4567fd9cc6229af2670b5b42434b852",
			want: Want{
				match:  true,
				result: "1ccc2c4c-1791-4c14-ac2a-688173af4f65",
				err:    false,
			},
			regex: regexp.MustCompile(`-4c14-ac2a`),
		},
		{
			name:    "Simple regex without match",
			blobSha: "ba50d9b9d4567fd9cc6229af2670b5b42434b852",
			want: Want{
				match:  false,
				result: "1ccc2c4c-1791-4c14-ac2a-688173af4f65",
				err:    false,
			},
			regex: regexp.MustCompile(`-918dasd0-ac2a`),
		},
		{
			name:    "Complex regex with match",
			blobSha: "ba50d9b9d4567fd9cc6229af2670b5b42434b852",
			want: Want{
				match:  true,
				result: "1ccc2c4c-1791-4c14-ac2a-688173af4f65",
				err:    false,
			},
			regex: regexp.MustCompile(`-.*-ac2a`),
		},
	}

	for _, tt := range expected {
		t.Run(tt.name, func(t *testing.T) {
			match, content, err := client.BlobMatches(ctx, "/tmp/poutine", tt.blobSha, tt.regex)
			if (err != nil) != tt.want.err {
				t.Error("got unwanted error")
				return
			}
			if match != tt.want.match {
				t.Error("should match")
				return
			}
			if !bytes.Equal(content, []byte(tt.want.result)) {
				t.Errorf("wrong content: got = %s, want = %s", string(content), tt.want.result)
			}

		})

	}
}

func TestGitClient_GetUniqWorkflowsBranches(t *testing.T) {
	mockCommand := &MockGitCommand{
		MockRun: func(cmd string, args []string, dir string) ([]byte, error) {
			for _, arg := range args {
				cmd += " " + arg
			}

			switch cmd {
			case "git ls-remote --heads":
				return []byte(`From https://token@github.com/Owner/Repo
c5f913e1af29f6f41b866b4ed0ef1bd2618d7d8f	refs/heads/main
f44e85d85347913cfb29732653b6dcfb090b00b9	refs/heads/a
c566b2dbbb664924bc0a917534311f822cba25d6	refs/heads/b
f44e85d85347913cfb29732653b6dcfb090b00b9	refs/heads/a2`), nil
			case "git ls-tree -r origin/main --full-tree .github/workflows":
				return []byte(`100644 blob ba50d9b9d4567fd9cc6229af2670b5b42434b852	.github/workflows/a.yml
100644 blob f1981e8f197e3a2e48976f7018a2cd00e84dc203	.github/workflows/b.yml
100644 blob ba50d9b9d4567fd9cc6229af2670b5b42434b852	.github/workflows/a2.yml
100644 blob 7991dd70e685c4f8e532620d3865bd3e2ad4fce4	.github/workflows/c.yml`), nil
			case "git ls-tree -r origin/a --full-tree .github/workflows":
				return []byte(`100644 blob ba50d9b9d4567fd9cc6229af2670b5b42434b852	.github/workflows/a.yml`), nil
			case "git ls-tree -r origin/a2 --full-tree .github/workflows":
				return []byte(`100644 blob ba50d9b9d4567fd9cc6229af2670b5b42434b852	.github/workflows/a.yml`), nil
			case "git ls-tree -r origin/b --full-tree .github/workflows":
				return []byte(`100644 blob 3c837e3a085bd40eb37cc7c3caef56df375fcba4	.github/workflows/a.yml`), nil
			}
			return nil, nil
		},
	}

	client := &GitClient{Command: mockCommand}
	ctx := context.Background()
	expected := map[string][]models.BranchInfo{
		"ba50d9b9d4567fd9cc6229af2670b5b42434b852": {
			{
				BranchName: "main",
				FilePath: []string{
					".github/workflows/a.yml",
					".github/workflows/a2.yml",
				},
			},
			{
				BranchName: "a",
				FilePath: []string{
					".github/workflows/a.yml",
				},
			},
			{
				BranchName: "a2",
				FilePath: []string{
					".github/workflows/a.yml",
				},
			},
		},
		"f1981e8f197e3a2e48976f7018a2cd00e84dc203": {
			{
				BranchName: "main",
				FilePath: []string{
					".github/workflows/b.yml",
				},
			},
		},
		"7991dd70e685c4f8e532620d3865bd3e2ad4fce4": {
			{
				BranchName: "main",
				FilePath: []string{
					".github/workflows/c.yml",
				},
			},
		},
		"3c837e3a085bd40eb37cc7c3caef56df375fcba4": {
			{
				BranchName: "b",
				FilePath: []string{
					".github/workflows/a.yml",
				},
			},
		},
	}

	sortBranchInfo := func(branches []models.BranchInfo) {
		sort.Slice(branches, func(i, j int) bool {
			return branches[i].BranchName < branches[j].BranchName
		})
	}

	t.Run("Complexe repo", func(t *testing.T) {
		path, err := os.MkdirTemp("/tmp", "poutine-")
		if err != nil {
			t.Error(fmt.Errorf("error creating temp dir: %w", err))
			return
		}
		defer os.RemoveAll(path)

		got, err := client.GetUniqWorkflowsBranches(ctx, path)
		if err != nil {
			assert.NoError(t, err)
			return
		}
		if len(got) != len(expected) {
			assert.Len(t, got, len(expected))
			return
		}
		for blobsha, exepect := range expected {
			gotVal, ok := got[blobsha]
			if !ok {
				assert.True(t, ok)
				continue
			}
			if len(gotVal) != len(exepect) {
				assert.Len(t, gotVal, len(exepect))
				return
			}
			sortBranchInfo(exepect)
			sortBranchInfo(gotVal)
			for j, branchInfo := range exepect {
				if len(gotVal[j].FilePath) != len(branchInfo.FilePath) {
					assert.Len(t, gotVal[j].FilePath, len(branchInfo.FilePath))
					return
				}
				slices.Sort(branchInfo.FilePath)
				slices.Sort(gotVal[j].FilePath)
				for k, filePath := range branchInfo.FilePath {
					assert.Equal(t, filePath, gotVal[j].FilePath[k])
				}
			}
		}

	})
}
