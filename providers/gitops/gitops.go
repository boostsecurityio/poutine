package gitops

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

type GitClient struct {
	Command GitCommand
}

func NewGitClient(command *GitCommand) *GitClient {
	if command != nil {
		return &GitClient{Command: *command}
	}
	return &GitClient{Command: &ExecGitCommand{}}
}

type GitCommand interface {
	Run(ctx context.Context, cmd string, args []string, dir string) ([]byte, error)
	ReadFile(path string) ([]byte, error)
}

type GitError interface {
	error
	Command() string
}

type GitCommandError struct {
	CommandStr string
	Err        error
}

func (e *GitCommandError) Error() string {
	return fmt.Sprintf("error running command `%s`: %v", e.CommandStr, e.Err)
}

func (e *GitCommandError) Unwrap() error {
	return e.Err
}

func (e *GitCommandError) Command() string {
	return e.CommandStr
}

type GitExitError struct {
	CommandStr string
	Stderr     string
	ExitCode   int
	Err        error
}

func (e *GitExitError) Error() string {
	return fmt.Sprintf("command `%s` failed with exit code %d: %v, stderr: %s", e.CommandStr, e.ExitCode, e.Err, e.Stderr)
}

func (e *GitExitError) Unwrap() error {
	return e.Err
}

func (e *GitExitError) Command() string {
	return e.CommandStr
}

type GitNotFoundError struct {
	CommandStr string
}

func (e *GitNotFoundError) Error() string {
	return fmt.Sprintf("git binary not found for command `%s`. Please ensure Git is installed and available in your PATH.", e.CommandStr)
}

func (e *GitNotFoundError) Command() string {
	return e.CommandStr
}

type ExecGitCommand struct{}

func (g *ExecGitCommand) Run(ctx context.Context, cmd string, args []string, dir string) ([]byte, error) {
	command := exec.CommandContext(ctx, cmd, args...)
	command.Dir = dir
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr

	err := command.Run()
	if err != nil {
		var execErr *exec.Error
		if errors.As(err, &execErr) && errors.Is(execErr.Err, exec.ErrNotFound) {
			return nil, &GitNotFoundError{
				CommandStr: command.String(),
			}
		}

		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode := exitErr.ExitCode()
			stderrMsg := strings.TrimSpace(stderr.String())

			if stderrMsg == "" {
				stderrMsg = exitErr.Error()
			}

			return nil, &GitExitError{
				CommandStr: command.String(),
				Stderr:     stderrMsg,
				ExitCode:   exitCode,
				Err:        exitErr,
			}
		}
		return nil, &GitCommandError{
			CommandStr: command.String(),
			Err:        err,
		}
	}

	return []byte(stdout.String()), nil
}

func (g *ExecGitCommand) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (g *GitClient) Clone(ctx context.Context, clonePath string, url string, token string, ref string) error {
	os.Setenv("POUTINE_GIT_ASKPASS_TOKEN", token)
	credentialHelperScript := "!f() { test \"$1\" = get && echo \"password=$POUTINE_GIT_ASKPASS_TOKEN\"; }; f"
	commands := []struct {
		cmd  string
		args []string
	}{
		{"git", []string{"init", "--quiet"}},
		{"git", []string{"remote", "add", "origin", url}},
		{"git", []string{"config", "credential.helper", credentialHelperScript}},
		{"git", []string{"config", "submodule.recurse", "false"}},
		{"git", []string{"config", "core.sparseCheckout", "true"}},
		{"git", []string{"config", "index.sparse", "true"}},
		{"git", []string{"sparse-checkout", "init", "--sparse-index"}},
		{"git", []string{"sparse-checkout", "set", "**/*.yml", "**/*.yaml"}},
		{"git", []string{"fetch", "--quiet", "--no-tags", "--depth", "1", "--filter=blob:none", "origin", ref}},
		{"git", []string{"checkout", "--quiet", "-b", "target", "FETCH_HEAD"}},
	}

	for _, c := range commands {
		if _, err := g.Command.Run(ctx, c.cmd, c.args, clonePath); err != nil {
			if token != "" && strings.Contains(err.Error(), token) {
				return errors.New(strings.ReplaceAll(err.Error(), token, "REDACTED"))
			}

			return err
		}
	}

	return nil
}

func (g *GitClient) FetchCone(ctx context.Context, clonePath, url, token, ref string, cone string) error {
	os.Setenv("POUTINE_GIT_ASKPASS_TOKEN", token)
	credentialHelperScript := "!f() { test \"$1\" = get && echo \"password=$POUTINE_GIT_ASKPASS_TOKEN\"; }; f"
	commands := []struct {
		cmd  string
		args []string
	}{
		{"git", []string{"init", "--quiet"}},
		{"git", []string{"remote", "add", "origin", url}},
		{"git", []string{"config", "credential.helper", credentialHelperScript}},
		{"git", []string{"config", "submodule.recurse", "false"}},
		{"git", []string{"config", "core.sparseCheckout", "true"}},
		{"git", []string{"config", "index.sparse", "true"}},
		{"git", []string{"sparse-checkout", "init", "--sparse-index", "--cone"}},
		{"git", []string{"sparse-checkout", "set", cone}},
		{"git", []string{"fetch", "--quiet", "--no-tags", "--depth", "1", "--filter=blob:none", "origin", ref}},
	}

	for _, c := range commands {
		if _, err := g.Command.Run(ctx, c.cmd, c.args, clonePath); err != nil {
			if token != "" && strings.Contains(err.Error(), token) {
				return errors.New(strings.ReplaceAll(err.Error(), token, "REDACTED"))
			}

			return fmt.Errorf("git error trying to fetch cone: %w", err)
		}
	}

	return nil
}

type BranchInfo struct {
	BranchName string
	FilePath   []string
}

func (g *GitClient) GetUniqWorkflowsBranches(ctx context.Context, clonePath string) (map[string][]BranchInfo, error) {
	branches, err := g.getRemoteBranches(ctx, clonePath)
	if err != nil {
		return nil, err
	}

	workflowsInfo := make(map[string][]BranchInfo)
	for _, branches := range branches {
		if len(branches) == 0 {
			continue
		}
		workflows, err := g.getBranchWorkflow(ctx, clonePath, branches[0])
		if err != nil {
			return nil, err
		}

		for blobsha, paths := range workflows {
			var infos []BranchInfo
			for _, branch := range branches {
				infos = append(infos, BranchInfo{
					BranchName: branch,
					FilePath:   paths,
				})
			}

			workflowsInfo[blobsha] = append(workflowsInfo[blobsha], infos...)
		}
	}

	return workflowsInfo, nil
}

// blobMatches returns true if the blob (by its SHA) matches the given regex.
func (g *GitClient) BlobMatches(ctx context.Context, clonePath, blobSha string, re *regexp.Regexp) (bool, []byte, error) {
	content, err := g.Command.Run(ctx, "git", []string{"cat-file", "blob", blobSha}, clonePath)
	if err != nil {
		return false, nil, fmt.Errorf("error cat-file blob %s: %w", blobSha, err)
	}
	return re.Match(content), content, nil
}

// processBranch uses the remote ref (origin/<branch>) to list YAML files under .github/workflows.
// It avoids checking out by operating on the remote reference directly.
func (g *GitClient) getBranchWorkflow(ctx context.Context, clonePath string, branch string) (map[string][]string, error) {
	ref := "origin/" + branch

	// List files under .github/workflows in the remote branch.
	lsOutput, err := g.Command.Run(ctx, "git", []string{"ls-tree", "-r", ref, "--full-tree", ".github/workflows"}, clonePath)
	if err != nil {
		// If the directory doesn’t exist, skip.
		if strings.Contains(err.Error(), "Not a valid object name") ||
			strings.Contains(err.Error(), "did not match any file") {
			return nil, nil
		}
		return nil, fmt.Errorf("error ls-tree ref %s: %w", ref, err)
	}

	records := make(map[string][]string)
	scanner := bufio.NewScanner(bytes.NewReader(lsOutput))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		blobSha := parts[2]
		filePath := parts[len(parts)-1]
		if !strings.HasSuffix(filePath, ".yml") && !strings.HasSuffix(filePath, ".yaml") {
			continue
		}

		records[blobSha] = append(records[blobSha], filePath)
	}
	return records, nil
}

// getRemoteBranches lists remote branches (excluding refs/pull/*) and deduplicates by commit SHA.
func (g *GitClient) getRemoteBranches(ctx context.Context, clonePath string) (map[string][]string, error) {
	output, err := g.Command.Run(ctx, "git", []string{"ls-remote", "--heads"}, clonePath)
	if err != nil {
		return nil, err
	}
	branches := make(map[string][]string)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue
		}
		commit := parts[0]
		ref := parts[1]
		if strings.Contains(ref, "refs/pull/") {
			continue
		}
		const prefix = "refs/heads/"
		if !strings.HasPrefix(ref, prefix) {
			continue
		}
		branchName := strings.TrimPrefix(ref, prefix)
		branches[commit] = append(branches[commit], branchName)
	}
	return branches, nil
}

func (g *GitClient) CommitSHA(clonePath string) (string, error) {
	out, err := g.Command.Run(context.Background(), "git", []string{"log", "-1", "--format=%H"}, clonePath)
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(out)), nil
}

func (g *GitClient) LastCommitDate(ctx context.Context, clonePath string) (time.Time, error) {
	out, err := g.Command.Run(ctx, "git", []string{"log", "-1", "--format=%ct"}, clonePath)
	if err != nil {
		return time.Time{}, err
	}
	unixTime, err := strconv.ParseInt(string(bytes.TrimSpace(out)), 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(unixTime, 0), nil
}

func (g *GitClient) GetRemoteOriginURL(ctx context.Context, repoPath string) (string, error) {
	cmd := "git"
	args := []string{"config", "--get", "remote.origin.url"}

	output, err := g.Command.Run(ctx, cmd, args, repoPath)
	if err != nil {
		return "", err
	}

	remoteURL := string(bytes.TrimSpace(output))

	return remoteURL, nil
}

func (g *GitClient) GetRepoHeadBranchName(ctx context.Context, repoPath string) (string, error) {
	cmd := "git"
	args := []string{"ls-remote", "--symref", "origin", "HEAD"}

	output, err := g.Command.Run(ctx, cmd, args, repoPath)
	if err != nil {
		return "", err
	}

	headBranch := string(bytes.TrimSpace(output))

	for _, line := range strings.Split(headBranch, "\n") {
		if strings.HasPrefix(line, "ref:") {
			parts := strings.Split(line, "\t")
			if len(parts) > 0 {
				branchRefPart := parts[0]
				branchName := strings.TrimPrefix(branchRefPart, "ref: refs/heads/")
				return branchName, nil
			}
		}
	}

	return "HEAD", nil
}

func NewLocalGitClient(command *GitCommand) *LocalGitClient {
	if command != nil {
		return &LocalGitClient{GitClient: &GitClient{Command: *command}}
	}
	return &LocalGitClient{GitClient: &GitClient{Command: &ExecGitCommand{}}}
}

type LocalGitClient struct {
	GitClient *GitClient
}

func (g *LocalGitClient) GetUniqWorkflowsBranches(ctx context.Context, clonePath string) (map[string][]BranchInfo, error) {
	branchInfo, err := g.GitClient.GetUniqWorkflowsBranches(ctx, clonePath)
	if err != nil {
		var gitErr GitError
		if errors.As(err, &gitErr) {
			log.Debug().Err(err).Msg("failed to get unique workflows for local repo")
			return nil, nil
		}
		return nil, err
	}
	return branchInfo, nil
}

func (g *LocalGitClient) FetchCone(ctx context.Context, clonePath, url, token, ref, cone string) error {
	err := g.GitClient.FetchCone(ctx, clonePath, url, token, ref, cone)
	if err != nil {
		var gitErr GitError
		if errors.As(err, &gitErr) {
			log.Debug().Err(err).Msg("failed to fetch cone for local repo")
			return nil
		}
		return err
	}
	return nil
}

func (g *LocalGitClient) BlobMatches(ctx context.Context, clonePath, blobSha string, re *regexp.Regexp) (bool, []byte, error) {
	match, content, err := g.GitClient.BlobMatches(ctx, clonePath, blobSha, re)
	if err != nil {
		var gitErr GitError
		if errors.As(err, &gitErr) {
			log.Debug().Err(err).Msg("failed to blob match for local repo")
			return false, nil, nil
		}
		return false, nil, err
	}
	return match, content, nil
}

func (g *LocalGitClient) GetRemoteOriginURL(ctx context.Context, repoPath string) (string, error) {
	remoteOriginURL, err := g.GitClient.GetRemoteOriginURL(ctx, repoPath)
	if err != nil {
		var gitErr GitError
		if errors.As(err, &gitErr) {
			log.Debug().Err(err).Msg("failed to get remote origin URL for local repo")
			return repoPath, nil
		}
		return "", err
	}
	return remoteOriginURL, nil
}

func (g *LocalGitClient) LastCommitDate(ctx context.Context, clonePath string) (time.Time, error) {
	lastCommitDate, err := g.GitClient.LastCommitDate(ctx, clonePath)
	if err != nil {
		var gitErr GitError
		if errors.As(err, &gitErr) {
			log.Debug().Err(err).Msg("failed to get last commit date for local repo")
			return time.Now(), nil
		}
		return time.Time{}, err
	}
	return lastCommitDate, nil
}

func (g *LocalGitClient) CommitSHA(clonePath string) (string, error) {
	commitSHA, err := g.GitClient.CommitSHA(clonePath)
	if err != nil {
		var gitErr GitError
		if errors.As(err, &gitErr) {
			log.Debug().Err(err).Msg("failed to get commit SHA for local repo")
			return "", nil
		}
		return "", err
	}
	return commitSHA, nil
}

func (g *LocalGitClient) Clone(ctx context.Context, clonePath string, url string, token string, ref string) error {
	log.Debug().Msgf("Local Git Client shouldn't be used to clone repositories")
	return nil
}

func (g *LocalGitClient) GetRepoHeadBranchName(ctx context.Context, repoPath string) (string, error) {
	cmd := "git"
	args := []string{"branch", "--show-current"}

	output, err := g.GitClient.Command.Run(ctx, cmd, args, repoPath)
	if err != nil {
		var gitErr GitError
		if errors.As(err, &gitErr) {
			log.Debug().Err(err).Msg("failed to get repo head branch name for local repo")
			return "local", nil
		}
		return "", err
	}

	headBranch := string(bytes.TrimSpace(output))

	return headBranch, nil
}
