package gitops

import (
	"bytes"
	"context"
	"github.com/rs/zerolog/log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type GitCloneError struct {
	msg string
}

func (e *GitCloneError) Error() string {
	return e.msg
}

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

type ExecGitCommand struct{}

func (g *ExecGitCommand) Run(ctx context.Context, cmd string, args []string, dir string) ([]byte, error) {
	command := exec.CommandContext(ctx, cmd, args...)
	command.Dir = dir
	return command.CombinedOutput()
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
			return err
		}
	}

	return nil
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

func (g *LocalGitClient) GetRemoteOriginURL(ctx context.Context, repoPath string) (string, error) {
	return g.GitClient.GetRemoteOriginURL(ctx, repoPath)
}

func (g *LocalGitClient) LastCommitDate(ctx context.Context, clonePath string) (time.Time, error) {
	return g.GitClient.LastCommitDate(ctx, clonePath)
}

func (g *LocalGitClient) CommitSHA(clonePath string) (string, error) {
	return g.GitClient.CommitSHA(clonePath)
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
		return "", err
	}

	headBranch := string(bytes.TrimSpace(output))

	return headBranch, nil
}
