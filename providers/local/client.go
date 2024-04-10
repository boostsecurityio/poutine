package local

import (
	"context"
	"errors"
	"fmt"
	"github.com/boostsecurityio/poutine/analyze"
	"github.com/boostsecurityio/poutine/providers/gitops"
	"github.com/rs/zerolog/log"
	"net/url"
	"strings"
)

func NewGitSCMClient(ctx context.Context, repoPath string, gitCommand *gitops.GitCommand) (*ScmClient, error) {
	client := gitops.NewGitClient(gitCommand)

	return &ScmClient{
		gitClient: client,
		repoPath:  repoPath,
	}, nil
}

type ScmClient struct {
	analyze.ScmClient
	gitClient *gitops.GitClient
	repoPath  string
}

func (s *ScmClient) GetOrgRepos(ctx context.Context, org string) <-chan analyze.RepoBatch {
	return nil
}
func (s *ScmClient) GetRepo(ctx context.Context, org string, name string) (analyze.Repository, error) {
	org, repo, err := s.ParseRepoAndOrg("")
	if err != nil {
		return nil, err
	}
	baseUrl := s.GetProviderBaseURL()
	return Repo{
		BaseUrl: baseUrl,
		Org:     org,
		Name:    repo,
	}, nil
}
func (s *ScmClient) GetToken() string {
	return ""
}
func (s *ScmClient) GetProviderName() string {
	return s.GetProviderBaseURL()
}
func (s *ScmClient) GetProviderVersion(ctx context.Context) (string, error) {
	return "", nil
}
func (s *ScmClient) GetProviderBaseURL() string {
	remote, err := s.gitClient.GetRemoteOriginURL(context.Background(), s.repoPath)
	if err != nil {
		log.Error().Err(err).Msg("failed to get remote url for repo")
		return ""
	}

	if strings.HasPrefix(remote, "git@") {
		return extractHostnameFromSSHURL(remote)
	}

	parsedURL, err := url.Parse(remote)
	if err != nil {
		log.Error().Err(err).Msg("failed to parse remote url")
		return ""
	}

	if parsedURL.Hostname() == "" {
		log.Error().Msg("repo remote url does not have a hostname")
		return ""
	}

	return parsedURL.Hostname()
}

func (s *ScmClient) ParseRepoAndOrg(repoString string) (string, string, error) {
	remoteURL, err := s.gitClient.GetRemoteOriginURL(context.Background(), s.repoPath)
	if err != nil {
		return "", "", err
	}
	if strings.Contains(remoteURL, "git@") {
		remoteURL = strings.Replace(remoteURL, ":", "/", 1)
	}

	parsedURL, err := url.Parse(remoteURL)
	if err != nil {
		return "", "", err
	}

	pathParts := strings.Split(strings.Trim(parsedURL.Path, "/"), "/")
	if len(pathParts) < 2 {
		return "", "", errors.New("git remote URL path does not contain organization and repository information")
	}

	org := pathParts[len(pathParts)-2]
	repo := strings.TrimSuffix(pathParts[len(pathParts)-1], ".git")

	return org, repo, nil
}

type Repo struct {
	analyze.Repository
	BaseUrl string
	Org     string
	Name    string
}

func (gl Repo) GetProviderName() string {
	if gl.BaseUrl == "github.com" || gl.BaseUrl == "gitlab.com" {
		return gl.BaseUrl[:len(gl.BaseUrl)-4]
	}
	return gl.BaseUrl
}

func (gl Repo) GetRepoIdentifier() string {
	if gl.BaseUrl == "github.com" || gl.BaseUrl == "gitlab.com" {
		return fmt.Sprintf("%s/%s", gl.Org, gl.Name)
	}
	return fmt.Sprintf("%s/%s/%s", gl.BaseUrl, gl.Org, gl.Name)
}

func (gl Repo) BuildGitURL(baseURL string) string {
	return ""
}

func extractHostnameFromSSHURL(sshURL string) string {
	parts := strings.Split(sshURL, "@")
	if len(parts) != 2 {
		log.Error().Msg("invalid SSH URL format")
		return ""
	}
	hostPart := parts[1]
	hostnameParts := strings.SplitN(hostPart, ":", 2)
	if len(hostnameParts) != 2 {
		log.Error().Msg("invalid SSH URL format")
		return ""
	}
	return hostnameParts[0]
}
