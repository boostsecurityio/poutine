package scm

import (
	"context"
	"fmt"
	"github.com/boostsecurityio/poutine/analyze"
	"github.com/boostsecurityio/poutine/providers/github"
	"github.com/boostsecurityio/poutine/providers/gitlab"
)

const (
	GitHub string = "github"
	GitLab string = "gitlab"
)

func NewScmClient(ctx context.Context, providerType string, baseURL string, token string, command string) (analyze.ScmClient, error) {
	tokenError := "token must be provided via --token flag or GH_TOKEN environment variable"
	if command == "analyze_local" {
		return nil, nil
	}
	switch providerType {
	case "":
		if token == "" {
			return nil, fmt.Errorf(tokenError)
		}
		return github.NewGithubSCMClient(ctx, baseURL, token)
	case GitHub:
		if token == "" {
			return nil, fmt.Errorf(tokenError)
		}
		return github.NewGithubSCMClient(ctx, baseURL, token)
	case GitLab:
		if token == "" {
			return nil, fmt.Errorf(tokenError)
		}
		return gitlab.NewGitlabSCMClient(ctx, baseURL, token)
	default:
		return nil, fmt.Errorf("unsupported provider type: %s", providerType)
	}
}
