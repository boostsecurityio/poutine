package gitlab

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/boostsecurityio/poutine/analyze"
	"github.com/xanzy/go-gitlab"
)

const GitLab string = "gitlab"

func NewGitlabSCMClient(ctx context.Context, baseURL string, token string) (*ScmClient, error) {
	domain := "gitlab.com"
	if baseURL != "" {
		domain = baseURL
	}

	client, err := NewClient(ctx, domain, token)
	if err != nil {
		return nil, err
	}

	return &ScmClient{
		client:  client,
		baseURL: domain,
	}, nil
}

type ScmClient struct {
	analyze.ScmClient
	client  *Client
	baseURL string
}

func (s *ScmClient) GetOrgRepos(ctx context.Context, org string) <-chan analyze.RepoBatch {
	return s.client.ListGroupProjects(ctx, org)
}
func (s *ScmClient) GetRepo(ctx context.Context, org string, name string) (analyze.Repository, error) {
	combined := org + "/" + name
	return s.client.GetProject(ctx, combined)
}
func (s *ScmClient) GetToken() string {
	return s.client.Token
}
func (s *ScmClient) GetProviderName() string {
	return GitLab
}
func (s *ScmClient) GetProviderBaseURL() string {
	return s.baseURL
}

func (s *ScmClient) ParseRepoAndOrg(repoString string) (string, string, error) {
	index := strings.Index(repoString, "/")
	if index == -1 {
		return "", "", errors.New("invalid gitlab repo format")
	}

	org := repoString[:index]

	repo := repoString[index+1:]

	if org == "" || repo == "" {
		return "", "", errors.New("invalid gitlab repo format")
	}

	return org, repo, nil
}

type GitLabRepo struct {
	analyze.Repository
	NameWithNamespace string
	IsFork            bool
	IsPrivate         bool
	IsMirror          bool
	IsArchived        bool
	StarCount         int
	ForksCount        int
}

func (gl GitLabRepo) GetProviderName() string {
	return GitLab
}

func (s *ScmClient) GetProviderVersion(ctx context.Context) (string, error) {
	met, _, err := s.client.client.Metadata.GetMetadata()
	if err != nil {
		return "", fmt.Errorf("failed to get gitlab metadata: %w", err)
	}

	return met.Version, nil
}

func (gl GitLabRepo) GetRepoIdentifier() string {
	return gl.NameWithNamespace
}

func (gl GitLabRepo) GetIsFork() bool {
	return gl.IsFork
}

func (gl GitLabRepo) BuildGitURL(baseURL string) string {
	return fmt.Sprintf("https://token@%s/%s", baseURL, gl.NameWithNamespace)
}

type Client struct {
	Token  string
	client *gitlab.Client
}

func NewClient(ctx context.Context, baseUrl string, token string) (*Client, error) {
	gitlabClient, err := gitlab.NewClient(token, gitlab.WithBaseURL(fmt.Sprintf("https://%s", baseUrl)))
	if err != nil {
		return nil, fmt.Errorf("failed to create gitlab client: %v", err)
	}
	return &Client{
		Token:  token,
		client: gitlabClient,
	}, nil
}

func (c *Client) ListGroupProjects(ctx context.Context, groupID string) <-chan analyze.RepoBatch {
	batchChan := make(chan analyze.RepoBatch)

	go func() {
		defer close(batchChan)
		opt := &gitlab.ListGroupProjectsOptions{
			ListOptions: gitlab.ListOptions{
				PerPage: 100,
				Page:    1,
			},
			IncludeSubGroups: gitlab.Ptr(true),
			Archived:         gitlab.Ptr(false),
		}

		for {
			ps, resp, err := c.client.Groups.ListGroupProjects(groupID, opt)
			if err != nil {
				batchChan <- analyze.RepoBatch{Err: err}
				return
			}

			batchChan <- analyze.RepoBatch{
				TotalCount:   resp.TotalItems,
				Repositories: projectsToRepos(ps),
			}

			if resp.NextPage == 0 {
				break
			}

			opt.Page = resp.NextPage
		}

	}()

	return batchChan
}

func (c *Client) GetProject(ctx context.Context, projectID string) (analyze.Repository, error) {
	project, _, err := c.client.Projects.GetProject(projectID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get project: %w", err)
	}
	repo := projectToRepo(project)
	if repo != nil {
		return repo, nil
	}
	return nil, nil
}

func projectToRepo(project *gitlab.Project) *GitLabRepo {
	if project.EmptyRepo {
		return nil
	}
	isFork := false
	if project.ForkedFromProject != nil {
		isFork = true
	}
	return &GitLabRepo{
		NameWithNamespace: project.PathWithNamespace,
		IsPrivate:         !(project.Visibility == gitlab.PublicVisibility),
		IsMirror:          project.Mirror,
		IsArchived:        project.Archived,
		StarCount:         project.StarCount,
		ForksCount:        project.ForksCount,
		IsFork:            isFork,
	}
}

func projectsToRepos(projects []*gitlab.Project) []analyze.Repository {
	repos := []analyze.Repository{}
	for _, project := range projects {
		processed := projectToRepo(project)
		if processed != nil {
			repos = append(repos, processed)
		}
	}
	return repos
}
