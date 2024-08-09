package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/boostsecurityio/poutine/analyze"
	"github.com/boostsecurityio/poutine/providers/scm/domain"
	"github.com/rs/zerolog/log"

	"github.com/gofri/go-github-ratelimit/github_ratelimit"
	"github.com/google/go-github/v59/github"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

const GitHub string = "github"

func NewGithubSCMClient(ctx context.Context, baseURL string, token string) (*ScmClient, error) {
	domain := scm_domain.DefaultGitHubDomain
	if baseURL != "" {
		domain = baseURL
	}

	client, err := NewClient(ctx, token, domain)
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
	return s.client.GetOrgRepos(ctx, org)
}
func (s *ScmClient) GetRepo(ctx context.Context, org string, name string) (analyze.Repository, error) {
	return s.client.GetRepository(ctx, org, name)
}
func (s *ScmClient) GetToken() string {
	return s.client.Token
}
func (s *ScmClient) GetProviderName() string {
	return GitHub
}

func (s *ScmClient) GetProviderBaseURL() string {
	return s.baseURL
}

func (s *ScmClient) ParseRepoAndOrg(repoString string) (string, string, error) {
	parts := strings.Split(repoString, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid repo format %q, expected format <org>/<repo>", repoString)
	}
	return parts[0], parts[1], nil
}

type GithubRepository struct {
	analyze.Repository
	NameWithOwner  string `graphql:"nameWithOwner"`
	IsFork         bool   `graphql:"isFork"`
	IsPrivate      bool   `graphql:"isPrivate"`
	IsMirror       bool   `graphql:"isMirror"`
	IsDisabled     bool   `graphql:"isDisabled"`
	IsEmpty        bool   `graphql:"isEmpty"`
	IsTemplate     bool   `graphql:"isTemplate"`
	IsArchived     bool   `graphql:"isArchived"`
	StargazerCount int    `graphql:"stargazerCount"`
	ForkCount      int    `graphql:"forkCount"`
	Owner          struct {
		ID string `graphql:"id"`
	} `graphql:"owner"`
	RepoID           string `graphql:"id"`
	RepoSize         int    `graphql:"diskUsage"` // kilobytes
	DefaultBranchRef struct {
		Name string `graphql:"name"`
	} `graphql:"defaultBranchRef"`
	HasIssues       bool `graphql:"hasIssuesEnabled"`
	HasWiki         bool `graphql:"hasWikiEnabled"`
	HasDiscussions  bool `graphql:"hasDiscussionsEnabled"`
	PrimaryLanguage struct {
		Name string `graphql:"name"`
	} `graphql:"primaryLanguage"`
	License struct {
		Name string `graphql:"name"`
	} `graphql:"licenseInfo"`
	Issues struct {
		TotalCount int `graphql:"totalCount"`
	} `graphql:"issues"`
}

func (gh GithubRepository) GetProviderName() string {
	return GitHub
}

func (s *ScmClient) GetProviderVersion(ctx context.Context) (string, error) {
	req, err := s.client.restClient.NewRequest("GET", "meta", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create github meta request: %w", err)
	}
	res, err := s.client.restClient.BareDo(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to get github meta: %w", err)
	}

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", fmt.Errorf("failed to parse JSON: %w", err)
	}

	if installedVersion, ok := data["installed_version"].(string); ok {
		return installedVersion, nil
	}

	return "github.com", nil
}

func (gh GithubRepository) GetRepoIdentifier() string {
	return gh.NameWithOwner
}

func (gh GithubRepository) BuildGitURL(baseURL string) string {
	return fmt.Sprintf("https://token@%s/%s", baseURL, gh.NameWithOwner)
}

func (gh GithubRepository) GetIsFork() bool {
	return gh.IsFork
}

func (gh GithubRepository) GetHasIssues() bool {
	return gh.HasIssues
}

func (gh GithubRepository) GetHasWiki() bool {
	return gh.HasWiki
}

func (gh GithubRepository) GetHasDiscussion() bool {
	return gh.HasDiscussions
}

func (gh GithubRepository) GetPrimaryLanguage() string {
	return gh.PrimaryLanguage.Name
}

func (gh GithubRepository) GetSize() int {
	return gh.RepoSize
}

func (gh GithubRepository) GetDefaultBranch() string {
	return gh.DefaultBranchRef.Name
}

func (gh GithubRepository) GetLicense() string {
	return gh.License.Name
}

func (gh GithubRepository) GetIsTemplate() bool {
	return gh.IsTemplate
}

func (gh GithubRepository) GetOrganizationID() string {
	return gh.Owner.ID
}

func (gh GithubRepository) GetRepositoryID() string {
	return gh.RepoID
}

func (gh GithubRepository) GetForksCount() int {
	return gh.ForkCount
}

func (gh GithubRepository) GetStarsCount() int {
	return gh.StargazerCount
}

func (gh GithubRepository) GetOpenIssuesCount() int {
	return gh.Issues.TotalCount
}

type Client struct {
	restClient    *github.Client
	graphQLClient *githubv4.Client
	Token         string
}

func NewClient(ctx context.Context, token string, domain string) (*Client, error) {
	rateLimiter, err := github_ratelimit.NewRateLimitWaiterClient(nil)
	if err != nil {
		return nil, err
	}

	var (
		// REST client
		restClient = github.NewClient(rateLimiter).WithAuthToken(token)
		// GraphQL client
		src = oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		httpClient    = oauth2.NewClient(ctx, src)
		graphQLClient *githubv4.Client
	)

	if domain == scm_domain.DefaultGitHubDomain {
		graphQLClient = githubv4.NewClient(httpClient)
	} else {
		baseURL := fmt.Sprintf("https://%s/", domain)
		restClient, err = restClient.WithEnterpriseURLs(baseURL, baseURL)
		if err != nil {
			return nil, err
		}

		graphQLClient = githubv4.NewEnterpriseClient(baseURL+"api/graphql", httpClient)
	}

	return &Client{
		restClient:    restClient,
		graphQLClient: graphQLClient,
		Token:         token,
	}, nil
}

func (c *Client) GetOrgActionsPermissions(ctx context.Context, org string) (*github.ActionsPermissions, error) {
	permissions, _, err := c.restClient.Actions.GetActionsPermissions(ctx, org)
	if err != nil {
		var errorResponse *github.ErrorResponse
		if errors.As(err, &errorResponse) {
			if errorResponse.Response.StatusCode == http.StatusNotFound {
				log.Debug().Msgf("Actions permissions for org %s could not be found", org)
				return nil, nil
			}
			if errorResponse.Response.StatusCode == http.StatusForbidden {
				log.Debug().Msgf("Forbidden to get actions permissions for org %s", org)
				return nil, nil
			}
		}
	}
	return permissions, err
}

func (c *Client) GetOrgWorkflowsPermissions(ctx context.Context, org string) (*github.DefaultWorkflowPermissionOrganization, error) {
	permissions, _, err := c.restClient.Actions.GetDefaultWorkflowPermissionsInOrganization(ctx, org)
	if err != nil {
		var errorResponse *github.ErrorResponse
		if errors.As(err, &errorResponse) {
			if errorResponse.Response.StatusCode == http.StatusNotFound {
				log.Debug().Msgf("Workflow permissions for org %s could not be found", org)
				return nil, nil
			}
		}
		if errorResponse.Response.StatusCode == http.StatusForbidden {
			log.Debug().Msgf("Forbidden to get workflow permissions for org %s", org)
			return nil, nil
		}
	}
	return permissions, err
}

func (c *Client) GetRepoActionsPermissions(ctx context.Context, org string, repo string) (*github.ActionsPermissionsRepository, error) {
	permissions, _, err := c.restClient.Repositories.GetActionsPermissions(ctx, org, repo)
	if err != nil {
		var errorResponse *github.ErrorResponse
		if errors.As(err, &errorResponse) {
			if errorResponse.Response.StatusCode == http.StatusNotFound {
				log.Debug().Msgf("Actions permissions for %s/%s could not be found", org, repo)
				return nil, nil
			}
			if errorResponse.Response.StatusCode == http.StatusForbidden {
				log.Debug().Msgf("Forbidden to get actions permissions for %s/%s", org, repo)
				return nil, nil
			}
		}
	}
	return permissions, err
}

func (c *Client) GetRepoWorkflowsPermissions(ctx context.Context, org string, repo string) (*github.DefaultWorkflowPermissionRepository, error) {
	permissions, _, err := c.restClient.Repositories.GetDefaultWorkflowPermissions(ctx, org, repo)
	if err != nil {
		var errorResponse *github.ErrorResponse
		if errors.As(err, &errorResponse) {
			if errorResponse.Response.StatusCode == http.StatusNotFound {
				log.Debug().Msgf("Default workflow permissions for %s/%s could not be found", org, repo)
				return nil, nil
			}
			if errorResponse.Response.StatusCode == http.StatusForbidden {
				log.Debug().Msgf("Forbidden to get default workflow permissions for %s/%s", org, repo)
				return nil, nil
			}
		}
	}
	return permissions, err
}

func (c *Client) GetRepository(ctx context.Context, owner, name string) (*GithubRepository, error) {
	variables := map[string]interface{}{
		"org":  githubv4.String(owner),
		"name": githubv4.String(name),
	}
	var query struct {
		Repository GithubRepository `graphql:"repository(owner: $org, name: $name)"`
	}
	err := c.graphQLClient.Query(ctx, &query, variables)
	if err != nil {
		return nil, err
	}
	return &query.Repository, err
}

func (c *Client) GetOrgRepos(ctx context.Context, org string) <-chan analyze.RepoBatch {
	batchChan := make(chan analyze.RepoBatch)

	go func() {
		defer close(batchChan)

		var totalCountSent bool

		variables := map[string]interface{}{
			"org":   githubv4.String(org),
			"after": (*githubv4.String)(nil),
		}

		for {
			var query struct {
				RepositoryOwner struct {
					Login        string
					Repositories struct {
						TotalCount int
						Nodes      []GithubRepository
						PageInfo   struct {
							EndCursor   githubv4.String
							HasNextPage bool
						}
					} `graphql:"repositories(first: 100, after: $after, isArchived: false, isLocked: false, orderBy: {field: UPDATED_AT, direction: DESC})"`
				} `graphql:"repositoryOwner(login: $org)"`
			}

			err := c.graphQLClient.Query(ctx, &query, variables)
			if err != nil {
				batchChan <- analyze.RepoBatch{Err: err}
				return
			}

			if query.RepositoryOwner.Login == "" {
				batchChan <- analyze.RepoBatch{Err: errors.New("org does not exist")}
				return
			}
			if query.RepositoryOwner.Repositories.TotalCount == 0 {
				log.Info().Msg("No repositories found for org. If this is unexpected, ensure your token has the correct permissions.")
				return
			}

			totalCount := 0
			if !totalCountSent {
				totalCount = query.RepositoryOwner.Repositories.TotalCount
				totalCountSent = true
			}

			batchChan <- analyze.RepoBatch{
				TotalCount:   totalCount,
				Repositories: convertToRepositorySlice(query.RepositoryOwner.Repositories.Nodes),
			}

			if !query.RepositoryOwner.Repositories.PageInfo.HasNextPage {
				break
			}

			variables["after"] = githubv4.NewString(query.RepositoryOwner.Repositories.PageInfo.EndCursor)
		}
	}()

	return batchChan
}

func convertToRepositorySlice(githubRepos []GithubRepository) []analyze.Repository {
	repos := make([]analyze.Repository, len(githubRepos))
	for i, repo := range githubRepos {
		repos[i] = repo
	}
	return repos
}
