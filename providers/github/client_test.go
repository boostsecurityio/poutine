package github

import (
	"context"
	"errors"
	"net/http"
	"testing"

	gh "github.com/google/go-github/v84/github"
)

type errorTransport struct {
	err error
}

func (t errorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, t.err
}

func TestGetOrgWorkflowsPermissions_NonErrorResponseError(t *testing.T) {
	wantErr := errors.New("network down")
	httpClient := &http.Client{Transport: errorTransport{err: wantErr}}
	client := &Client{restClient: gh.NewClient(httpClient)}

	permissions, err := client.GetOrgWorkflowsPermissions(context.Background(), "org")
	if permissions != nil {
		t.Fatalf("expected nil permissions, got %v", permissions)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected underlying error to be propagated, got %v", err)
	}
}
