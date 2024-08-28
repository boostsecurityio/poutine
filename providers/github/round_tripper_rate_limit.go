package github

import (
	"fmt"
	"net/http"
)

type retryTransport struct{}

type RateLimitError struct {
	RetryAfter string
	Err        error
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("retry after %s: %v", e.RetryAfter, e.Err)
}

func (e *RateLimitError) Unwrap() error {
	return e.Err
}

func (s *retryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		return nil, err
	}

	if resp != nil {
		retryAfter := resp.Header.Get("Retry-After")
		if retryAfter != "" {
			return nil, &RateLimitError{
				RetryAfter: retryAfter,
				Err:        fmt.Errorf("github graphql rate limit"),
			}
		}
	}

	return resp, err
}
