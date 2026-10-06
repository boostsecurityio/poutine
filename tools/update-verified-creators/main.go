// Refresh the rule's verified creators from GitHub Marketplace.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

const marketplace = "https://github.com/marketplace"

var embeddedData = regexp.MustCompile(`<script type="application/json" data-target="react-app.embeddedData">(.*?)</script>`)
var creatorLine = regexp.MustCompile(`(?m)^github_verified_partners contains p if some p in \[.*\]$`)
var loginPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,38}$`)
var slugPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

type action struct {
	ID       int    `json:"id"`
	Slug     string `json:"slug"`
	Type     string `json:"type"`
	Verified bool   `json:"isVerifiedOwner"`
	Owner    string `json:"ownerLogin"`
}

type searchResults struct {
	Results    []action `json:"results"`
	Total      int      `json:"total"`
	TotalPages int      `json:"totalPages"`
}

type sourceSnapshot struct {
	Total   int      `json:"total"`
	Actions []action `json:"actions"`
}

func main() {
	input := flag.String("input", "", "replay a saved snapshot instead of fetching Marketplace")
	snapshot := flag.String("snapshot", "", "save fetched action metadata for offline replay")
	rule := flag.String("rule", "opa/rego/rules/github_action_from_unverified_creator_used.rego", "rule to update")
	flag.Parse()
	if err := run(*input, *snapshot, *rule); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(input, snapshot, rule string) error {
	var actions []action
	if input != "" {
		data, err := os.ReadFile(input)
		if err != nil {
			return fmt.Errorf("read snapshot: %w", err)
		}
		var saved sourceSnapshot
		if err := json.Unmarshal(data, &saved); err != nil {
			return fmt.Errorf("decode snapshot: %w", err)
		}
		if saved.Total < 1 || saved.Total != len(saved.Actions) {
			return errors.New("empty or incomplete snapshot")
		}
		actions = saved.Actions
	} else {
		client := &http.Client{Timeout: 30 * time.Second}
		pace := time.NewTicker(time.Second)
		defer pace.Stop()
		var err error
		actions, err = collect(context.Background(), func(ctx context.Context, url string) ([]byte, error) {
			return fetchPage(ctx, client, url, pace.C)
		})
		if err != nil {
			return err
		}
	}
	updated, err := render(rule, actions)
	if err != nil {
		return err
	}
	if snapshot != "" {
		sort.Slice(actions, func(i, j int) bool { return actions[i].Slug < actions[j].Slug })
		data, err := json.MarshalIndent(sourceSnapshot{Total: len(actions), Actions: actions}, "", "  ")
		if err != nil {
			return fmt.Errorf("encode snapshot: %w", err)
		}
		if err := writeFile(snapshot, append(data, '\n')); err != nil {
			return err
		}
	}
	return writeFile(rule, updated)
}

func fetchPage(ctx context.Context, client *http.Client, url string, pace <-chan time.Time) ([]byte, error) {
	for attempt := 0; attempt < 3; attempt++ {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%s: %w", url, ctx.Err())
		case <-pace:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("User-Agent", "poutine-verified-creators-updater")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("GitHub-Is-React", "true")
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", url, err)
		}
		if resp.StatusCode == http.StatusOK {
			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", url, err)
			}
			return data, nil
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusTooManyRequests || attempt == 2 {
			return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
		}
		delay := time.Minute
		if seconds, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && seconds >= 0 {
			delay = time.Duration(seconds) * time.Second
		} else if deadline, err := http.ParseTime(resp.Header.Get("Retry-After")); err == nil {
			delay = max(0, time.Until(deadline))
		}
		fmt.Fprintf(os.Stderr, "Rate limited; retrying after %s\n", delay)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("%s: %w", url, ctx.Err())
		case <-timer.C:
		}
	}
	return nil, fmt.Errorf("%s: rate limit retries exhausted", url)
}

func payload(data []byte, target interface{}) error {
	if !json.Valid(data) {
		match := embeddedData.FindSubmatch(data)
		if len(match) != 2 {
			return errors.New("marketplace embedded JSON is missing")
		}
		data = match[1]
	}
	var envelope struct {
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("decode page: %w", err)
	}
	if err := json.Unmarshal(envelope.Payload, target); err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}
	return nil
}

func collect(ctx context.Context, fetch func(context.Context, string) ([]byte, error)) ([]action, error) {
	var actions []action
	var total, pages int
	seen := map[int]bool{}
	slugs := map[string]bool{}
	for page := 1; page == 1 || page <= pages; page++ {
		url := fmt.Sprintf("%s?type=actions&verification=verified_creator&query=sort%%3Aname-asc&page=%d", marketplace, page)
		data, err := fetch(ctx, url)
		if err != nil {
			return nil, err
		}
		var result struct {
			Search searchResults `json:"searchResults"`
		}
		if json.Valid(data) {
			err = json.Unmarshal(data, &result.Search)
		} else {
			err = payload(data, &result)
		}
		if err != nil {
			return nil, fmt.Errorf("page %d: %w", page, err)
		}
		if page == 1 {
			total, pages = result.Search.Total, result.Search.TotalPages
		}
		if total < 1 || pages < 1 || pages > 500 || result.Search.Total != total || result.Search.TotalPages != pages || len(result.Search.Results) == 0 {
			return nil, fmt.Errorf("page %d: missing or changing pagination metadata", page)
		}
		for _, a := range result.Search.Results {
			if a.ID <= 0 || !slugPattern.MatchString(a.Slug) || a.Type != "repository_action" || !a.Verified || seen[a.ID] || slugs[a.Slug] {
				return nil, fmt.Errorf("page %d: invalid, unverified, or duplicate action %q", page, a.Slug)
			}
			seen[a.ID], slugs[a.Slug] = true, true
			actions = append(actions, a)
		}
	}
	if len(actions) != total {
		return nil, fmt.Errorf("incomplete Marketplace results: got %d, expected %d", len(actions), total)
	}
	fmt.Fprintf(os.Stderr, "Validated %d listings across %d pages; fetching publisher metadata\n", total, pages)
	group, ctx := errgroup.WithContext(ctx)
	group.SetLimit(4)
	for i, listing := range actions {
		if i%100 == 0 {
			fmt.Fprintf(os.Stderr, "Publisher metadata: %d/%d\n", i, total)
		}
		group.Go(func() error {
			data, err := fetch(ctx, marketplace+"/actions/"+listing.Slug)
			if err != nil {
				return err
			}
			var detail struct {
				Action action `json:"action"`
			}
			if err := payload(data, &detail); err != nil {
				return fmt.Errorf("%s: %w", listing.Slug, err)
			}
			if detail.Action.ID != listing.ID || detail.Action.Slug != listing.Slug || detail.Action.Type != listing.Type || !detail.Action.Verified || !loginPattern.MatchString(detail.Action.Owner) {
				return fmt.Errorf("%s: missing, changed, or unverified publisher metadata", listing.Slug)
			}
			actions[i] = detail.Action
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, fmt.Errorf("fetch publisher metadata: %w", err)
	}
	return actions, nil
}

func render(rule string, actions []action) ([]byte, error) {
	if len(actions) == 0 {
		return nil, errors.New("empty creator snapshot")
	}
	owners := map[string]bool{}
	ids := map[int]bool{}
	slugs := map[string]bool{}
	for _, a := range actions {
		if a.ID <= 0 || !slugPattern.MatchString(a.Slug) || a.Type != "repository_action" || !a.Verified || !loginPattern.MatchString(a.Owner) || ids[a.ID] || slugs[a.Slug] {
			return nil, fmt.Errorf("invalid or unverified action %q", a.Slug)
		}
		ids[a.ID], slugs[a.Slug] = true, true
		owners[strings.ToLower(a.Owner)] = true
	}
	names := make([]string, 0, len(owners))
	for owner := range owners {
		names = append(names, owner)
	}
	sort.Strings(names)
	list, err := json.Marshal(names)
	if err != nil {
		return nil, fmt.Errorf("encode creators: %w", err)
	}
	data, err := os.ReadFile(rule)
	if err != nil {
		return nil, fmt.Errorf("read rule: %w", err)
	}
	if len(creatorLine.FindAll(data, -1)) != 1 {
		return nil, fmt.Errorf("expected exactly one verified-creator list in %s", rule)
	}
	line := "github_verified_partners contains p if some p in " + strings.ReplaceAll(string(list), ",", ", ")
	return creatorLine.ReplaceAll(data, []byte(line)), nil
}

func writeFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".verified-creators-*")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", path, err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return fmt.Errorf("set permissions for %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}
