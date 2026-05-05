package versioncheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	// DisableEnv toggles the version check off when set to a truthy value.
	DisableEnv = "POUTINE_DISABLE_VERSION_CHECK"
	// URLEnv overrides the compiled-in endpoint, primarily for staging.
	URLEnv = "POUTINE_VERSION_CHECK_URL"
)

const (
	checkInterval = 24 * time.Hour
	checkTimeout  = 1200 * time.Millisecond
)

// VersionCheckURL is the default endpoint. It can be overridden at runtime
// via the POUTINE_VERSION_CHECK_URL environment variable, primarily for
// staging or local testing.
var VersionCheckURL = "https://version-check.cicd.fun/v1/check"

// Result mirrors the JSON response from the oss-telemetry /v1/check endpoint.
type Result struct {
	LatestVersion   string `json:"latest_version,omitempty"`
	LatestURL       string `json:"latest_url,omitempty"`
	UpdateAvailable bool   `json:"update_available"`
}

type options struct {
	Config     *Config
	Version    string
	URL        string
	Disabled   bool
	Client     *http.Client
	Now        func() time.Time
	SaveConfig func(*Config) error
	Env        func(string) string
	NewID      func() string
}

// Run records a CLI start and, at most once every 24 hours, reports anonymous
// telemetry to the configured endpoint and returns the latest release info.
// The HTTP call is bounded by checkTimeout (derived from ctx) so it never
// noticeably slows down poutine startup.
func Run(ctx context.Context, version string, disabled bool) *Result {
	if disabled || isDisabledByEnv(os.Getenv(DisableEnv)) {
		return nil
	}

	cfg, _ := LoadConfig()
	if cfg == nil {
		cfg = &Config{}
	}
	recordStart(cfg, uuid.NewString)
	_ = SaveConfig(cfg)

	timeoutCtx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()

	result, _ := run(timeoutCtx, options{
		Config:     cfg,
		Version:    version,
		URL:        VersionCheckURL,
		Client:     &http.Client{Timeout: checkTimeout},
		Now:        time.Now,
		SaveConfig: SaveConfig,
		Env:        os.Getenv,
		NewID:      uuid.NewString,
	})
	return result
}

func run(ctx context.Context, opts options) (*Result, error) {
	if opts.Config == nil {
		opts.Config = &Config{}
	}
	if opts.Env == nil {
		opts.Env = os.Getenv
	}
	if opts.Disabled || isDisabledByEnv(opts.Env(DisableEnv)) {
		return nil, nil
	}

	endpoint := strings.TrimSpace(opts.Env(URLEnv))
	envEndpoint := endpoint != ""
	if endpoint == "" {
		endpoint = strings.TrimSpace(opts.URL)
	}
	version := strings.TrimSpace(opts.Version)
	if endpoint == "" || version == "" {
		return nil, nil
	}
	if isDevVersion(version) && !envEndpoint {
		return nil, nil
	}

	now := time.Now()
	if opts.Now != nil {
		now = opts.Now()
	}
	if !opts.Config.LastVersionCheckAt.IsZero() && now.Sub(opts.Config.LastVersionCheckAt) < checkInterval {
		return nil, nil
	}

	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse version-check endpoint: %w", err)
	}
	instanceID := ensureInstanceID(opts.Config, opts.NewID)
	startsSinceLastCheck := startsSinceLastReport(opts.Config)
	requestURL := buildRequestURL(u, version, instanceID, opts.Config.StartCount, startsSinceLastCheck)

	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: checkTimeout}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build version-check request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "poutine/"+version)

	resp, doErr := client.Do(req)
	opts.Config.LastVersionCheckAt = now
	if opts.SaveConfig == nil {
		opts.SaveConfig = SaveConfig
	}
	var result *Result
	var resultErr error
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			opts.Config.LastReportedStartCount = opts.Config.StartCount
			result, resultErr = readResult(resp)
		} else {
			_, _ = io.Copy(io.Discard, resp.Body)
		}
	}
	saveErr := opts.SaveConfig(opts.Config)
	if doErr != nil {
		return nil, fmt.Errorf("call version-check endpoint: %w", doErr)
	}
	if resultErr != nil {
		return nil, resultErr
	}
	if saveErr != nil {
		return result, saveErr
	}
	return result, nil
}

func isDisabledByEnv(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func isDevVersion(version string) bool {
	version = strings.TrimSpace(version)
	return version == "" ||
		version == "dev" ||
		version == "development" ||
		version == "unknown" ||
		strings.Contains(version, "SNAPSHOT")
}

func recordStart(cfg *Config, newID func() string) {
	if cfg == nil {
		return
	}
	ensureInstanceID(cfg, newID)
	cfg.StartCount++
}

func ensureInstanceID(cfg *Config, newID func() string) string {
	id := strings.TrimSpace(cfg.InstanceID)
	if id == "" {
		if newID == nil {
			newID = uuid.NewString
		}
		id = strings.TrimSpace(newID())
		cfg.InstanceID = id
		return id
	}
	cfg.InstanceID = id
	return id
}

func startsSinceLastReport(cfg *Config) int {
	starts := cfg.StartCount - cfg.LastReportedStartCount
	if starts < 0 {
		return cfg.StartCount
	}
	return starts
}

func readResult(resp *http.Response) (*Result, error) {
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read version-check response: %w", err)
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil, nil
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("decode version-check response: %w", err)
	}
	return &result, nil
}

func buildRequestURL(u *url.URL, version, instanceID string, startCount, startsSinceLastCheck int) string {
	q := u.Query()
	q.Set("project", "poutine")
	q.Set("component", "cli")
	q.Set("version", version)
	q.Set("instance_id", instanceID)
	if startCount > 0 {
		q.Set("start_count", strconv.Itoa(startCount))
		q.Set("starts_since_last_check", strconv.Itoa(startsSinceLastCheck))
	}
	u.RawQuery = q.Encode()
	return u.String()
}
