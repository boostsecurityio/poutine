package versioncheck

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRun_SendsVersionAndRecordsTimestamp(t *testing.T) {
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	instanceID := "2ed05245-10d7-4d21-a8e8-7c4e8a9851b4"
	cfg := &Config{
		InstanceID: instanceID,
		StartCount: 7,
	}
	var gotReq *http.Request
	var saved *Config

	result, err := run(context.Background(), options{
		Config:  cfg,
		Version: "v0.18.0",
		URL:     "https://updates.example/check?channel=stable",
		Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			gotReq = req
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		})},
		Now: func() time.Time { return now },
		SaveConfig: func(cfg *Config) error {
			c := *cfg
			saved = &c
			return nil
		},
		Env:   func(string) string { return "" },
		NewID: func() string { return instanceID },
	})

	require.NoError(t, err)
	assert.Nil(t, result)
	require.NotNil(t, gotReq)
	assert.Equal(t, "poutine", gotReq.URL.Query().Get("project"))
	assert.Equal(t, "cli", gotReq.URL.Query().Get("component"))
	assert.Equal(t, "v0.18.0", gotReq.URL.Query().Get("version"))
	assert.Equal(t, instanceID, gotReq.URL.Query().Get("instance_id"))
	assert.Equal(t, "7", gotReq.URL.Query().Get("start_count"))
	assert.Equal(t, "7", gotReq.URL.Query().Get("starts_since_last_check"))
	assert.Equal(t, "stable", gotReq.URL.Query().Get("channel"))
	assert.Equal(t, "poutine/v0.18.0", gotReq.Header.Get("User-Agent"))
	require.NotNil(t, saved)
	assert.Equal(t, instanceID, saved.InstanceID)
	assert.Equal(t, 7, saved.StartCount)
	assert.Equal(t, 7, saved.LastReportedStartCount)
	assert.Equal(t, now, saved.LastVersionCheckAt)
}

func TestRun_ReturnsUpdateResult(t *testing.T) {
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	cfg := &Config{
		InstanceID:             "2ed05245-10d7-4d21-a8e8-7c4e8a9851b4",
		StartCount:             5,
		LastReportedStartCount: 4,
	}

	result, err := run(context.Background(), options{
		Config:  cfg,
		Version: "v0.18.0",
		URL:     "https://updates.example/check",
		Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, "1", req.URL.Query().Get("starts_since_last_check"))
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(`{
					"latest_version":"v0.18.1",
					"latest_url":"https://github.com/boostsecurityio/poutine/releases/tag/v0.18.1",
					"update_available":true
				}`)),
			}, nil
		})},
		Now:        func() time.Time { return now },
		SaveConfig: func(*Config) error { return nil },
		Env:        func(string) string { return "" },
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.UpdateAvailable)
	assert.Equal(t, "v0.18.1", result.LatestVersion)
	assert.Equal(t, "https://github.com/boostsecurityio/poutine/releases/tag/v0.18.1", result.LatestURL)
	assert.Equal(t, 5, cfg.LastReportedStartCount)
}

func TestRun_DisabledByEnv(t *testing.T) {
	called := false
	cfg := &Config{}

	result, err := run(context.Background(), options{
		Config:  cfg,
		Version: "v0.18.0",
		URL:     "https://updates.example/check",
		Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("unexpected request")
		})},
		Env: func(key string) string {
			if key == DisableEnv {
				return "true"
			}
			return ""
		},
	})

	require.NoError(t, err)
	assert.Nil(t, result)
	assert.False(t, called)
	assert.Empty(t, cfg.InstanceID)
	assert.Zero(t, cfg.StartCount)
	assert.True(t, cfg.LastVersionCheckAt.IsZero())
}

func TestRun_DisabledByOption(t *testing.T) {
	called := false
	cfg := &Config{}

	result, err := run(context.Background(), options{
		Config:   cfg,
		Version:  "v0.18.0",
		URL:      "https://updates.example/check",
		Disabled: true,
		Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("unexpected request")
		})},
		Env: func(string) string { return "" },
	})

	require.NoError(t, err)
	assert.Nil(t, result)
	assert.False(t, called)
	assert.True(t, cfg.LastVersionCheckAt.IsZero())
}

func TestRun_RespectsInterval(t *testing.T) {
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	called := false
	cfg := &Config{LastVersionCheckAt: now.Add(-time.Hour)}

	result, err := run(context.Background(), options{
		Config:  cfg,
		Version: "v0.18.0",
		URL:     "https://updates.example/check",
		Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("unexpected request")
		})},
		Now: func() time.Time { return now },
		Env: func(string) string { return "" },
	})

	require.NoError(t, err)
	assert.Nil(t, result)
	assert.False(t, called)
	assert.Empty(t, cfg.InstanceID)
}

func TestRecordStart_GeneratesInstanceIDAndIncrementsCount(t *testing.T) {
	cfg := &Config{}

	recordStart(cfg, func() string {
		return "97c5d9f0-7a5c-4a61-9f2a-09f4903de44e"
	})
	recordStart(cfg, func() string {
		t.Fatal("existing instance_id should be reused")
		return ""
	})

	assert.Equal(t, "97c5d9f0-7a5c-4a61-9f2a-09f4903de44e", cfg.InstanceID)
	assert.Equal(t, 2, cfg.StartCount)
}

func TestRun_ReusesInstanceIDAndReportsStartCount(t *testing.T) {
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	cfg := &Config{
		InstanceID:             "97c5d9f0-7a5c-4a61-9f2a-09f4903de44e",
		StartCount:             42,
		LastReportedStartCount: 40,
		LastVersionCheckAt:     now.Add(-25 * time.Hour),
	}
	var gotReq *http.Request

	result, err := run(context.Background(), options{
		Config:  cfg,
		Version: "v0.18.0",
		URL:     "https://updates.example/check",
		Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			gotReq = req
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		})},
		Now:        func() time.Time { return now },
		SaveConfig: func(*Config) error { return nil },
		Env:        func(string) string { return "" },
		NewID: func() string {
			t.Fatal("existing instance_id should be reused")
			return ""
		},
	})

	require.NoError(t, err)
	assert.Nil(t, result)
	require.NotNil(t, gotReq)
	assert.Equal(t, "97c5d9f0-7a5c-4a61-9f2a-09f4903de44e", gotReq.URL.Query().Get("instance_id"))
	assert.Equal(t, "42", gotReq.URL.Query().Get("start_count"))
	assert.Equal(t, "2", gotReq.URL.Query().Get("starts_since_last_check"))
	assert.Equal(t, 42, cfg.StartCount)
	assert.Equal(t, 42, cfg.LastReportedStartCount)
	assert.Equal(t, now, cfg.LastVersionCheckAt)
}

func TestRun_SkipsDevVersionWithoutExplicitEndpoint(t *testing.T) {
	called := false

	result, err := run(context.Background(), options{
		Config:  &Config{},
		Version: "development",
		URL:     "https://updates.example/check",
		Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("unexpected request")
		})},
		Env: func(string) string { return "" },
	})

	require.NoError(t, err)
	assert.Nil(t, result)
	assert.False(t, called)
}

func TestRun_ExplicitEndpointAllowsDevVersion(t *testing.T) {
	called := false

	result, err := run(context.Background(), options{
		Config:  &Config{},
		Version: "development",
		URL:     "https://updates.example/default",
		Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			assert.Equal(t, "https://override.example/check", req.URL.Scheme+"://"+req.URL.Host+req.URL.Path)
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		})},
		SaveConfig: func(*Config) error { return nil },
		Env: func(key string) string {
			if key == URLEnv {
				return "https://override.example/check"
			}
			return ""
		},
	})

	require.NoError(t, err)
	assert.Nil(t, result)
	assert.True(t, called)
}

func TestLoadConfig_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("POUTINE_CONFIG_DIR", dir)

	loaded, err := LoadConfig()
	require.NoError(t, err)
	assert.Nil(t, loaded)

	cfg := &Config{
		InstanceID:             "2ed05245-10d7-4d21-a8e8-7c4e8a9851b4",
		StartCount:             3,
		LastReportedStartCount: 2,
		LastVersionCheckAt:     time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC),
	}
	require.NoError(t, SaveConfig(cfg))

	loaded, err = LoadConfig()
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, cfg.InstanceID, loaded.InstanceID)
	assert.Equal(t, cfg.StartCount, loaded.StartCount)
	assert.Equal(t, cfg.LastReportedStartCount, loaded.LastReportedStartCount)
	assert.True(t, cfg.LastVersionCheckAt.Equal(loaded.LastVersionCheckAt))
}

func TestRun_DisabledShortCircuitsBeforeAnyDiskWrite(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("POUTINE_CONFIG_DIR", dir)
	t.Setenv(DisableEnv, "")

	// Disabled via the option (CLI flag / config path).
	result := Run(context.Background(), "v0.18.0", true)
	assert.Nil(t, result)

	_, err := os.Stat(filepath.Join(dir, "config.yaml"))
	assert.True(t, os.IsNotExist(err), "no state file should be written when disabled")

	// Disabled via env var, even if the option is false.
	t.Setenv(DisableEnv, "1")
	result = Run(context.Background(), "v0.18.0", false)
	assert.Nil(t, result)

	_, err = os.Stat(filepath.Join(dir, "config.yaml"))
	assert.True(t, os.IsNotExist(err), "no state file should be written when disabled by env")
}

func TestIsDisabledByEnv(t *testing.T) {
	for _, value := range []string{"1", "true", "TRUE", "yes", "on"} {
		assert.True(t, isDisabledByEnv(value), value)
	}
	for _, value := range []string{"", "0", "false", "no", "off", "anything"} {
		assert.False(t, isDisabledByEnv(value), value)
	}
}
