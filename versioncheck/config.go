// Package versioncheck implements a lightweight, opt-out version-check that
// reports anonymous start telemetry to the Boost OSS telemetry endpoint and
// notifies the user when a newer poutine release is available.
package versioncheck

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the user-level state persisted between poutine invocations to
// support the once-per-day version check. It is intentionally separate from
// the project-level models.Config that is loaded from .poutine.yml.
type Config struct {
	InstanceID             string    `yaml:"instance_id,omitempty"`
	StartCount             int       `yaml:"start_count,omitempty"`
	LastReportedStartCount int       `yaml:"last_reported_start_count,omitempty"`
	LastVersionCheckAt     time.Time `yaml:"last_version_check_timestamp,omitempty"`
}

// ConfigPath returns the path to the user-level state file. It honors
// POUTINE_CONFIG_DIR for tests and constrained environments and otherwise
// defaults to ~/.poutine/config.yaml.
func ConfigPath() string {
	if dir := os.Getenv("POUTINE_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, "config.yaml")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".poutine", "config.yaml")
}

// LoadConfig reads the user-level state file. A missing file is not an error
// and yields a nil Config so callers can treat it as a first run.
func LoadConfig() (*Config, error) {
	path := ConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read version-check state %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid version-check state: %w", err)
	}
	return &cfg, nil
}

// SaveConfig writes the user-level state file, creating the parent directory
// when needed. The file is written with restrictive permissions because it
// holds an anonymous instance identifier.
func SaveConfig(cfg *Config) error {
	path := ConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create version-check state dir: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal version-check state: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write version-check state %s: %w", path, err)
	}
	return nil
}
