package main

import (
	"context"
)

const image = "ghcr.io/boostsecurityio/poutine"
const currentVersion = "0.11.0@sha256:16cb292caf729d72a412bb4c06a54619ecc48aa6e687017e45eabd4c2023ca20"

type Poutine struct {
	Config     string
	ConfigSrc  *Directory
	Format     string
	Scm        string
	ScmBaseUrl string
	Threads    string
	Version    string
}

// Poutine analysis options
func New(ctx context.Context,
	// Path to the configuration file
	//+optional
	config string,
	// Directory containing additional configuration files
	// +optional
	configSrc *Directory,
	// Output format (pretty, json, sarif)
	//+optional
	format string,
	// SCM platform
	//+optional
	scm string,
	// Base URI of the self-hosted SCM platform
	//+optional
	scmBaseUrl string,
	// The number of threads to use for analysis
	// +optional
	threads string,
	// Version of poutine to use
	//+optional
	version string,

) *Poutine {
	return &Poutine{
		Config:     config,
		ConfigSrc:  configSrc,
		Format:     format,
		Scm:        scm,
		ScmBaseUrl: scmBaseUrl,
		Threads:    threads,
		Version:    version,
	}
}

func (m *Poutine) Container() *Container {
	version := m.Version
	if version == "" {
		version = currentVersion
	}

	return dag.Container().
		From(image + ":" + version).
		WithoutEntrypoint().
		WithExec([]string{"git", "config", "--global", "--add", "safe.directory", "/src"}).
		With(func(c *Container) *Container {
			if m.ConfigSrc != nil {
				return c.
					WithMountedDirectory("/config", m.ConfigSrc).
					WithWorkdir("/config")
			} else {
				return c.WithWorkdir("/src")
			}
		})
}

// Analyze a Git repository in a directory
func (m *Poutine) AnalyzeLocal(ctx context.Context, src *Directory) (string, error) {
	args := []string{"poutine", "analyze_local", "/src"}
	args = append(args, m.poutineArgs()...)

	return m.Container().
		WithMountedDirectory("/src", src).
		WithExec(args).
		Stdout(ctx)
}

// Analyze a remote repository
func (m *Poutine) AnalyzeRepo(ctx context.Context,
	// Repository to analyze in the format owner/repo
	repo string,
	// SCM access token
	token *Secret,
) (string, error) {
	args := []string{"poutine", "analyze_repo", repo}
	args = append(args, m.poutineArgs()...)

	return m.Container().
		WithSecretVariable("GH_TOKEN", token).
		WithExec(args).
		Stdout(ctx)
}

// Analyze an organization's repositories
func (m *Poutine) AnalyzeOrg(ctx context.Context,
	// Organization name
	org string,
	// SCM access token
	token *Secret,
	// Ignore forked repositories
	//+optional
	ignoreForks bool,
) (string, error) {
	args := []string{"poutine", "analyze_org", org}
	args = append(args, m.poutineArgs()...)

	if ignoreForks {
		args = append(args, "--ignore-forks")
	}

	return m.Container().
		WithSecretVariable("GH_TOKEN", token).
		WithExec(args).
		Stdout(ctx)
}

func (m *Poutine) poutineArgs() []string {
	args := []string{}
	if m.Format != "" {
		args = append(args, "--format", m.Format)
	}

	if m.Config != "" {
		args = append(args, "--config", m.Config)
	}

	if m.Scm != "" {
		args = append(args, "--scm", m.Scm)
	}

	if m.ScmBaseUrl != "" {
		args = append(args, "--scm-base-url", m.ScmBaseUrl)
	}

	if m.Threads != "" {
		args = append(args, "--threads", m.Threads)
	}

	return args
}
