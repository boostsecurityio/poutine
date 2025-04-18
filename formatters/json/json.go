package json

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/boostsecurityio/poutine/results"
)

func NewFormat(opa *opa.Opa, format string, out io.Writer) *Format {
	return &Format{
		opa:    opa,
		format: format,
		out:    out,
	}
}

type Format struct {
	opa    *opa.Opa
	out    io.Writer
	format string
}

func (f *Format) Format(ctx context.Context, packages []*models.PackageInsights) error {
	var result struct {
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	report := &results.FindingsResult{
		Findings: make([]results.Finding, 0),
		Rules:    map[string]results.Rule{},
	}
	for _, pkg := range packages {
		for _, finding := range pkg.FindingsResults.Findings {
			report.Findings = append(report.Findings, finding)
		}
		for _, rule := range pkg.FindingsResults.Rules {
			report.Rules[rule.Id] = rule
		}
	}
	if err := f.opa.Eval(ctx,
		"data.poutine.queries.format.result",
		map[string]interface{}{
			"packages":        packages,
			"results":         report,
			"format":          f.format,
			"builtin_formats": []string{"sarif", "pretty"},
		},
		&result,
	); err != nil {
		return err
	}

	if result.Error != "" {
		return errors.New(result.Error)
	}

	fmt.Fprint(f.out, result.Output)
	return nil
}

func (f *Format) FormatWithPath(ctx context.Context, packages []*models.PackageInsights, pathAssociations map[string][]models.BranchInfo) error {
	var result struct {
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	report := &results.FindingsResult{
		Findings: make([]results.Finding, 0),
		Rules:    map[string]results.Rule{},
	}
	for _, pkg := range packages {
		for _, finding := range pkg.FindingsResults.Findings {
			report.Findings = append(report.Findings, finding)
		}
		for _, rule := range pkg.FindingsResults.Rules {
			report.Rules[rule.Id] = rule
		}
	}
	err := f.opa.Eval(ctx,
		"data.poutine.queries.format.result",
		map[string]any{
			"packages":        packages,
			"results":         report,
			"format":          f.format,
			"builtin_formats": []string{"sarif", "pretty"},
		},
		&result,
	)
	if err != nil {
		return fmt.Errorf("error evaluating rego: %w", err)
	}

	if result.Error != "" {
		return fmt.Errorf("error in rego format: %s", result.Error)
	}

	// Replace path with blobsha
	var resultJson results.FindingsResult
	err = json.Unmarshal([]byte(result.Output), &resultJson)
	if err != nil {
		return fmt.Errorf("error unmarshal rego output: %w", err)
	}
	for i, v := range resultJson.Findings {
		filename := filepath.Base(v.Meta.Path)
		resultJson.Findings[i].Meta.Blobsha = strings.TrimRight(filename, filepath.Ext(filename))
		resultJson.Findings[i].Meta.Path = ""
	}
	resultJsonStr, err := json.Marshal(resultJson)
	if err != nil {
		return fmt.Errorf("error marshal result: %w", err)
	}

	// Add blobshas associations
	var resultBlobshas map[string]any
	err = json.Unmarshal(resultJsonStr, &resultBlobshas)
	if err != nil {
		return fmt.Errorf("error unmarshal rego output: %w", err)
	}
	resultBlobshas["blobshas"] = pathAssociations
	content, err := json.Marshal(resultBlobshas)
	if err != nil {
		return fmt.Errorf("error marshal result: %w", err)
	}

	fmt.Fprint(f.out, string(content))
	return nil
}
