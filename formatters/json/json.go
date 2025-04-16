package json

import (
	"context"
	"errors"
	"fmt"
	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/boostsecurityio/poutine/results"
	"io"
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
