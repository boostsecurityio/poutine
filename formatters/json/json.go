package json

import (
	"context"
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

func (f *Format) Format(ctx context.Context, report *results.FindingsResult, packages []*models.PackageInsights) error {
	var result struct {
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	err := f.opa.Eval(ctx,
		"data.poutine.queries.format.result",
		map[string]interface{}{
			"packages":        packages,
			"results":         report,
			"format":          f.format,
			"builtin_formats": []string{"sarif", "pretty"},
		},
		&result,
	)
	if err != nil {
		return err
	}

	if result.Error != "" {
		return fmt.Errorf(result.Error)
	}

	fmt.Fprint(f.out, result.Output)
	return nil
}
