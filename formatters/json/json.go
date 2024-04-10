package json

import (
	"context"
	"fmt"
	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/opa"
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

func (f *Format) Format(ctx context.Context, report *opa.FindingsResult, packages []*models.PackageInsights) error {
	var reportString string
	err := f.opa.Eval(ctx,
		"data.poutine.format[input.format].result",
		map[string]interface{}{
			"packages": packages,
			"results":  report,
			"format":   f.format,
		},
		&reportString,
	)
	if err != nil {
		return err
	}

	fmt.Fprint(f.out, reportString)
	return nil
}
