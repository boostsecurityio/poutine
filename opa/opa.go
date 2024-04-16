package opa

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/print"
	"io/fs"
)

//go:embed rego
var regoFs embed.FS

type Opa struct {
	Compiler *ast.Compiler
}

func NewOpa() (*Opa, error) {
	modules := make(map[string]string)
	err := fs.WalkDir(regoFs, "rego", func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return err
		}

		content, err := regoFs.ReadFile(path)
		if err != nil {
			return err
		}

		modules[path] = string(content)
		return nil
	})
	if err != nil {
		return nil, err
	}

	registerBuiltinFunctions()

	compiler, err := ast.CompileModulesWithOpt(modules, ast.CompileOpts{
		EnablePrintStatements: true,
	})

	if err != nil {
		return nil, err
	}

	return &Opa{
		Compiler: compiler,
	}, nil
}

func (o *Opa) Print(ctx print.Context, s string) error {
	fmt.Println(s)
	return nil
}

func (o *Opa) Eval(ctx context.Context, query string, input map[string]interface{}, result interface{}) error {
	rego := rego.New(
		rego.Query(query),
		rego.Compiler(o.Compiler),
		rego.PrintHook(o),
		rego.Input(input),
		rego.Imports([]string{"data.poutine.utils"}),
	)

	rs, err := rego.Eval(ctx)
	if err != nil {
		return err
	}

	if len(rs) == 0 {
		return fmt.Errorf("opa result set is empty")
	}

	val := rs[0].Expressions[0].Value
	data, err := json.Marshal(val)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, result)
}
