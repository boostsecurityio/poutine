package opa

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"github.com/boostsecurityio/poutine/models"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/loader"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown/print"
	"github.com/rs/zerolog/log"
	"io/fs"
	"os"
	"strings"
)

//go:embed rego
var regoFs embed.FS

//go:embed capabilities.json
var capabilitiesJson []byte

type Opa struct {
	Compiler  *ast.Compiler
	Store     storage.Store
	LoadPaths []string
}

func NewOpa(ctx context.Context, config *models.Config) (*Opa, error) {
	registerBuiltinFunctions()

	newOpa := &Opa{
		Store: inmem.NewFromObject(map[string]interface {
		}{
			"config": models.DefaultConfig(),
		}),
	}

	err := newOpa.WithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to set opa with config: %w", err)
	}

	err = newOpa.Compile(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize opa compiler: %w", err)
	}

	return newOpa, nil
}

func (o *Opa) Print(ctx print.Context, s string) error {
	log.Debug().Ctx(ctx.Context).Str("location", ctx.Location.String()).Msg(s)
	return nil
}

func (o *Opa) WithConfig(ctx context.Context, config *models.Config) error {
	o.LoadPaths = make([]string, 0)
	for _, include := range config.Include {
		for _, path := range include.Path {
			if path == "" {
				continue
			}
			o.LoadPaths = append(o.LoadPaths, path)
		}
	}

	return storage.WriteOne(ctx,
		o.Store,
		storage.ReplaceOp,
		storage.MustParsePath("/config"),
		config,
	)
}

func (o *Opa) Compile(ctx context.Context) error {
	modules := make(map[string]string)
	err := fs.WalkDir(regoFs, "rego", func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return err
		}

		content, err := regoFs.ReadFile(path)
		if err != nil {
			return err
		}

		modules["poutine/opa/"+path] = string(content)
		return nil
	})
	if err != nil {
		return err
	}

	result, err := loader.NewFileLoader().
		WithProcessAnnotation(true).
		WithRegoVersion(ast.RegoV0CompatV1).
		Filtered(o.LoadPaths, fileLoaderFilter)
	if err != nil {
		return err
	}

	for name, mod := range result.Modules {
		modules["include/"+name] = string(mod.Raw)
	}

	capabilities, err := Capabilities()
	if err != nil {
		return err
	}

	compiler, err := ast.CompileModulesWithOpt(modules, ast.CompileOpts{
		EnablePrintStatements: true,
		ParserOptions: ast.ParserOptions{
			Capabilities: capabilities,
		},
	})

	if err != nil {
		return err
	}

	o.Compiler = compiler
	return nil
}

func (o *Opa) Eval(ctx context.Context, query string, input map[string]interface{}, result interface{}) error {
	regoInstance := rego.New(
		rego.Query(query),
		rego.Compiler(o.Compiler),
		rego.PrintHook(o),
		rego.Input(input),
		rego.Imports([]string{"data.poutine.utils"}),
		rego.Store(o.Store),
	)

	rs, err := regoInstance.Eval(ctx)
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

func Capabilities() (*ast.Capabilities, error) {
	capabilites := &ast.Capabilities{}
	err := json.Unmarshal(capabilitiesJson, capabilites)
	if err != nil {
		return nil, err
	}
	if len(capabilites.AllowNet) != 0 {
		return nil, fmt.Errorf("capabilities allow_net not empty")
	}
	return capabilites, nil
}

func fileLoaderFilter(abspath string, info os.FileInfo, depth int) bool {
	if !info.IsDir() {
		return !strings.HasSuffix(abspath, ".rego")
	}
	return false
}
