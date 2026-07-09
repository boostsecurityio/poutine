package opa

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/boostsecurityio/poutine/models"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/loader"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown/print"
	"github.com/open-policy-agent/opa/v1/types"
	"github.com/rs/zerolog/log"
)

//go:embed rego
var regoFs embed.FS

//go:embed capabilities.json
var capabilitiesJson []byte

type embeddedSource struct {
	fs embed.FS
}

type Opa struct {
	Compiler            *ast.Compiler
	Store               storage.Store
	LoadPaths           []string
	customEmbeddedRules []embeddedSource

	// preparedMu guards prepared. prepared caches one compiled query plan
	// (rego.PreparedEvalQuery) per query string so Eval does not re-run
	// PrepareForEval — the query compile + evaluation-plan build — on every call.
	// The cache is invalidated in Compile, which is the only thing that changes
	// the rule set the plans are bound to (config lives in the store and is read
	// fresh on every eval, so it needs no invalidation).
	preparedMu sync.RWMutex
	prepared   map[string]rego.PreparedEvalQuery
}

func NewOpa(ctx context.Context, config *models.Config) (*Opa, error) {
	registerBuiltinFunctions()

	newOpa := &Opa{
		Store: inmem.NewFromObject(map[string]interface {
		}{
			"config": models.DefaultConfig(),
		}),
	}

	if err := newOpa.WithConfig(ctx, config); err != nil {
		return nil, fmt.Errorf("failed to set opa with config: %w", err)
	}

	subset := []string{}
	for _, skip := range config.Skip {
		if skip.HasOnlyRule() {
			subset = append(subset, skip.Rule...)
		}
	}

	if err := newOpa.Compile(ctx, subset, config.AllowedRules); err != nil {
		return nil, fmt.Errorf("failed to initialize opa compiler: %w", err)
	}

	return newOpa, nil
}

// NewOpaWithEmbeddedRules creates a new Opa instance with custom embedded Rego rules.
// This allows library consumers to embed their own Rego rules directly in their binaries
// alongside Poutine's built-in rules, creating fully self-contained deployments.
//
// Example usage:
//
//	//go:embed rules
//	var CustomRules embed.FS
//
//	opa, err := poutineOpa.NewOpaWithEmbeddedRules(ctx, config, CustomRules)
func NewOpaWithEmbeddedRules(ctx context.Context, config *models.Config, customFS embed.FS) (*Opa, error) {
	registerBuiltinFunctions()

	newOpa := &Opa{
		Store: inmem.NewFromObject(map[string]interface {
		}{
			"config": models.DefaultConfig(),
		}),
		customEmbeddedRules: []embeddedSource{{fs: customFS}},
	}

	if err := newOpa.WithConfig(ctx, config); err != nil {
		return nil, fmt.Errorf("failed to set opa with config: %w", err)
	}

	subset := []string{}
	for _, skip := range config.Skip {
		if skip.HasOnlyRule() {
			subset = append(subset, skip.Rule...)
		}
	}

	if err := newOpa.Compile(ctx, subset, config.AllowedRules); err != nil {
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

func skipRule(path string, skip []string, allowed []string) bool {
	if !strings.Contains(filepath.ToSlash(path), "/rules/") {
		return false
	}
	filename := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if len(allowed) > 0 {
		if !slices.Contains(allowed, filename) {
			return true
		}
	}
	if slices.Contains(skip, filename) {
		return true
	}
	return false
}

func (o *Opa) Compile(ctx context.Context, skip []string, allowed []string) error {
	modules := make(map[string]string)

	// Load Poutine's built-in rules
	err := fs.WalkDir(regoFs, "rego", func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return err
		}

		if skipRule(path, skip, allowed) {
			return nil
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

	// Load custom embedded rules
	for _, source := range o.customEmbeddedRules {
		err := fs.WalkDir(source.fs, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() {
				return nil
			}

			if skipRule(path, skip, allowed) {
				return nil
			}

			content, err := source.fs.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read custom embedded rule %s: %w", path, err)
			}

			modules["custom/"+path] = string(content)
			return nil
		})
		if err != nil {
			return fmt.Errorf("failed to load custom embedded rules: %w", err)
		}
	}

	// Load rules from filesystem paths
	result, err := loader.NewFileLoader().
		WithProcessAnnotation(true).
		WithRegoVersion(ast.RegoV0CompatV1).
		Filtered(o.LoadPaths, fileLoaderFilter)
	if err != nil {
		return err
	}

	for name, mod := range result.Modules {
		if skipRule(name, skip, allowed) {
			continue
		}
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

	// Cached plans are bound to the previous compiler (and thus the previous rule
	// set); drop them so subsequent Evals re-prepare against the new compiler.
	o.preparedMu.Lock()
	o.prepared = nil
	o.preparedMu.Unlock()

	return nil
}

func (o *Opa) Eval(ctx context.Context, query string, input map[string]interface{}, result interface{}) error {
	pq, err := o.preparedQuery(ctx, query)
	if err != nil {
		return err
	}

	// Input is supplied per call via EvalInput; the cached plan holds no input,
	// and each Eval opens a fresh store transaction, so config changes written by
	// WithConfig are observed here without invalidating the cache.
	rs, err := pq.Eval(ctx, rego.EvalInput(input))
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

// preparedQuery returns the cached compiled plan for query, preparing (and
// caching) it on first use. The compiled plan is bound to the current compiler
// and is safe for concurrent evaluation; Compile clears the cache when it swaps
// the compiler out.
func (o *Opa) preparedQuery(ctx context.Context, query string) (rego.PreparedEvalQuery, error) {
	o.preparedMu.RLock()
	pq, ok := o.prepared[query]
	o.preparedMu.RUnlock()
	if ok {
		return pq, nil
	}

	pq, err := rego.New(
		rego.Query(query),
		rego.Compiler(o.Compiler),
		rego.PrintHook(o),
		rego.Imports([]string{"data.poutine.utils"}),
		rego.Store(o.Store),
	).PrepareForEval(ctx)
	if err != nil {
		return rego.PreparedEvalQuery{}, fmt.Errorf("failed to prepare query: %w", err)
	}

	o.preparedMu.Lock()
	defer o.preparedMu.Unlock()
	// Another goroutine may have prepared the same query while we were preparing;
	// prefer the already-cached one so all callers share a single plan.
	if existing, ok := o.prepared[query]; ok {
		return existing, nil
	}
	if o.prepared == nil {
		o.prepared = make(map[string]rego.PreparedEvalQuery)
	}
	o.prepared[query] = pq
	return pq, nil
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

	// Register custom builtins so the compiler recognizes them during validation.
	// These match the functions registered at runtime via rego.RegisterBuiltinX() in builtins.go.
	capabilites.Builtins = append(capabilites.Builtins,
		&ast.Builtin{
			Name: "purl.parse_docker_image",
			Decl: types.NewFunction(types.Args(types.S), types.S),
		},
		&ast.Builtin{
			Name: "purl.parse_github_actions",
			Decl: types.NewFunction(types.Args(types.S, types.S, types.S), types.S),
		},
		&ast.Builtin{
			Name: "semver.constraint_check",
			Decl: types.NewFunction(types.Args(types.S, types.S), types.S),
		},
	)

	return capabilites, nil
}

func fileLoaderFilter(abspath string, info os.FileInfo, depth int) bool {
	if !info.IsDir() {
		return !strings.HasSuffix(abspath, ".rego")
	}
	return false
}
