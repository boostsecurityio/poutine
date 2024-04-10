package opa

import (
	"github.com/boostsecurityio/poutine/models"
	"github.com/hashicorp/go-version"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
)

func registerBuiltinFunctions() {
	rego.RegisterBuiltin1(
		&rego.Function{
			Name: "purl.parse_docker_image",
			Decl: types.NewFunction(types.Args(types.S), types.S),
		},
		func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
			var uses string
			if err := ast.As(a.Value, &uses); err != nil {
				return nil, err
			}

			purl, err := models.PurlFromDockerImage(uses)
			if err != nil {
				return nil, err
			}

			return ast.StringTerm(purl.String()), nil
		},
	)

	rego.RegisterBuiltin1(
		&rego.Function{
			Name: "purl.parse_github_actions",
			Decl: types.NewFunction(types.Args(types.S), types.S),
		},
		func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
			var uses string
			if err := ast.As(a.Value, &uses); err != nil {
				return nil, err
			}

			purl, err := models.PurlFromGithubActions(uses)
			if err != nil {
				return nil, err
			}

			return ast.StringTerm(purl.String()), nil
		},
	)

	rego.RegisterBuiltin2(
		&rego.Function{
			Name: "semver.constraint_check",
			Decl: types.NewFunction(types.Args(types.S, types.S), types.S),
		},
		func(_ rego.BuiltinContext, a *ast.Term, b *ast.Term) (*ast.Term, error) {
			var constraintsStr string
			if err := ast.As(a.Value, &constraintsStr); err != nil {
				return nil, err
			}

			var versionStr string
			if err := ast.As(b.Value, &versionStr); err != nil {
				return nil, err
			}

			semver, err := version.NewVersion(versionStr)
			if err != nil {
				print(err)
				return nil, err
			}

			constraints, err := version.NewConstraint(constraintsStr)
			if err != nil {
				return nil, err
			}

			return ast.BooleanTerm(constraints.Check(semver)), nil
		},
	)

}
