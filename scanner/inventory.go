package scanner

import (
	"context"
	"fmt"
	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/boostsecurityio/poutine/providers/pkgsupply"
	"sync"
)

type ReputationClient interface {
	GetReputation(ctx context.Context, purls []string) (*pkgsupply.ReputationResponse, error)
}

type Inventory struct {
	Packages        []*models.PackageInsights
	providerVersion string
	provider        string

	opa             *opa.Opa
	pkgsupplyClient ReputationClient
}

var packageMu sync.Mutex

func NewInventory(opa *opa.Opa, pkgsupplyClient ReputationClient, provider string, providerVersion string) *Inventory {
	return &Inventory{
		Packages:        make([]*models.PackageInsights, 0),
		opa:             opa,
		pkgsupplyClient: pkgsupplyClient,
		provider:        provider,
		providerVersion: providerVersion,
	}
}

func (i *Inventory) AddPackage(ctx context.Context, pkg *models.PackageInsights, workdir string) error {
	s := NewScanner(workdir)
	s.Package = pkg

	err := s.Run(ctx, i.opa)
	if err != nil {
		return err
	}

	packageMu.Lock()
	defer packageMu.Unlock()
	i.Packages = append(i.Packages, s.Package)
	return nil
}

func (i *Inventory) Purls() []string {
	set := make(map[string]bool)
	for _, pkg := range i.Packages {
		for _, dep := range pkg.BuildDependencies {
			set[dep] = true
		}
		for _, dep := range pkg.PackageDependencies {
			set[dep] = true
		}
	}

	purls := make([]string, 0, len(set))
	for purl := range set {
		purls = append(purls, purl)
	}

	return purls
}

func (i *Inventory) Findings(ctx context.Context) (*opa.FindingsResult, error) {
	results := &opa.FindingsResult{}
	reputation, err := i.Reputation(ctx)
	if err != nil && i.pkgsupplyClient != nil {
		return nil, err
	}

	err = i.opa.Eval(ctx,
		"data.poutine.queries.findings.result",
		map[string]interface{}{
			"packages":   i.Packages,
			"reputation": reputation,
			"provider":   i.provider,
			"version":    i.providerVersion,
		},
		results,
	)

	if err != nil {
		return nil, err
	}

	return results, nil
}

func (i *Inventory) Reputation(ctx context.Context) (*pkgsupply.ReputationResponse, error) {
	if i.pkgsupplyClient == nil {
		return nil, fmt.Errorf("no pkgsupply client")
	}

	return i.pkgsupplyClient.GetReputation(ctx, i.Purls())
}
