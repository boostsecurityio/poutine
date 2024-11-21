package scanner

import (
	"context"
	"fmt"
	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/boostsecurityio/poutine/providers/pkgsupply"
	"github.com/boostsecurityio/poutine/results"
)

type ReputationClient interface {
	GetReputation(ctx context.Context, purls []string) (*pkgsupply.ReputationResponse, error)
}

type Inventory struct {
	opa             *opa.Opa
	pkgsupplyClient ReputationClient
	providerVersion string
	provider        string
}

func NewInventory(opa *opa.Opa, pkgSupplyClient ReputationClient, provider string, providerVersion string) *Inventory {
	return &Inventory{
		opa:             opa,
		pkgsupplyClient: pkgSupplyClient,
		provider:        provider,
		providerVersion: providerVersion,
	}
}

func (i *Inventory) ScanPackage(ctx context.Context, pkgInsights models.PackageInsights, workdir string) (*models.PackageInsights, error) {
	inventoryScanner := NewInventoryScanner(workdir)

	refPkgInsights := &pkgInsights

	if err := inventoryScanner.Run(refPkgInsights); err != nil {
		return nil, fmt.Errorf("failed to run inventory scanner on package: %w", err)
	}

	if err := i.performDependenciesInventory(ctx, refPkgInsights); err != nil {
		return nil, fmt.Errorf("failed to perform dependencies inventory on package: %w", err)
	}

	findingsResults, err := i.analyzePackageForFindings(ctx, pkgInsights)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze package for findings: %w", err)
	}

	if findingsResults != nil {
		refPkgInsights.FindingsResults = *findingsResults
	}

	return refPkgInsights, nil
}

func (i *Inventory) performDependenciesInventory(ctx context.Context, pkg *models.PackageInsights) error {
	result := opa.InventoryResult{}
	err := i.opa.Eval(ctx,
		"data.poutine.queries.inventory.result",
		map[string]interface{}{
			"packages": []interface{}{pkg},
		},
		&result,
	)
	if err != nil {
		return err
	}

	pkg.BuildDependencies = result.BuildDependencies
	pkg.PackageDependencies = result.PackageDependencies

	return nil
}

func (i *Inventory) Purls(pkgInsights models.PackageInsights) []string {
	set := make(map[string]bool)
	for _, dep := range pkgInsights.BuildDependencies {
		set[dep] = true
	}
	for _, dep := range pkgInsights.PackageDependencies {
		set[dep] = true
	}

	purls := make([]string, 0, len(set))
	for purl := range set {
		purls = append(purls, purl)
	}

	return purls
}

func (i *Inventory) analyzePackageForFindings(ctx context.Context, pkgInsights models.PackageInsights) (*results.FindingsResult, error) {
	analysisResults := &results.FindingsResult{}
	reputation, err := i.reputation(ctx, pkgInsights)
	if err != nil && i.pkgsupplyClient != nil {
		return nil, err
	}

	err = i.opa.Eval(ctx,
		"data.poutine.queries.findings.result",
		map[string]interface{}{
			"packages": []models.PackageInsights{
				pkgInsights,
			},
			"reputation": reputation,
			"provider":   i.provider,
			"version":    i.providerVersion,
		},
		analysisResults,
	)

	if err != nil {
		return nil, err
	}

	return analysisResults, nil
}

func (i *Inventory) reputation(ctx context.Context, pkgInsights models.PackageInsights) (*pkgsupply.ReputationResponse, error) {
	if i.pkgsupplyClient == nil {
		return nil, fmt.Errorf("no pkgsupply client")
	}

	return i.pkgsupplyClient.GetReputation(ctx, i.Purls(pkgInsights))
}
