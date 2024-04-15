package sarif

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/boostsecurityio/poutine/docs"
	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

func NewFormat(out io.Writer) *Format {
	return &Format{
		out: out,
	}
}

type Format struct {
	out io.Writer
}

func (f *Format) Format(ctx context.Context, report *opa.FindingsResult, packages []*models.PackageInsights) error {
	sarifReport, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}

	normalizePurl := func(purl string) string {
		parts := strings.Split(purl, "@")
		return parts[0]
	}

	findingsByPurl := make(map[string][]opa.Finding)
	for _, finding := range report.Findings {
		findingsByPurl[finding.Purl] = append(findingsByPurl[finding.Purl], finding)
	}

	docs := docs.GetPagesContent()

	for _, pkg := range packages {
		run := sarif.NewRunWithInformationURI("poutine", "https://github.com/boostsecurityio/poutine")
		run.Tool.Driver.WithSemanticVersion("0.9.0")
		run.Properties = map[string]interface{}{
			"purl": pkg.Purl,
		}

		run.AddVersionControlProvenance(
			sarif.NewVersionControlDetails().
				WithRepositoryURI(pkg.GetSourceGitRepoURI()).
				WithRevisionID(pkg.SourceGitCommitSha).
				WithBranch(pkg.SourceGitRef),
		)

		pkgFindings := findingsByPurl[pkg.Purl]
		for _, depPurl := range pkg.PackageDependencies {
			normalizedDepPurl := normalizePurl(depPurl)
			if depFindings, exists := findingsByPurl[normalizedDepPurl]; exists {
				pkgFindings = append(pkgFindings, depFindings...)
			}
		}

		for _, finding := range pkgFindings {
			rule := report.Rules[finding.RuleId]
			ruleId := rule.Id
			ruleDescription := rule.Description
			meta := finding.Meta
			path := meta.Path
			line := meta.Line
			if line == 0 {
				line = 1
			}
			ruleDoc := docs[ruleId]
			ruleUrl := fmt.Sprintf("https://github.com/boostsecurityio/poutine/tree/main/docs/content/en/rules/%s.md", ruleId)

			run.AddRule(ruleId).
				WithName(rule.Title).
				WithDescription(rule.Title).
				WithFullDescription(
					sarif.NewMultiformatMessageString(ruleDescription),
				).
				WithHelpURI(ruleUrl).
				WithTextHelp(ruleUrl).
				WithMarkdownHelp(ruleDoc)

			run.AddDistinctArtifact(path)

			run.CreateResultForRule(ruleId).
				WithLevel(rule.Level).
				WithMessage(sarif.NewTextMessage(ruleDescription)).
				WithPartialFingerPrints(map[string]interface{}{
					"primaryLocationLineHash": finding.GenerateFindingFingerprint(),
				}).
				AddLocation(
					sarif.NewLocationWithPhysicalLocation(
						sarif.NewPhysicalLocation().
							WithArtifactLocation(
								sarif.NewSimpleArtifactLocation(path),
							).
							WithRegion(
								sarif.NewSimpleRegion(line, line),
							),
					),
				)
		}
		sarifReport.AddRun(run)
	}

	_ = sarifReport.PrettyWrite(f.out)

	return nil
}
