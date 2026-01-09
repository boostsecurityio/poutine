package sarif

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/boostsecurityio/poutine/results"

	"github.com/boostsecurityio/poutine/docs"
	"github.com/boostsecurityio/poutine/models"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

func NewFormat(out io.Writer, version string) *Format {
	return &Format{
		out:     out,
		version: version,
	}
}

type Format struct {
	out     io.Writer
	version string
}

func (f *Format) Format(ctx context.Context, packages []*models.PackageInsights) error {
	sarifReport, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}

	normalizePurl := func(purl string) string {
		parts := strings.Split(purl, "@")
		return parts[0]
	}

	levelToConfidence := func(level string) string {
		switch level {
		case "error":
			return "high"
		case "warning":
			return "medium"
		case "note":
			return "low"
		case "none":
			return "not_set"
		default:
			return "not_set"
		}
	}

	docs := docs.GetPagesContent()

	for _, pkg := range packages {
		run := sarif.NewRunWithInformationURI("poutine", "https://github.com/boostsecurityio/poutine")
		run.Tool.Driver.WithSemanticVersion(f.version)
		run.Tool.Driver.WithOrganization("boostsecurity")
		run.Properties = map[string]interface{}{
			"purl": pkg.Purl,
		}
		version := "1.0.0"
		organization := "boostsecurity"

		taxonomy := &sarif.ToolComponent{
			Name:         "boost/sast",
			Version:      &version,
			Organization: &organization,
			Rules:        []*sarif.ReportingDescriptor{},
		}

		taxonomyRef := sarif.NewToolComponentReference().
			WithName("boost/sast").
			WithIndex(0).
			WithGuid("00000000-0000-0000-0000-000000000000")
		run.Tool.Driver.WithSupportedTaxonomies([]*sarif.ToolComponentReference{taxonomyRef})

		run.WithTaxonomies([]*sarif.ToolComponent{taxonomy})

		sourceGitRepoURI := pkg.GetSourceGitRepoURI()

		if IsValidGitURL(sourceGitRepoURI) {
			versionControlProvenance := sarif.NewVersionControlDetails().
				WithRevisionID(pkg.SourceGitCommitSha).
				WithBranch(pkg.SourceGitRef).
				WithRepositoryURI(sourceGitRepoURI)
			run.AddVersionControlProvenance(
				versionControlProvenance,
			)
		}

		findingsByPurl := make(map[string][]results.Finding)
		for _, finding := range pkg.FindingsResults.Findings {
			findingsByPurl[finding.Purl] = append(findingsByPurl[finding.Purl], finding)
		}

		pkgFindings := findingsByPurl[pkg.Purl]
		for _, depPurl := range pkg.PackageDependencies {
			normalizedDepPurl := normalizePurl(depPurl)
			if depFindings, exists := findingsByPurl[normalizedDepPurl]; exists {
				pkgFindings = append(pkgFindings, depFindings...)
			}
		}

		for _, finding := range pkgFindings {
			rule := pkg.FindingsResults.Rules[finding.RuleId]
			ruleId := rule.Id
			ruleDescription := rule.Description
			meta := finding.Meta
			path := meta.Path
			line := meta.Line
			if line == 0 {
				line = 1
			}
			ruleDoc := docs[ruleId]
			ruleUrl := fmt.Sprintf("https://boostsecurityio.github.io/poutine/rules/%s", ruleId)

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

			fingerprint := finding.GenerateFindingFingerprint()
			confidence := levelToConfidence(rule.Level)

			result := run.CreateResultForRule(ruleId).
				WithLevel(rule.Level).
				WithMessage(sarif.NewTextMessage(ruleDescription)).
				WithPartialFingerPrints(map[string]interface{}{
					"primaryLocationLineHash": fingerprint,
				})

			result.AddLocation(
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

			result.AttachPropertyBag(&sarif.PropertyBag{
				Properties: map[string]interface{}{
					"boost/confidence": confidence,
				},
			})
		}
		sarifReport.AddRun(run)
	}

	_ = sarifReport.PrettyWrite(f.out)

	return nil
}

func (f *Format) FormatWithPath(ctx context.Context, packages []*models.PackageInsights, pathAssociations map[string][]*models.RepoInfo) error {
	return errors.New("not implemented")
}

// IsValidGitURL validates if a string is a valid Git URL (HTTP(S) or SSH format)
func IsValidGitURL(gitURL string) bool {
	if strings.HasPrefix(gitURL, "http://") || strings.HasPrefix(gitURL, "https://") {
		parsedURL, err := url.Parse(gitURL)
		if err != nil {
			return false
		}
		return parsedURL.Host != "" && parsedURL.Path != ""
	}

	if strings.HasPrefix(gitURL, "ssh://") {
		parsedURL, err := url.Parse(gitURL)
		if err != nil {
			return false
		}
		return parsedURL.Host != "" && parsedURL.Path != ""
	}

	sshPattern := regexp.MustCompile(`^[a-zA-Z0-9_-]+@[a-zA-Z0-9._-]+:[a-zA-Z0-9/._-]+$`)
	return sshPattern.MatchString(gitURL)
}
