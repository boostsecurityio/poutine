package pretty

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/boostsecurityio/poutine/results"

	"github.com/rs/zerolog/log"

	"github.com/boostsecurityio/poutine/models"
	"github.com/olekukonko/tablewriter"
)

type Format struct {
}

func (f *Format) Format(ctx context.Context, packages []*models.PackageInsights) error {
	failures := map[string]int{}
	findings := map[string][]results.Finding{}
	rules := map[string]results.Rule{}

	for _, pkg := range packages {
		if len(pkg.FindingsResults.Findings) == 0 {
			log.Info().Msg("No results returned by analysis")
			continue
		}

		for _, finding := range pkg.FindingsResults.Findings {
			failures[finding.RuleId]++
			findings[finding.RuleId] = append(findings[finding.RuleId], finding)
		}

		for _, rule := range pkg.FindingsResults.Rules {
			rules[rule.Id] = rule
		}
	}

	printFindingsPerRule(os.Stdout, findings, rules)
	printSummaryTable(os.Stdout, failures, rules)

	return nil
}

func (f *Format) FormatWithPath(ctx context.Context, packages []*models.PackageInsights, pathAssociations map[string][]models.BranchInfo) error {
	failures := map[string]int{}
	rules := map[string]results.Rule{}

	for _, pkg := range packages {
		findings := map[string][]string{}
		for _, finding := range pkg.FindingsResults.Findings {
			failures[finding.RuleId]++
			filename := filepath.Base(finding.Meta.Path)
			filename = strings.TrimSuffix(filename, filepath.Ext(filename))
			findings[filename] = append(findings[filename], finding.RuleId)
		}

		for _, rule := range pkg.FindingsResults.Rules {
			rules[rule.Id] = rule
		}

		_ = f.printFindingsPerWorkflow(os.Stdout, findings, pkg.Purl, pathAssociations)
	}
	printSummaryTable(os.Stdout, failures, rules)

	return nil
}

func (f *Format) printFindingsPerWorkflow(out io.Writer, results map[string][]string, purlStr string, pathAssociations map[string][]models.BranchInfo) error {
	// Skip rules with no findings.
	table := tablewriter.NewWriter(out)
	table.SetAutoMergeCells(true)
	table.SetHeader([]string{"Workflow sha", "Rule", "Branch", "URL"})

	purl, err := models.NewPurl(purlStr)
	if err != nil {
		return err
	}
	for blobsha, branchInfos := range pathAssociations {
		findings := results[blobsha]
		if len(findings) == 0 {
			continue
		}
		largestElement := len(findings)
		sumPath := 0
		for _, branchInfo := range branchInfos {
			sumPath += len(branchInfo.FilePath)
		}
		blobshaTable := make([][]string, max(largestElement, sumPath))
		for i := range blobshaTable {
			blobshaTable[i] = make([]string, 4)
		}

		blobshaTable[0][0] = blobsha

		for i, finding := range findings {
			blobshaTable[i][1] = finding
		}

		index := 0
		for _, branchInfo := range branchInfos {
			for j, path := range branchInfo.FilePath {
				if j == 0 {
					blobshaTable[index][2] = branchInfo.BranchName
				}

				blobshaTable[index][3] = purl.Link() + "/tree/" + branchInfo.BranchName + "/" + path
				index += 1
			}
		}

		table.AppendBulk(blobshaTable)
		table.Append([]string{"", "", "", ""})
	}

	table.Render()
	fmt.Fprint(out, "\n")
	return nil
}

func printFindingsPerRule(out io.Writer, results map[string][]results.Finding, rules map[string]results.Rule) {

	var sortedRuleIDs []string
	for ruleID := range rules {
		sortedRuleIDs = append(sortedRuleIDs, ruleID)
	}
	sort.Strings(sortedRuleIDs)

	for _, ruleId := range sortedRuleIDs {
		// Skip rules with no findings.
		if len(results[ruleId]) == 0 {
			continue
		}

		table := tablewriter.NewWriter(out)
		table.SetAutoMergeCells(true)
		table.SetHeader([]string{"Repository", "Details", "URL"})

		fmt.Fprintf(out, "Rule: %s\n", rules[ruleId].Title)
		fmt.Fprintf(out, "Severity: %s\n", rules[ruleId].Level)
		fmt.Fprintf(out, "Description: %s\n", rules[ruleId].Description)
		fmt.Fprintf(out, "Documentation: https://boostsecurityio.github.io/poutine/rules/%s\n\n", ruleId)

		for _, finding := range results[ruleId] {
			purl, _ := models.NewPurl(finding.Purl)
			if purl.Version == "" && finding.Meta.Path != "" {
				purl.Version = "HEAD"
			}

			repo := purl.FullName()
			link := purl.Link()
			if purl.Version != "" {
				link += fmt.Sprintf("/tree/%s", purl.Version)
			}

			if finding.Meta.Path != "" {
				link += "/" + finding.Meta.Path
				if finding.Meta.Line > 0 {
					link = fmt.Sprintf("%s#L%d", link, finding.Meta.Line)
				}

				table.Append([]string{repo, finding.Meta.Path, link})
			}

			if finding.Meta.Job != "" {
				table.Append([]string{repo, "Job: " + finding.Meta.Job, link})
			}

			if finding.Meta.Step != "" {
				table.Append([]string{repo, "Step: " + finding.Meta.Step, link})
			}

			if finding.Meta.OsvId != "" {
				table.Append([]string{repo, "OSV ID: " + finding.Meta.OsvId, link})
			}

			if finding.Meta.Details != "" {
				table.Append([]string{repo, finding.Meta.Details, link})
			}

			table.Append([]string{repo, "", link})
			table.Append([]string{})
		}

		table.Render()
		fmt.Fprint(out, "\n")
	}
}

func printSummaryTable(out io.Writer, failures map[string]int, rules map[string]results.Rule) {
	table := tablewriter.NewWriter(out)
	table.SetHeader([]string{"Rule ID", "Rule Name", "Failures", "Status"})
	table.SetColWidth(80)

	var sortedRuleIDs []string
	for ruleID := range rules {
		sortedRuleIDs = append(sortedRuleIDs, ruleID)
	}
	sort.Strings(sortedRuleIDs)

	for _, ruleId := range sortedRuleIDs {
		failCount, found := failures[ruleId]
		status := "Passed"

		if found {
			status = "Failed"
		}

		table.Append([]string{ruleId, rules[ruleId].Title, fmt.Sprintf("%d", failCount), status})
	}
	fmt.Fprint(out, "\nSummary of findings:\n")
	table.Render()
}
