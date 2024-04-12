package pretty

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/olekukonko/tablewriter"
)

type Format struct {
}

func (f *Format) Format(ctx context.Context, report *opa.FindingsResult, packages []*models.PackageInsights) error {
	failures := map[string]int{}
	findings := map[string][]opa.Finding{}

	for _, finding := range report.Findings {
		failures[finding.RuleId]++
		findings[finding.RuleId] = append(findings[finding.RuleId], finding)
	}

	printFindingsPerRule(os.Stdout, findings, report.Rules)
	printSummaryTable(os.Stdout, failures, report.Rules)

	return nil
}

func printFindingsPerRule(out io.Writer, results map[string][]opa.Finding, rules map[string]opa.Rule) {

	var sortedRuleIDs []string
	for ruleID := range rules {
		sortedRuleIDs = append(sortedRuleIDs, ruleID)
	}
	sort.Strings(sortedRuleIDs)

	for _, ruleId := range sortedRuleIDs {
		table := tablewriter.NewWriter(out)
		table.SetAutoMergeCells(true)
		table.SetHeader([]string{"Repository", "Details", "URL"})

		fmt.Fprintf(out, "Rule: %s\n", rules[ruleId].Title)
		fmt.Fprintf(out, "Severity: %s\n", rules[ruleId].Level)
		fmt.Fprintf(out, "Description: %s\n", rules[ruleId].Description)
		fmt.Fprintf(out, "Documentation: https://github.com/boostsecurityio/poutine/blob/main/docs/content/en/rules/%s.md\n\n", ruleId)

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

		if len(results[ruleId]) == 0 {
			fmt.Fprint(out, "\nNo findings for this repository\n")
		} else {
			table.Render()
		}
		fmt.Fprint(out, "\n")
	}
}

func printSummaryTable(out io.Writer, failures map[string]int, rules map[string]opa.Rule) {
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
