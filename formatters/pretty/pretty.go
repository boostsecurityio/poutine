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
	"github.com/olekukonko/tablewriter/tw"

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

func (f *Format) FormatWithPath(ctx context.Context, packages []*models.PackageInsights, pathAssociations map[string][]*models.RepoInfo) error {
	failures := map[string]int{}
	rules := map[string]results.Rule{}

	for _, pkg := range packages {
		findings := make(map[string]map[string]bool)
		for _, finding := range pkg.FindingsResults.Findings {
			filename := filepath.Base(finding.Meta.Path)
			filename = strings.TrimSuffix(filename, filepath.Ext(filename))
			if _, ok := findings[filename]; !ok {
				findings[filename] = make(map[string]bool)
			}
			if _, ok := findings[filename][finding.RuleId]; !ok {
				failures[finding.RuleId]++
			}
			findings[filename][finding.RuleId] = true
		}

		for _, rule := range pkg.FindingsResults.Rules {
			rules[rule.Id] = rule
		}

		_ = f.printFindingsPerWorkflow(os.Stdout, findings, pathAssociations)
	}
	printSummaryTable(os.Stdout, failures, rules)

	return nil
}

func (f *Format) printFindingsPerWorkflow(out io.Writer, results map[string]map[string]bool, pathAssociations map[string][]*models.RepoInfo) error {
	// Skip rules with no findings.
	table := tablewriter.NewWriter(out)
	table.Options(tablewriter.WithConfig(tablewriter.Config{
		Row: tw.CellConfig{
			Formatting: tw.CellFormatting{MergeMode: tw.MergeHierarchical},
		},
	}))
	table.Header([]string{"Workflow sha", "Rule", "Location", "URL"})

	for blobsha, repoInfos := range pathAssociations {
		findings := results[blobsha]
		if len(findings) == 0 {
			continue
		}
		largestElement := len(findings)
		sumPath := 0
		for _, repoInfo := range repoInfos {
			for _, branchInfo := range repoInfo.BranchInfos {
				sumPath += len(branchInfo.FilePath)
			}
		}
		blobshaTable := make([][]string, max(largestElement, sumPath))
		for i := range blobshaTable {
			blobshaTable[i] = make([]string, 4)
		}

		blobshaTable[0][0] = blobsha

		// Extract and sort the keys of the findings map
		sortedFindings := make([]string, 0, len(findings))
		for finding := range findings {
			sortedFindings = append(sortedFindings, finding)
		}
		sort.Strings(sortedFindings)

		// Iterate over the sorted keys
		i := 0
		for _, finding := range sortedFindings {
			blobshaTable[i][1] = finding
			i++
		}

		index := 0
		for _, repoInfo := range repoInfos {
			purl, err := models.NewPurl(repoInfo.Purl)
			if err != nil {
				return fmt.Errorf("failed to parse purl: %w", err)
			}
			for _, branchInfo := range repoInfo.BranchInfos {
				for j, path := range branchInfo.FilePath {
					if j == 0 {
						blobshaTable[index][2] = repoInfo.RepoName + "/" + branchInfo.BranchName
					}

					blobshaTable[index][3] = purl.Link() + "/tree/" + branchInfo.BranchName + "/" + path
					index += 1
				}
			}
		}

		err := table.Bulk(blobshaTable)
		if err != nil {
			return fmt.Errorf("failed to bulk insert into table: %w", err)
		}
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
		table.Options(tablewriter.WithConfig(tablewriter.Config{
			Row: tw.CellConfig{
				Formatting: tw.CellFormatting{MergeMode: tw.MergeHierarchical},
			},
		}))
		table.Header([]string{"Repository", "Details", "URL"})

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
	table.Options(tablewriter.WithConfig(tablewriter.Config{
		Row: tw.CellConfig{
			ColMaxWidths: tw.CellWidth{Global: 80},
		},
	}))
	table.Header([]string{"Rule ID", "Rule Name", "Failures", "Status"})

	sortedRuleIDs := make([]string, 0, len(rules))
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
