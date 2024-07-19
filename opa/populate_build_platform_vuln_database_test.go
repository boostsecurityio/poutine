//go:build build_platform_vuln_database
// +build build_platform_vuln_database

package opa

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/boostsecurityio/poutine/providers/gitops"
	"github.com/stretchr/testify/assert"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type CVEItem struct {
	OsvId                   string     `json:"osv_id"`
	Published               string     `json:"published"`
	Aliases                 []string   `json:"aliases"`
	Summary                 string     `json:"summary"`
	Severity                []Severity `json:"severity"`
	CweIds                  []string   `json:"cwe_ids"`
	VulnerableVersions      []string   `json:"vulnerable_versions"`
	VulnerableVersionRanges []string   `json:"vulnerable_version_ranges"`
	VulnerableCommitSHAs    []string   `json:"vulnerable_commit_shas"`
}

type PlatformAdvisories map[string]map[string]CVEItem

type CVEData struct {
	CveMetadata struct {
		ID            string `json:"cveId"`
		DatePublished string `json:"datePublished"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			Affected []struct {
				Vendor   string `json:"vendor"`
				Product  string `json:"product"`
				Versions []struct {
					LessThan    string `json:"lessThan"`
					Version     string `json:"version"`
					VersionType string `json:"versionType"`
				}
			} `json:"affected"`
			Descriptions []struct {
				Value string `json:"value"`
			}
			ProblemTypes []struct {
				Descriptions []struct {
					CweId string `json:"cweId"`
				}
			} `json:"problemTypes"`
			Metrics []struct {
				CvssV31 struct {
					VectorString string `json:"vectorString"`
				} `json:"cvssV3_1"`
			} `json:"metrics"`
		} `json:"cna"`
	} `json:"containers"`
}

func TransformCVEDataToAdvisories(cveData []CVEData) PlatformAdvisories {
	advisories := PlatformAdvisories{}

	for _, data := range cveData {
		for _, affected := range data.Containers.CNA.Affected {
			vendor := strings.ToLower(affected.Vendor)
			if vendor != "github" && vendor != "gitlab" {
				continue
			}

			cveItem := CVEItem{
				OsvId:                   data.CveMetadata.ID,
				Published:               data.CveMetadata.DatePublished,
				Aliases:                 []string{},
				Summary:                 data.Containers.CNA.Descriptions[0].Value,
				Severity:                []Severity{},
				CweIds:                  []string{},
				VulnerableVersions:      []string{},
				VulnerableVersionRanges: []string{},
				VulnerableCommitSHAs:    []string{},
			}

			for _, problemType := range data.Containers.CNA.ProblemTypes {
				for _, description := range problemType.Descriptions {
					cveItem.CweIds = append(cveItem.CweIds, description.CweId)
				}
			}

			for _, metric := range data.Containers.CNA.Metrics {
				cveItem.Severity = append(cveItem.Severity, Severity{
					Type:  "CVSS_V3",
					Score: metric.CvssV31.VectorString,
				})
			}

			var versionRanges []string

			for _, version := range affected.Versions {
				if version.VersionType == "custom" || version.VersionType == "semver" {
					if version.LessThan != "" && version.Version != "" {
						versionRange := fmt.Sprintf(">=%s,<%s", version.Version, version.LessThan)
						versionRanges = append(versionRanges, versionRange)
					}
				} else {
					if strings.Contains(version.Version, "<") || strings.Contains(version.Version, ">") {
						versionRanges = append(versionRanges, version.Version)
					}
				}
			}

			cveItem.VulnerableVersionRanges = append(cveItem.VulnerableVersionRanges, versionRanges...)

			if _, ok := advisories[vendor]; !ok {
				advisories[vendor] = make(map[string]CVEItem)
			}
			advisories[vendor][data.CveMetadata.ID] = cveItem
		}
	}

	return advisories
}

func AdvisoriesToJSON(advisories PlatformAdvisories) (string, error) {
	jsonData, err := json.MarshalIndent(advisories, "", "    ")
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

func TestPopulateDatabase(t *testing.T) {
	command := &gitops.ExecGitCommand{}
	commands := []struct {
		cmd  string
		args []string
	}{
		{"git", []string{"init", "--quiet"}},
		{"git", []string{"remote", "add", "origin", "https://github.com/CVEProject/cvelistV5"}},
		{"git", []string{"config", "submodule.recurse", "false"}},
		{"git", []string{"config", "core.sparseCheckout", "true"}},
		{"git", []string{"config", "index.sparse", "true"}},
		{"git", []string{"sparse-checkout", "init", "--sparse-index"}},
		{"git", []string{"sparse-checkout", "set", "cves/2020", "cves/2021", "cves/2022", "cves/2023", "cves/2024", "cves/2025", "cves/2026"}},
		{"git", []string{"fetch", "--quiet", "--no-tags", "--depth", "1", "--filter=blob:none", "origin", "main"}},
		{"git", []string{"checkout", "--quiet", "-b", "target", "FETCH_HEAD"}},
	}

	tempDir, err := os.MkdirTemp("", "")
	assert.NoError(t, err)

	defer os.RemoveAll(tempDir)

	for _, c := range commands {
		if _, err := command.Run(context.TODO(), c.cmd, c.args, tempDir); err != nil {
			assert.NoError(t, err)
		}
	}

	cves := []CVEData{}

	err = filepath.WalkDir(tempDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var cveData CVEData
		if err := json.Unmarshal(data, &cveData); err != nil {
			return err
		}

		if len(cveData.Containers.CNA.Affected) > 0 {
			vendor := strings.ToLower(cveData.Containers.CNA.Affected[0].Vendor)
			product := strings.ToLower(cveData.Containers.CNA.Affected[0].Product)
			if vendor == "github" || vendor == "gitlab" {

				if product == "github enterprise server" || product == "gitlab" {
					cves = append(cves, cveData)
				}

			}
		}

		return nil
	})

	advisories := TransformCVEDataToAdvisories(cves)

	advisoriesJson, err := AdvisoriesToJSON(advisories)
	assert.NoError(t, err)

	regoFilePath := "rego/external/build_platform.rego"

	content, err := os.ReadFile(regoFilePath)
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}

	contentStr := string(content)

	re := regexp.MustCompile(`(?s)advisories = \{.*?\n}`)
	updatedContent := re.ReplaceAllString(contentStr, "advisories = "+advisoriesJson)

	err = os.WriteFile(regoFilePath, []byte(updatedContent), 0644)
	if err != nil {
		log.Fatalf("Failed to write updated content to file: %v", err)
	}
}
