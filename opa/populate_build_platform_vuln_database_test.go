package opa

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/boostsecurityio/poutine/providers/gitops"
	"github.com/stretchr/testify/assert"
	"io/fs"
	"os"
	"path/filepath"
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
					LessThanOrEqual string `json:"lessThanOrEqual"`
					Version         string `json:"version"`
					VersionType     string `json:"versionType"`
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
				OsvId:     data.CveMetadata.ID,
				Published: data.CveMetadata.DatePublished,
				Summary:   data.Containers.CNA.Descriptions[0].Value,
				CweIds:    []string{},
				Severity:  []Severity{},
			}

			// Populate CWE IDs
			for _, problemType := range data.Containers.CNA.ProblemTypes {
				for _, description := range problemType.Descriptions {
					cveItem.CweIds = append(cveItem.CweIds, description.CweId)
				}
			}

			// Populate Severity
			for _, metric := range data.Containers.CNA.Metrics {
				cveItem.Severity = append(cveItem.Severity, Severity{
					Type:  "CVSS_V3", // Assuming all are CVSS V3 for simplicity
					Score: metric.CvssV31.VectorString,
				})
			}

			if _, ok := advisories[vendor]; !ok {
				advisories[vendor] = make(map[string]CVEItem)
			}
			advisories[vendor][data.CveMetadata.ID] = cveItem
		}
	}

	return advisories
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
		{"git", []string{"sparse-checkout", "set", "cves/2022", "cves/2023", "cves/2024"}},
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
					fmt.Println("Found matching file:", path)
					// Process the file as needed
				}

			}
		}

		return nil
	})

	advisories := TransformCVEDataToAdvisories(cves)

	assert.Len(t, advisories, 2)
}
