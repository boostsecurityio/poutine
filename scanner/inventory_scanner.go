package scanner

import (
	"github.com/boostsecurityio/poutine/models"
	"github.com/rs/zerolog/log"
	"io/fs"
	"path/filepath"
	"regexp"
)

type Parser interface {
	MatchPattern() *regexp.Regexp
	Parse(filePath string, scanningPath string, pkgInsights *models.PackageInsights) error
}

type InventoryScanner struct {
	Path    string
	Parsers []Parser
}

func NewInventoryScanner(path string) *InventoryScanner {
	return &InventoryScanner{
		Path: path,
		Parsers: []Parser{
			NewGithubActionsMetadataParser(),
			NewGithubActionWorkflowParser(),
			NewAzurePipelinesParser(),
			NewGitlabCiParser(),
			NewPipelineAsCodeTektonParser(),
		},
	}
}

func (s *InventoryScanner) Run(pkgInsights *models.PackageInsights) error {
	return filepath.Walk(s.Path, func(filePath string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && info.Name() == ".git" {
			return filepath.SkipDir
		}
		if info.IsDir() {
			return nil
		}
		relativePath, err := filepath.Rel(s.Path, filePath)
		if err != nil {
			log.Error().Err(err).Msg("error getting relative path")
			return err
		}
		for _, parser := range s.Parsers {
			if parser.MatchPattern().MatchString(relativePath) {
				if err := parser.Parse(filePath, s.Path, pkgInsights); err != nil {
					log.Error().Str("file", filePath).Err(err).Msg("error parsing matched file")
					continue
				}
			}
		}
		return nil
	})
}
