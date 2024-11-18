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
	Parse(filePath string, info fs.FileInfo, pkgInsights *models.PackageInsights) error
}

type InventoryScanner struct {
	Path    string
	Parsers []Parser
}

func NewInventoryScanner(path string, parsers []Parser) *InventoryScanner {
	return &InventoryScanner{
		Path:    path,
		Parsers: parsers,
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
				if err := parser.Parse(filePath, info, pkgInsights); err != nil {
					log.Error().Str("file", filePath).Err(err).Msg("error parsing matched file")
					continue
				}
			}
		}
		return nil
	})
}
