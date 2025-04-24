package scanner

import (
	"regexp"

	"github.com/boostsecurityio/poutine/models"
	"github.com/rs/zerolog/log"
)

type MemParser interface {
	MatchPattern() *regexp.Regexp
	ParseFromMemory(data []byte, filePath string, pkgInsights *models.PackageInsights) error
}

type InventoryScannerMem struct {
	Files   map[string][]byte
	Parsers []MemParser
}

func (s *InventoryScannerMem) Run(pkgInsights *models.PackageInsights) error {
	for path, data := range s.Files {
		for _, parser := range s.Parsers {
			if !parser.MatchPattern().MatchString(path) {
				continue
			}
			if err := parser.ParseFromMemory(data, path, pkgInsights); err != nil {
				log.Error().Str("file", path).Err(err).Msg("error parsing matched file")
			}
		}
	}
	return nil
}
