package docs

import (
	"embed"
	"fmt"
	"path"
	"strings"
)

//go:embed content
var content embed.FS

type Page struct {
	Content string `yaml:"-"`
}

func GetPagesContent() map[string]string {
	docs := map[string]string{}
	entries, err := content.ReadDir(path.Join("content", "en", "rules"))
	if err != nil {
		return docs
	}

	for _, entry := range entries {
		ruleId := strings.TrimSuffix(entry.Name(), ".md")
		page, err := GetPage(ruleId)
		if err != nil {
			continue
		}

		docs[ruleId] = page.Content
	}

	return docs
}

func GetPage(ruleId string) (*Page, error) {
	doc, err := content.ReadFile(
		path.Join("content", "en", "rules", ruleId+".md"))
	if err != nil {
		return nil, err
	}

	parts := strings.SplitAfterN(string(doc), "---\n", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid doc page %s.md", ruleId)
	}

	return &Page{Content: strings.TrimSpace(parts[2])}, nil
}
