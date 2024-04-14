package docs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetRuleDocs(t *testing.T) {
	page, err := GetPage("debug_enabled")

	assert.Nil(t, err)
	assert.True(t,
		strings.HasPrefix(page.Content, "## Description"),
		"content should be trimmed '%s'...", page.Content[0:10],
	)
}
