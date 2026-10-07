package models_test

import (
	"testing"

	"github.com/boostsecurityio/poutine/models"
	"github.com/stretchr/testify/assert"
)

func TestConfig_IsRepoExcluded(t *testing.T) {
	cfg := &models.Config{
		ExcludeRepos: []string{"org/repo1", "repo2", "org/Repo3"},
	}

	assert.True(t, cfg.IsRepoExcluded("org/repo1"))
	assert.True(t, cfg.IsRepoExcluded("org/repo2"))
	assert.True(t, cfg.IsRepoExcluded("org/repo3"))
	assert.False(t, cfg.IsRepoExcluded("org/repo4"))

	var nilCfg *models.Config
	assert.False(t, nilCfg.IsRepoExcluded("org/repo1"))

	emptyCfg := &models.Config{}
	assert.False(t, emptyCfg.IsRepoExcluded("org/repo1"))
}
