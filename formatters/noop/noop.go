package noop

import (
	"context"

	"github.com/boostsecurityio/poutine/models"
)

type Format struct {
}

func (f *Format) Format(ctx context.Context, packages []*models.PackageInsights) error {
	return nil
}

func (f *Format) FormatWithPath(ctx context.Context, packages []*models.PackageInsights, pathAssociations map[string][]*models.RepoInfo) error {
	return nil
}
