package pkgsupply

import (
	"bufio"
	"context"
	_ "embed"
	"github.com/boostsecurityio/poutine/models"
	"strings"
)

//go:embed unpinnable_actions.txt
var unpinnableActions string

type CachedPackageReputation struct {
	Purl string   `json:"purl"`
	Tags []string `json:"tags"`
}

type StaticClient struct {
	unpinnableActions map[string]bool
}

func NewStaticClient() *StaticClient {
	client := &StaticClient{
		unpinnableActions: make(map[string]bool),
	}
	scanner := bufio.NewScanner(strings.NewReader(unpinnableActions))
	for scanner.Scan() {
		client.unpinnableActions[scanner.Text()] = true
	}

	return client
}

func (c *StaticClient) GetReputation(ctx context.Context, purls []string) (*ReputationResponse, error) {
	var reputation ReputationResponse

	for _, purl := range purls {
		p, err := models.NewPurl(purl)
		if err != nil {
			continue
		}

		purlPrefix := "pkg:githubactions/" + p.FullName()
		if len(p.Subpath) > 0 {
			purlPrefix += "/" + p.Subpath
		}

		if !c.unpinnableActions[purlPrefix] {
			continue
		}

		reputation.Packages = append(reputation.Packages, PackageReputation{
			Purl: purl,
			Risk: 1,
			Attributes: map[string]string{
				"unpinnable": "true",
			},
		})
	}

	return &reputation, nil
}
