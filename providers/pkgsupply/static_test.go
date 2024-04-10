package pkgsupply

import (
	"context"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestStaticGetReputation(t *testing.T) {
	client := NewStaticClient()
	p := "pkg:githubactions/bridgecrewio/checkov-action@foobar"
	res, err := client.GetReputation(context.TODO(), []string{p})
	assert.Nil(t, err)

	assert.Equal(t, 1, len(res.Packages))
	assert.Equal(t, p, res.Packages[0].Purl)
	assert.Equal(t, "true", res.Packages[0].Attributes["unpinnable"])
}
