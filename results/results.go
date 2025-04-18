package results

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/rs/zerolog/log"
)

type FindingsResult struct {
	Findings []Finding       `json:"findings"`
	Rules    map[string]Rule `json:"rules"`
}

type FindingMeta struct {
	Path          string   `json:"path,omitempty"`
	Line          int      `json:"line,omitempty"`
	Job           string   `json:"job,omitempty"`
	Step          string   `json:"step,omitempty"`
	OsvId         string   `json:"osv_id,omitempty"`
	Details       string   `json:"details,omitempty"`
	EventTriggers []string `json:"event_triggers,omitempty"`
	BlobSHA       string   `json:"blobsha,omitempty"`
}

type Finding struct {
	RuleId string      `json:"rule_id"`
	Purl   string      `json:"purl"`
	Meta   FindingMeta `json:"meta"`
}

func (f *Finding) GenerateFindingFingerprint() string {
	fingerprintString := f.Meta.Path + strconv.Itoa(f.Meta.Line) + f.Meta.Job + f.Meta.Step + f.RuleId
	h := sha256.New()
	h.Write([]byte(fingerprintString))
	fingerprint := h.Sum(nil)
	return fmt.Sprintf("%x", fingerprint)
}

func (m *FindingMeta) UnmarshalJSON(data []byte) error {
	type meta FindingMeta
	aux := &struct {
		Step json.Number `json:"step"`
		*meta
	}{
		meta: (*meta)(m),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		log.Error().RawJSON("meta", data).Err(err).Msg("failed to unmarshal FindingMeta")
		return nil
	}
	m.Step = aux.Step.String()
	return nil
}

type Rule struct {
	Id          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Level       string `json:"level"`
	Refs        []struct {
		Ref         string `json:"ref"`
		Description string `json:"description"`
	} `json:"refs,omitempty"`
	Config map[string]RuleConfig `json:"config,omitempty"`
}

type RuleConfig struct {
	Default     interface{} `json:"default"`
	Description string      `json:"description"`
	Value       interface{} `json:"value"`
}
