package models

import (
	"bytes"
	"fmt"
	"gopkg.in/yaml.v3"
	"strings"
)

type GitlabciJobVariables []GitlabciJobVariable
type GitlabciGlobalVariables []GitlabciGlobalVariable
type GitlabciConfigInputs []GitlabciConfigInput
type GitlabciIncludeItems []GitlabciIncludeItem
type GitlabciIncludeInputs []GitlabciIncludeInput
type GitlabciStringRef string

var invalidJobNames map[string]bool = map[string]bool{
	"image":         true,
	"services":      true,
	"stages":        true,
	"types":         true,
	"before_script": true,
	"after_script":  true,
	"variables":     true,
	"cache":         true,
	"include":       true,
	"true":          true,
	"false":         true,
	"nil":           true,
}

func ParseGitlabciConfig(doc []byte) (*GitlabciConfig, error) {
	var config GitlabciConfig
	reader := bytes.NewReader(doc)
	decoder := yaml.NewDecoder(reader)
	err := decoder.Decode(&config)
	if err != nil {
		return nil, err
	}

	if len(config.Spec.Inputs) == 0 {
		return &config, nil
	}

	spec := config.Spec
	err = decoder.Decode(&config)
	config.Spec = spec
	return &config, err
}

// https://gitlab.com/gitlab-org/gitlab/-/blob/b95c5fe22ae341370bc5ed34eb78ffecb2133ab1/app/assets/javascripts/editor/schema/ci.json
type GitlabciConfig struct {
	Path      string                  `json:"path"`
	Default   GitlabciJob             `json:"default"`
	Stages    []string                `json:"stages"`
	Variables GitlabciGlobalVariables `json:"variables"`
	Include   GitlabciIncludeItems    `json:"include"`

	Jobs []GitlabciJob      `json:"jobs" yaml:"-"`
	Spec GitlabciConfigSpec `json:"spec" yaml:"-"`
}

type GitlabciConfigSpec struct {
	Inputs GitlabciConfigInputs `json:"inputs"`
}

type GitlabciConfigInput struct {
	Name        string     `json:"name" yaml:"-"`
	Default     string     `json:"default"`
	Description string     `json:"description"`
	Options     StringList `json:"options"`
	Regex       string     `json:"regex"`
}

type GitlabciJob struct {
	Name         string               `json:"name" yaml:"-"`
	Hidden       bool                 `json:"hidden" yaml:"-"`
	Stage        StringList           `json:"stage"`
	Image        GitlabciImage        `json:"image"`
	Services     []GitlabciService    `json:"services"`
	BeforeScript []GitlabciScript     `json:"before_script" yaml:"before_script"`
	AfterScript  []GitlabciScript     `json:"after_script" yaml:"after_script"`
	Script       []GitlabciScript     `json:"script"`
	Variables    GitlabciJobVariables `json:"variables"`
	Hooks        GitlabciJobHooks     `json:"hooks"`
	Inherit      StringList           `json:"inherit"`
	Line         int                  `json:"line" yaml:"-"`
}

type GitlabciJobHooks struct {
	PreGetSourcesScript StringList `json:"pre_get_sources_script"`
}

type GitlabciIncludeItem struct {
	Local     string                `json:"local,omitempty"`
	Remote    string                `json:"remote,omitempty"`
	Template  string                `json:"template,omitempty"`
	Project   string                `json:"project,omitempty"`
	File      StringList            `json:"file,omitempty"`
	Ref       string                `json:"ref,omitempty"`
	Component string                `json:"component,omitempty"`
	Inputs    GitlabciIncludeInputs `json:"inputs,omitempty"`
}

type GitlabciImage struct {
	Name       string   `json:"name"`
	Entrypoint []string `json:"entrypoint"`
	Docker     struct {
		Platform string `json:"platform"`
		User     string `json:"user"`
	} `json:"docker"`
}

type GitlabciService struct {
	Name       string   `json:"name"`
	Entrypoint []string `json:"entrypoint"`
	Docker     struct {
		Platform string `json:"platform"`
		User     string `json:"user"`
	} `json:"docker"`
	Command   []string             `json:"command"`
	Alias     string               `json:"alias"`
	Variables GitlabciJobVariables `json:"variables"`
}

type GitlabciJobVariable struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Expand bool   `json:"expand"`
}

type GitlabciGlobalVariable struct {
	Name        string   `json:"name"`
	Value       string   `json:"value"`
	Options     []string `json:"options"`
	Description string   `json:"description"`
	Expand      bool     `json:"expand"`
}

type GitlabciIncludeInput struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type GitlabciScript struct {
	Run  GitlabciStringRef `json:"run" yaml:"-"`
	Line int               `json:"line" yaml:"-"`
}

func (o *GitlabciConfig) UnmarshalYAML(node *yaml.Node) error {
	type Alias GitlabciConfig
	alias := Alias{}

	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("expected config to be a map")
	}

	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i].Value
		value := node.Content[i+1]
		switch key {
		case "image":
			_ = value.Decode(&alias.Default.Image)
		case "services":
			_ = value.Decode(&alias.Default.Services)
		case "before_script":
			_ = value.Decode(&alias.Default.BeforeScript)
		case "after_script":
			_ = value.Decode(&alias.Default.AfterScript)
		case "spec":
			_ = value.Decode(&alias.Spec)
		default:
			if _, ok := invalidJobNames[key]; ok {
				continue
			}

			var job GitlabciJob
			if key == "default" {
				alias.Default.Name = key
				alias.Default.Line = node.Content[i].Line
				job = alias.Default
			} else {
				job = GitlabciJob{
					Name:   key,
					Hidden: key[0] == '.',
					Line:   node.Content[i].Line,
				}

			}
			err := value.Decode(&job)
			if err != nil {
				continue
			}

			alias.Jobs = append(alias.Jobs, job)
		}
	}

	if err := node.Decode(&alias); err != nil {
		return err
	}

	*o = GitlabciConfig(alias)
	return nil

}

func (o *GitlabciImage) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err == nil {
		o.Name = s
		return nil
	}

	type Alias GitlabciImage
	alias := Alias{}
	if err := node.Decode(&alias); err != nil {
		return err
	}

	*o = GitlabciImage(alias)
	return nil
}

func (o *GitlabciJobVariables) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("expected variables to be a map")
	}

	for i := 0; i < len(node.Content); i += 2 {
		k := node.Content[i].Value
		v := node.Content[i+1]
		variable := GitlabciJobVariable{
			Name: k,
		}

		switch v.Kind {
		case yaml.ScalarNode:
			if err := v.Decode(&variable.Value); err != nil {
				return err
			}
		case yaml.MappingNode:
			if err := v.Decode(&variable); err != nil {
				return err
			}
		case yaml.SequenceNode:
			if v.Tag == "!reference" {
				val, _ := yaml.Marshal(v)
				variable.Value = string(val)
			}
		default:
			return fmt.Errorf("unexpected node type for variable value")
		}
		*o = append(*o, variable)
	}
	return nil
}

func (o *GitlabciGlobalVariables) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("expected variables to be a map")
	}

	for i := 0; i < len(node.Content); i += 2 {
		k := node.Content[i].Value
		v := node.Content[i+1]
		variable := GitlabciGlobalVariable{
			Name: k,
		}

		switch v.Kind {
		case yaml.ScalarNode:
			if err := v.Decode(&variable.Value); err != nil {
				return err
			}
		case yaml.MappingNode:
			if err := v.Decode(&variable); err != nil {
				return err
			}
		case yaml.SequenceNode:
			if node.Content[i+1].Tag == "!reference" {
				ref, _ := yaml.Marshal(v)
				variable.Value = string(ref)
			}
		default:
			continue
		}

		*o = append(*o, variable)
	}

	return nil
}

func (o *GitlabciConfigInputs) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("expected inputs to be a map")
	}

	var inputs []GitlabciConfigInput
	for i := 0; i < len(node.Content); i += 2 {
		k := node.Content[i].Value
		v := node.Content[i+1]
		input := GitlabciConfigInput{
			Name: k,
		}

		if err := v.Decode(&input); err != nil {
			return err
		}

		inputs = append(inputs, input)
	}

	*o = inputs
	return nil
}

func (o *GitlabciIncludeItems) UnmarshalYAML(node *yaml.Node) error {
	var includes []GitlabciIncludeItem

	switch node.Kind {
	case yaml.SequenceNode:
		if err := node.Decode(&includes); err != nil {
			return err
		}
	case yaml.MappingNode:
		var include GitlabciIncludeItem
		if err := node.Decode(&include); err != nil {
			return err
		}
		includes = append(includes, include)
	default:
		return fmt.Errorf("unexpected node type for includes")
	}

	*o = includes
	return nil
}

func (o *GitlabciIncludeItem) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var s string
		if err := node.Decode(&s); err != nil {
			return err
		}

		if strings.HasPrefix(s, "http:") || strings.HasPrefix(s, "https:") {
			o.Remote = s
		} else {
			o.Local = s
		}
		return nil
	case yaml.MappingNode:
		type Alias GitlabciIncludeItem
		alias := Alias{}
		if err := node.Decode(&alias); err != nil {
			return err
		}

		*o = GitlabciIncludeItem(alias)
		return nil
	}

	return fmt.Errorf("unexpected node type for include item")
}

func (o *GitlabciIncludeInputs) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("expected include inputs to be a map")
	}

	var inputs []GitlabciIncludeInput
	for i := 0; i < len(node.Content); i += 2 {
		var value string
		name := node.Content[i].Value
		if err := node.Content[i+1].Decode(&value); err != nil {
			return err
		}

		inputs = append(inputs, GitlabciIncludeInput{
			Name:  name,
			Value: value,
		})
	}

	*o = inputs
	return nil
}

func (o *GitlabciStringRef) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.SequenceNode:
		if node.Tag == "!reference" {
			val, _ := yaml.Marshal(node)
			*o = GitlabciStringRef(val)
		} else {
			return fmt.Errorf("unexpected string or reference")
		}
	case yaml.ScalarNode:
		var s string
		if err := node.Decode(&s); err != nil {
			return err
		}
		*o = GitlabciStringRef(s)
	}

	return nil
}

func (o *GitlabciScript) UnmarshalYAML(node *yaml.Node) error {
	if err := node.Decode(&o.Run); err != nil {
		return err
	}

	o.Line = node.Line
	return nil
}
