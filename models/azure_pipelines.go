package models

import (
	"fmt"
	"gopkg.in/yaml.v3"
)

// https://learn.microsoft.com/en-us/azure/devops/pipelines/yaml-schema/pipeline?view=azure-pipelines
type AzurePipeline struct {
	Path string `json:"path" yaml:"-"`

	Stages    []AzureStage           `json:"stages"`
	Pr        AzurePr                `json:"pr"`
	Variables AzurePipelineVariables `json:"variables"`
}

func (o AzurePipeline) IsValid() bool {
	return len(o.Stages) > 0 && len(o.Stages[0].Jobs) > 0
}

// https://learn.microsoft.com/en-us/azure/devops/pipelines/yaml-schema/stages-stage?view=azure-pipelines
type AzureStage struct {
	Stage string     `json:"stage"`
	Jobs  []AzureJob `json:"jobs"`
}

// https://learn.microsoft.com/en-us/azure/devops/pipelines/yaml-schema/jobs-job?view=azure-pipelines
type AzureJob struct {
	Job   string      `json:"job"`
	Steps []AzureStep `json:"steps"`
}

// https://learn.microsoft.com/en-us/azure/devops/pipelines/yaml-schema/steps?view=azure-pipelines
type AzureStep struct {
	Task       string `json:"task,omitempty"`
	Script     string `json:"script,omitempty"`
	Powershell string `json:"powershell,omitempty"`
	Pwsh       string `json:"pwsh,omitempty"`
	Bash       string `json:"bash,omitempty"`
	Checkout   string `json:"checkout,omitempty"`

	Lines map[string]int `json:"lines" yaml:"-"`
}

// https://learn.microsoft.com/en-us/azure/devops/pipelines/yaml-schema/pr?view=azure-pipelines
type AzurePr struct {
	Disabled bool `json:"disabled" yaml:"-"`

	Branches *AzureIncludeExclude `json:"branches"`
	Paths    *AzureIncludeExclude `json:"paths"`
	Tags     *AzureIncludeExclude `json:"tags"`
	Drafts   bool                 `json:"drafts"`
}

type AzureIncludeExclude struct {
	Include StringList `json:"include"`
	Exclude StringList `json:"exclude"`
}

func (o *AzurePipeline) UnmarshalYAML(node *yaml.Node) error {
	type pipeline AzurePipeline
	var p pipeline
	if err := node.Decode(&p); err != nil {
		return err
	}

	if len(p.Stages) == 0 {
		stage := AzureStage{}
		if err := node.Decode(&stage); err != nil {
			return err
		}

		if len(stage.Jobs) == 0 {
			job := AzureJob{}
			if err := node.Decode(&job); err != nil {
				return err
			}

			stage.Jobs = append(stage.Jobs, job)
		}

		p.Stages = append(p.Stages, stage)
	}

	*o = AzurePipeline(p)
	return nil
}

func (o *AzurePr) UnmarshalYAML(node *yaml.Node) error {
	o.Drafts = true

	switch node.Kind {
	case yaml.ScalarNode:
		if node.Value == "none" {
			o.Disabled = true
			return nil
		}
		return fmt.Errorf("invalid scalar value for AzurePr: %s", node.Value)
	case yaml.SequenceNode:
		o.Branches = &AzureIncludeExclude{}
		return node.Decode(&o.Branches.Include)
	case yaml.MappingNode:
		type pr AzurePr
		return node.Decode((*pr)(o))
	}

	return nil
}

func (o *AzureStep) UnmarshalYAML(node *yaml.Node) error {
	type step AzureStep
	var s step
	if err := node.Decode(&s); err != nil {
		return err
	}

	if node.Kind == yaml.MappingNode {
		s.Lines = map[string]int{"start": node.Line}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i].Value
			switch key {
			case "task", "script", "powershell", "pwsh", "bash", "checkout":
				s.Lines[key] = node.Content[i+1].Line
			}
		}
	}

	*o = AzureStep(s)
	return nil
}

type AzurePipelineVariable struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

type AzurePipelineVariables struct {
	Map map[string]string `json:"map"`
}

func (v *AzurePipelineVariables) UnmarshalYAML(value *yaml.Node) error {
	v.Map = make(map[string]string)

	var mapFormat map[string]string
	if err := value.Decode(&mapFormat); err == nil {
		v.Map = mapFormat
		return nil
	}

	var listFormat []AzurePipelineVariable
	if err := value.Decode(&listFormat); err == nil {
		for _, variable := range listFormat {
			v.Map[variable.Name] = variable.Value
		}
		return nil
	}

	return fmt.Errorf("variables must be either a map or a list of objects")
}
