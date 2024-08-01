package models

import "gopkg.in/yaml.v3"

type PipelineAsCodeTekton struct {
	ApiVersion string `json:"api_version" yaml:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name        string            `json:"name"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec PipelineRunSpec `json:"spec,omitempty" yaml:"spec"`

	Path string `json:"path" yaml:"-"`
}

type PipelineRunSpec struct {
	PipelineSpec *PipelineSpec `json:"pipeline_spec,omitempty" yaml:"pipelineSpec"`
}

type PipelineSpec struct {
	Tasks []PipelineTask `json:"tasks,omitempty" yaml:"tasks"`
}

type PipelineTask struct {
	Name string `json:"name,omitempty"`

	TaskSpec *TaskSpec `json:"task_spec,omitempty" yaml:"taskSpec"`
}

type TaskSpec struct {
	Steps []Step `json:"steps,omitempty"`
}

type Step struct {
	Name   string         `json:"name"`
	Script string         `json:"script,omitempty"`
	Lines  map[string]int `json:"lines" yaml:"-"`
}

func (o *Step) UnmarshalYAML(node *yaml.Node) error {
	type step Step
	var s step
	if err := node.Decode(&s); err != nil {
		return err
	}

	if node.Kind == yaml.MappingNode {
		s.Lines = map[string]int{"start": node.Line}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i].Value
			switch key {
			case "script":
				s.Lines[key] = node.Content[i+1].Line
			}
		}
	}

	*o = Step(s)
	return nil
}
