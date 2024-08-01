package models

type PipelineAsCodeTekton struct {
	ApiVersion string `json:"apiVersion" yaml:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name        string            `json:"name"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec PipelineRunSpec `json:"spec,omitempty" yaml:"spec"`
}

type PipelineRunSpec struct {
	PipelineSpec *PipelineSpec `json:"pipelineSpec,omitempty" yaml:"pipelineSpec"`
}

type PipelineSpec struct {
	Tasks []PipelineTask `json:"tasks,omitempty" yaml:"tasks"`
}

type PipelineTask struct {
	Name string `json:"name,omitempty"`

	TaskSpec *TaskSpec `json:"taskSpec,omitempty" yaml:"taskSpec"`
}

type TaskSpec struct {
	Steps []Step `json:"steps,omitempty"`
}

type Step struct {
	Name   string `json:"name"`
	Script string `json:"script,omitempty"`
}
