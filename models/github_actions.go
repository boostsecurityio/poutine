package models

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"strings"
)

const (
	ScopeMetadata           = "metadata"
	ScopeActions            = "actions"
	ScopeAttestations       = "attestations"
	ScopeChecks             = "checks"
	ScopeContents           = "contents"
	ScopeDeployments        = "deployments"
	ScopeIDToken            = "id-token"
	ScopeIssues             = "issues"
	ScopeDiscussions        = "discussions"
	ScopePackages           = "packages"
	ScopePages              = "pages"
	ScopePullRequests       = "pull-requests"
	ScopeRepositoryProjects = "repository-projects"
	ScopeSecurityEvents     = "security-events"
	ScopeStatuses           = "statuses"

	PermissionRead  = "read"
	PermissionWrite = "write"
	PermissionNone  = "none"
)

var AllScopes = []string{
	ScopeMetadata,
	ScopeActions,
	ScopeAttestations,
	ScopeChecks,
	ScopeContents,
	ScopeDeployments,
	ScopeIDToken,
	ScopeIssues,
	ScopeDiscussions,
	ScopePackages,
	ScopePages,
	ScopePullRequests,
	ScopeRepositoryProjects,
	ScopeSecurityEvents,
	ScopeStatuses,
}

const AllSecrets = "*ALL"

type GithubActionsInputs []GithubActionsInput
type GithubActionsOutputs []GithubActionsOutput
type GithubActionsEnvs []GithubActionsEnv
type GithubActionsSteps []GithubActionsStep
type GithubActionsPermissions []GithubActionsPermission
type GithubActionsEvents []GithubActionsEvent
type GithubActionsJobEnvironments []GithubActionsJobEnvironment
type GithubActionsJobs []GithubActionsJob
type GithubActionsJobSecrets []GithubActionsJobSecret
type GithubActionsSecrets = GithubActionsInputs
type GithubActionsWith = GithubActionsEnvs
type GithubActionsJobRunsOn StringList
type StringList []string

type GithubActionsInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
	Type        string `json:"type"`
}

type GithubActionsOutput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Value       string `json:"value"`
}

type GithubActionsEnv struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type GithubActionsStep struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	If               string            `json:"if"`
	Env              GithubActionsEnvs `json:"env"`
	Uses             string            `json:"uses"`
	Shell            string            `json:"shell"`
	Run              string            `json:"run" yaml:"run"`
	WorkingDirectory string            `json:"working_directory" yaml:"working-directory"`
	With             GithubActionsWith `json:"with"`
	WithRef          string            `json:"with_ref" yaml:"-"`
	WithScript       string            `json:"with_script" yaml:"-"`
	Line             int               `json:"line" yaml:"-"`
	Action           string            `json:"action" yaml:"-"`

	Lines map[string]int `json:"lines" yaml:"-"`
}

type GithubActionsMetadata struct {
	Path        string               `json:"path"`
	Name        string               `json:"name" yaml:"name"`
	Description string               `json:"description" yaml:"description"`
	Author      string               `json:"author" yaml:"author"`
	Inputs      GithubActionsInputs  `json:"inputs"`
	Outputs     GithubActionsOutputs `json:"outputs"`
	Runs        struct {
		Using          string             `json:"using"`
		Main           string             `json:"main"`
		Pre            string             `json:"pre"`
		PreIf          string             `json:"pre-if"`
		Post           string             `json:"post"`
		PostIf         string             `json:"post-if"`
		Steps          GithubActionsSteps `json:"steps"`
		Image          string             `json:"image"`
		Entrypoint     string             `json:"entrypoint"`
		PreEntrypoint  string             `json:"pre-entrypoint"`
		PostEntrypoint string             `json:"post-entrypoint"`
		Args           []string           `json:"args"`
	} `json:"runs"`
}

type GithubActionsPermission struct {
	Scope      string `json:"scope"`
	Permission string `json:"permission"`
}

type GithubActionsEvent struct {
	Name           string               `json:"name"`
	Types          StringList           `json:"types"`
	Branches       StringList           `json:"branches"`
	BranchesIgnore StringList           `json:"branches_ignore"`
	Paths          StringList           `json:"paths"`
	PathsIgnore    StringList           `json:"paths_ignore"`
	Tags           StringList           `json:"tags"`
	TagsIgnore     StringList           `json:"tags_ignore"`
	Cron           StringList           `json:"cron"`
	Inputs         GithubActionsInputs  `json:"inputs"`
	Outputs        GithubActionsOutputs `json:"outputs"`
	Secrets        GithubActionsSecrets `json:"secrets"`
	Workflows      StringList           `json:"workflows"`
}

type GithubActionsJobContainer struct {
	Image string `json:"image"`
}

type GithubActionsJobEnvironment struct {
	Name string `json:"name"`
	Url  string `json:"url"`
}

type GithubActionsJobSecret struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type GithubActionsJob struct {
	ID                string                       `json:"id"`
	Name              string                       `json:"name"`
	Uses              string                       `json:"uses"`
	Secrets           GithubActionsJobSecrets      `json:"secrets"`
	With              GithubActionsWith            `json:"with"`
	Permissions       GithubActionsPermissions     `json:"permissions"`
	Needs             StringList                   `json:"needs"`
	If                string                       `json:"if"`
	RunsOn            GithubActionsJobRunsOn       `json:"runs_on" yaml:"runs-on"`
	Container         GithubActionsJobContainer    `json:"container"`
	Environment       GithubActionsJobEnvironments `json:"environment"`
	Outputs           GithubActionsEnvs            `json:"outputs"`
	Env               GithubActionsEnvs            `json:"env"`
	Steps             GithubActionsSteps           `json:"steps"`
	ReferencesSecrets []string                     `json:"references_secrets" yaml:"-"`
	Line              int                          `json:"line" yaml:"-"`

	Lines map[string]int `json:"lines" yaml:"-"`
}

type GithubActionsWorkflow struct {
	Path        string                   `json:"path" yaml:"-"`
	Name        string                   `json:"name"`
	Events      GithubActionsEvents      `json:"events" yaml:"on"`
	Permissions GithubActionsPermissions `json:"permissions"`
	Env         GithubActionsEnvs        `json:"env"`
	Jobs        GithubActionsJobs        `json:"jobs"`
}

func (o GithubActionsWorkflow) IsValid() bool {
	return len(o.Jobs) > 0 && len(o.Events) > 0
}

func (o GithubActionsMetadata) IsValid() bool {
	return o.Runs.Using != ""
}

func (o *GithubActionsJobs) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("invalid yaml node type for jobs")
	}

	*o = make(GithubActionsJobs, 0, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		name := node.Content[i].Value
		value := node.Content[i+1]

		job := GithubActionsJob{
			ID:   name,
			Line: node.Content[i].Line,
			Lines: map[string]int{
				"start": node.Content[i].Line,
			},
		}
		err := value.Decode(&job)
		if err != nil {
			return err
		}

		for j := 0; j < len(value.Content); j += 2 {
			key := value.Content[j].Value
			value := value.Content[j+1]

			switch key {
			case "runs-on":
				job.Lines["runs_on"] = value.Line
			case "if":
				job.Lines[key] = value.Line
			}
		}

		*o = append(*o, job)
	}

	return nil
}

func (o *GithubActionsJobSecrets) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode && node.Value == "inherit" {
		*o = GithubActionsJobSecrets{{Name: AllSecrets, Value: "inherit"}}
		return nil
	}

	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("invalid yaml node type for secrets")
	}

	for i := 0; i < len(node.Content); i += 2 {
		name := node.Content[i].Value
		value := node.Content[i+1].Value
		*o = append(*o, GithubActionsJobSecret{Name: name, Value: value})
	}

	return nil
}

func (o *StringList) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		*o = []string{node.Value}
		return nil
	}

	if node.Kind != yaml.SequenceNode {
		return fmt.Errorf("invalid yaml node type %v for string list", node.Kind)
	}

	var l []string = make([]string, len(node.Content))
	err := node.Decode(&l)
	if err != nil {
		return err
	}

	*o = l
	return nil
}

func (o *GithubActionsEvents) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		// on: push
		*o = GithubActionsEvents{{Name: node.Value}}
	case yaml.SequenceNode:
		// on: [push]
		*o = make(GithubActionsEvents, 0, len(node.Content))
		for _, item := range node.Content {
			*o = append(*o, GithubActionsEvent{Name: item.Value})
		}
	case yaml.MappingNode:
		// on: {push: ...}
		*o = make(GithubActionsEvents, 0, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			name := node.Content[i].Value
			value := node.Content[i+1]
			event := GithubActionsEvent{Name: name}

			if name == "schedule" {
				var crons []struct {
					Cron string `json:"cron"`
				}

				err := value.Decode(&crons)
				if err != nil {
					return err
				}

				for _, c := range crons {
					if c.Cron == "" {
						return fmt.Errorf("invalid cron object")
					}

					event.Cron = append(event.Cron, c.Cron)
				}
			} else {
				err := value.Decode(&event)
				if err != nil {
					return err
				}
			}

			*o = append(*o, event)
		}
	}

	return nil
}

func (o *GithubActionsOutputs) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("invalid yaml node type for outputs")
	}

	for i := 0; i < len(node.Content); i += 2 {
		name := node.Content[i].Value
		value := node.Content[i+1]
		var output GithubActionsOutput

		if value.Kind == yaml.ScalarNode {
			output = GithubActionsOutput{Name: name, Value: value.Value}
			*o = append(*o, output)
		} else if value.Kind == yaml.MappingNode {
			output = GithubActionsOutput{Name: name}
			err := value.Decode(&output)
			if err != nil {
				return err
			}
			*o = append(*o, output)
		}

	}

	return nil
}

func (o *GithubActionsInputs) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("invalid yaml node type for inputs")
	}

	for i := 0; i < len(node.Content); i += 2 {
		name := node.Content[i].Value
		value := node.Content[i+1]
		input := GithubActionsInput{Name: name}
		err := value.Decode(&input)

		if err != nil {
			return err
		}

		*o = append(*o, input)
	}

	return nil
}

func (o *GithubActionsEnvs) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		if len(node.Value) > 0 && node.Value[0] == '$' {
			*o = GithubActionsEnvs{{Value: node.Value}}
			return nil
		}
	}

	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("invalid yaml node type for env")
	}

	for i := 0; i < len(node.Content); i += 2 {
		name := node.Content[i].Value
		value := node.Content[i+1].Value
		*o = append(*o, GithubActionsEnv{name, value})
	}

	return nil
}

func (o *GithubActionsStep) UnmarshalYAML(node *yaml.Node) error {
	type Alias GithubActionsStep
	t := Alias{
		Line:  node.Line,
		Lines: map[string]int{"start": node.Line},
	}
	err := node.Decode(&t)
	if err != nil {
		return err
	}

	*o = GithubActionsStep(t)

	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i].Value
		value := node.Content[i+1]

		switch key {
		case "uses", "run", "if":
			o.Lines[key] = value.Line
		case "with":
			if value.Kind != yaml.MappingNode {
				continue
			}

			for j := 0; j < len(value.Content); j += 2 {
				name := value.Content[j].Value
				arg := value.Content[j+1]

				switch name {
				case "ref":
					o.Lines["with_ref"] = arg.Line
					o.WithRef = arg.Value
				case "script":
					o.Lines["with_script"] = arg.Line
					o.WithScript = arg.Value
				}
			}
		}
	}

	o.Action, _, _ = strings.Cut(o.Uses, "@")

	return nil
}

func (o *GithubActionsPermissions) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		var permission string
		switch node.Value {
		case "write-all":
			permission = PermissionWrite
		case "read-all":
			permission = PermissionRead
		default:
			return fmt.Errorf("invalid permission %s", node.Value)
		}

		*o = make(GithubActionsPermissions, 0, len(AllScopes))
		for _, scope := range AllScopes {
			*o = append(*o, GithubActionsPermission{scope, permission})
		}
		return nil
	}

	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("invalid yaml node type for permissions")
	}

	*o = make(GithubActionsPermissions, 0, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		scope := node.Content[i].Value
		permission := node.Content[i+1].Value

		*o = append(*o, GithubActionsPermission{scope, permission})
	}

	return nil
}

func (o *GithubActionsJobRunsOn) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.SequenceNode || node.Kind == yaml.ScalarNode {
		var runsOn StringList
		err := node.Decode(&runsOn)
		if err != nil {
			return err
		}
		*o = GithubActionsJobRunsOn(runsOn)
	}

	if node.Kind == yaml.MappingNode {
		type RunsOn struct {
			Group  StringList `json:"group"`
			Labels StringList `json:"labels"`
		}
		var runsOn RunsOn
		err := node.Decode(&runsOn)
		if err != nil {
			return err
		}
		for _, group := range runsOn.Group {
			if group == "" {
				return fmt.Errorf("unexpected empty group")
			}
			*o = append(*o, fmt.Sprintf("group:%s", group))
		}

		for _, label := range runsOn.Labels {
			if label == "" {
				return fmt.Errorf("unexpected empty label")
			}
			*o = append(*o, fmt.Sprintf("label:%s", label))
		}
	}

	return nil
}

func (o *GithubActionsJobContainer) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		o.Image = node.Value
		return nil
	}

	type container GithubActionsJobContainer
	var c container
	err := node.Decode(&c)
	if err != nil {
		return err
	}
	*o = GithubActionsJobContainer(c)
	return nil
}

func (o *GithubActionsJobEnvironments) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		*o = GithubActionsJobEnvironments{{Name: node.Value}}
		return nil
	}

	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("invalid yaml node type for environment")
	}

	var env GithubActionsJobEnvironment
	err := node.Decode(&env)
	if err != nil {
		return err
	}

	*o = GithubActionsJobEnvironments{env}
	return nil
}
