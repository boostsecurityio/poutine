package scanner

import (
	"context"
	"errors"
	"github.com/boostsecurityio/poutine/models"
	"github.com/rs/zerolog/log"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/boostsecurityio/poutine/opa"
	"gopkg.in/yaml.v3"
	"regexp"
)

const MAX_DEPTH = 150

type Scanner struct {
	Path          string
	Package       *models.PackageInsights
	ResolvedPurls map[string]bool
}

func NewScanner(path string) Scanner {
	return Scanner{
		Path:          path,
		Package:       &models.PackageInsights{},
		ResolvedPurls: map[string]bool{},
	}
}

func (s *Scanner) Run(ctx context.Context, o *opa.Opa) error {
	err := s.parse()
	if err != nil {
		return err
	}

	return s.inventory(ctx, o)
}

func (s *Scanner) inventory(ctx context.Context, o *opa.Opa) error {
	result := opa.InventoryResult{}
	err := o.Eval(ctx,
		"data.poutine.queries.inventory.result",
		map[string]interface{}{
			"packages": []interface{}{s.Package},
		},
		&result,
	)
	if err != nil {
		return err
	}

	s.Package.BuildDependencies = result.BuildDependencies
	s.Package.PackageDependencies = result.PackageDependencies

	return nil
}

func (s *Scanner) parse() error {
	var err error
	s.Package.GithubActionsMetadata, err = s.GithubActionsMetadata()
	if err != nil {
		return err
	}

	s.Package.GithubActionsWorkflows, err = s.GithubWorkflows()
	if err != nil {
		return err
	}

	s.Package.GitlabciConfigs, err = s.GitlabciConfigs()
	if err != nil {
		return err
	}

	s.Package.AzurePipelines, err = s.AzurePipelines()
	if err != nil {
		return err
	}

	return nil
}

func (s *Scanner) GithubActionsMetadata() ([]models.GithubActionsMetadata, error) {
	metadata := make([]models.GithubActionsMetadata, 0)

	err := filepath.Walk(s.Path,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() && info.Name() == ".git" {
				return filepath.SkipDir
			}

			if info.IsDir() || (info.Name() != "action.yml" && info.Name() != "action.yaml") {
				return nil
			}

			rel_path, err := filepath.Rel(s.Path, path)
			if err != nil {
				return err
			}

			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			meta := models.GithubActionsMetadata{
				Path: rel_path,
			}
			err = yaml.Unmarshal(data, &meta)
			if err != nil {
				log.Debug().Err(err).Str("file", rel_path).Msg("failed to unmarshal yaml file")
				return nil
			}

			if meta.IsValid() {
				metadata = append(metadata, meta)
			} else {
				log.Debug().Str("file", rel_path).Msg("failed to parse github actions metadata")
			}

			return nil
		},
	)

	return metadata, err
}

func (s *Scanner) GithubWorkflows() ([]models.GithubActionsWorkflow, error) {
	folder := filepath.Join(s.Path, ".github/workflows")
	files, err := os.ReadDir(folder)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []models.GithubActionsWorkflow{}, nil
		}
		return nil, err
	}

	workflows := make([]models.GithubActionsWorkflow, 0, len(files))
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		path := path.Join(folder, file.Name())
		if !strings.HasSuffix(path, ".yml") && !strings.HasSuffix(path, ".yaml") {
			continue
		}
		rel_path, err := filepath.Rel(s.Path, path)
		if err != nil {
			return nil, err
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		workflow := models.GithubActionsWorkflow{Path: rel_path}
		err = yaml.Unmarshal(data, &workflow)
		if err != nil {
			log.Debug().Err(err).Str("file", rel_path).Msg("failed to unmarshal yaml file")
			continue
		}

		if workflow.IsValid() {
			workflows = append(workflows, workflow)
		} else {
			log.Debug().Str("file", rel_path).Msg("failed to parse github actions workflow")
		}
	}

	return workflows, err
}

func (s *Scanner) GitlabciConfigs() ([]models.GitlabciConfig, error) {
	files := map[string]bool{}
	queue := []string{"/.gitlab-ci.yml"}
	configs := []models.GitlabciConfig{}

	for len(queue) > 0 && len(configs) < MAX_DEPTH {
		repoPath := filepath.Join("/", queue[0])
		configPath := filepath.Join(s.Path, repoPath)
		queue = queue[1:]

		if files[repoPath] {
			continue
		}

		files[repoPath] = true

		if strings.Contains(repoPath, "*") || strings.Contains(repoPath, "$") {
			continue
		}

		data, err := os.ReadFile(configPath)
		if err != nil {
			// skip missing files
			continue
		}

		config, err := models.ParseGitlabciConfig(data)
		if err != nil {
			log.Debug().Err(err).Str("file", repoPath).Msg("failed to parse gitlabci config")
			continue
		}

		config.Path = repoPath[1:]
		for _, include := range config.Include {
			if include.Local == "" {
				continue
			}
			queue = append(queue, include.Local)
		}

		configs = append(configs, *config)
	}

	return configs, nil
}

var azurePipelineFileRegex = regexp.MustCompile(`\.?azure-pipelines(-.+)?\.ya?ml$`)

func (s *Scanner) AzurePipelines() ([]models.AzurePipeline, error) {
	pipelines := []models.AzurePipeline{}
	err := filepath.Walk(s.Path,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() && info.Name() == ".git" {
				return filepath.SkipDir
			}

			if info.IsDir() {
				return nil
			}

			if !azurePipelineFileRegex.MatchString(info.Name()) {
				return nil
			}

			rel_path, err := filepath.Rel(s.Path, path)
			if err != nil {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			pipeline := models.AzurePipeline{}
			err = yaml.Unmarshal(data, &pipeline)
			if err != nil {
				return err
			}

			if pipeline.IsValid() {
				pipeline.Path = rel_path
				pipelines = append(pipelines, pipeline)
			} else {
				log.Debug().Str("file", rel_path).Msg("failed to parse azure pipeline")
			}

			return nil
		},
	)

	if err != nil {
		return nil, err
	}

	return pipelines, nil
}
