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

type parseFunc func(*Scanner, string, fs.FileInfo) error

func parseGithubActionsMetadata(scanner *Scanner, filePath string, fileInfo fs.FileInfo) error {
	metadata := make([]models.GithubActionsMetadata, 0)

	if fileInfo.IsDir() && fileInfo.Name() == ".git" {
		return filepath.SkipDir
	}

	if fileInfo.IsDir() || (fileInfo.Name() != "action.yml" && fileInfo.Name() != "action.yaml") {
		return nil
	}

	relPath, err := filepath.Rel(scanner.Path, filePath)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	meta := models.GithubActionsMetadata{
		Path: relPath,
	}
	err = yaml.Unmarshal(data, &meta)
	if err != nil {
		log.Debug().Err(err).Str("file", relPath).Msg("failed to unmarshal yaml file")
		return nil
	}

	if meta.IsValid() {
		metadata = append(metadata, meta)
	} else {
		log.Debug().Str("file", relPath).Msg("failed to parse github actions metadata")
	}

	scanner.Package.GithubActionsMetadata = append(scanner.Package.GithubActionsMetadata, metadata...)

	return nil
}

func parseGithubWorkflows(scanner *Scanner, filePath string, fileInfo fs.FileInfo) error {
	folder := filepath.Join(scanner.Path, ".github/workflows")
	files, err := os.ReadDir(folder)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}

	workflows := make([]models.GithubActionsWorkflow, 0, len(files))
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		workflowFilePath := path.Join(folder, file.Name())
		if !strings.HasSuffix(workflowFilePath, ".yml") && !strings.HasSuffix(workflowFilePath, ".yaml") {
			continue
		}
		relPath, err := filepath.Rel(scanner.Path, workflowFilePath)
		if err != nil {
			return err
		}

		data, err := os.ReadFile(workflowFilePath)
		if err != nil {
			return err
		}

		workflow := models.GithubActionsWorkflow{Path: relPath}
		err = yaml.Unmarshal(data, &workflow)
		if err != nil {
			log.Debug().Err(err).Str("file", relPath).Msg("failed to unmarshal yaml file")
			continue
		}

		if workflow.IsValid() {
			workflows = append(workflows, workflow)
		} else {
			log.Debug().Str("file", relPath).Msg("failed to parse github actions workflow")
		}
	}

	scanner.Package.GithubActionsWorkflows = append(scanner.Package.GithubActionsWorkflows, workflows...)

	return nil
}

func parseAzurePipelines(scanner *Scanner, filePath string, fileInfo fs.FileInfo) error {
	pipelines := []models.AzurePipeline{}
	if fileInfo.IsDir() && fileInfo.Name() == ".git" {
		return filepath.SkipDir
	}

	if fileInfo.IsDir() {
		return nil
	}
	relPath, err := filepath.Rel(scanner.Path, filePath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	pipeline := models.AzurePipeline{}
	err = yaml.Unmarshal(data, &pipeline)
	if err != nil {
		return err
	}

	if pipeline.IsValid() {
		pipeline.Path = relPath
		pipelines = append(pipelines, pipeline)
	} else {
		log.Debug().Str("file", relPath).Msg("failed to parse azure pipeline")
	}

	scanner.Package.AzurePipelines = append(scanner.Package.AzurePipelines, pipelines...)

	return nil
}

func parseGitlabCi(scanner *Scanner, filePath string, fileInfo fs.FileInfo) error {
	files := map[string]bool{}
	queue := []string{"/.gitlab-ci.yml"}
	configs := []models.GitlabciConfig{}

	for len(queue) > 0 && len(configs) < MAX_DEPTH {
		repoPath := filepath.Join("/", queue[0])
		configPath := filepath.Join(scanner.Path, repoPath)
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

	scanner.Package.GitlabciConfigs = append(scanner.Package.GitlabciConfigs, configs...)

	return nil
}

type Scanner struct {
	Path          string
	Package       *models.PackageInsights
	ResolvedPurls map[string]bool
	ParseFuncs    map[*regexp.Regexp]parseFunc
}

func NewScanner(path string) Scanner {
	return Scanner{
		Path:          path,
		Package:       &models.PackageInsights{},
		ResolvedPurls: map[string]bool{},
		ParseFuncs: map[*regexp.Regexp]parseFunc{
			regexp.MustCompile(`action\.ya?ml$`):                   parseGithubActionsMetadata,
			regexp.MustCompile(`.github`):                          parseGithubWorkflows,
			regexp.MustCompile(`\.?azure-pipelines(-.+)?\.ya?ml$`): parseAzurePipelines,
			regexp.MustCompile(`\.?gitlab-ci(-.+)?\.y?ml$`):        parseGitlabCi,
		},
	}
}

func (s *Scanner) Run(ctx context.Context, o *opa.Opa) error {
	err := s.walkAndParse()
	if err != nil {
		return err
	}

	return s.inventory(ctx, o)
}

func (s *Scanner) walkAndParse() error {
	return filepath.Walk(s.Path, func(filePath string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		for pattern, parseFunc := range s.ParseFuncs {
			if pattern.MatchString(info.Name()) {
				if err := parseFunc(s, filePath, info); err != nil {
					log.Error().Err(err).Msg("error parsing file")
					// Decide whether to return error or continue processing other files
				}
			}
		}
		return nil
	})
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
