package scanner

import (
	"context"
	"github.com/boostsecurityio/poutine/models"
	"github.com/rs/zerolog/log"
	"io/fs"
	"os"
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
	relPath, err := filepath.Rel(scanner.Path, filePath)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	workflow := models.GithubActionsWorkflow{Path: relPath}
	err = yaml.Unmarshal(data, &workflow)
	if err != nil {
		log.Debug().Err(err).Str("file", relPath).Msg("failed to unmarshal yaml file")
		return nil
	}

	if workflow.IsValid() {
		scanner.Package.GithubActionsWorkflows = append(scanner.Package.GithubActionsWorkflows, workflow)
	} else {
		log.Debug().Str("file", relPath).Msg("failed to parse github actions workflow")
	}

	return nil
}

func parseAzurePipelines(scanner *Scanner, filePath string, fileInfo fs.FileInfo) error {
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
		log.Debug().Err(err).Str("file", relPath).Msg("failed to unmarshal yaml file")
		return nil
	}

	if pipeline.IsValid() {
		pipeline.Path = relPath
		scanner.Package.AzurePipelines = append(scanner.Package.AzurePipelines, pipeline)
	} else {
		log.Debug().Str("file", relPath).Msg("failed to parse azure pipeline")
	}

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

func parsePipelineAsCodeTekton(scanner *Scanner, filePath string, fileInfo fs.FileInfo) error {
	relPath, err := filepath.Rel(scanner.Path, filePath)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	pipelineAsCode := models.PipelineAsCodeTekton{}
	err = yaml.Unmarshal(data, &pipelineAsCode)
	if err != nil {
		log.Debug().Err(err).Str("file", relPath).Msg("failed to unmarshal pipeline as code yaml file")
		return nil
	}

	scanner.Package.PipelineAsCodeTekton = append(scanner.Package.PipelineAsCodeTekton, pipelineAsCode)

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
			regexp.MustCompile(`(\b|/)action\.ya?ml$`):              parseGithubActionsMetadata,
			regexp.MustCompile(`^\.github/workflows/[^/]+\.ya?ml$`): parseGithubWorkflows,
			regexp.MustCompile(`^\.tekton/[^/]+\.ya?ml$`):           parsePipelineAsCodeTekton,
			regexp.MustCompile(`\.?azure-pipelines(-.+)?\.ya?ml$`):  parseAzurePipelines,
			regexp.MustCompile(`\.?gitlab-ci(-.+)?\.ya?ml$`):        parseGitlabCi,
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
		if info.IsDir() && info.Name() == ".git" {
			return filepath.SkipDir
		}
		if info.IsDir() {
			return nil
		}
		relativePath, err := filepath.Rel(s.Path, filePath)
		if err != nil {
			log.Error().Err(err).Msg("error getting relative path")
			return err
		}
		for pattern, parseFunc := range s.ParseFuncs {
			if pattern.MatchString(relativePath) {
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
