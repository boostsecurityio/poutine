package scanner

import (
	"github.com/boostsecurityio/poutine/models"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type GithubActionsMetadataParser struct {
	pattern      *regexp.Regexp
	scanningPath string
}

func NewGithubActionsMetadataParser(scanningPath string) *GithubActionsMetadataParser {
	return &GithubActionsMetadataParser{
		pattern:      regexp.MustCompile(`(\b|/)action\.ya?ml$`),
		scanningPath: scanningPath,
	}
}

func (p *GithubActionsMetadataParser) MatchPattern() *regexp.Regexp {
	return p.pattern
}

func (p *GithubActionsMetadataParser) Parse(filePath string, info fs.FileInfo, pkgInsights *models.PackageInsights) error {
	relPath, err := filepath.Rel(p.scanningPath, filePath)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	var meta models.GithubActionsMetadata
	err = yaml.Unmarshal(data, &meta)
	if err != nil {
		log.Debug().Err(err).Str("file", relPath).Msg("failed to unmarshal YAML file")
		return nil
	}

	if meta.IsValid() {
		meta.Path = relPath
		pkgInsights.GithubActionsMetadata = append(pkgInsights.GithubActionsMetadata, meta)
	} else {
		log.Debug().Str("file", relPath).Msg("invalid Github Actions metadata")
	}

	return nil
}

type GithubActionWorkflowParser struct {
	pattern      *regexp.Regexp
	scanningPath string
}

func NewGithubActionWorkflowParser(scanningPath string) *GithubActionWorkflowParser {
	return &GithubActionWorkflowParser{
		pattern:      regexp.MustCompile(`^\.github/workflows/[^/]+\.ya?ml$`),
		scanningPath: scanningPath,
	}
}

func (p *GithubActionWorkflowParser) MatchPattern() *regexp.Regexp {
	return p.pattern
}

func (p *GithubActionWorkflowParser) Parse(filePath string, info fs.FileInfo, pkgInsights *models.PackageInsights) error {
	relPath, err := filepath.Rel(p.scanningPath, filePath)
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
		pkgInsights.GithubActionsWorkflows = append(pkgInsights.GithubActionsWorkflows, workflow)
	} else {
		log.Debug().Str("file", relPath).Msg("failed to parse github actions workflow")
	}

	return nil
}

type AzurePipelinesParser struct {
	pattern      *regexp.Regexp
	scanningPath string
}

func NewAzurePipelinesParser(scanningPath string) *AzurePipelinesParser {
	return &AzurePipelinesParser{
		pattern:      regexp.MustCompile(`\.?azure-pipelines(-.+)?\.ya?ml$`),
		scanningPath: scanningPath,
	}
}

func (p *AzurePipelinesParser) MatchPattern() *regexp.Regexp {
	return p.pattern
}

func (p *AzurePipelinesParser) Parse(filePath string, info fs.FileInfo, pkgInsights *models.PackageInsights) error {
	relPath, err := filepath.Rel(p.scanningPath, filePath)
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
		pkgInsights.AzurePipelines = append(pkgInsights.AzurePipelines, pipeline)
	} else {
		log.Debug().Str("file", relPath).Msg("failed to parse azure pipeline")
	}

	return nil
}

const MAX_DEPTH = 150

type GitlabCiParser struct {
	pattern      *regexp.Regexp
	scanningPath string
}

func NewGitlabCiParser(scanningPath string) *GitlabCiParser {
	return &GitlabCiParser{
		pattern:      regexp.MustCompile(`\.?gitlab-ci(-.+)?\.ya?ml$`),
		scanningPath: scanningPath,
	}
}

func (p *GitlabCiParser) MatchPattern() *regexp.Regexp {
	return p.pattern
}

func (p *GitlabCiParser) Parse(filePath string, info fs.FileInfo, pkgInsights *models.PackageInsights) error {
	files := map[string]bool{}
	queue := []string{"/.gitlab-ci.yml"}
	configs := []models.GitlabciConfig{}

	for len(queue) > 0 && len(configs) < MAX_DEPTH {
		repoPath := filepath.Join("/", queue[0])
		configPath := filepath.Join(p.scanningPath, repoPath)
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

	pkgInsights.GitlabciConfigs = append(pkgInsights.GitlabciConfigs, configs...)

	return nil
}

type PipelineAsCodeTektonParser struct {
	pattern      *regexp.Regexp
	scanningPath string
}

func NewPipelineAsCodeTektonParser(scanningPath string) *PipelineAsCodeTektonParser {
	return &PipelineAsCodeTektonParser{
		pattern:      regexp.MustCompile(`^\.tekton/[^/]+\.ya?ml$`),
		scanningPath: scanningPath,
	}
}

func (p *PipelineAsCodeTektonParser) MatchPattern() *regexp.Regexp {
	return p.pattern
}

func (p *PipelineAsCodeTektonParser) Parse(filePath string, info fs.FileInfo, pkgInsights *models.PackageInsights) error {
	relPath, err := filepath.Rel(p.scanningPath, filePath)
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

	pipelineAsCode.Path = relPath
	pkgInsights.PipelineAsCodeTekton = append(pkgInsights.PipelineAsCodeTekton, pipelineAsCode)

	return nil
}
