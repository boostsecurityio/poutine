package models

import (
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"
)

type Purl struct {
	packageurl.PackageURL
}

func NewPurl(purl string) (Purl, error) {
	p, err := packageurl.FromString(purl)
	if err != nil {
		return Purl{}, err
	}

	return Purl{PackageURL: p}, nil
}

func (p *Purl) Normalize() {
	if p.Type == "githubactions" {
		ns := p.Namespace
		if ns != "" {
			ns += "/"
		}
		parts := strings.SplitN(ns+p.Name, "/", 3)
		if len(parts) >= 2 {
			p.Namespace = strings.ToLower(parts[0])
			p.Name = strings.ToLower(parts[1])
		}

		if len(parts) == 3 {
			p.Subpath = parts[2]
		}
	}
}

func (p *Purl) FullName() string {
	name := p.Name
	if p.Namespace != "" {
		name = p.Namespace + "/" + name
	}
	return name
}

func (p *Purl) Link() string {
	repo := p.FullName()
	qualifiers := p.Qualifiers.Map()
	repoUrl := qualifiers["repository_url"]

	if p.Type == "githubactions" || p.Type == "github" {
		if repoUrl != "" {
			return fmt.Sprintf("https://%s/%s", repoUrl, repo)
		} else {
			return fmt.Sprintf("https://github.com/%s", repo)
		}
	}
	if p.Type == "gitlab" {
		if repoUrl != "" {
			return fmt.Sprintf("https://%s/%s", repoUrl, repo)
		} else {
			return fmt.Sprintf("https://gitlab.com/%s", repo)
		}
	}
	return ""
}

func PurlFromDockerImage(image string) (Purl, error) {
	purl, err := packageurl.FromString("pkg:docker/" + image)
	return Purl{PackageURL: purl}, err
}

func PurlFromGithubActions(uses string, sourceGitRepo string, sourceGitRef string) (Purl, error) {
	purl := Purl{}

	if len(uses) == 0 {
		return purl, fmt.Errorf("invalid uses string")
	}

	isLocal := uses[0] == '.'
	if isLocal {
		if strings.Contains(uses, "..") {
			return purl, fmt.Errorf("invalid uses string")
		}
		subPath := uses[2:]
		purl.Subpath = subPath
		purl.Type = "githubactions"

		purl.Name = sourceGitRepo
		purl.Version = sourceGitRef

		purl.Normalize()
		return purl, nil
	}

	if strings.HasPrefix(uses, "docker://") {
		image := uses[9:]
		return PurlFromDockerImage(image)
	}

	parts := strings.Split(uses, "@")

	if len(parts) != 2 {
		return purl, fmt.Errorf("invalid uses string")
	}

	actionName := parts[0]
	actionVersion := parts[1]

	purl.Type = "githubactions"
	purl.Name = actionName
	purl.Version = actionVersion

	purl.Normalize()
	return purl, nil
}
