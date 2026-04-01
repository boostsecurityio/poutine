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

// PurlFromDockerImage parses a Docker image reference and returns a valid
// Docker PURL per https://github.com/package-url/purl-spec/blob/main/types/docker-definition.json
//
// Examples:
//
//	alpine:latest           -> pkg:docker/alpine@latest
//	ghcr.io/org/image:tag   -> pkg:docker/org/image@tag?repository_url=ghcr.io
//	myimage@sha256:abcdef   -> pkg:docker/myimage@sha256%3Aabcdef
func PurlFromDockerImage(image string) (Purl, error) {
	if image == "" {
		return Purl{}, fmt.Errorf("empty docker image reference")
	}

	var name, version string
	var qualifiers packageurl.Qualifiers

	// Split off version: either @digest or :tag
	if idx := strings.Index(image, "@"); idx != -1 {
		version = image[idx+1:]
		image = image[:idx]
	} else if idx := strings.LastIndex(image, ":"); idx != -1 {
		// Ensure the colon is after the last slash (i.e. it's a tag, not a port/registry part)
		if slashIdx := strings.LastIndex(image, "/"); idx > slashIdx {
			version = image[idx+1:]
			image = image[:idx]
		}
	}

	// Split registry from the path.
	// A registry is present if the first path component contains a dot or colon,
	// or is "localhost" (standard Docker reference parsing heuristic).
	parts := strings.SplitN(image, "/", 2)
	if len(parts) == 2 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		registry := parts[0]
		qualifiers = packageurl.QualifiersFromMap(map[string]string{
			"repository_url": registry,
		})
		image = parts[1]
	}

	// Split remaining path into namespace and name
	if idx := strings.LastIndex(image, "/"); idx != -1 {
		namespace := image[:idx]
		name = image[idx+1:]
		p := packageurl.NewPackageURL("docker", namespace, name, version, qualifiers, "")
		return Purl{PackageURL: *p}, nil
	}

	p := packageurl.NewPackageURL("docker", "", image, version, qualifiers, "")
	return Purl{PackageURL: *p}, nil
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
