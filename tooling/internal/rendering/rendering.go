package rendering

import (
	"fmt"
	"path/filepath"

	"github.com/mindclade/gitops/tooling/internal/release"
)

var environmentDocuments = []string{
	"cluster-set.yaml",
	"infrastructure-exports.yaml",
	"platform-releases.yaml",
	"service-releases.yaml",
	"worker-releases.yaml",
	"policy-bindings.yaml",
	"secret-references.yaml",
}

type Input struct {
	Path     string         `json:"path"`
	Digest   string         `json:"digest"`
	Document map[string]any `json:"document"`
}

type Render struct {
	SchemaVersion string  `json:"schemaVersion"`
	Environment   string  `json:"environment"`
	Inputs        []Input `json:"inputs"`
}

func Environment(root, environment string) ([]byte, error) {
	if !release.ValidEnvironment(environment) {
		return nil, fmt.Errorf("unknown environment %q", environment)
	}
	result := Render{SchemaVersion: "v1", Environment: environment, Inputs: make([]Input, 0, len(environmentDocuments))}
	for _, name := range environmentDocuments {
		relative := filepath.ToSlash(filepath.Join("environments", environment, name))
		path := filepath.Join(root, filepath.FromSlash(relative))
		document, err := release.ReadObject(path)
		if err != nil {
			return nil, err
		}
		digest, err := release.FileDigest(path)
		if err != nil {
			return nil, err
		}
		result.Inputs = append(result.Inputs, Input{Path: relative, Digest: digest, Document: document})
	}
	return release.CanonicalJSON(result)
}
