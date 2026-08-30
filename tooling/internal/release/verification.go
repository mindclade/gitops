package release

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
)

var (
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

var Environments = []string{"development", "staging", "production", "restricted"}

func ValidEnvironment(value string) bool {
	for _, environment := range Environments {
		if value == environment {
			return true
		}
	}
	return false
}

func ValidateDigest(value string) error {
	if !digestPattern.MatchString(value) {
		return fmt.Errorf("%q is not an immutable sha256 digest", value)
	}
	return nil
}

func ValidateRevision(value string) error {
	if !revisionPattern.MatchString(value) {
		return fmt.Errorf("%q is not a 40-character source revision", value)
	}
	return nil
}

func ReadObject(path string) (map[string]any, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var value map[string]any
	if err := json.Unmarshal(content, &value); err != nil {
		return nil, fmt.Errorf("%s must be JSON-compatible YAML: %w", path, err)
	}
	if value == nil {
		return nil, errors.New("document must be an object")
	}
	return value, nil
}

func CanonicalJSON(value any) ([]byte, error) {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(content, '\n'), nil
}

func FileDigest(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
