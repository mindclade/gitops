package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mindclade/gitops/tooling/internal/release"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
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

var environmentSchemas = map[string]string{
	"cluster-set.yaml":            "cluster_set.schema.json",
	"infrastructure-exports.yaml": "infrastructure_exports.schema.json",
	"platform-releases.yaml":      "platform_releases.schema.json",
	"service-releases.yaml":       "workload_releases.schema.json",
	"worker-releases.yaml":        "workload_releases.schema.json",
	"policy-bindings.yaml":        "policy_bindings.schema.json",
	"secret-references.yaml":      "secret_references.schema.json",
}

// The source intentionally carries no authoritative external evidence
// verifier yet. Active desired state must remain impossible to qualify until a
// reviewed cryptographic verifier replaces this blocker in code.
const connectedEvidenceVerifierImplementation = "unbound"

// These source modules are contract-only until their independent reconcilers
// are implemented. Keep their blockers separate from connected evidence so a
// verifier implementation cannot accidentally make inert contracts active.
const (
	platformDeploymentImplementation          = "unbound"
	policyBindingReconcilerImplementation     = "unbound"
	secretReferenceMaterializerImplementation = "unbound"
	reviewedArgoVersion                       = "v3.5.2"
	reviewedArgoRevision                      = "e258ee23c3e52266d407572f4bcdfe7d9ed36cb5"
	reviewedArgoSHA256                        = "9a87f2b3e14c278f12501eb0ef5c3955b27cf05370ca425381c6a908cf85a5c5"
)

var bootstrapProvenanceKeys = []string{
	"upstream-version",
	"upstream-revision",
	"upstream-url",
	"upstream-sha256",
	"argocd-image",
	"dex-image",
	"redis-image",
}

var argoRBACPolicyLines = []string{
	"p, role:security-auditor, applications, get, */*, allow",
	"p, role:security-auditor, logs, get, */*, allow",
	"p, role:release-promoter, applications, get, services/*, allow",
	"p, role:release-promoter, applications, get, workers/*, allow",
	"p, role:release-promoter, applications, sync, services/*, allow",
	"p, role:release-promoter, applications, sync, workers/*, allow",
	"p, role:platform-operator, applications, get, platform/*, allow",
	"p, role:platform-operator, applications, sync, platform/*, allow",
	"p, role:platform-operator, applications, action/*, platform/*, allow",
	"g, mindclade:security, role:security-auditor",
	"g, mindclade:release, role:release-promoter",
	"g, mindclade:platform, role:platform-operator",
}

var reviewedBootstrapImages = map[string]string{
	"argocd-image": "quay.io/argoproj/argocd@sha256:e2aadfae709d904e87f46ba4aa49601d827b3022db22cd4d03aae816a2e7097b",
	"dex-image":    "ghcr.io/dexidp/dex@sha256:8499afd690c437f52301efd2b05b2455da5bd2dfc20332cd697dc9937f808462",
	"redis-image":  "public.ecr.aws/docker/library/redis@sha256:08ad0b1d280850169a790dba1393ff7a90aef951fc19632cf4d3ce4f78e679ba",
}

var reviewedAppProjectDigests = map[string]string{
	"default":    "99f8a6f36b018af95922854d595d59d51d60e0732b042987e11009a4f5988aed",
	"platform":   "ddd4d417a6dc48b041b4e1fe3a033bce3b422e1eb5953e1f03669ba65fa7b19d",
	"restricted": "325676cf18996f3b05524a4f0f31b364f287e474d7617af23b3839144acf6787",
	"services":   "c5a12a3ea6090f8cdbe0b8fb47b0e03ac832fb1d667090f8b97a9d2e37e0e17a",
	"workers":    "6bc1642458e3ff44c053b386e501f4d4cb589ce5015f4d775f75832a74b667fd",
}

func addPaths(target map[string]bool, prefix string, names ...string) {
	for _, name := range names {
		target[filepath.ToSlash(filepath.Join(prefix, name))] = true
	}
}

func ExpectedSourceFiles() map[string]bool {
	expected := map[string]bool{}
	addPaths(expected, "", ".editorconfig", ".gitignore", "BUILD.bazel", "LICENSE", "MODULE.bazel", "README.md", "SECURITY.md", "component.yaml", "justfile")
	addPaths(expected, ".github", "CODEOWNERS", "dependabot.yml", "pull_request_template.md")
	addPaths(expected, ".github/workflows", "pull-request.yml", "promotion.yml", "drift-detection.yml", "rollback-verification.yml")
	addPaths(expected, "controllers/argocd", "namespace.yaml", "repository-credentials-reference.yaml", "notifications.yaml", "resource-customizations.yaml", "kustomization.yaml")
	addPaths(expected, "controllers/applicationsets", "platform-components.yaml", "control-plane-services.yaml", "execution-workers.yaml", "environment-root.yaml")
	addPaths(expected, "projects", "platform.appproject.yaml", "services.appproject.yaml", "workers.appproject.yaml", "restricted.appproject.yaml")
	for _, component := range []string{"kueue", "jobset", "otel-collector", "external-secrets", "policy-controller", "gpu-operator", "ingress"} {
		addPaths(expected, "platform/"+component, "release.yaml", "values.yaml", "kustomization.yaml")
	}
	for _, environment := range release.Environments {
		addPaths(expected, "environments/"+environment, append(environmentDocuments, "kustomization.yaml")...)
	}
	addPaths(expected, "schemas/v1", "cluster_set.schema.json", "infrastructure_exports.schema.json", "platform_releases.schema.json", "workload_releases.schema.json", "policy_bindings.schema.json", "secret_references.schema.json", "promotion_receipt.schema.json")
	policies := []string{"signed_release", "immutable_digest", "approved_environment", "destination_allowlist", "secret_reference", "rollout_safety"}
	for _, name := range policies {
		addPaths(expected, "policy", name+".rego")
		addPaths(expected, "policy/tests", name+"_test.rego")
	}
	addPaths(expected, "tests/render", "test_development_render.py", "test_staging_render.py", "test_production_render.py", "test_restricted_render.py")
	addPaths(expected, "tests/promotion", "test_evidence_chain.py", "test_schema_compatibility.py")
	addPaths(expected, "tests/failure", "test_partial_sync.py")
	addPaths(expected, "tests/rollback", "test_previous_digest.py")
	addPaths(expected, "tests/drift", "test_live_object_diff.py")
	addPaths(expected, "tooling", "go.mod", "go.sum", "BUILD.bazel")
	addPaths(expected, "tooling/cmd/promotectl", "main.go")
	addPaths(expected, "tooling/internal/release", "verification.go")
	addPaths(expected, "tooling/internal/rendering", "rendering.go")
	addPaths(expected, "tooling/internal/policy", "policy.go")
	addPaths(expected, "tooling/internal/promotion", "promotion.go")
	addPaths(expected, "tooling/internal/rollback", "rollback.go")
	addPaths(expected, "tooling/internal/evidence", "receipt.go")
	addPaths(expected, "runbooks", "argocd-unavailable.md", "failed-synchronization.md", "deployment-drift.md", "compromised-release.md", "emergency-rollback.md", "cluster-rebootstrap.md")
	return expected
}

func actualSourceFiles(root string) (map[string]bool, error) {
	actual := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && entry.Name() == ".git" {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("source symlink is forbidden: %s", path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		actual[filepath.ToSlash(relative)] = true
		return nil
	})
	return actual, err
}

type componentDocument struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name        string            `yaml:"name"`
		Description string            `yaml:"description"`
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
	Spec struct {
		Type                string   `yaml:"type"`
		Lifecycle           string   `yaml:"lifecycle"`
		Maturity            string   `yaml:"maturity"`
		Owner               string   `yaml:"owner"`
		RepositoryClass     string   `yaml:"repository_class"`
		DataClassification  string   `yaml:"data_classification"`
		ProductionAuthority bool     `yaml:"production_authority"`
		Dependencies        []string `yaml:"dependencies"`
		Provides            []string `yaml:"provides"`
		Consumers           []string `yaml:"consumers"`
		Release             struct {
			Strategy  string   `yaml:"strategy"`
			Artifact  string   `yaml:"artifact"`
			Immutable bool     `yaml:"immutable"`
			Evidence  []string `yaml:"evidence"`
		} `yaml:"release"`
	} `yaml:"spec"`
}

type bootstrapPatch struct {
	Path   string `yaml:"path"`
	Target struct {
		Group   string `yaml:"group"`
		Version string `yaml:"version"`
		Kind    string `yaml:"kind"`
		Name    string `yaml:"name"`
	} `yaml:"target"`
	Patch string `yaml:"patch"`
}

type bootstrapKustomization struct {
	APIVersion       string   `yaml:"apiVersion"`
	Kind             string   `yaml:"kind"`
	Namespace        string   `yaml:"namespace"`
	Resources        []string `yaml:"resources"`
	GeneratorOptions struct {
		DisableNameSuffixHash bool              `yaml:"disableNameSuffixHash"`
		Labels                map[string]string `yaml:"labels"`
		Annotations           map[string]string `yaml:"annotations"`
	} `yaml:"generatorOptions"`
	ConfigMapGenerator []struct {
		Name     string   `yaml:"name"`
		Literals []string `yaml:"literals"`
		Files    []string `yaml:"files"`
		Envs     []string `yaml:"envs"`
		Behavior string   `yaml:"behavior"`
		Options  any      `yaml:"options"`
	} `yaml:"configMapGenerator"`
	Images []struct {
		Name    string `yaml:"name"`
		NewName string `yaml:"newName"`
		NewTag  string `yaml:"newTag"`
		Digest  string `yaml:"digest"`
	} `yaml:"images"`
	Patches []bootstrapPatch `yaml:"patches"`
}

type applicationSetContract struct {
	record               string
	collection           string
	invariants           []string
	applicationName      string
	project              string
	releaseClass         string
	sourcePath           string
	sourceImage          string
	sourceNamePrefix     string
	destinationName      string
	destinationNamespace string
}

func validateComponent(root string) error {
	path := filepath.Join(root, "component.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var component componentDocument
	if err := decoder.Decode(&component); err != nil {
		return fmt.Errorf("validate component.yaml: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("validate component.yaml: multiple YAML documents are not allowed")
	}
	if component.APIVersion != "mindclade.io/v1alpha1" || component.Kind != "Component" || component.Metadata.Name != "gitops" {
		return fmt.Errorf("validate component.yaml: invalid component identity")
	}
	if strings.TrimSpace(component.Metadata.Description) == "" || component.Metadata.Description != strings.TrimSpace(component.Metadata.Description) ||
		component.Metadata.Annotations["github.com/project-slug"] != "mindclade/gitops" {
		return fmt.Errorf("validate component.yaml: metadata contract is incomplete")
	}
	if component.Spec.Type != "deployment-control-plane" || component.Spec.Lifecycle != "production" || component.Spec.Maturity != "production" ||
		component.Spec.Owner != "release" || component.Spec.RepositoryClass != "deployment-source" || component.Spec.DataClassification != "confidential" ||
		!component.Spec.ProductionAuthority {
		return fmt.Errorf("validate component.yaml: owner/maturity/authority contract is invalid")
	}
	if err := validateComponentReferences("dependency", component.Spec.Dependencies, true); err != nil {
		return err
	}
	if err := requireExactComponentReferences("dependency", component.Spec.Dependencies, "component:infrastructure-live", "component:mindclade"); err != nil {
		return err
	}
	if err := validateComponentReferences("provided contract", component.Spec.Provides, false); err != nil {
		return err
	}
	if err := requireExactComponentReferences("provided contract", component.Spec.Provides, "cluster-desired-state-v1", "promotion-receipt-v1", "rollback-evidence-v1"); err != nil {
		return err
	}
	if err := validateComponentReferences("consumer", component.Spec.Consumers, true); err != nil {
		return err
	}
	if err := requireExactComponentReferences("consumer", component.Spec.Consumers, "component:argocd"); err != nil {
		return err
	}
	if component.Spec.Release.Strategy != "protected-digest-promotion" || component.Spec.Release.Artifact != "source-commit" || !component.Spec.Release.Immutable {
		return fmt.Errorf("validate component.yaml: release metadata is invalid")
	}
	requiredEvidence := map[string]bool{
		"signed-release":                 true,
		"immutable-artifact-digest":      true,
		"policy-verification":            true,
		"protected-environment-approval": true,
	}
	if len(component.Spec.Release.Evidence) != len(requiredEvidence) {
		return fmt.Errorf("validate component.yaml: release evidence contract is incomplete")
	}
	seen := map[string]bool{}
	for _, evidence := range component.Spec.Release.Evidence {
		if !requiredEvidence[evidence] || seen[evidence] {
			return fmt.Errorf("validate component.yaml: invalid release evidence %q", evidence)
		}
		seen[evidence] = true
	}
	return nil
}

func validateComponentReferences(label string, values []string, requireComponentPrefix bool) error {
	if len(values) == 0 {
		return fmt.Errorf("validate component.yaml: %s metadata is empty", label)
	}
	seen := map[string]bool{}
	for _, value := range values {
		if value == "" || value != strings.TrimSpace(value) || seen[value] {
			return fmt.Errorf("validate component.yaml: invalid %s %q", label, value)
		}
		if requireComponentPrefix && (!strings.HasPrefix(value, "component:") || strings.TrimPrefix(value, "component:") == "") {
			return fmt.Errorf("validate component.yaml: invalid %s %q", label, value)
		}
		seen[value] = true
	}
	return nil
}

func requireExactComponentReferences(label string, values []string, expected ...string) error {
	if len(values) != len(expected) {
		return fmt.Errorf("validate component.yaml: %s metadata must contain exactly the reviewed references", label)
	}
	for index, value := range expected {
		if values[index] != value {
			return fmt.Errorf("validate component.yaml: %s[%d] must equal %q", label, index, value)
		}
	}
	return nil
}

func ValidateRepository(root string) error {
	expected := ExpectedSourceFiles()
	actual, err := actualSourceFiles(root)
	if err != nil {
		return err
	}
	var missing, extra []string
	for path := range expected {
		if !actual[path] {
			missing = append(missing, path)
		}
	}
	for path := range actual {
		if !expected[path] {
			extra = append(extra, path)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 || len(extra) > 0 {
		return fmt.Errorf("source tree drift: missing=%v extra=%v", missing, extra)
	}
	if len(expected) != 126 {
		return fmt.Errorf("internal source manifest has %d files, expected 126", len(expected))
	}
	if err := validateComponent(root); err != nil {
		return err
	}
	if err := validateSchemaSet(root); err != nil {
		return err
	}
	for _, environment := range release.Environments {
		if err := ValidateEnvironment(root, environment); err != nil {
			return err
		}
	}
	if err := validatePlatformKustomizations(root); err != nil {
		return err
	}
	if err := validateCrossEnvironmentClusters(root); err != nil {
		return err
	}
	if err := validateUnboundModuleActivation(root); err != nil {
		return err
	}
	if err := validateConnectedEvidenceActivation(root); err != nil {
		return err
	}
	if err := validateFailClosedSources(root); err != nil {
		return err
	}
	return nil
}

func compileSchema(root, relative string) (*jsonschema.Schema, error) {
	absolute, err := filepath.Abs(filepath.Join(root, relative))
	if err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile("file://" + filepath.ToSlash(absolute))
	if err != nil {
		return nil, fmt.Errorf("compile %s: %w", relative, err)
	}
	return schema, nil
}

func validateSchemaSet(root string) error {
	schemas := []string{
		"cluster_set.schema.json",
		"infrastructure_exports.schema.json",
		"platform_releases.schema.json",
		"workload_releases.schema.json",
		"policy_bindings.schema.json",
		"secret_references.schema.json",
		"promotion_receipt.schema.json",
	}
	for _, name := range schemas {
		if _, err := compileSchema(root, filepath.Join("schemas", "v1", name)); err != nil {
			return err
		}
	}
	receiptSchema, err := compileSchema(root, filepath.Join("schemas", "v1", "promotion_receipt.schema.json"))
	if err != nil {
		return err
	}
	receipt := map[string]any{
		"schemaVersion": "v1", "action": "promote", "environment": "development",
		"releaseClass": "service", "component": "api-service", "cluster": "dev-cluster",
		"sourceRevision": strings.Repeat("a", 40), "artifactDigest": "sha256:" + strings.Repeat("b", 64),
		"artifactReference": "registry.example/api@sha256:" + strings.Repeat("b", 64),
		"priorDigest":       "sha256:" + strings.Repeat("c", 64), "attestationDigest": "sha256:" + strings.Repeat("d", 64),
		"signer": "https://issuer.example/workload/release", "issuedAt": "2026-08-29T12:00:00Z",
		"issuer":    "https://issuer.example",
		"approvals": []any{"github-environment:development-promotion", "governance-evidence:sha256:" + strings.Repeat("e", 64)}, "repository": "mindclade/gitops",
		"workflowRunID": "1", "workflowRunAttempt": "1", "checkedOutRevision": strings.Repeat("a", 40),
		"requester": "release-operator",
	}
	if err := receiptSchema.Validate(receipt); err != nil {
		return fmt.Errorf("validate promotion receipt contract: %w", err)
	}
	return nil
}

func ValidateEnvironment(root, environment string) error {
	if !release.ValidEnvironment(environment) {
		return fmt.Errorf("unknown environment %q", environment)
	}
	documents := map[string]map[string]any{}
	activeDocuments := map[string]bool{}
	for _, name := range environmentDocuments {
		relative := filepath.Join("environments", environment, name)
		document, err := validateSchemaDocument(root, relative, filepath.Join("schemas", "v1", environmentSchemas[name]))
		if err != nil {
			return err
		}
		if document["schemaVersion"] != "v1" || document["environment"] != environment {
			return fmt.Errorf("%s has inconsistent schema or environment", relative)
		}
		active, ok := document["active"].(bool)
		if !ok {
			return fmt.Errorf("%s must declare boolean active", relative)
		}
		activeDocuments[name] = active
		documents[name] = document
	}
	rootActive := activeDocuments["cluster-set.yaml"]
	if activeDocuments["infrastructure-exports.yaml"] != rootActive {
		return fmt.Errorf("%s cluster-set.yaml and infrastructure-exports.yaml active states must match", environment)
	}
	if err := validateEnvironmentKustomization(root, environment, rootActive); err != nil {
		return err
	}
	for _, name := range []string{"platform-releases.yaml", "service-releases.yaml", "worker-releases.yaml", "policy-bindings.yaml", "secret-references.yaml"} {
		if activeDocuments[name] && !rootActive {
			return fmt.Errorf("%s cannot be active before the %s environment root", name, environment)
		}
	}

	clusters, err := validateClusters(documents["cluster-set.yaml"], environment)
	if err != nil {
		return err
	}
	memberships, err := validateInfrastructureExports(documents["infrastructure-exports.yaml"], environment)
	if err != nil {
		return err
	}
	if rootActive {
		for cluster := range clusters {
			if !memberships[cluster] {
				return fmt.Errorf("active cluster %q has no matching infrastructure cluster-membership export", cluster)
			}
		}
		for membership := range memberships {
			if !clusters[membership] {
				return fmt.Errorf("infrastructure cluster-membership %q has no matching active cluster record", membership)
			}
		}
	}
	for _, name := range []string{"platform-releases.yaml", "service-releases.yaml", "worker-releases.yaml"} {
		if err := validateReleaseSet(documents[name], environment, clusters, name); err != nil {
			return err
		}
	}
	if err := validatePolicyBindings(documents["policy-bindings.yaml"]); err != nil {
		return err
	}
	if err := validateSecretReferences(documents["secret-references.yaml"]); err != nil {
		return err
	}
	return nil
}

func validateEnvironmentKustomization(root, environment string, rootActive bool) error {
	relative := filepath.Join("environments", environment, "kustomization.yaml")
	data, err := os.ReadFile(filepath.Join(root, relative))
	if err != nil {
		return err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("validate %s: %w", relative, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("validate %s: multiple YAML documents are not allowed", relative)
	}
	if document["apiVersion"] != "kustomize.config.k8s.io/v1beta1" || document["kind"] != "Kustomization" {
		return fmt.Errorf("validate %s: invalid Kustomization identity", relative)
	}
	if err := requireExactObjectKeys(document, relative, "apiVersion", "kind", "generatorOptions", "configMapGenerator"); err != nil {
		return err
	}
	generatorOptions, ok := document["generatorOptions"].(map[string]any)
	if !ok {
		return fmt.Errorf("validate %s: generatorOptions must be an object", relative)
	}
	if err := requireExactObjectKeys(generatorOptions, relative+".generatorOptions", "disableNameSuffixHash", "labels"); err != nil {
		return err
	}
	if disabled, ok := generatorOptions["disableNameSuffixHash"].(bool); !ok || !disabled {
		return fmt.Errorf("validate %s: generatorOptions.disableNameSuffixHash must be true", relative)
	}
	expectedActivation := "inactive"
	if rootActive {
		expectedActivation = "active"
	}
	if err := requireExactStringMap(generatorOptions["labels"], relative+".generatorOptions.labels", map[string]string{
		"gitops.mindclade.io/environment": environment,
		"gitops.mindclade.io/activation":  expectedActivation,
	}); err != nil {
		return fmt.Errorf("validate %s: %w", relative, err)
	}
	generators, ok := document["configMapGenerator"].([]any)
	if !ok || len(generators) != 1 {
		return fmt.Errorf("validate %s: configMapGenerator must contain exactly one contract generator", relative)
	}
	generator, ok := generators[0].(map[string]any)
	if !ok {
		return fmt.Errorf("validate %s: configMapGenerator[0] must be an object", relative)
	}
	if err := requireExactObjectKeys(generator, relative+".configMapGenerator[0]", "name", "files"); err != nil {
		return err
	}
	if generator["name"] != environment+"-gitops-contracts" {
		return fmt.Errorf("validate %s: configMapGenerator[0].name must equal %s-gitops-contracts", relative, environment)
	}
	if err := requireExactStringArray(generator["files"], relative+".configMapGenerator[0].files", environmentDocuments...); err != nil {
		return err
	}
	return nil
}

func validatePlatformKustomizations(root string) error {
	contracts := []struct {
		component string
		namespace string
	}{
		{component: "kueue", namespace: "kueue-system"},
		{component: "jobset", namespace: "jobset-system"},
		{component: "otel-collector", namespace: "observability"},
		{component: "external-secrets", namespace: "external-secrets"},
		{component: "policy-controller", namespace: "policy-system"},
		{component: "gpu-operator", namespace: "gpu-operator"},
		{component: "ingress", namespace: "ingress-system"},
	}
	for _, contract := range contracts {
		relative := filepath.Join("platform", contract.component, "kustomization.yaml")
		data, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			return err
		}
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		var document map[string]any
		if err := decoder.Decode(&document); err != nil {
			return fmt.Errorf("validate %s: %w", relative, err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return fmt.Errorf("validate %s: multiple YAML documents are not allowed", relative)
		}
		if err := requireExactObjectKeys(document, relative, "apiVersion", "kind", "namespace", "generatorOptions", "configMapGenerator"); err != nil {
			return err
		}
		if document["apiVersion"] != "kustomize.config.k8s.io/v1beta1" || document["kind"] != "Kustomization" || document["namespace"] != contract.namespace {
			return fmt.Errorf("validate %s: invalid contract Kustomization identity", relative)
		}
		options, ok := document["generatorOptions"].(map[string]any)
		if !ok {
			return fmt.Errorf("validate %s: generatorOptions must be an object", relative)
		}
		if err := requireExactObjectKeys(options, relative+".generatorOptions", "disableNameSuffixHash", "labels"); err != nil {
			return err
		}
		if options["disableNameSuffixHash"] != true {
			return fmt.Errorf("validate %s: generatorOptions.disableNameSuffixHash must be true", relative)
		}
		if err := requireExactStringMap(options["labels"], relative+".generatorOptions.labels", map[string]string{
			"app.kubernetes.io/part-of":      "mindclade-platform",
			"gitops.mindclade.io/activation": "inactive",
		}); err != nil {
			return err
		}
		generators, ok := document["configMapGenerator"].([]any)
		if !ok || len(generators) != 1 {
			return fmt.Errorf("validate %s: configMapGenerator must contain exactly one contract generator", relative)
		}
		generator, ok := generators[0].(map[string]any)
		if !ok {
			return fmt.Errorf("validate %s: configMapGenerator[0] must be an object", relative)
		}
		if err := requireExactObjectKeys(generator, relative+".configMapGenerator[0]", "name", "files"); err != nil {
			return err
		}
		if generator["name"] != contract.component+"-release-contract" {
			return fmt.Errorf("validate %s: configMapGenerator[0].name must equal %s-release-contract", relative, contract.component)
		}
		if err := requireExactStringArray(generator["files"], relative+".configMapGenerator[0].files", "release.yaml", "values.yaml"); err != nil {
			return err
		}
	}
	return nil
}

func validatePolicyBindings(document map[string]any) error {
	bindings, err := objectArray(document, "bindings", "policy-bindings.yaml")
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, binding := range bindings {
		name := fmt.Sprint(binding["name"])
		if seen[name] {
			return fmt.Errorf("policy-bindings.yaml contains duplicate binding name %q", name)
		}
		seen[name] = true
	}
	return nil
}

func validateSecretReferences(document map[string]any) error {
	references, err := objectArray(document, "references", "secret-references.yaml")
	if err != nil {
		return err
	}
	identities := map[string]bool{}
	externalSecrets := map[string]bool{}
	for _, reference := range references {
		namespace := fmt.Sprint(reference["namespace"])
		identity := namespace + "/" + fmt.Sprint(reference["name"])
		externalSecret := namespace + "/" + fmt.Sprint(reference["externalSecret"])
		if identities[identity] {
			return fmt.Errorf("secret-references.yaml contains duplicate reference identity %q", identity)
		}
		if externalSecrets[externalSecret] {
			return fmt.Errorf("secret-references.yaml contains duplicate ExternalSecret identity %q", externalSecret)
		}
		identities[identity] = true
		externalSecrets[externalSecret] = true
	}
	return nil
}

type workloadReleaseContract struct {
	releaseClass string
	directory    string
}

var workloadReleaseContracts = map[string]workloadReleaseContract{
	"service-releases.yaml": {releaseClass: "service", directory: "services"},
	"worker-releases.yaml":  {releaseClass: "worker", directory: "workers"},
}

func validateWorkloadReleaseMetadata(document map[string]any, environment, source string) error {
	contract, workload := workloadReleaseContracts[source]
	if !workload {
		return nil
	}
	declaredClass := fmt.Sprint(document["releaseClass"])
	if declaredClass != contract.releaseClass {
		return fmt.Errorf("%s declares releaseClass %q; required class is %q", source, declaredClass, contract.releaseClass)
	}
	values, err := objectArray(document, "releases", source)
	if err != nil {
		return err
	}
	for _, record := range values {
		component := fmt.Sprint(record["component"])
		expected := filepath.ToSlash(filepath.Join("environments", environment, contract.directory, component))
		if actual := fmt.Sprint(record["desiredStatePath"]); actual != expected {
			return fmt.Errorf("%s release %s desiredStatePath %q must equal %q", source, component, actual, expected)
		}
	}
	return nil
}

func validateSchemaDocument(root, documentPath, schemaPath string) (map[string]any, error) {
	content, err := os.ReadFile(filepath.Join(root, documentPath))
	if err != nil {
		return nil, err
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		return nil, fmt.Errorf("%s must be JSON-compatible YAML: %w", documentPath, err)
	}
	schema, err := compileSchema(root, schemaPath)
	if err != nil {
		return nil, err
	}
	if err := schema.Validate(document); err != nil {
		return nil, fmt.Errorf("validate %s: %w", documentPath, err)
	}
	return document, nil
}

func objectArray(document map[string]any, field, source string) ([]map[string]any, error) {
	rawValues, ok := document[field].([]any)
	if !ok {
		return nil, fmt.Errorf("%s.%s must be an array", source, field)
	}
	values := make([]map[string]any, 0, len(rawValues))
	for index, raw := range rawValues {
		value, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s.%s[%d] must be an object", source, field, index)
		}
		values = append(values, value)
	}
	return values, nil
}

func requireExactObjectKeys(document map[string]any, source string, expected ...string) error {
	allowed := make(map[string]bool, len(expected))
	for _, key := range expected {
		allowed[key] = true
		if _, exists := document[key]; !exists {
			return fmt.Errorf("%s lacks required field %q", source, key)
		}
	}
	for key := range document {
		if !allowed[key] {
			return fmt.Errorf("%s contains undeclared field %q", source, key)
		}
	}
	return nil
}

func requireExactStringArray(value any, source string, expected ...string) error {
	values, ok := value.([]any)
	if !ok || len(values) != len(expected) {
		return fmt.Errorf("%s must contain exactly %d entries", source, len(expected))
	}
	for index, wanted := range expected {
		if values[index] != wanted {
			return fmt.Errorf("%s[%d] must equal %q", source, index, wanted)
		}
	}
	return nil
}

func requireExactStringMap(value any, source string, expected map[string]string) error {
	document, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("%s must be an object", source)
	}
	keys := make([]string, 0, len(expected))
	for key := range expected {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if err := requireExactObjectKeys(document, source, keys...); err != nil {
		return err
	}
	for _, key := range keys {
		if document[key] != expected[key] {
			return fmt.Errorf("%s.%s must equal %q", source, key, expected[key])
		}
	}
	return nil
}

func validateClusters(document map[string]any, environment string) (map[string]bool, error) {
	values, err := objectArray(document, "clusters", "cluster-set.yaml")
	if err != nil {
		return nil, err
	}
	clusters := map[string]bool{}
	servers := map[string]bool{}
	for _, cluster := range values {
		name := fmt.Sprint(cluster["name"])
		server := fmt.Sprint(cluster["server"])
		canonicalServer, ok := canonicalClusterServer(server)
		if !ok {
			return nil, fmt.Errorf("cluster %s has an unsafe API server URI", name)
		}
		if clusters[name] || servers[canonicalServer] {
			return nil, fmt.Errorf("cluster-set.yaml contains a duplicate cluster name or server")
		}
		clusters[name] = true
		servers[canonicalServer] = true
		if err := release.ValidateRevision(fmt.Sprint(cluster["desiredStateRevision"])); err != nil {
			return nil, fmt.Errorf("cluster %s desired state: %w", name, err)
		}
		if err := release.ValidateDigest(fmt.Sprint(cluster["activationRecordDigest"])); err != nil {
			return nil, fmt.Errorf("cluster %s activation record: %w", name, err)
		}
		labels, ok := cluster["labels"].(map[string]any)
		if !ok || labels["gitops.mindclade.io/active"] != "true" || labels["gitops.mindclade.io/environment"] != environment {
			return nil, fmt.Errorf("cluster %s labels do not authorize %s activation", name, environment)
		}
	}
	return clusters, nil
}

func canonicalClusterServer(raw string) (string, bool) {
	if raw == "" || len(raw) > 2048 || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, " \r\n\t") {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") || strings.HasSuffix(parsed.Host, ":") {
		return "", false
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if host == "" {
		return "", false
	}
	port := 443
	if parsed.Port() != "" {
		port, err = strconv.Atoi(parsed.Port())
		if err != nil || port < 1 || port > 65535 {
			return "", false
		}
	}
	return "https://" + net.JoinHostPort(host, strconv.Itoa(port)), true
}

func validateReleaseSet(document map[string]any, environment string, clusters map[string]bool, source string) error {
	if err := validateWorkloadReleaseMetadata(document, environment, source); err != nil {
		return err
	}
	values, err := objectArray(document, "releases", source)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, record := range values {
		component := fmt.Sprint(record["component"])
		cluster := fmt.Sprint(record["cluster"])
		identity := cluster + "/" + component
		if seen[identity] {
			return fmt.Errorf("%s contains duplicate release %s", source, identity)
		}
		seen[identity] = true
		if !clusters[cluster] {
			return fmt.Errorf("%s release %s targets cluster absent from %s cluster-set", source, identity, environment)
		}
		for _, field := range []string{"sourceRevision", "desiredStateRevision"} {
			if err := release.ValidateRevision(fmt.Sprint(record[field])); err != nil {
				return fmt.Errorf("%s release %s %s: %w", source, identity, field, err)
			}
		}
		for _, field := range []string{"digest", "priorDigest", "releaseRecordDigest", "promotionReceiptDigest", "governanceEvidenceDigest"} {
			if err := release.ValidateDigest(fmt.Sprint(record[field])); err != nil {
				return fmt.Errorf("%s release %s %s: %w", source, identity, field, err)
			}
		}
		if configuration, exists := record["configurationDigest"]; exists {
			if err := release.ValidateDigest(fmt.Sprint(configuration)); err != nil {
				return fmt.Errorf("%s release %s configurationDigest: %w", source, identity, err)
			}
		}
		if fmt.Sprint(record["digest"]) == fmt.Sprint(record["priorDigest"]) {
			return fmt.Errorf("%s release %s digest must differ from priorDigest", source, identity)
		}
		releaseClass := "platform"
		if source != "platform-releases.yaml" {
			releaseClass = fmt.Sprint(document["releaseClass"])
		}
		if err := release.ValidateArtifactReference(fmt.Sprint(record["artifact"]), releaseClass); err != nil {
			return fmt.Errorf("%s release %s artifact: %w", source, identity, err)
		}
		if !strings.HasSuffix(fmt.Sprint(record["artifact"]), "@"+fmt.Sprint(record["digest"])) {
			return fmt.Errorf("%s release %s artifact does not match its digest", source, identity)
		}
		evidence, ok := record["evidence"].(map[string]any)
		if !ok {
			return fmt.Errorf("%s release %s evidence must be an object", source, identity)
		}
		for _, field := range []string{"signature", "sbom", "provenance", "vulnerabilityScan"} {
			if err := release.ValidateDigest(fmt.Sprint(evidence[field])); err != nil {
				return fmt.Errorf("%s release %s %s evidence: %w", source, identity, field, err)
			}
		}
		if source != "platform-releases.yaml" {
			if err := release.ValidateDigest(fmt.Sprint(evidence["evaluation"])); err != nil {
				return fmt.Errorf("%s release %s evaluation evidence: %w", source, identity, err)
			}
		}
		if !safeIdentityURI(fmt.Sprint(evidence["signer"])) {
			return fmt.Errorf("%s release %s has an unsafe signer identity", source, identity)
		}
		if !safeIdentityURI(fmt.Sprint(evidence["issuer"])) {
			return fmt.Errorf("%s release %s has an unsafe issuer identity", source, identity)
		}
		if environment == "production" || environment == "restricted" {
			if rollout, exists := record["rollout"].(map[string]any); exists {
				initialPercent, ok := rollout["initialPercent"].(float64)
				if !ok || initialPercent > 10 {
					return fmt.Errorf("%s release %s protected canary may not begin above 10 percent", source, identity)
				}
				if automatic, ok := rollout["automaticPromotion"].(bool); !ok || automatic {
					return fmt.Errorf("%s release %s protected rollout requires manual promotion", source, identity)
				}
			}
		}
		if rollout, exists := record["rollout"].(map[string]any); exists && rollout["strategy"] != "manual" {
			return fmt.Errorf("%s release %s rollout strategy must remain manual until a rollout controller is implemented", source, identity)
		}
	}
	return nil
}

func safeIdentityURI(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && !parsed.ForceQuery && parsed.Fragment == "" && strings.TrimSpace(raw) == raw
}

func validateCrossEnvironmentClusters(root string) error {
	names := map[string]string{}
	servers := map[string]string{}
	for _, environment := range release.Environments {
		document, err := release.ReadObject(filepath.Join(root, "environments", environment, "cluster-set.yaml"))
		if err != nil {
			return err
		}
		clusters, err := objectArray(document, "clusters", filepath.ToSlash(filepath.Join("environments", environment, "cluster-set.yaml")))
		if err != nil {
			return err
		}
		for _, cluster := range clusters {
			name := fmt.Sprint(cluster["name"])
			server, ok := canonicalClusterServer(fmt.Sprint(cluster["server"]))
			if !ok {
				return fmt.Errorf("cluster %s has an unsafe API server URI", name)
			}
			if previous, exists := names[name]; exists && previous != environment {
				return fmt.Errorf("cluster name %q is reused across environments %s and %s", name, previous, environment)
			}
			if previous, exists := servers[server]; exists && previous != environment {
				return fmt.Errorf("cluster server %q is reused across environments %s and %s", server, previous, environment)
			}
			names[name] = environment
			servers[server] = environment
		}
	}
	return nil
}

func validateUnboundModuleActivation(root string) error {
	implementations := []struct {
		filename       string
		implementation string
		description    string
	}{
		{filename: "platform-releases.yaml", implementation: platformDeploymentImplementation, description: "platform deployment implementation"},
		{filename: "policy-bindings.yaml", implementation: policyBindingReconcilerImplementation, description: "policy binding reconciler implementation"},
		{filename: "secret-references.yaml", implementation: secretReferenceMaterializerImplementation, description: "secret reference materializer implementation"},
	}
	for _, implementation := range implementations {
		if implementation.implementation != "unbound" {
			return fmt.Errorf("unknown %s %q", implementation.description, implementation.implementation)
		}
	}
	for _, environment := range release.Environments {
		for _, implementation := range implementations {
			document, err := release.ReadObject(filepath.Join(root, "environments", environment, implementation.filename))
			if err != nil {
				return err
			}
			if active, _ := document["active"].(bool); active {
				return fmt.Errorf("%s %s activation is blocked: the %s is unbound", environment, implementation.filename, implementation.description)
			}
		}
	}
	return nil
}

func validateConnectedEvidenceActivation(root string) error {
	if connectedEvidenceVerifierImplementation != "unbound" {
		return fmt.Errorf("unknown connected evidence verifier implementation %q", connectedEvidenceVerifierImplementation)
	}
	for _, environment := range release.Environments {
		document, err := release.ReadObject(filepath.Join(root, "environments", environment, "cluster-set.yaml"))
		if err != nil {
			return err
		}
		if active, _ := document["active"].(bool); active {
			return fmt.Errorf("%s activation is blocked: the external signature and attestation verifier implementation is unbound", environment)
		}
	}
	return nil
}

// VerifyTransition proves a requested promotion or rollback against the
// currently admitted record in the checked-out GitOps revision. It does not
// claim to verify external signatures; the workflow remains source-blocked
// until that separate cryptographic verifier is implemented.
func VerifyTransition(root, action, environment, releaseClass, component, cluster, artifactDigest, priorDigest string) error {
	if action != "promote" && action != "rollback" {
		return fmt.Errorf("unsupported transition action %q", action)
	}
	if !release.ValidEnvironment(environment) {
		return fmt.Errorf("unknown environment %q", environment)
	}
	if err := release.ValidateDigest(artifactDigest); err != nil {
		return err
	}
	if err := release.ValidateDigest(priorDigest); err != nil {
		return err
	}
	filename := map[string]string{
		"platform": "platform-releases.yaml",
		"service":  "service-releases.yaml",
		"worker":   "worker-releases.yaml",
	}[releaseClass]
	if filename == "" {
		return fmt.Errorf("unknown release class %q", releaseClass)
	}
	if err := ValidateEnvironment(root, environment); err != nil {
		return fmt.Errorf("validate checked-out %s environment: %w", environment, err)
	}
	document, err := validateSchemaDocument(root, filepath.Join("environments", environment, filename), filepath.Join("schemas", "v1", environmentSchemas[filename]))
	if err != nil {
		return err
	}
	if err := validateWorkloadReleaseMetadata(document, environment, filename); err != nil {
		return err
	}
	if active, _ := document["active"].(bool); !active {
		return fmt.Errorf("%s %s release set is inactive", environment, releaseClass)
	}
	values, err := objectArray(document, "releases", filename)
	if err != nil {
		return err
	}
	for _, record := range values {
		if fmt.Sprint(record["component"]) != component || fmt.Sprint(record["cluster"]) != cluster {
			continue
		}
		current := fmt.Sprint(record["digest"])
		previous := fmt.Sprint(record["priorDigest"])
		if priorDigest != current {
			return fmt.Errorf("requested prior digest does not equal the checked-out admitted digest")
		}
		if action == "promote" {
			if artifactDigest == current {
				return fmt.Errorf("promotion artifact already equals the admitted digest")
			}
			if artifactDigest == previous {
				return fmt.Errorf("promotion artifact equals the checked-out rollback digest; use the rollback transition")
			}
			return nil
		}
		if artifactDigest != previous {
			return fmt.Errorf("rollback artifact does not equal the checked-out previous digest")
		}
		return nil
	}
	return fmt.Errorf("checked-out %s record %s/%s was not found", releaseClass, cluster, component)
}

func validateInfrastructureExports(document map[string]any, environment string) (map[string]bool, error) {
	exports, err := objectArray(document, "exports", "infrastructure-exports.yaml")
	if err != nil {
		return nil, err
	}
	stacks := map[string]bool{}
	resources := map[string]bool{}
	memberships := map[string]bool{}
	for _, export := range exports {
		metadata, ok := export["metadata"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("infrastructure export metadata must be an object")
		}
		stack := fmt.Sprint(metadata["stack"])
		if metadata["environment"] != environment {
			return nil, fmt.Errorf("infrastructure export stack %s does not match wrapper environment %s", stack, environment)
		}
		if stacks[stack] {
			return nil, fmt.Errorf("duplicate infrastructure export stack %s", stack)
		}
		stacks[stack] = true
		if fmt.Sprint(metadata["root"]) != "opentofu/live/"+environment+"/"+stack {
			return nil, fmt.Errorf("infrastructure export stack %s root does not match environment and stack", stack)
		}
		if err := release.ValidateRevision(fmt.Sprint(metadata["sourceCommit"])); err != nil {
			return nil, fmt.Errorf("infrastructure export stack %s source commit: %w", stack, err)
		}
		for _, field := range []string{"planDigest", "schemaDigest"} {
			if err := release.ValidateDigest(fmt.Sprint(metadata[field])); err != nil {
				return nil, fmt.Errorf("infrastructure export stack %s %s: %w", stack, field, err)
			}
		}
		generatedAt := fmt.Sprint(metadata["generatedAt"])
		parsed, err := time.Parse(time.RFC3339, generatedAt)
		if err != nil || parsed.Format(time.RFC3339) != generatedAt || !strings.HasSuffix(generatedAt, "Z") {
			return nil, fmt.Errorf("infrastructure export stack %s generatedAt must be canonical RFC3339 UTC", stack)
		}
		spec, ok := export["spec"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("infrastructure export stack %s spec must be an object", stack)
		}
		items, err := objectArray(spec, "resources", "infrastructure export "+stack)
		if err != nil {
			return nil, err
		}
		for _, resource := range items {
			kind := fmt.Sprint(resource["kind"])
			name := fmt.Sprint(resource["name"])
			identity := kind + "/" + name
			if resources[identity] {
				return nil, fmt.Errorf("duplicate infrastructure resource %s", identity)
			}
			resources[identity] = true
			if !safeReferenceURI(fmt.Sprint(resource["uri"]), true) {
				return nil, fmt.Errorf("infrastructure resource %s has an unsafe URI", identity)
			}
			if kind == "cluster-membership" {
				memberships[name] = true
			}
		}
		evidence, ok := spec["evidence"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("infrastructure export stack %s evidence must be an object", stack)
		}
		for _, name := range []string{"signature", "provenance"} {
			reference, ok := evidence[name].(map[string]any)
			if !ok || !safeReferenceURI(fmt.Sprint(reference["uri"]), false) {
				return nil, fmt.Errorf("infrastructure export stack %s has unsafe %s evidence URI", stack, name)
			}
			if err := release.ValidateDigest(fmt.Sprint(reference["digest"])); err != nil {
				return nil, fmt.Errorf("infrastructure export stack %s %s evidence: %w", stack, name, err)
			}
		}
	}
	return memberships, nil
}

func safeReferenceURI(raw string, allowSchemeRelative bool) bool {
	if raw == "" || len(raw) > 2048 || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, " \r\n\t") {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return false
	}
	if strings.HasPrefix(raw, "//") {
		return allowSchemeRelative && parsed.Scheme == "" && parsed.Host != "" && parsed.Path != "" && parsed.Path != "/"
	}
	return parsed.Scheme == "https" && parsed.Host != "" && parsed.Path != "" && parsed.Path != "/"
}

func readYAMLObjects(path, source string) ([]map[string]any, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	var documents []map[string]any
	for {
		var document map[string]any
		err := decoder.Decode(&document)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", source, err)
		}
		if document != nil {
			documents = append(documents, document)
		}
	}
	if len(documents) == 0 {
		return nil, fmt.Errorf("parse %s: no YAML objects found", source)
	}
	return documents, nil
}

func readSingleYAMLObject(path, source string) (map[string]any, error) {
	documents, err := readYAMLObjects(path, source)
	if err != nil {
		return nil, err
	}
	if len(documents) != 1 {
		return nil, fmt.Errorf("parse %s: expected exactly one YAML document", source)
	}
	return documents[0], nil
}

func validateArgoCoreConfig(document map[string]any, rendered bool) error {
	metadata, ok := document["metadata"].(map[string]any)
	if document["apiVersion"] != "v1" || document["kind"] != "ConfigMap" || !ok || metadata["name"] != "argocd-cm" {
		return fmt.Errorf("Argo CD core ConfigMap identity must remain canonical")
	}
	data, ok := document["data"].(map[string]any)
	if !ok {
		return fmt.Errorf("Argo CD core ConfigMap data must be an object")
	}
	expected := map[string]string{
		"admin.enabled":                      "false",
		"users.anonymous.enabled":            "false",
		"exec.enabled":                       "false",
		"statusbadge.enabled":                "false",
		"application.resourceTrackingMethod": "annotation+label",
		"resource.respectRBAC":               "strict",
		"dex.config": "connectors:\n" +
			"  - type: github\n" +
			"    id: github\n" +
			"    name: Mindclade GitHub\n" +
			"    config:\n" +
			"      clientID: $dex.github.clientID\n" +
			"      clientSecret: $dex.github.clientSecret\n" +
			"      orgs:\n" +
			"        - name: mindclade\n" +
			"          teams:\n" +
			"            - platform\n" +
			"            - release\n" +
			"            - security\n",
		"resource.customizations.ignoreDifferences.all": "jqPathExpressions:\n  - .metadata.managedFields\n",
	}
	if !rendered {
		keys := make([]string, 0, len(expected))
		for key := range expected {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if err := requireExactObjectKeys(data, "Argo CD core ConfigMap data", keys...); err != nil {
			return err
		}
	} else {
		for key := range data {
			if _, reviewed := expected[key]; reviewed {
				continue
			}
			if key == "resource.exclusions" || strings.HasPrefix(key, "resource.customizations.ignoreResourceUpdates.") {
				continue
			}
			return fmt.Errorf("rendered Argo CD core ConfigMap contains unreviewed field %q", key)
		}
	}
	for key, value := range expected {
		if data[key] != value {
			return fmt.Errorf("Argo CD core ConfigMap %s must equal %q", key, value)
		}
	}
	return nil
}

func validateArgoRBACPolicyCSV(value any) error {
	raw, ok := value.(string)
	if !ok {
		return fmt.Errorf("Argo CD RBAC policy.csv must be a string")
	}
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) != len(argoRBACPolicyLines) {
		return fmt.Errorf("Argo CD RBAC policy.csv must contain exactly the reviewed policy rules")
	}
	for index, expected := range argoRBACPolicyLines {
		if strings.TrimSpace(lines[index]) != expected {
			return fmt.Errorf("Argo CD RBAC policy.csv rule[%d] must equal %q", index, expected)
		}
	}
	return nil
}

func validateArgoRBACConfig(document map[string]any) error {
	metadata, ok := document["metadata"].(map[string]any)
	if document["apiVersion"] != "v1" || document["kind"] != "ConfigMap" || !ok || metadata["name"] != "argocd-rbac-cm" {
		return fmt.Errorf("Argo CD RBAC ConfigMap identity must remain canonical")
	}
	data, ok := document["data"].(map[string]any)
	if !ok || data["policy.default"] != "role:deny-all" || data["policy.matchMode"] != "glob" || data["scopes"] != "[groups]" {
		return fmt.Errorf("Argo CD RBAC ConfigMap fail-closed defaults must remain canonical")
	}
	if err := validateArgoRBACPolicyCSV(data["policy.csv"]); err != nil {
		return err
	}
	return nil
}

func validateUnboundAppProject(document map[string]any, expectedName string) error {
	metadata, ok := document["metadata"].(map[string]any)
	if document["apiVersion"] != "argoproj.io/v1alpha1" || document["kind"] != "AppProject" || !ok || metadata["name"] != expectedName || metadata["namespace"] != "argocd" {
		return fmt.Errorf("unbound project %s identity must remain canonical", expectedName)
	}
	spec, ok := document["spec"].(map[string]any)
	if !ok {
		return fmt.Errorf("unbound project %s spec must be an object", expectedName)
	}
	destinations, ok := spec["destinations"].([]any)
	if !ok || len(destinations) != 0 {
		return fmt.Errorf("unbound project %s must have no destinations", expectedName)
	}
	if err := requireExactStringArray(spec["sourceRepos"], "unbound project "+expectedName+" sourceRepos", "https://github.com/mindclade/gitops.git"); err != nil {
		return err
	}
	return validateReviewedAppProject(document, expectedName)
}

func validateDefaultAppProject(document map[string]any) error {
	metadata, ok := document["metadata"].(map[string]any)
	if document["apiVersion"] != "argoproj.io/v1alpha1" || document["kind"] != "AppProject" || !ok || metadata["name"] != "default" || metadata["namespace"] != "argocd" {
		return fmt.Errorf("default project identity must remain canonical")
	}
	spec, ok := document["spec"].(map[string]any)
	if !ok {
		return fmt.Errorf("default project spec must be an object")
	}
	for _, field := range []string{"sourceRepos", "destinations", "clusterResourceWhitelist"} {
		values, ok := spec[field].([]any)
		if !ok || len(values) != 0 {
			return fmt.Errorf("default project %s must remain empty", field)
		}
	}
	return validateReviewedAppProject(document, "default")
}

func validateReviewedAppProject(document map[string]any, name string) error {
	expected, ok := reviewedAppProjectDigests[name]
	if !ok {
		return fmt.Errorf("AppProject %s has no reviewed semantic contract", name)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("normalize AppProject %s: %w", name, err)
	}
	actual := fmt.Sprintf("%x", sha256.Sum256(encoded))
	if actual != expected {
		return fmt.Errorf("AppProject %s differs from its reviewed semantic contract", name)
	}
	return nil
}

// ValidateArgoRender validates custom Argo resources against the CRDs carried
// by the same commit-pinned bootstrap and enforces render-only invariants that
// kubeconform cannot express for custom resources.
func ValidateArgoRender(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := yaml.NewDecoder(file)
	var documents []map[string]any
	for {
		var decoded any
		err := decoder.Decode(&decoded)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("parse bootstrap render: %w", err)
		}
		if decoded == nil {
			continue
		}
		encoded, err := json.Marshal(decoded)
		if err != nil {
			return fmt.Errorf("normalize bootstrap render: %w", err)
		}
		var document map[string]any
		if err := json.Unmarshal(encoded, &document); err != nil {
			return fmt.Errorf("normalize bootstrap render: %w", err)
		}
		documents = append(documents, document)
	}

	crdSchemas := map[string]map[string]any{}
	for _, document := range documents {
		if document["kind"] != "CustomResourceDefinition" {
			continue
		}
		spec, ok := document["spec"].(map[string]any)
		if !ok || spec["group"] != "argoproj.io" {
			continue
		}
		names, ok := spec["names"].(map[string]any)
		if !ok {
			continue
		}
		kind := fmt.Sprint(names["kind"])
		versions, ok := spec["versions"].([]any)
		if !ok {
			continue
		}
		for _, rawVersion := range versions {
			version, ok := rawVersion.(map[string]any)
			if !ok || version["name"] != "v1alpha1" {
				continue
			}
			schemaContainer, ok := version["schema"].(map[string]any)
			if !ok {
				continue
			}
			schema, ok := schemaContainer["openAPIV3Schema"].(map[string]any)
			if ok {
				crdSchemas[kind] = schema
			}
		}
	}
	compiled := map[string]*jsonschema.Schema{}
	for _, kind := range []string{"AppProject", "ApplicationSet"} {
		schemaDocument, ok := crdSchemas[kind]
		if !ok {
			return fmt.Errorf("pinned bootstrap lacks the %s v1alpha1 CRD schema", kind)
		}
		content, err := json.Marshal(schemaDocument)
		if err != nil {
			return err
		}
		location := "memory://" + strings.ToLower(kind) + ".schema.json"
		compiler := jsonschema.NewCompiler()
		if err := compiler.AddResource(location, bytes.NewReader(content)); err != nil {
			return fmt.Errorf("load pinned %s CRD schema: %w", kind, err)
		}
		compiled[kind], err = compiler.Compile(location)
		if err != nil {
			return fmt.Errorf("compile pinned %s CRD schema: %w", kind, err)
		}
	}
	counts := map[string]int{}
	imageCount := 0
	coreConfigSeen := false
	rbacConfigSeen := false
	unboundProjects := map[string]bool{}
	for _, document := range documents {
		kind := fmt.Sprint(document["kind"])
		counts[kind]++
		if schema := compiled[kind]; schema != nil {
			if err := schema.Validate(document); err != nil {
				metadata, _ := document["metadata"].(map[string]any)
				return fmt.Errorf("validate rendered %s %s against pinned CRD: %w", kind, metadata["name"], err)
			}
		}
		if err := validateRenderedImages(document, &imageCount); err != nil {
			return err
		}
		metadata, _ := document["metadata"].(map[string]any)
		name := fmt.Sprint(metadata["name"])
		if kind == "ConfigMap" && name == "argocd-cm" {
			if err := validateArgoCoreConfig(document, true); err != nil {
				return err
			}
			coreConfigSeen = true
		}
		if kind == "ConfigMap" && name == "argocd-rbac-cm" {
			if err := validateArgoRBACConfig(document); err != nil {
				return err
			}
			rbacConfigSeen = true
		}
		if kind == "AppProject" {
			if name == "default" {
				if err := validateDefaultAppProject(document); err != nil {
					return err
				}
				unboundProjects["default"] = true
			}
			for _, project := range []string{"platform", "services", "workers", "restricted"} {
				if name != project {
					continue
				}
				if err := validateUnboundAppProject(document, project); err != nil {
					return err
				}
				unboundProjects[project] = true
			}
		}
	}
	if counts["Application"] != 0 || counts["ApplicationSet"] != 4 || counts["AppProject"] != 5 || counts["ExternalSecret"] != 0 {
		return fmt.Errorf("unexpected rendered custom-resource counts: Application=%d ApplicationSet=%d AppProject=%d ExternalSecret=%d", counts["Application"], counts["ApplicationSet"], counts["AppProject"], counts["ExternalSecret"])
	}
	if imageCount == 0 {
		return fmt.Errorf("bootstrap render contains no workload images")
	}
	if !coreConfigSeen || !rbacConfigSeen {
		return fmt.Errorf("bootstrap render lacks the semantically validated Argo CD core or RBAC ConfigMap")
	}
	for _, project := range []string{"default", "platform", "services", "workers", "restricted"} {
		if !unboundProjects[project] {
			return fmt.Errorf("bootstrap render lacks semantically validated unbound project %s", project)
		}
	}
	return nil
}

func validateRenderedImages(value any, count *int) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "image" {
				if image, ok := child.(string); ok {
					*count++
					separator := strings.LastIndex(image, "@")
					if separator <= 0 || strings.Contains(image[:separator], "@") || strings.ContainsAny(image, " \r\n\t") || release.ValidateDigest(image[separator+1:]) != nil {
						return fmt.Errorf("rendered workload image is not digest pinned: %s", image)
					}
				}
			}
			if err := validateRenderedImages(child, count); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := validateRenderedImages(child, count); err != nil {
				return err
			}
		}
	}
	return nil
}

// BootstrapProvenance parses the source Kustomization as a single strict YAML
// document and binds every declared provenance value to the remote resource it
// controls. Both repository validation and the standalone bootstrap verifier
// use this function so their source contract cannot drift.
func BootstrapProvenance(content []byte) (map[string]string, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	var document bootstrapKustomization
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("parse Argo CD Kustomization: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("parse Argo CD Kustomization: multiple YAML documents are not allowed")
	}
	if document.APIVersion != "kustomize.config.k8s.io/v1beta1" || document.Kind != "Kustomization" {
		return nil, fmt.Errorf("invalid Argo CD Kustomization identity")
	}
	if document.Namespace != "argocd" || !document.GeneratorOptions.DisableNameSuffixHash || len(document.GeneratorOptions.Annotations) != 0 {
		return nil, fmt.Errorf("Argo CD Kustomization namespace and stable generator options must remain canonical")
	}
	if len(document.GeneratorOptions.Labels) != 1 || document.GeneratorOptions.Labels["app.kubernetes.io/part-of"] != "argocd" {
		return nil, fmt.Errorf("Argo CD Kustomization generator labels must remain canonical")
	}
	remoteResources := make([]string, 0, 1)
	for _, resource := range document.Resources {
		if strings.Contains(resource, "://") {
			remoteResources = append(remoteResources, resource)
		}
	}
	if len(remoteResources) != 1 {
		return nil, fmt.Errorf("Argo CD Kustomization must contain exactly one remote upstream resource")
	}
	if len(document.ConfigMapGenerator) != 1 {
		return nil, fmt.Errorf("Argo CD Kustomization must contain exactly one provenance generator and no other generated resources")
	}
	provenanceGenerators := 0
	values := map[string]string{}
	for _, generator := range document.ConfigMapGenerator {
		if generator.Name != "argocd-bootstrap-provenance" {
			continue
		}
		provenanceGenerators++
		if len(generator.Files) != 0 || len(generator.Envs) != 0 || generator.Behavior != "" || generator.Options != nil {
			return nil, fmt.Errorf("Argo CD bootstrap provenance must use literal values only")
		}
		for _, literal := range generator.Literals {
			parts := strings.SplitN(literal, "=", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				return nil, fmt.Errorf("invalid Argo CD bootstrap provenance literal %q", literal)
			}
			known := false
			for _, key := range bootstrapProvenanceKeys {
				if parts[0] == key {
					known = true
					break
				}
			}
			if !known {
				return nil, fmt.Errorf("unknown Argo CD bootstrap provenance key %q", parts[0])
			}
			if values[parts[0]] != "" {
				return nil, fmt.Errorf("duplicate Argo CD bootstrap provenance key %q", parts[0])
			}
			values[parts[0]] = parts[1]
		}
	}
	if provenanceGenerators != 1 {
		return nil, fmt.Errorf("Argo CD Kustomization must contain exactly one provenance generator")
	}
	for _, key := range bootstrapProvenanceKeys {
		if values[key] == "" {
			return nil, fmt.Errorf("bootstrap provenance lacks %s", key)
		}
	}
	if values["upstream-version"] != reviewedArgoVersion || values["upstream-revision"] != reviewedArgoRevision || values["upstream-sha256"] != reviewedArgoSHA256 {
		return nil, fmt.Errorf("Argo CD upstream version, revision, and checksum must equal the reviewed release contract")
	}
	if err := release.ValidateRevision(values["upstream-revision"]); err != nil {
		return nil, fmt.Errorf("Argo CD upstream revision: %w", err)
	}
	expectedURL := "https://raw.githubusercontent.com/argoproj/argo-cd/" + reviewedArgoRevision + "/manifests/install.yaml"
	if values["upstream-url"] != expectedURL || remoteResources[0] != expectedURL {
		return nil, fmt.Errorf("Argo CD Kustomization remote resource and provenance URL must equal the trusted revision-pinned manifest")
	}
	expectedResources := []string{
		"namespace.yaml",
		expectedURL,
		"repository-credentials-reference.yaml",
		"../../projects/platform.appproject.yaml",
		"../../projects/services.appproject.yaml",
		"../../projects/workers.appproject.yaml",
		"../../projects/restricted.appproject.yaml",
		"../applicationsets/platform-components.yaml",
		"../applicationsets/control-plane-services.yaml",
		"../applicationsets/execution-workers.yaml",
		"../applicationsets/environment-root.yaml",
	}
	if len(document.Resources) != len(expectedResources) {
		return nil, fmt.Errorf("Argo CD Kustomization must contain exactly the reviewed bootstrap resources")
	}
	for index, resource := range expectedResources {
		if document.Resources[index] != resource {
			return nil, fmt.Errorf("Argo CD Kustomization resource[%d] must equal %q", index, resource)
		}
	}
	if err := release.ValidateDigest("sha256:" + values["upstream-sha256"]); err != nil {
		return nil, fmt.Errorf("Argo CD upstream checksum: %w", err)
	}
	if len(document.Images) != 3 {
		return nil, fmt.Errorf("Argo CD Kustomization must contain exactly three provenance-bound image overrides")
	}
	imageOverrides := map[string]string{}
	for _, image := range document.Images {
		if image.Name == "" || image.NewName != "" || image.NewTag != "" || release.ValidateDigest(image.Digest) != nil {
			return nil, fmt.Errorf("Argo CD Kustomization contains a non-canonical image override for %q", image.Name)
		}
		if _, exists := imageOverrides[image.Name]; exists {
			return nil, fmt.Errorf("Argo CD Kustomization contains a duplicate image override for %q", image.Name)
		}
		imageOverrides[image.Name] = image.Digest
	}
	for _, key := range []string{"argocd-image", "dex-image", "redis-image"} {
		if values[key] != reviewedBootstrapImages[key] {
			return nil, fmt.Errorf("bootstrap provenance %s must equal its reviewed immutable image reference", key)
		}
		parts := strings.Split(values[key], "@")
		if len(parts) != 2 || release.ValidateDigest(parts[1]) != nil {
			return nil, fmt.Errorf("bootstrap provenance %s is not bound to its reviewed image identity and immutable digest", key)
		}
		if imageOverrides[parts[0]] != parts[1] {
			return nil, fmt.Errorf("bootstrap provenance %s does not match its effective Kustomize image override", key)
		}
		delete(imageOverrides, parts[0])
	}
	if len(imageOverrides) != 0 {
		return nil, fmt.Errorf("Argo CD Kustomization contains an image override without matching provenance")
	}
	if err := validateBootstrapPatches(document.Patches); err != nil {
		return nil, err
	}
	return values, nil
}

func validateBootstrapPatches(patches []bootstrapPatch) error {
	if len(patches) != 4 {
		return fmt.Errorf("Argo CD Kustomization must contain exactly four reviewed patches")
	}
	for index, expectedPath := range []string{"notifications.yaml", "resource-customizations.yaml"} {
		patch := patches[index]
		if patch.Path != expectedPath || patch.Patch != "" || patch.Target.Group != "" || patch.Target.Version != "" || patch.Target.Kind != "" || patch.Target.Name != "" {
			return fmt.Errorf("Argo CD Kustomization patch[%d] must reference only %s", index, expectedPath)
		}
	}
	rbac := patches[2]
	if rbac.Path != "" || rbac.Target.Group != "" || rbac.Target.Version != "v1" || rbac.Target.Kind != "ConfigMap" || rbac.Target.Name != "argocd-rbac-cm" {
		return fmt.Errorf("Argo CD Kustomization must contain the canonical RBAC ConfigMap patch")
	}
	var rbacDocument map[string]any
	rbacDecoder := yaml.NewDecoder(strings.NewReader(rbac.Patch))
	if err := rbacDecoder.Decode(&rbacDocument); err != nil {
		return fmt.Errorf("parse Argo CD RBAC patch: %w", err)
	}
	var rbacTrailing any
	if err := rbacDecoder.Decode(&rbacTrailing); err != io.EOF {
		return fmt.Errorf("parse Argo CD RBAC patch: multiple YAML documents are not allowed")
	}
	if err := requireExactObjectKeys(rbacDocument, "Argo CD RBAC patch", "apiVersion", "kind", "metadata", "data"); err != nil {
		return err
	}
	metadata, ok := rbacDocument["metadata"].(map[string]any)
	if !ok || metadata["name"] != "argocd-rbac-cm" || len(metadata) != 1 || rbacDocument["apiVersion"] != "v1" || rbacDocument["kind"] != "ConfigMap" {
		return fmt.Errorf("Argo CD RBAC patch identity must remain canonical")
	}
	data, ok := rbacDocument["data"].(map[string]any)
	if !ok {
		return fmt.Errorf("Argo CD RBAC patch data must be an object")
	}
	if err := requireExactObjectKeys(data, "Argo CD RBAC patch data", "policy.default", "policy.matchMode", "scopes", "policy.csv"); err != nil {
		return err
	}
	if data["policy.default"] != "role:deny-all" || data["policy.matchMode"] != "glob" || data["scopes"] != "[groups]" {
		return fmt.Errorf("Argo CD RBAC patch fail-closed defaults must remain canonical")
	}
	if err := validateArgoRBACPolicyCSV(data["policy.csv"]); err != nil {
		return err
	}
	server := patches[3]
	if server.Path != "" || server.Target.Group != "apps" || server.Target.Version != "v1" || server.Target.Kind != "Deployment" || server.Target.Name != "argocd-server" {
		return fmt.Errorf("Argo CD Kustomization must contain the canonical server availability patch")
	}
	var operations []map[string]any
	serverDecoder := yaml.NewDecoder(strings.NewReader(server.Patch))
	if err := serverDecoder.Decode(&operations); err != nil {
		return fmt.Errorf("parse Argo CD server patch: %w", err)
	}
	var serverTrailing any
	if err := serverDecoder.Decode(&serverTrailing); err != io.EOF {
		return fmt.Errorf("parse Argo CD server patch: multiple YAML documents are not allowed")
	}
	if len(operations) != 1 {
		return fmt.Errorf("Argo CD server patch must only set two replicas")
	}
	replicas, replicasAreInteger := operations[0]["value"].(int)
	if len(operations[0]) != 3 || operations[0]["op"] != "replace" || operations[0]["path"] != "/spec/replicas" || !replicasAreInteger || replicas != 2 {
		return fmt.Errorf("Argo CD server patch must only set two replicas")
	}
	return nil
}

func validateApplicationSet(content []byte, filename string, contract applicationSetContract) error {
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	var applicationSet map[string]any
	if err := decoder.Decode(&applicationSet); err != nil {
		return fmt.Errorf("parse %s: %w", filename, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("parse %s: multiple YAML documents are not allowed", filename)
	}
	if err := requireExactObjectKeys(applicationSet, filename, "apiVersion", "kind", "metadata", "spec"); err != nil {
		return err
	}
	if applicationSet["apiVersion"] != "argoproj.io/v1alpha1" || applicationSet["kind"] != "ApplicationSet" {
		return fmt.Errorf("%s has an invalid ApplicationSet identity", filename)
	}
	metadata, ok := applicationSet["metadata"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s metadata must be an object", filename)
	}
	if err := requireExactObjectKeys(metadata, filename+" metadata", "name", "namespace"); err != nil {
		return err
	}
	if metadata["name"] != strings.TrimSuffix(filename, ".yaml") || metadata["namespace"] != "argocd" {
		return fmt.Errorf("%s metadata identity must remain canonical", filename)
	}
	spec, ok := applicationSet["spec"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s spec must be an object", filename)
	}
	if err := requireExactObjectKeys(spec, filename+" spec", "goTemplate", "goTemplateOptions", "generators", "template", "syncPolicy"); err != nil {
		return err
	}
	if spec["goTemplate"] != true {
		return fmt.Errorf("%s must enable Go templates", filename)
	}
	if err := requireExactStringArray(spec["goTemplateOptions"], filename+" spec.goTemplateOptions", "missingkey=error"); err != nil {
		return err
	}

	generators, ok := spec["generators"].([]any)
	if !ok || len(generators) != 1 {
		return fmt.Errorf("%s spec.generators must contain exactly one matrix generator", filename)
	}
	matrixWrapper, ok := generators[0].(map[string]any)
	if !ok {
		return fmt.Errorf("%s matrix generator must be an object", filename)
	}
	if err := requireExactObjectKeys(matrixWrapper, filename+" matrix generator", "matrix"); err != nil {
		return err
	}
	matrix, ok := matrixWrapper["matrix"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s matrix must be an object", filename)
	}
	if err := requireExactObjectKeys(matrix, filename+" matrix", "generators"); err != nil {
		return err
	}
	nested, ok := matrix["generators"].([]any)
	if !ok || len(nested) != 2 {
		return fmt.Errorf("%s matrix must contain exactly the reviewed Git and list generators", filename)
	}
	gitWrapper, ok := nested[0].(map[string]any)
	if !ok {
		return fmt.Errorf("%s Git generator wrapper must be an object", filename)
	}
	if err := requireExactObjectKeys(gitWrapper, filename+" Git generator wrapper", "git"); err != nil {
		return err
	}
	gitGenerator, ok := gitWrapper["git"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s Git generator must be an object", filename)
	}
	if err := requireExactObjectKeys(gitGenerator, filename+" Git generator", "repoURL", "revision", "files"); err != nil {
		return err
	}
	if gitGenerator["repoURL"] != "https://github.com/mindclade/gitops.git" || gitGenerator["revision"] != "main" {
		return fmt.Errorf("%s Git generator repository and revision must remain canonical", filename)
	}
	files, ok := gitGenerator["files"].([]any)
	if !ok || len(files) != 1 {
		return fmt.Errorf("%s Git generator must read exactly one reviewed contract glob", filename)
	}
	fileSelector, ok := files[0].(map[string]any)
	if !ok {
		return fmt.Errorf("%s Git file selector must be an object", filename)
	}
	if err := requireExactObjectKeys(fileSelector, filename+" Git file selector", "path"); err != nil {
		return err
	}
	if fileSelector["path"] != "environments/*/"+contract.record {
		return fmt.Errorf("%s Git file selector path must equal environments/*/%s", filename, contract.record)
	}
	listWrapper, ok := nested[1].(map[string]any)
	if !ok {
		return fmt.Errorf("%s list generator wrapper must be an object", filename)
	}
	if err := requireExactObjectKeys(listWrapper, filename+" list generator wrapper", "list"); err != nil {
		return err
	}
	listGenerator, ok := listWrapper["list"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s list generator must be an object", filename)
	}
	if err := requireExactObjectKeys(listGenerator, filename+" list generator", "elementsYaml"); err != nil {
		return err
	}
	expectedElements := "{{ if .active }}{{ ." + contract.collection + " | toJson }}{{ else }}[]{{ end }}"
	if listGenerator["elementsYaml"] != expectedElements {
		return fmt.Errorf("%s list generator must be gated by active and consume only %s", filename, contract.collection)
	}

	template, ok := spec["template"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s template must be an object", filename)
	}
	if err := requireExactObjectKeys(template, filename+" template", "metadata", "spec"); err != nil {
		return err
	}
	templateMetadata, ok := template["metadata"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s template.metadata must be an object", filename)
	}
	if err := requireExactObjectKeys(templateMetadata, filename+" template.metadata", "name", "labels", "annotations"); err != nil {
		return err
	}
	if templateMetadata["name"] != contract.applicationName {
		return fmt.Errorf("%s template name must equal %q", filename, contract.applicationName)
	}
	labels := map[string]string{"gitops.mindclade.io/environment": "{{.environment}}"}
	annotations := map[string]string{}
	if contract.releaseClass == "" {
		annotations["gitops.mindclade.io/activation-record-digest"] = "{{.activationRecordDigest}}"
	} else {
		labels["gitops.mindclade.io/release-class"] = contract.releaseClass
		labels["gitops.mindclade.io/component"] = "{{.component}}"
		annotations["gitops.mindclade.io/release-record-digest"] = "{{.releaseRecordDigest}}"
		annotations["gitops.mindclade.io/promotion-receipt-digest"] = "{{.promotionReceiptDigest}}"
		annotations["gitops.mindclade.io/governance-evidence-digest"] = "{{.governanceEvidenceDigest}}"
	}
	if err := requireExactStringMap(templateMetadata["labels"], filename+" template labels", labels); err != nil {
		return err
	}
	if err := requireExactStringMap(templateMetadata["annotations"], filename+" template annotations", annotations); err != nil {
		return err
	}

	templateSpec, ok := template["spec"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s template.spec must be an object", filename)
	}
	if err := requireExactObjectKeys(templateSpec, filename+" template.spec", "project", "source", "destination", "syncPolicy"); err != nil {
		return err
	}
	if templateSpec["project"] != contract.project {
		return fmt.Errorf("%s template project must equal %q", filename, contract.project)
	}
	source, ok := templateSpec["source"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s template source must be an object", filename)
	}
	sourceKeys := []string{"repoURL", "targetRevision", "path"}
	if contract.sourceImage != "" || contract.sourceNamePrefix != "" {
		sourceKeys = append(sourceKeys, "kustomize")
	}
	if err := requireExactObjectKeys(source, filename+" template source", sourceKeys...); err != nil {
		return err
	}
	if source["repoURL"] != "https://github.com/mindclade/gitops.git" || source["targetRevision"] != "{{.desiredStateRevision}}" || source["path"] != contract.sourcePath {
		return fmt.Errorf("%s template source repoURL, targetRevision, and path must remain canonical", filename)
	}
	if contract.sourceImage != "" {
		kustomize, ok := source["kustomize"].(map[string]any)
		if !ok {
			return fmt.Errorf("%s template source.kustomize must be an object", filename)
		}
		if err := requireExactObjectKeys(kustomize, filename+" template source.kustomize", "images"); err != nil {
			return err
		}
		if err := requireExactStringArray(kustomize["images"], filename+" template source.kustomize.images", contract.sourceImage); err != nil {
			return err
		}
	}
	if contract.sourceNamePrefix != "" {
		kustomize, ok := source["kustomize"].(map[string]any)
		if !ok {
			return fmt.Errorf("%s template source.kustomize must be an object", filename)
		}
		if err := requireExactObjectKeys(kustomize, filename+" template source.kustomize", "namePrefix"); err != nil {
			return err
		}
		if kustomize["namePrefix"] != contract.sourceNamePrefix {
			return fmt.Errorf("%s template source.kustomize.namePrefix must equal %q", filename, contract.sourceNamePrefix)
		}
	}
	destination, ok := templateSpec["destination"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s template destination must be an object", filename)
	}
	if err := requireExactObjectKeys(destination, filename+" template destination", "name", "namespace"); err != nil {
		return err
	}
	if destination["name"] != contract.destinationName || destination["namespace"] != contract.destinationNamespace {
		return fmt.Errorf("%s template destination must remain canonical", filename)
	}
	templateSyncPolicy, ok := templateSpec["syncPolicy"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s template syncPolicy must be an object", filename)
	}
	if err := requireExactObjectKeys(templateSyncPolicy, filename+" template syncPolicy", "syncOptions"); err != nil {
		return err
	}
	if err := requireExactStringArray(templateSyncPolicy["syncOptions"], filename+" template syncPolicy.syncOptions",
		"CreateNamespace=false", "ApplyOutOfSyncOnly=true", "RespectIgnoreDifferences=true", "FailOnSharedResource=true"); err != nil {
		return err
	}
	applicationSetSyncPolicy, ok := spec["syncPolicy"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s syncPolicy must be an object", filename)
	}
	if err := requireExactObjectKeys(applicationSetSyncPolicy, filename+" syncPolicy", "applicationsSync", "preserveResourcesOnDeletion"); err != nil {
		return err
	}
	if applicationSetSyncPolicy["applicationsSync"] != "create-update" || applicationSetSyncPolicy["preserveResourcesOnDeletion"] != true {
		return fmt.Errorf("%s ApplicationSet deletion policy must remain fail closed", filename)
	}
	return nil
}

func validateFailClosedSources(root string) error {
	for _, relative := range []string{
		"controllers/argocd/resource-customizations.yaml",
		"controllers/argocd/repository-credentials-reference.yaml",
		"controllers/argocd/kustomization.yaml",
		"projects/platform.appproject.yaml",
		"projects/services.appproject.yaml",
		"projects/workers.appproject.yaml",
		"projects/restricted.appproject.yaml",
		".github/workflows/promotion.yml",
		".github/workflows/rollback-verification.yml",
	} {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			return err
		}
		text := string(content)
		if regexp.MustCompile(`(?m)^kind:\s+Secret\s*$`).MatchString(text) || regexp.MustCompile(`(?m)^\s*stringData:\s*$`).MatchString(text) {
			return fmt.Errorf("plaintext Secret material is forbidden in %s", relative)
		}
		if regexp.MustCompile(`(?m)targetRevision:\s*(HEAD|main|master|refs/heads/)`).MatchString(text) || strings.Contains(text, ":latest") {
			return fmt.Errorf("mutable reference is forbidden in %s", relative)
		}
	}
	rbac, err := os.ReadFile(filepath.Join(root, "controllers", "argocd", "resource-customizations.yaml"))
	if err != nil {
		return err
	}
	coreConfig, err := readSingleYAMLObject(filepath.Join(root, "controllers", "argocd", "resource-customizations.yaml"), "controllers/argocd/resource-customizations.yaml")
	if err != nil {
		return err
	}
	if err := validateArgoCoreConfig(coreConfig, false); err != nil {
		return err
	}
	kustomization, err := os.ReadFile(filepath.Join(root, "controllers", "argocd", "kustomization.yaml"))
	if err != nil {
		return err
	}
	if _, err := BootstrapProvenance(kustomization); err != nil {
		return err
	}
	rbacText := string(rbac) + "\n" + string(kustomization)
	for _, invariant := range []string{`admin.enabled: "false"`, `users.anonymous.enabled: "false"`, "policy.default: role:deny-all"} {
		if !strings.Contains(rbacText, invariant) {
			return fmt.Errorf("Argo CD invariant %q is missing", invariant)
		}
	}
	if regexp.MustCompile(`(?m)^\s*p, role:deny-all,`).MatchString(rbacText) {
		return fmt.Errorf("the empty default RBAC role must not contain deny rules that override mapped roles")
	}
	for _, key := range []string{"argocd-image", "dex-image", "redis-image"} {
		image := reviewedBootstrapImages[key]
		if !strings.Contains(string(kustomization), image) {
			return fmt.Errorf("Argo CD bootstrap lacks digest-pinned image provenance %s", image)
		}
		parts := strings.SplitN(image, "@", 2)
		override := "- name: " + parts[0] + "\n    digest: " + parts[1]
		if !strings.Contains(string(kustomization), override) {
			return fmt.Errorf("Argo CD bootstrap lacks image override %s", image)
		}
	}
	credentials, err := os.ReadFile(filepath.Join(root, "controllers", "argocd", "repository-credentials-reference.yaml"))
	if err != nil {
		return err
	}
	credentialText := string(credentials)
	for _, invariant := range []string{"kind: ConfigMap", "status: inactive", "provider: ExternalSecret"} {
		if !strings.Contains(credentialText, invariant) {
			return fmt.Errorf("inactive credential binding lacks %q", invariant)
		}
	}
	for _, forbidden := range []string{"kind: ExternalSecret", "secretStoreRef:", "remoteRef:"} {
		if strings.Contains(credentialText, forbidden) {
			return fmt.Errorf("inactive credential binding contains premature binding %q", forbidden)
		}
	}
	applicationSets := map[string]applicationSetContract{
		"environment-root.yaml": {
			record:               "cluster-set.yaml",
			collection:           "clusters",
			invariants:           []string{`name: '{{.environment}}.root.{{.name}}'`},
			applicationName:      "{{.environment}}.root.{{.name}}",
			project:              "platform",
			sourcePath:           "environments/{{.environment}}",
			sourceNamePrefix:     "environment-root-",
			destinationName:      "{{.name}}",
			destinationNamespace: "argocd",
		},
		"platform-components.yaml": {
			record:               "platform-releases.yaml",
			collection:           "releases",
			invariants:           []string{`name: '{{.environment}}.platform.{{.cluster}}.{{.component}}'`, "gitops.mindclade.io/release-class: platform"},
			applicationName:      "{{.environment}}.platform.{{.cluster}}.{{.component}}",
			project:              "platform",
			releaseClass:         "platform",
			sourcePath:           "platform/{{.component}}",
			destinationName:      "{{.cluster}}",
			destinationNamespace: "{{.namespace}}",
		},
		"control-plane-services.yaml": {
			record:               "service-releases.yaml",
			collection:           "releases",
			invariants:           []string{`name: '{{.environment}}.service.{{.cluster}}.{{.component}}'`, "gitops.mindclade.io/release-class: service", `path: '{{.desiredStatePath}}'`, "images:", `- '{{.component}}={{.artifact}}'`},
			applicationName:      "{{.environment}}.service.{{.cluster}}.{{.component}}",
			project:              `{{ if eq .environment "restricted" }}restricted{{ else }}services{{ end }}`,
			releaseClass:         "service",
			sourcePath:           "{{.desiredStatePath}}",
			sourceImage:          "{{.component}}={{.artifact}}",
			destinationName:      "{{.cluster}}",
			destinationNamespace: "{{.namespace}}",
		},
		"execution-workers.yaml": {
			record:               "worker-releases.yaml",
			collection:           "releases",
			invariants:           []string{`name: '{{.environment}}.worker.{{.cluster}}.{{.component}}'`, "gitops.mindclade.io/release-class: worker", `path: '{{.desiredStatePath}}'`, "images:", `- '{{.component}}={{.artifact}}'`},
			applicationName:      "{{.environment}}.worker.{{.cluster}}.{{.component}}",
			project:              `{{ if eq .environment "restricted" }}restricted{{ else }}workers{{ end }}`,
			releaseClass:         "worker",
			sourcePath:           "{{.desiredStatePath}}",
			sourceImage:          "{{.component}}={{.artifact}}",
			destinationName:      "{{.cluster}}",
			destinationNamespace: "{{.namespace}}",
		},
	}
	applicationSetNames := make([]string, 0, len(applicationSets))
	for name := range applicationSets {
		applicationSetNames = append(applicationSetNames, name)
	}
	sort.Strings(applicationSetNames)
	for _, name := range applicationSetNames {
		contract := applicationSets[name]
		content, err := os.ReadFile(filepath.Join(root, "controllers", "applicationsets", name))
		if err != nil {
			return err
		}
		text := string(content)
		for _, invariant := range append([]string{"matrix:", "elementsYaml:", "if .active", "environments/*/" + contract.record}, contract.invariants...) {
			if !strings.Contains(text, invariant) {
				return fmt.Errorf("%s lacks dynamic release gating %q", name, invariant)
			}
		}
		if err := validateApplicationSet(content, name, contract); err != nil {
			return err
		}
		if strings.Contains(text, "elements: []") {
			return fmt.Errorf("%s uses a hand-edited static generator", name)
		}
		if contract.record == "service-releases.yaml" || contract.record == "worker-releases.yaml" {
			for _, forbidden := range []string{`path: 'environments/{{.environment}}'`, "namePrefix:"} {
				if strings.Contains(text, forbidden) {
					return fmt.Errorf("%s contains shared workload rendering %q", name, forbidden)
				}
			}
		}
	}
	for _, project := range []string{"platform", "services", "workers", "restricted"} {
		relative := filepath.Join("projects", project+".appproject.yaml")
		documents, err := readYAMLObjects(filepath.Join(root, relative), filepath.ToSlash(relative))
		if err != nil {
			return err
		}
		projectCount := 0
		defaultCount := 0
		for _, document := range documents {
			metadata, _ := document["metadata"].(map[string]any)
			name := fmt.Sprint(metadata["name"])
			switch name {
			case project:
				if err := validateUnboundAppProject(document, project); err != nil {
					return err
				}
				projectCount++
			case "default":
				if project != "restricted" {
					return fmt.Errorf("unexpected default project in %s", filepath.ToSlash(relative))
				}
				if err := validateDefaultAppProject(document); err != nil {
					return err
				}
				defaultCount++
			default:
				return fmt.Errorf("unexpected AppProject %q in %s", name, filepath.ToSlash(relative))
			}
		}
		if projectCount != 1 {
			return fmt.Errorf("%s must contain exactly one unbound project %s", filepath.ToSlash(relative), project)
		}
		expectedDefaultCount := 0
		if project == "restricted" {
			expectedDefaultCount = 1
		}
		if defaultCount != expectedDefaultCount || len(documents) != 1+expectedDefaultCount {
			return fmt.Errorf("%s must contain exactly its reviewed AppProject documents", filepath.ToSlash(relative))
		}
	}
	for _, workflow := range []string{"promotion.yml", "rollback-verification.yml"} {
		content, err := os.ReadFile(filepath.Join(root, ".github", "workflows", workflow))
		if err != nil {
			return err
		}
		text := string(content)
		for _, invariant := range []string{"CONNECTED_GOVERNANCE_READY", "PROMOTION_GOVERNANCE_EVIDENCE", "PROMOTION_TRUSTED_SIGNER", "PROMOTION_TRUSTED_ISSUER", "refs/heads/main", `EVIDENCE_VERIFIER_IMPLEMENTATION: unbound`, `!= verified-v1`, "verify-transition --root ..", "ARTIFACT_SOURCE_REVISION", "AUTOMATION_REVISION", "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", "--checked-out-revision", "--workflow-run-id", "retention-days: 90", `[[ "$GOVERNANCE_EVIDENCE" =~ ^sha256:[0-9a-f]{64}$ ]]`, `[[ "$ARTIFACT_REFERENCE" =~ ^(oci://)?[a-z0-9]+([.-][a-z0-9]+)*(:[1-9][0-9]{0,4})?/[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*@sha256:[0-9a-f]{64}$ ]]`, `if [[ "$RELEASE_CLASS" = platform ]]`, `[[ "$ARTIFACT_REFERENCE" != oci://* ]]`} {
			if !strings.Contains(text, invariant) {
				return fmt.Errorf("%s lacks connected-governance preflight %q", workflow, invariant)
			}
		}
		if strings.Contains(text, "signer:\n        description:") || strings.Contains(text, "issued_at:\n        description:") {
			return fmt.Errorf("%s accepts caller-supplied trust or receipt time", workflow)
		}
	}
	pullRequest, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "pull-request.yml"))
	if err != nil {
		return err
	}
	for _, invariant := range []string{"--proto-redir '=https'", "--location", "-kubernetes-version 1.34.0", `USE_BAZEL_VERSION: "9.2.0"`} {
		if !strings.Contains(string(pullRequest), invariant) {
			return fmt.Errorf("pull-request workflow lacks hardened tool bootstrap %q", invariant)
		}
	}
	justfile, err := os.ReadFile(filepath.Join(root, "justfile"))
	if err != nil {
		return err
	}
	if !strings.Contains(string(justfile), "USE_BAZEL_VERSION=9.2.0 bazelisk") {
		return fmt.Errorf("just bazel-test lacks a pinned Bazel release")
	}
	namespace, err := os.ReadFile(filepath.Join(root, "controllers", "argocd", "namespace.yaml"))
	if err != nil {
		return err
	}
	for _, mode := range []string{"enforce", "audit", "warn"} {
		if !strings.Contains(string(namespace), "pod-security.kubernetes.io/"+mode+"-version: v1.34") {
			return fmt.Errorf("Argo CD namespace lacks pinned %s PSS version", mode)
		}
	}
	return nil
}
