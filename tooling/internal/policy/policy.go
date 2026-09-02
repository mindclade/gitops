package policy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"

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

var environmentSchemas = map[string]string{
	"cluster-set.yaml":            "cluster_set.schema.json",
	"infrastructure-exports.yaml": "infrastructure_exports.schema.json",
	"platform-releases.yaml":      "platform_releases.schema.json",
	"service-releases.yaml":       "workload_releases.schema.json",
	"worker-releases.yaml":        "workload_releases.schema.json",
	"policy-bindings.yaml":        "policy_bindings.schema.json",
	"secret-references.yaml":      "secret_references.schema.json",
}

// The JIT-09 verifier is source-ready, but active desired state remains
// impossible until connected identity, storage, KMS, and tamper qualification
// evidence has been independently reviewed.
const connectedEvidenceVerifierGate = "source-ready-unqualified-jit09-v1"

// JIT-05 must ratify the deployment-package, policy-controller, and
// secret-materialization boundaries before the Wave 5 infrastructure merge.
// Keep those gates separate from JIT-09 so evidence qualification cannot
// accidentally activate an inert deployment module.
const (
	platformDeploymentGate                   = "blocked-pending-jit-05"
	policyBindingReconcilerGate              = "blocked-pending-jit-05"
	secretReferenceMaterializerGate          = "blocked-pending-jit-05"
	infrastructureExportStateDigestDomain    = "mindclade.gitops.previous-infrastructure-state.v1\x00"
	reviewedInfrastructureExportSchemaDigest = "sha256:12fddd3a67b663499a8f5d3972cce56343da0c43795ac5caf8891c176957648a"
	reviewedArgoVersion                      = "v3.5.2"
	reviewedArgoRevision                     = "e258ee23c3e52266d407572f4bcdfe7d9ed36cb5"
	reviewedArgoSHA256                       = "9a87f2b3e14c278f12501eb0ef5c3955b27cf05370ca425381c6a908cf85a5c5"
)

var (
	infrastructureExportKeyVersionPattern = regexp.MustCompile(
		`^projects/([a-z][a-z0-9-]{4,28}[a-z0-9]|[1-9][0-9]{5,})/locations/us-central1/keyRings/bootstrap-signing/cryptoKeys/infrastructure-export/cryptoKeyVersions/[1-9][0-9]*$`,
	)
	infrastructureExportLineagePattern = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
	)
	infrastructureExportProvenancePattern = regexp.MustCompile(
		`^https://github\.com/mindclade/infrastructure-live/actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*$`,
	)
	infrastructureExportProjectIDPattern      = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	infrastructureExportBucketPattern         = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$`)
	infrastructureExportServiceAccountPattern = regexp.MustCompile(
		`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`,
	)
)

var infrastructureExportKindsByStack = map[string]map[string]bool{
	"foundation":    {"project": true},
	"network":       {"network": true, "subnetwork": true, "private-dns-zone": true},
	"artifacts":     {"artifact-registry": true, "artifact-bucket": true, "kms-key-reference": true},
	"data-services": {"database-instance": true, "topic": true, "kms-key-reference": true},
	"clusters":      {"gke-cluster": true, "cluster-membership": true, "workload-identity-pool": true, "argocd-prerequisite": true},
	"ci-execution":  {"build-execution-pool": true},
	"observability": {"log-bucket": true, "metrics-scope": true},
}

var infrastructureExportProviderPathPatterns = map[string]*regexp.Regexp{
	"network":              regexp.MustCompile(`^projects/[^/]+/global/networks/[^/]+$`),
	"subnetwork":           regexp.MustCompile(`^projects/[^/]+/regions/[^/]+/subnetworks/[^/]+$`),
	"private-dns-zone":     regexp.MustCompile(`^projects/[^/]+/managedZones/[^/]+$`),
	"artifact-registry":    regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/repositories/[^/]+$`),
	"database-instance":    regexp.MustCompile(`^projects/[^/]+/instances/[^/]+$`),
	"topic":                regexp.MustCompile(`^projects/[^/]+/topics/[^/]+$`),
	"kms-key-reference":    regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$`),
	"gke-cluster":          regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/clusters/[^/]+$`),
	"cluster-membership":   regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/memberships/[^/]+$`),
	"build-execution-pool": regexp.MustCompile(`^projects/[^/]+/regions/[^/]+/instanceGroupManagers/[^/]+$`),
	"log-bucket":           regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/buckets/[^/]+$`),
}

var infrastructureExportProviderHosts = map[string]string{
	"network": "compute.googleapis.com", "subnetwork": "compute.googleapis.com",
	"private-dns-zone": "dns.googleapis.com", "artifact-registry": "artifactregistry.googleapis.com",
	"database-instance": "sqladmin.googleapis.com", "topic": "pubsub.googleapis.com",
	"kms-key-reference": "cloudkms.googleapis.com", "gke-cluster": "container.googleapis.com",
	"cluster-membership": "gkehub.googleapis.com", "build-execution-pool": "compute.googleapis.com",
	"log-bucket": "logging.googleapis.com",
}

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
	"g, mindclade:security, role:security-auditor",
	"g, mindclade:release-engineering, role:release-promoter",
	"g, mindclade:platform-operations, role:platform-operator",
}

var reviewedBootstrapImages = map[string]string{
	"argocd-image": "quay.io/argoproj/argocd@sha256:e2aadfae709d904e87f46ba4aa49601d827b3022db22cd4d03aae816a2e7097b",
	"dex-image":    "ghcr.io/dexidp/dex@sha256:8499afd690c437f52301efd2b05b2455da5bd2dfc20332cd697dc9937f808462",
	"redis-image":  "public.ecr.aws/docker/library/redis@sha256:08ad0b1d280850169a790dba1393ff7a90aef951fc19632cf4d3ce4f78e679ba",
}

var reviewedAppProjectDigests = map[string]string{
	"default":    "99f8a6f36b018af95922854d595d59d51d60e0732b042987e11009a4f5988aed",
	"platform":   "304b13d80420c1b945e39f60d50ba6426cef940edf78557f956da161c928db7a",
	"restricted": "bb62f9cfed49eb58ab913827965e740f8c1420a7bca73ad6137f23c696d409d0",
	"services":   "c4fc9149f32c073469066cd184b553d02cd340db2ea63865cd06c8543698db1c",
	"workers":    "3b65f8001ae0408c134ece67c7bf83375fdf6dec3264c198af595fff3075f093",
}

func addPaths(target map[string]bool, prefix string, names ...string) {
	for _, name := range names {
		target[filepath.ToSlash(filepath.Join(prefix, name))] = true
	}
}

func ExpectedSourceFiles() map[string]bool {
	expected := map[string]bool{}
	addPaths(expected, "", ".bazelignore", ".bazelrc", ".bazelversion", ".editorconfig", ".gitignore", ".golangci.yml", ".markdownlint-cli2.yaml", ".pre-commit-config.yaml", ".yamllint.yaml", "BUILD.bazel", "CONTRIBUTING.md", "LICENSE", "MODULE.bazel", "MODULE.bazel.lock", "README.md", "SECURITY.md", "biome.json", "component.yaml", "flake.lock", "flake.nix", "justfile", "pyproject.toml")
	addPaths(expected, "generated", "bazelrc.common", "nix-bazel-policy.lock.json", "nix-bazel-policy.nix", "toolchain-manifest.defaults.json")
	addPaths(expected, ".vscode", "extensions.json", "settings.json")
	addPaths(expected, ".github", "CODEOWNERS", "actionlint.yaml", "pull_request_template.md", "renovate.json")
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
	addPaths(expected, "schemas/v1", "cluster_set.schema.json", "infrastructure_exports.schema.json", "platform_releases.schema.json", "workload_releases.schema.json", "policy_bindings.schema.json", "secret_references.schema.json", "promotion_receipt.schema.json", "gitops_promotion_envelope.schema.json")
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
	addPaths(expected, "tooling/internal/evidence", "supply_chain.go", "supply_chain_test.go")
	addPaths(expected, "tooling/internal/evidence", "promotion_envelope.go", "promotion_envelope_test.go")
	addPaths(expected, "runbooks", "argocd-unavailable.md", "failed-synchronization.md", "deployment-drift.md", "compromised-release.md", "emergency-rollback.md", "cluster-rebootstrap.md")
	return expected
}

func actualSourceFiles(root string) (map[string]bool, error) {
	actual := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() && (name == ".git" || name == ".cache" || name == ".pytest_cache" || name == ".ruff_cache" || name == "__pycache__") {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			return nil
		}
		if filepath.Dir(path) == filepath.Clean(root) && name == ".git" {
			return nil
		}
		if filepath.Dir(path) == filepath.Clean(root) && (strings.HasPrefix(name, "bazel-") || name == "result") {
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
		SecurityReviewers   []string `yaml:"security_reviewers"`
		RepositoryClass     string   `yaml:"repository_class"`
		DataClassification  string   `yaml:"data_classification"`
		ProductionAuthority bool     `yaml:"production_authority"`
		Dependencies        []string `yaml:"dependencies"`
		Provides            []string `yaml:"provides"`
		Consumers           []string `yaml:"consumers"`
		Activation          struct {
			SourceReady struct {
				Description string `yaml:"description"`
			} `yaml:"source_ready"`
			Connected struct {
				Description string `yaml:"description"`
			} `yaml:"connected"`
		} `yaml:"activation"`
		Release struct {
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
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("validate component.yaml: multiple YAML documents are not allowed")
	}
	if component.APIVersion != "mindclade.io/v1alpha1" || component.Kind != "Component" || component.Metadata.Name != "gitops" {
		return errors.New("validate component.yaml: invalid component identity")
	}
	if strings.TrimSpace(component.Metadata.Description) == "" || component.Metadata.Description != strings.TrimSpace(component.Metadata.Description) ||
		component.Metadata.Annotations["github.com/project-slug"] != "mindclade/gitops" ||
		component.Metadata.Annotations["mindclade.dev/security-owner"] != "security" ||
		component.Metadata.Annotations["mindclade.dev/trust-tier"] != "deployment-control" ||
		component.Metadata.Annotations["mindclade.dev/recovery-tier"] != "isolated-git" ||
		component.Metadata.Annotations["mindclade.io/qualification-status"] != "FAIL" {
		return errors.New("validate component.yaml: metadata contract is incomplete")
	}
	if component.Spec.Type != "deployment-control-plane" || component.Spec.Lifecycle != "pre-production" || component.Spec.Maturity != "pre-production" ||
		component.Spec.Owner != "platform-operations" || component.Spec.RepositoryClass != "deployment-source" || component.Spec.DataClassification != "public" ||
		component.Spec.ProductionAuthority {
		return errors.New("validate component.yaml: owner/qualification/authority contract is invalid")
	}
	if len(component.Spec.SecurityReviewers) != 1 || component.Spec.SecurityReviewers[0] != "security" {
		return errors.New("validate component.yaml: security co-ownership contract is invalid")
	}
	if strings.TrimSpace(component.Spec.Activation.SourceReady.Description) == "" || strings.TrimSpace(component.Spec.Activation.Connected.Description) == "" {
		return errors.New("validate component.yaml: activation boundary is incomplete")
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
		return errors.New("validate component.yaml: release metadata is invalid")
	}
	requiredEvidence := map[string]bool{
		"signed-release":                 true,
		"immutable-artifact-digest":      true,
		"policy-verification":            true,
		"protected-environment-approval": true,
	}
	if len(component.Spec.Release.Evidence) != len(requiredEvidence) {
		return errors.New("validate component.yaml: release evidence contract is incomplete")
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

// ValidationOptions supplies trust inputs that are intentionally kept outside
// the desired-state repository. They are optional while every environment
// root is inactive and mandatory before an InfrastructureExport can activate.
type ValidationOptions struct {
	InfrastructureExportTrustBundle       string
	InfrastructureExportTrustBundleDigest string
	BootstrapSourceRevision               string
	PreviousRepositoryRoot                string
	PreviousRepositoryRevision            string
	PreviousInfrastructureStateDigest     string
}

func ValidateRepository(root string) error {
	return ValidateRepositoryWithOptions(root, ValidationOptions{})
}

func ValidateRepositoryWithOptions(root string, options ValidationOptions) error {
	infrastructureContext, err := newInfrastructureExportValidationContext(root, options)
	if err != nil {
		return err
	}
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
	if err := validateComponent(root); err != nil {
		return err
	}
	if err := validateSchemaSet(root); err != nil {
		return err
	}
	for _, environment := range release.Environments {
		if err := validateEnvironment(root, environment, infrastructureContext); err != nil {
			return err
		}
	}
	if err := validatePlatformKustomizations(root); err != nil {
		return err
	}
	if err := validateCrossEnvironmentClusters(root); err != nil {
		return err
	}
	if err := validateDeferredModuleActivation(root); err != nil {
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
	return ValidateEnvironmentWithOptions(root, environment, ValidationOptions{})
}

func ValidateEnvironmentWithOptions(root, environment string, options ValidationOptions) error {
	infrastructureContext, err := newInfrastructureExportValidationContext(root, options)
	if err != nil {
		return err
	}
	return validateEnvironment(root, environment, infrastructureContext)
}

func validateEnvironment(root, environment string, infrastructureContext *infrastructureExportValidationContext) error {
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
	memberships, err := validateInfrastructureExports(documents["infrastructure-exports.yaml"], environment, infrastructureContext)
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
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
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
	if disabled, disabledOK := generatorOptions["disableNameSuffixHash"].(bool); !disabledOK || !disabled {
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
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
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
	return validateSchemaDocumentFromRoots(root, root, documentPath, schemaPath)
}

func validateSchemaDocumentFromRoots(documentRoot, schemaRoot, documentPath, schemaPath string) (map[string]any, error) {
	content, err := os.ReadFile(filepath.Join(documentRoot, documentPath))
	if err != nil {
		return nil, err
	}
	return validateSchemaDocumentContent(content, schemaRoot, documentPath, schemaPath)
}

func validateSchemaDocumentContent(content []byte, schemaRoot, documentPath, schemaPath string) (map[string]any, error) {
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("%s must be JSON-compatible YAML: %w", documentPath, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%s must contain exactly one JSON document", documentPath)
		}
		return nil, fmt.Errorf("%s has invalid trailing JSON: %w", documentPath, err)
	}
	schema, err := compileSchema(schemaRoot, schemaPath)
	if err != nil {
		return nil, err
	}
	if err := schema.Validate(document); err != nil {
		return nil, fmt.Errorf("validate %s: %w", documentPath, err)
	}
	return document, nil
}

func exactUnsignedJSONInteger(value any) (uint64, error) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, errors.New("must be a JSON integer")
	}
	parsed, err := strconv.ParseUint(number.String(), 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != number.String() {
		return 0, errors.New("must be a canonical unsigned JSON integer")
	}
	return parsed, nil
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
			return nil, errors.New("cluster-set.yaml contains a duplicate cluster name or server")
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
				initialPercent, err := exactUnsignedJSONInteger(rollout["initialPercent"])
				if err != nil || initialPercent > 10 {
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

func validateDeferredModuleActivation(root string) error {
	gates := []struct {
		filename    string
		gate        string
		description string
	}{
		{filename: "platform-releases.yaml", gate: platformDeploymentGate, description: "platform deployment boundary"},
		{filename: "policy-bindings.yaml", gate: policyBindingReconcilerGate, description: "policy binding reconciliation boundary"},
		{filename: "secret-references.yaml", gate: secretReferenceMaterializerGate, description: "secret reference materialization boundary"},
	}
	for _, gate := range gates {
		if gate.gate != "blocked-pending-jit-05" {
			return fmt.Errorf("unknown %s activation gate %q", gate.description, gate.gate)
		}
	}
	for _, environment := range release.Environments {
		for _, gate := range gates {
			document, err := release.ReadObject(filepath.Join(root, "environments", environment, gate.filename))
			if err != nil {
				return err
			}
			if active, _ := document["active"].(bool); active {
				return fmt.Errorf("%s %s activation is blocked: the %s is pending JIT-05 ratification and qualification", environment, gate.filename, gate.description)
			}
		}
	}
	return nil
}

func validateConnectedEvidenceActivation(root string) error {
	if connectedEvidenceVerifierGate != "source-ready-unqualified-jit09-v1" {
		return fmt.Errorf("unknown connected evidence verifier activation gate %q", connectedEvidenceVerifierGate)
	}
	for _, environment := range release.Environments {
		document, err := release.ReadObject(filepath.Join(root, "environments", environment, "cluster-set.yaml"))
		if err != nil {
			return err
		}
		if active, _ := document["active"].(bool); active {
			return fmt.Errorf("%s activation is blocked: the JIT-09 verifier lacks connected identity, storage, KMS, and tamper qualification", environment)
		}
	}
	return nil
}

// VerifyTransition proves a requested promotion or rollback against the
// currently admitted record in the checked-out GitOps revision. Release
// evidence remains source-blocked until its separate connected verifier is
// qualified; active infrastructure exports already require bootstrap trust.
func VerifyTransition(root, action, environment, releaseClass, component, cluster, artifactDigest, priorDigest string) error {
	return VerifyTransitionWithOptions(root, action, environment, releaseClass, component, cluster, artifactDigest, priorDigest, ValidationOptions{})
}

func VerifyTransitionWithOptions(root, action, environment, releaseClass, component, cluster, artifactDigest, priorDigest string, options ValidationOptions) error {
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
	if err := ValidateEnvironmentWithOptions(root, environment, options); err != nil {
		return fmt.Errorf("validate checked-out %s environment: %w", environment, err)
	}
	document, err := validateSchemaDocument(root, filepath.Join("environments", environment, filename), filepath.Join("schemas", "v1", environmentSchemas[filename]))
	if err != nil {
		return err
	}
	if validationErr := validateWorkloadReleaseMetadata(document, environment, filename); validationErr != nil {
		return validationErr
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
			return errors.New("requested prior digest does not equal the checked-out admitted digest")
		}
		if action == "promote" {
			if artifactDigest == current {
				return errors.New("promotion artifact already equals the admitted digest")
			}
			if artifactDigest == previous {
				return errors.New("promotion artifact equals the checked-out rollback digest; use the rollback transition")
			}
			return nil
		}
		if artifactDigest != previous {
			return errors.New("rollback artifact does not equal the checked-out previous digest")
		}
		return nil
	}
	return fmt.Errorf("checked-out %s record %s/%s was not found", releaseClass, cluster, component)
}

type infrastructureExportMetadata struct {
	Environment        string `json:"environment"`
	Stack              string `json:"stack"`
	SourceRepository   string `json:"sourceRepository"`
	SourceCommit       string `json:"sourceCommit"`
	Root               string `json:"root"`
	PlanDigest         string `json:"planDigest"`
	ProviderLockDigest string `json:"providerLockDigest"`
	BackendStateDigest string `json:"backendStateDigest"`
	BackendLineage     string `json:"backendLineage"`
	BackendSerial      uint64 `json:"backendSerial"`
	SchemaDigest       string `json:"schemaDigest"`
	GeneratedAt        string `json:"generatedAt"`
}

type infrastructureExportResource struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	URI  string `json:"uri"`
}

type infrastructureExportReference struct {
	URI    string `json:"uri"`
	Digest string `json:"digest"`
}

type infrastructureExportSignedSpec struct {
	Resources  []infrastructureExportResource `json:"resources"`
	Provenance infrastructureExportReference  `json:"provenance"`
}

type infrastructureExportSignedPayload struct {
	APIVersion string                         `json:"apiVersion"`
	Kind       string                         `json:"kind"`
	Metadata   infrastructureExportMetadata   `json:"metadata"`
	Spec       infrastructureExportSignedSpec `json:"spec"`
}

type infrastructureExportTrustBundleDocument struct {
	SchemaVersion    string                                 `json:"schemaVersion"`
	SourceRepository string                                 `json:"sourceRepository"`
	SourceRevision   string                                 `json:"sourceRevision"`
	Purpose          string                                 `json:"purpose"`
	Keys             []infrastructureExportTrustKeyDocument `json:"keys"`
}

type infrastructureExportTrustKeyDocument struct {
	Algorithm          string `json:"algorithm"`
	KeyVersion         string `json:"keyVersion"`
	PublicKey          string `json:"publicKey"`
	PublicKeyDigest    string `json:"publicKeyDigest"`
	PublicKeyPEM       string `json:"publicKeyPEM"`
	PublicKeyPEMSHA256 string `json:"publicKeyPEMSHA256"`
	ValidFrom          string `json:"validFrom"`
	ValidUntil         string `json:"validUntil"`
	Revoked            *bool  `json:"revoked"`
}

type infrastructureExportTrustAnchor struct {
	publicKeyDER    []byte
	publicKey       *ecdsa.PublicKey
	publicKeyDigest string
	validFrom       time.Time
	validUntil      time.Time
	revoked         bool
}

type infrastructureExportPreviousState struct {
	backendStateDigest string
	backendLineage     string
	backendSerial      uint64
}

type infrastructureExportValidationContext struct {
	now            time.Time
	trustAnchors   map[string]infrastructureExportTrustAnchor
	previousStates map[string]infrastructureExportPreviousState
}

func newInfrastructureExportValidationContext(root string, options ValidationOptions) (*infrastructureExportValidationContext, error) {
	trustPath := options.InfrastructureExportTrustBundle
	trustDigest := options.InfrastructureExportTrustBundleDigest
	bootstrapRevision := options.BootstrapSourceRevision
	previousRoot := options.PreviousRepositoryRoot
	previousRevision := options.PreviousRepositoryRevision
	previousStateDigest := options.PreviousInfrastructureStateDigest
	inputs := []string{trustPath, trustDigest, bootstrapRevision, previousRoot, previousRevision, previousStateDigest}
	provided := 0
	for _, input := range inputs {
		if input != strings.TrimSpace(input) {
			return nil, errors.New("infrastructure trust inputs must not contain surrounding whitespace")
		}
		if input != "" {
			provided++
		}
	}
	context := &infrastructureExportValidationContext{now: time.Now().UTC()}
	if provided == 0 {
		return context, nil
	}
	if provided != len(inputs) {
		return nil, infrastructureExportTrustInputsError()
	}
	if err := release.ValidateDigest(trustDigest); err != nil {
		return nil, fmt.Errorf("infrastructure export trust bundle digest: %w", err)
	}
	if err := release.ValidateRevision(bootstrapRevision); err != nil {
		return nil, fmt.Errorf("bootstrap source revision: %w", err)
	}
	if err := release.ValidateRevision(previousRevision); err != nil {
		return nil, fmt.Errorf("previous repository revision: %w", err)
	}
	if err := release.ValidateDigest(previousStateDigest); err != nil {
		return nil, fmt.Errorf("previous infrastructure state digest: %w", err)
	}
	currentResolved, err := resolvedDirectory(root, "repository root")
	if err != nil {
		return nil, err
	}
	previousResolved, err := resolvedDirectory(previousRoot, "previous repository root")
	if err != nil {
		return nil, err
	}
	if currentResolved == previousResolved {
		return nil, errors.New("previous repository root must be an independently supplied snapshot, not the current repository root")
	}
	context.trustAnchors, err = loadInfrastructureExportTrustBundle(trustPath, trustDigest, bootstrapRevision)
	if err != nil {
		return nil, err
	}
	context.previousStates, err = loadPreviousInfrastructureExportStates(currentResolved, previousResolved, previousRevision, previousStateDigest)
	if err != nil {
		return nil, err
	}
	return context, nil
}

func infrastructureExportTrustInputsError() error {
	return errors.New("active infrastructure exports require independently protected --infrastructure-export-trust-bundle, --infrastructure-export-trust-bundle-digest, --bootstrap-source-revision, --previous-repository-root, --previous-repository-revision, and --previous-infrastructure-state-digest inputs")
}

func resolvedDirectory(path, label string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", label, err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", label, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", label, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s must be a directory", label)
	}
	return filepath.Clean(resolved), nil
}

func readBoundedRegularFile(path, label string, maximum int64) ([]byte, error) {
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 || !linkInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular non-symlink file", label)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	defer func() { _ = file.Close() }()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened %s: %w", label, err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(linkInfo, openedInfo) {
		return nil, fmt.Errorf("%s changed while it was being opened", label)
	}
	if openedInfo.Size() > maximum {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", label, maximum)
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	if int64(len(content)) > maximum {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", label, maximum)
	}
	return content, nil
}

func loadInfrastructureExportTrustBundle(path, expectedDigest, expectedBootstrapRevision string) (map[string]infrastructureExportTrustAnchor, error) {
	content, err := readBoundedRegularFile(path, "infrastructure export trust bundle", 1<<20)
	if err != nil {
		return nil, err
	}
	rawDigest := sha256.Sum256(content)
	actualDigest := "sha256:" + hex.EncodeToString(rawDigest[:])
	if subtle.ConstantTimeCompare([]byte(actualDigest), []byte(expectedDigest)) != 1 {
		return nil, fmt.Errorf("infrastructure export trust bundle raw digest %s does not equal protected digest %s", actualDigest, expectedDigest)
	}
	// yaml.v3 rejects duplicate mapping keys. JSON's standard decoder accepts
	// them, so preflight the JSON subset before applying strict struct decoding.
	var duplicateKeyCheck any
	if err := yaml.Unmarshal(content, &duplicateKeyCheck); err != nil {
		return nil, fmt.Errorf("infrastructure export trust bundle contains duplicate or invalid fields: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var document infrastructureExportTrustBundleDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("infrastructure export trust bundle must be strict JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, errors.New("infrastructure export trust bundle must contain exactly one JSON document")
		}
		return nil, fmt.Errorf("infrastructure export trust bundle has invalid trailing JSON: %w", err)
	}
	if document.SchemaVersion != "v1" || document.SourceRepository != "mindclade/bootstrap" || document.Purpose != "infrastructure-export-signing" {
		return nil, errors.New("infrastructure export trust bundle identity is not the reviewed bootstrap v1 contract")
	}
	if document.SourceRevision != expectedBootstrapRevision {
		return nil, fmt.Errorf("infrastructure export trust bundle sourceRevision %s does not equal protected bootstrap revision %s", document.SourceRevision, expectedBootstrapRevision)
	}
	if len(document.Keys) == 0 || len(document.Keys) > 16 {
		return nil, errors.New("infrastructure export trust bundle must contain 1 to 16 rotation keys")
	}
	anchors := make(map[string]infrastructureExportTrustAnchor, len(document.Keys))
	digests := make(map[string]bool, len(document.Keys))
	var previousKeyPrefix string
	var previousKeyVersion uint64
	var previousValidFrom time.Time
	var previousValidUntil time.Time
	for index, key := range document.Keys {
		label := fmt.Sprintf("infrastructure export trust bundle key[%d]", index)
		if key.Algorithm != "EC_SIGN_P256_SHA256" {
			return nil, fmt.Errorf("%s algorithm must be EC_SIGN_P256_SHA256", label)
		}
		if !infrastructureExportKeyVersionPattern.MatchString(key.KeyVersion) {
			return nil, fmt.Errorf("%s keyVersion is not a bootstrap infrastructure-export key version", label)
		}
		keyPrefix, keyVersion, err := splitInfrastructureExportKeyVersion(key.KeyVersion)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		if _, duplicate := anchors[key.KeyVersion]; duplicate {
			return nil, fmt.Errorf("%s duplicates keyVersion %s", label, key.KeyVersion)
		}
		publicKeyDER, publicKey, publicKeyDigest, err := parseInfrastructureExportPublicKey(key.PublicKey, label+" public key")
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare([]byte(key.PublicKeyDigest), []byte(publicKeyDigest)) != 1 {
			return nil, fmt.Errorf("%s publicKeyDigest does not match its canonical SPKI DER public key", label)
		}
		if validationErr := validateInfrastructureExportPublicKeyPEM(key, publicKeyDER, label); validationErr != nil {
			return nil, validationErr
		}
		if digests[publicKeyDigest] {
			return nil, fmt.Errorf("%s duplicates publicKeyDigest %s", label, publicKeyDigest)
		}
		digests[publicKeyDigest] = true
		validFrom, err := parseCanonicalInfrastructureExportTime(key.ValidFrom, label+" validFrom")
		if err != nil {
			return nil, err
		}
		validUntil, err := parseCanonicalInfrastructureExportTime(key.ValidUntil, label+" validUntil")
		if err != nil {
			return nil, err
		}
		if validUntil.Sub(validFrom) != 90*24*time.Hour {
			return nil, fmt.Errorf("%s must declare the exact reviewed 90-day bootstrap rotation window", label)
		}
		if key.Revoked == nil {
			return nil, fmt.Errorf("%s must explicitly declare revoked", label)
		}
		if index > 0 {
			if keyPrefix != previousKeyPrefix {
				return nil, fmt.Errorf("%s must retain the same bootstrap CryptoKey prefix during rotation", label)
			}
			if keyVersion <= previousKeyVersion {
				return nil, fmt.Errorf("%s numeric key version must increase monotonically", label)
			}
			overlapStart := validFrom
			if previousValidFrom.After(overlapStart) {
				overlapStart = previousValidFrom
			}
			overlapEnd := validUntil
			if previousValidUntil.Before(overlapEnd) {
				overlapEnd = previousValidUntil
			}
			overlap := overlapEnd.Sub(overlapStart)
			if overlap <= 0 || overlap > 24*time.Hour {
				return nil, fmt.Errorf("%s rotation overlap with the preceding key must be greater than zero and no more than 24 hours", label)
			}
		}
		anchors[key.KeyVersion] = infrastructureExportTrustAnchor{
			publicKeyDER: publicKeyDER, publicKey: publicKey, publicKeyDigest: publicKeyDigest,
			validFrom: validFrom, validUntil: validUntil, revoked: *key.Revoked,
		}
		previousKeyPrefix = keyPrefix
		previousKeyVersion = keyVersion
		previousValidFrom = validFrom
		previousValidUntil = validUntil
	}
	return anchors, nil
}

func validateInfrastructureExportPublicKeyPEM(key infrastructureExportTrustKeyDocument, publicKeyDER []byte, label string) error {
	publicKeyPEM := []byte(key.PublicKeyPEM)
	if len(publicKeyPEM) == 0 || len(publicKeyPEM) > 16*1024 {
		return fmt.Errorf("%s publicKeyPEM must contain the bounded exact bootstrap public-key PEM", label)
	}
	pemDigest := sha256.Sum256(publicKeyPEM)
	expectedPEMDigest := hex.EncodeToString(pemDigest[:])
	if subtle.ConstantTimeCompare([]byte(key.PublicKeyPEMSHA256), []byte(expectedPEMDigest)) != 1 {
		return fmt.Errorf("%s publicKeyPEMSHA256 does not match the exact UTF-8 bootstrap PEM bytes", label)
	}
	block, trailing := pem.Decode(publicKeyPEM)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(trailing) != 0 {
		return fmt.Errorf("%s publicKeyPEM must contain exactly one headerless PKIX PUBLIC KEY block", label)
	}
	canonicalPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: block.Bytes})
	if subtle.ConstantTimeCompare(canonicalPEM, publicKeyPEM) != 1 {
		return fmt.Errorf("%s publicKeyPEM must use canonical PEM encoding", label)
	}
	if subtle.ConstantTimeCompare(block.Bytes, publicKeyDER) != 1 {
		return fmt.Errorf("%s publicKeyPEM SPKI DER does not match publicKey and publicKeyDigest", label)
	}
	return nil
}

func splitInfrastructureExportKeyVersion(keyVersion string) (string, uint64, error) {
	separator := strings.LastIndexByte(keyVersion, '/')
	if separator < 1 || separator == len(keyVersion)-1 {
		return "", 0, errors.New("keyVersion lacks a numeric version suffix")
	}
	version, err := strconv.ParseUint(keyVersion[separator+1:], 10, 64)
	if err != nil || version == 0 {
		return "", 0, errors.New("keyVersion has an invalid numeric version suffix")
	}
	return keyVersion[:separator], version, nil
}

func parseInfrastructureExportPublicKey(encoded, label string) ([]byte, *ecdsa.PublicKey, string, error) {
	publicKeyDER, err := decodeCanonicalInfrastructureExportBase64(encoded, 64, 512, label)
	if err != nil {
		return nil, nil, "", err
	}
	parsedKey, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return nil, nil, "", fmt.Errorf("%s must be canonical PKIX SubjectPublicKeyInfo: %w", label, err)
	}
	publicKey, ok := parsedKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, nil, "", fmt.Errorf("%s must be ECDSA P-256", label)
	}
	canonicalDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil || subtle.ConstantTimeCompare(canonicalDER, publicKeyDER) != 1 {
		return nil, nil, "", fmt.Errorf("%s must use canonical PKIX SubjectPublicKeyInfo DER", label)
	}
	digest := sha256.Sum256(publicKeyDER)
	return publicKeyDER, publicKey, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func parseCanonicalInfrastructureExportTime(value, label string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Format(time.RFC3339) != value || !strings.HasSuffix(value, "Z") {
		return time.Time{}, fmt.Errorf("%s must be canonical RFC3339 UTC", label)
	}
	return parsed, nil
}

func canonicalInfrastructureExportPayloadDigest(export map[string]any, environment string) (string, error) {
	metadata, ok := export["metadata"].(map[string]any)
	if !ok {
		return "", errors.New("infrastructure export metadata must be an object")
	}
	backendSerial, err := exactUnsignedJSONInteger(metadata["backendSerial"])
	if err != nil {
		return "", errors.New("infrastructure export backendSerial must be an unsigned integer")
	}
	spec, ok := export["spec"].(map[string]any)
	if !ok {
		return "", errors.New("infrastructure export spec must be an object")
	}
	resources, err := objectArray(spec, "resources", "infrastructure export")
	if err != nil {
		return "", err
	}
	canonicalResources := make([]infrastructureExportResource, 0, len(resources))
	for _, resource := range resources {
		canonicalResources = append(canonicalResources, infrastructureExportResource{
			Kind: fmt.Sprint(resource["kind"]), Name: fmt.Sprint(resource["name"]), URI: fmt.Sprint(resource["uri"]),
		})
	}
	evidence, ok := spec["evidence"].(map[string]any)
	if !ok {
		return "", errors.New("infrastructure export evidence must be an object")
	}
	provenanceValue, ok := evidence["provenance"].(map[string]any)
	if !ok {
		return "", errors.New("infrastructure export provenance evidence must be an object")
	}
	payload := infrastructureExportSignedPayload{
		APIVersion: fmt.Sprint(export["apiVersion"]),
		Kind:       fmt.Sprint(export["kind"]),
		Metadata: infrastructureExportMetadata{
			Environment:        environment,
			Stack:              fmt.Sprint(metadata["stack"]),
			SourceRepository:   fmt.Sprint(metadata["sourceRepository"]),
			SourceCommit:       fmt.Sprint(metadata["sourceCommit"]),
			Root:               fmt.Sprint(metadata["root"]),
			PlanDigest:         fmt.Sprint(metadata["planDigest"]),
			ProviderLockDigest: fmt.Sprint(metadata["providerLockDigest"]),
			BackendStateDigest: fmt.Sprint(metadata["backendStateDigest"]),
			BackendLineage:     fmt.Sprint(metadata["backendLineage"]),
			BackendSerial:      backendSerial,
			SchemaDigest:       fmt.Sprint(metadata["schemaDigest"]),
			GeneratedAt:        fmt.Sprint(metadata["generatedAt"]),
		},
		Spec: infrastructureExportSignedSpec{
			Resources: canonicalResources,
			Provenance: infrastructureExportReference{
				URI: fmt.Sprint(provenanceValue["uri"]), Digest: fmt.Sprint(provenanceValue["digest"]),
			},
		},
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("canonical infrastructure export payload: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func loadPreviousInfrastructureExportStates(schemaRoot, previousRoot, previousRevision, expectedDigest string) (map[string]infrastructureExportPreviousState, error) {
	documents := make(map[string][]byte, len(release.Environments))
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(infrastructureExportStateDigestDomain))
	writeInfrastructureExportStateDigestField(hasher, "previousRepositoryRevision", []byte(previousRevision))
	for _, environment := range release.Environments {
		relative := filepath.Join("environments", environment, "infrastructure-exports.yaml")
		content, err := readBoundedRegularFile(filepath.Join(previousRoot, relative), "previous repository "+relative, 1<<20)
		if err != nil {
			return nil, err
		}
		documents[environment] = content
		writeInfrastructureExportStateDigestField(hasher, filepath.ToSlash(relative), content)
	}
	actualDigest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(actualDigest), []byte(expectedDigest)) != 1 {
		return nil, fmt.Errorf("previous infrastructure state digest %s does not equal protected digest %s for revision %s", actualDigest, expectedDigest, previousRevision)
	}

	states := map[string]infrastructureExportPreviousState{}
	for _, environment := range release.Environments {
		relative := filepath.Join("environments", environment, "infrastructure-exports.yaml")
		document, err := validateSchemaDocumentContent(documents[environment], schemaRoot, relative, filepath.Join("schemas", "v1", environmentSchemas["infrastructure-exports.yaml"]))
		if err != nil {
			return nil, fmt.Errorf("validate previous repository root: %w", err)
		}
		if document["schemaVersion"] != "v1" || document["environment"] != environment {
			return nil, fmt.Errorf("previous repository %s has inconsistent schema or environment", relative)
		}
		exports, err := objectArray(document, "exports", "previous "+relative)
		if err != nil {
			return nil, err
		}
		for _, export := range exports {
			metadata, ok := export["metadata"].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("previous repository %s export metadata must be an object", relative)
			}
			stack := fmt.Sprint(metadata["stack"])
			if metadata["environment"] != environment || fmt.Sprint(metadata["root"]) != "opentofu/live/"+environment+"/"+stack {
				return nil, fmt.Errorf("previous repository infrastructure export stack %s does not match %s", stack, environment)
			}
			backendLineage := fmt.Sprint(metadata["backendLineage"])
			if !infrastructureExportLineagePattern.MatchString(backendLineage) {
				return nil, fmt.Errorf("previous repository infrastructure export stack %s backendLineage must be a canonical UUID", stack)
			}
			backendSerial, err := exactUnsignedJSONInteger(metadata["backendSerial"])
			if err != nil {
				return nil, fmt.Errorf("previous repository infrastructure export stack %s backendSerial must be an unsigned integer", stack)
			}
			backendStateDigest := fmt.Sprint(metadata["backendStateDigest"])
			if digestErr := release.ValidateDigest(backendStateDigest); digestErr != nil {
				return nil, fmt.Errorf("previous repository infrastructure export stack %s backendStateDigest: %w", stack, digestErr)
			}
			identity := environment + "/" + stack
			if _, duplicate := states[identity]; duplicate {
				return nil, fmt.Errorf("previous repository contains duplicate infrastructure export stack %s", identity)
			}
			payloadDigest, err := canonicalInfrastructureExportPayloadDigest(export, environment)
			if err != nil {
				return nil, fmt.Errorf("previous repository infrastructure export stack %s: %w", stack, err)
			}
			spec, _ := export["spec"].(map[string]any)
			evidence, _ := spec["evidence"].(map[string]any)
			signature, ok := evidence["signature"].(map[string]any)
			if !ok || subtle.ConstantTimeCompare([]byte(fmt.Sprint(signature["payloadDigest"])), []byte(payloadDigest)) != 1 {
				return nil, fmt.Errorf("previous repository infrastructure export stack %s payloadDigest does not match its canonical signed payload", stack)
			}
			states[identity] = infrastructureExportPreviousState{
				backendStateDigest: backendStateDigest,
				backendLineage:     backendLineage,
				backendSerial:      backendSerial,
			}
		}
	}
	return states, nil
}

func writeInfrastructureExportStateDigestField(writer io.Writer, label string, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(label)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write([]byte(label))
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}

func (context *infrastructureExportValidationContext) validateState(environment, stack, backendStateDigest, backendLineage string, backendSerial uint64) error {
	if len(context.trustAnchors) == 0 || context.previousStates == nil {
		return infrastructureExportTrustInputsError()
	}
	previous, exists := context.previousStates[environment+"/"+stack]
	if !exists {
		return nil
	}
	if backendLineage != previous.backendLineage {
		return fmt.Errorf("infrastructure export stack %s backend lineage changed; no reviewed recovery contract authorizes lineage replacement", stack)
	}
	if backendSerial < previous.backendSerial {
		return fmt.Errorf("infrastructure export stack %s backend serial regressed from %d to %d", stack, previous.backendSerial, backendSerial)
	}
	if backendSerial == previous.backendSerial && backendStateDigest != previous.backendStateDigest {
		return fmt.Errorf("infrastructure export stack %s reused backend serial %d with a different backend state digest", stack, backendSerial)
	}
	return nil
}

func (context *infrastructureExportValidationContext) validateRetainedStacks(environment string, currentStacks map[string]bool) error {
	if context == nil || context.previousStates == nil {
		return nil
	}
	prefix := environment + "/"
	for identity := range context.previousStates {
		if !strings.HasPrefix(identity, prefix) {
			continue
		}
		stack := strings.TrimPrefix(identity, prefix)
		if !currentStacks[stack] {
			return fmt.Errorf("infrastructure export stack %s disappeared from %s; stack retirement requires a future reviewed tombstone contract", stack, environment)
		}
	}
	return nil
}

func validateInfrastructureExports(document map[string]any, environment string, context *infrastructureExportValidationContext) (map[string]bool, error) {
	exports, err := objectArray(document, "exports", "infrastructure-exports.yaml")
	if err != nil {
		return nil, err
	}
	if len(exports) > 0 && (context == nil || len(context.trustAnchors) == 0 || context.previousStates == nil) {
		return nil, infrastructureExportTrustInputsError()
	}
	stacks := map[string]bool{}
	resources := map[string]bool{}
	memberships := map[string]bool{}
	for _, export := range exports {
		metadata, ok := export["metadata"].(map[string]any)
		if !ok {
			return nil, errors.New("infrastructure export metadata must be an object")
		}
		stack := fmt.Sprint(metadata["stack"])
		if metadata["environment"] != environment {
			return nil, fmt.Errorf("infrastructure export stack %s does not match wrapper environment %s", stack, environment)
		}
		if stacks[stack] {
			return nil, fmt.Errorf("duplicate infrastructure export stack %s", stack)
		}
		stacks[stack] = true
		if fmt.Sprint(metadata["sourceRepository"]) != "mindclade/infrastructure-live" {
			return nil, fmt.Errorf("infrastructure export stack %s source repository is not authoritative", stack)
		}
		if fmt.Sprint(metadata["root"]) != "opentofu/live/"+environment+"/"+stack {
			return nil, fmt.Errorf("infrastructure export stack %s root does not match environment and stack", stack)
		}
		if err := release.ValidateRevision(fmt.Sprint(metadata["sourceCommit"])); err != nil {
			return nil, fmt.Errorf("infrastructure export stack %s source commit: %w", stack, err)
		}
		for _, field := range []string{"planDigest", "providerLockDigest", "backendStateDigest"} {
			if err := release.ValidateDigest(fmt.Sprint(metadata[field])); err != nil {
				return nil, fmt.Errorf("infrastructure export stack %s %s: %w", stack, field, err)
			}
		}
		if fmt.Sprint(metadata["schemaDigest"]) != reviewedInfrastructureExportSchemaDigest {
			return nil, fmt.Errorf("infrastructure export stack %s schemaDigest does not match the reviewed producer schema", stack)
		}
		backendLineage := fmt.Sprint(metadata["backendLineage"])
		if !infrastructureExportLineagePattern.MatchString(backendLineage) {
			return nil, fmt.Errorf("infrastructure export stack %s backendLineage must be a canonical UUID", stack)
		}
		backendSerial, err := exactUnsignedJSONInteger(metadata["backendSerial"])
		if err != nil {
			return nil, fmt.Errorf("infrastructure export stack %s backendSerial must be an unsigned integer", stack)
		}
		generatedAt := fmt.Sprint(metadata["generatedAt"])
		generatedAtTime, err := parseCanonicalInfrastructureExportTime(generatedAt, "infrastructure export stack "+stack+" generatedAt")
		if err != nil {
			return nil, err
		}
		spec, ok := export["spec"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("infrastructure export stack %s spec must be an object", stack)
		}
		items, err := objectArray(spec, "resources", "infrastructure export "+stack)
		if err != nil {
			return nil, err
		}
		canonicalResources := make([]infrastructureExportResource, 0, len(items))
		for _, resource := range items {
			kind := fmt.Sprint(resource["kind"])
			name := fmt.Sprint(resource["name"])
			uri := fmt.Sprint(resource["uri"])
			identity := kind + "/" + name
			if !infrastructureExportKindsByStack[stack][kind] {
				return nil, fmt.Errorf("infrastructure resource kind %s is not allowed for stack %s", kind, stack)
			}
			if resources[identity] {
				return nil, fmt.Errorf("duplicate infrastructure resource %s", identity)
			}
			resources[identity] = true
			if !safeReferenceURI(uri, true) || !validInfrastructureExportResourceURI(kind, uri) {
				return nil, fmt.Errorf("infrastructure resource %s has an unsafe or non-canonical URI", identity)
			}
			canonicalResources = append(canonicalResources, infrastructureExportResource{Kind: kind, Name: name, URI: uri})
			if kind == "cluster-membership" {
				memberships[name] = true
			}
		}
		if !infrastructureExportResourcesSorted(canonicalResources) {
			return nil, fmt.Errorf("infrastructure export stack %s resources are not in canonical producer order", stack)
		}
		evidence, ok := spec["evidence"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("infrastructure export stack %s evidence must be an object", stack)
		}
		provenanceValue, ok := evidence["provenance"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("infrastructure export stack %s provenance evidence must be an object", stack)
		}
		provenance := infrastructureExportReference{
			URI:    fmt.Sprint(provenanceValue["uri"]),
			Digest: fmt.Sprint(provenanceValue["digest"]),
		}
		if !safeReferenceURI(provenance.URI, false) || !infrastructureExportProvenancePattern.MatchString(provenance.URI) {
			return nil, fmt.Errorf("infrastructure export stack %s has unsafe or non-canonical provenance evidence URI", stack)
		}
		if digestErr := release.ValidateDigest(provenance.Digest); digestErr != nil {
			return nil, fmt.Errorf("infrastructure export stack %s provenance evidence: %w", stack, digestErr)
		}
		signature, ok := evidence["signature"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("infrastructure export stack %s signature evidence must be an object", stack)
		}
		payload := infrastructureExportSignedPayload{
			APIVersion: fmt.Sprint(export["apiVersion"]),
			Kind:       fmt.Sprint(export["kind"]),
			Metadata: infrastructureExportMetadata{
				Environment:        environment,
				Stack:              stack,
				SourceRepository:   fmt.Sprint(metadata["sourceRepository"]),
				SourceCommit:       fmt.Sprint(metadata["sourceCommit"]),
				Root:               fmt.Sprint(metadata["root"]),
				PlanDigest:         fmt.Sprint(metadata["planDigest"]),
				ProviderLockDigest: fmt.Sprint(metadata["providerLockDigest"]),
				BackendStateDigest: fmt.Sprint(metadata["backendStateDigest"]),
				BackendLineage:     backendLineage,
				BackendSerial:      backendSerial,
				SchemaDigest:       fmt.Sprint(metadata["schemaDigest"]),
				GeneratedAt:        generatedAt,
			},
			Spec: infrastructureExportSignedSpec{Resources: canonicalResources, Provenance: provenance},
		}
		encodedPayload, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("infrastructure export stack %s canonical payload: %w", stack, err)
		}
		if err := verifyInfrastructureExportSignature(signature, encodedPayload, generatedAtTime, context); err != nil {
			return nil, fmt.Errorf("infrastructure export stack %s: %w", stack, err)
		}
		if err := context.validateState(environment, stack, fmt.Sprint(metadata["backendStateDigest"]), backendLineage, backendSerial); err != nil {
			return nil, err
		}
	}
	if err := context.validateRetainedStacks(environment, stacks); err != nil {
		return nil, err
	}
	return memberships, nil
}

func infrastructureExportResourcesSorted(resources []infrastructureExportResource) bool {
	for index := 1; index < len(resources); index++ {
		left, right := resources[index-1], resources[index]
		if left.Kind > right.Kind ||
			(left.Kind == right.Kind && left.Name > right.Name) ||
			(left.Kind == right.Kind && left.Name == right.Name && left.URI > right.URI) {
			return false
		}
	}
	return true
}

func verifyInfrastructureExportSignature(signature map[string]any, payload []byte, generatedAt time.Time, context *infrastructureExportValidationContext) error {
	if fmt.Sprint(signature["algorithm"]) != "EC_SIGN_P256_SHA256" {
		return errors.New("signature algorithm must be EC_SIGN_P256_SHA256")
	}
	keyVersion := fmt.Sprint(signature["keyVersion"])
	if !infrastructureExportKeyVersionPattern.MatchString(keyVersion) {
		return errors.New("signature keyVersion must be the exact bootstrap infrastructure-export key version")
	}
	anchor, trusted := context.trustAnchors[keyVersion]
	if !trusted {
		return fmt.Errorf("signature keyVersion %s is absent from the independently supplied bootstrap trust bundle", keyVersion)
	}
	if anchor.revoked {
		return fmt.Errorf("signature keyVersion %s is revoked by the bootstrap trust bundle", keyVersion)
	}
	if context.now.Before(anchor.validFrom) || !context.now.Before(anchor.validUntil) {
		return fmt.Errorf("signature keyVersion %s is outside its current bootstrap trust validity window", keyVersion)
	}
	if generatedAt.Before(anchor.validFrom) || !generatedAt.Before(anchor.validUntil) {
		return fmt.Errorf("signature keyVersion %s was used outside its bootstrap trust validity window", keyVersion)
	}
	publicKeyDER, _, embeddedPublicKeyDigest, err := parseInfrastructureExportPublicKey(fmt.Sprint(signature["publicKey"]), "signature public key")
	if err != nil {
		return err
	}
	signatureValue, err := decodeCanonicalInfrastructureExportBase64(fmt.Sprint(signature["value"]), 8, 256, "signature value")
	if err != nil {
		return err
	}
	declaredPublicKeyDigest := fmt.Sprint(signature["publicKeyDigest"])
	if subtle.ConstantTimeCompare([]byte(declaredPublicKeyDigest), []byte(embeddedPublicKeyDigest)) != 1 {
		return errors.New("signature publicKeyDigest does not match the embedded public key")
	}
	if subtle.ConstantTimeCompare([]byte(declaredPublicKeyDigest), []byte(anchor.publicKeyDigest)) != 1 ||
		subtle.ConstantTimeCompare(publicKeyDER, anchor.publicKeyDER) != 1 {
		return fmt.Errorf("signature public key does not match keyVersion %s in the independently supplied bootstrap trust bundle", keyVersion)
	}
	payloadHash := sha256.Sum256(payload)
	expectedPayloadDigest := "sha256:" + hex.EncodeToString(payloadHash[:])
	if subtle.ConstantTimeCompare([]byte(fmt.Sprint(signature["payloadDigest"])), []byte(expectedPayloadDigest)) != 1 {
		return errors.New("signature payloadDigest does not match the canonical export payload")
	}
	if !ecdsa.VerifyASN1(anchor.publicKey, payloadHash[:], signatureValue) {
		return errors.New("GCP KMS ECDSA P-256 signature verification failed")
	}
	return nil
}

func decodeCanonicalInfrastructureExportBase64(value string, minimumLength, maximumLength int, name string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) < minimumLength || len(decoded) > maximumLength || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("%s must be canonical base64 encoding of %d to %d bytes", name, minimumLength, maximumLength)
	}
	return decoded, nil
}

func validInfrastructureExportResourceURI(kind, raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "" || !strings.HasPrefix(raw, "//") {
		return false
	}
	path := strings.TrimPrefix(parsed.EscapedPath(), "/")
	if pattern := infrastructureExportProviderPathPatterns[kind]; pattern != nil {
		return parsed.Hostname() == infrastructureExportProviderHosts[kind] && pattern.MatchString(path)
	}
	switch kind {
	case "project":
		return parsed.Hostname() == "cloudresourcemanager.googleapis.com" &&
			strings.HasPrefix(path, "projects/") && infrastructureExportProjectIDPattern.MatchString(strings.TrimPrefix(path, "projects/"))
	case "artifact-bucket":
		return parsed.Hostname() == "storage.googleapis.com" && infrastructureExportBucketPattern.MatchString(path)
	case "workload-identity-pool":
		value := strings.TrimPrefix(path, "workloadIdentityPools/")
		project := strings.TrimSuffix(value, ".svc.id.goog")
		return parsed.Hostname() == "container.googleapis.com" && value != path && project != value && infrastructureExportProjectIDPattern.MatchString(project)
	case "argocd-prerequisite":
		identity := strings.TrimPrefix(path, "projects/-/serviceAccounts/")
		return parsed.Hostname() == "iam.googleapis.com" && identity != path && infrastructureExportServiceAccountPattern.MatchString(identity)
	case "metrics-scope":
		project := strings.TrimPrefix(path, "locations/global/metricsScopes/")
		return parsed.Hostname() == "monitoring.googleapis.com" && project != path && infrastructureExportProjectIDPattern.MatchString(project)
	default:
		return false
	}
}

func safeReferenceURI(raw string, allowSchemeRelative bool) bool {
	if len(raw) > 2048 || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, " \r\n\t?#") {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" || parsed.Path == "" || parsed.Path == "/" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	return allowSchemeRelative && parsed.Scheme == "" && strings.HasPrefix(raw, "//")
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

func decodeEmbeddedYAML(value any, source string, target any) error {
	raw, ok := value.(string)
	if !ok || strings.TrimSpace(raw) == "" {
		return fmt.Errorf("%s must be a non-empty YAML string", source)
	}
	decoder := yaml.NewDecoder(strings.NewReader(raw))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("parse %s: %w", source, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("parse %s: %w", source, err)
		}
		return fmt.Errorf("parse %s: multiple YAML documents are forbidden", source)
	}
	return nil
}

func validateDormantArgoCredentialContract(document map[string]any) error {
	const source = "Argo CD credential binding contract"
	if err := requireExactObjectKeys(document, source, "apiVersion", "kind", "metadata", "data"); err != nil {
		return err
	}
	if document["apiVersion"] != "v1" || document["kind"] != "ConfigMap" {
		return fmt.Errorf("%s identity must remain canonical", source)
	}
	metadata, ok := document["metadata"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s metadata must be an object", source)
	}
	if err := requireExactObjectKeys(metadata, source+" metadata", "name", "namespace", "labels"); err != nil {
		return err
	}
	if metadata["name"] != "argocd-credential-binding-contract" || metadata["namespace"] != "argocd" {
		return fmt.Errorf("%s metadata identity must remain canonical", source)
	}
	if err := requireExactStringMap(metadata["labels"], source+" metadata.labels", map[string]string{
		"app.kubernetes.io/part-of":      "argocd",
		"gitops.mindclade.io/activation": "inactive",
	}); err != nil {
		return err
	}

	data, ok := document["data"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s data must be an object", source)
	}
	if err := requireExactObjectKeys(data, source+" data", "status", "provider", "activation-gate", "required-targets", "sso-contract", "activation-requirements"); err != nil {
		return err
	}
	if data["status"] != "inactive" || data["provider"] != "ExternalSecret" || data["activation-gate"] != "blocked-pending-jit-05" {
		return fmt.Errorf("%s must remain inactive behind JIT-05 and use ExternalSecret", source)
	}

	var targets map[string]any
	if err := decodeEmbeddedYAML(data["required-targets"], source+" required-targets", &targets); err != nil {
		return err
	}
	if err := requireExactObjectKeys(targets, source+" required-targets", "repositoryCredentials", "argocdRuntime", "argocdSSO"); err != nil {
		return err
	}
	repositoryCredentials, ok := targets["repositoryCredentials"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s required-targets.repositoryCredentials must be an object", source)
	}
	if err := requireExactObjectKeys(repositoryCredentials, source+" required-targets.repositoryCredentials", "secretType", "fields"); err != nil {
		return err
	}
	if repositoryCredentials["secretType"] != "repo-creds" {
		return fmt.Errorf("%s required-targets.repositoryCredentials.secretType must equal %q", source, "repo-creds")
	}
	if err := requireExactStringArray(repositoryCredentials["fields"], source+" required-targets.repositoryCredentials.fields", "url", "githubAppID", "githubAppInstallationID", "githubAppPrivateKey"); err != nil {
		return err
	}
	argocdRuntime, ok := targets["argocdRuntime"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s required-targets.argocdRuntime must be an object", source)
	}
	if err := requireExactObjectKeys(argocdRuntime, source+" required-targets.argocdRuntime", "targetSecret", "fields"); err != nil {
		return err
	}
	if argocdRuntime["targetSecret"] != "argocd-secret" {
		return fmt.Errorf("%s required-targets.argocdRuntime.targetSecret must equal %q", source, "argocd-secret")
	}
	if err := requireExactStringArray(argocdRuntime["fields"], source+" required-targets.argocdRuntime.fields", "dex.github.clientID", "dex.github.clientSecret"); err != nil {
		return err
	}
	argocdSSO, ok := targets["argocdSSO"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s required-targets.argocdSSO must be an object", source)
	}
	if err := requireExactObjectKeys(argocdSSO, source+" required-targets.argocdSSO", "targetConfigMap", "fields"); err != nil {
		return err
	}
	if argocdSSO["targetConfigMap"] != "argocd-cm" {
		return fmt.Errorf("%s required-targets.argocdSSO.targetConfigMap must equal %q", source, "argocd-cm")
	}
	if err := requireExactStringArray(argocdSSO["fields"], source+" required-targets.argocdSSO.fields", "url", "dex.config"); err != nil {
		return err
	}

	var sso map[string]any
	if err := decodeEmbeddedYAML(data["sso-contract"], source+" sso-contract", &sso); err != nil {
		return err
	}
	if err := requireExactObjectKeys(sso, source+" sso-contract", "provider", "org", "teamNameField", "teams", "callbackPath"); err != nil {
		return err
	}
	if sso["provider"] != "github" || sso["org"] != "mindclade" || sso["teamNameField"] != "slug" || sso["callbackPath"] != "/api/dex/callback" {
		return fmt.Errorf("%s sso-contract identity must remain canonical", source)
	}
	contractTeams := []string{"platform-operations", "release-engineering", "security"}
	if err := requireExactStringArray(sso["teams"], source+" sso-contract.teams", contractTeams...); err != nil {
		return err
	}
	rbacTeams := make([]string, 0, len(contractTeams))
	for _, line := range argoRBACPolicyLines {
		const prefix = "g, mindclade:"
		if strings.HasPrefix(line, prefix) {
			rbacTeams = append(rbacTeams, strings.SplitN(strings.TrimPrefix(line, prefix), ",", 2)[0])
		}
	}
	sortedContractTeams := append([]string(nil), contractTeams...)
	sort.Strings(sortedContractTeams)
	sort.Strings(rbacTeams)
	if strings.Join(sortedContractTeams, "\x00") != strings.Join(rbacTeams, "\x00") {
		return fmt.Errorf("%s sso-contract teams must exactly match the reviewed RBAC groups", source)
	}

	var requirements []any
	if err := decodeEmbeddedYAML(data["activation-requirements"], source+" activation-requirements", &requirements); err != nil {
		return err
	}
	return requireExactStringArray(requirements, source+" activation-requirements",
		"External Secrets Operator is installed and qualified.",
		"A reviewed SecretStore or ClusterSecretStore binding exists.",
		"Remote reference identifiers are approved for this environment.",
		"JIT-05 ratifies the Argo CD SSO identity, public URL, callback, and secret-binding boundary.",
		"The reviewed HTTPS Argo CD URL resolves and its callback appends /api/dex/callback exactly.",
		"argocd-cm data.url and data.dex.config plus the argocd-secret Dex credential fields are activated atomically in one reviewed change.",
		"Until every requirement passes, argocd-cm omits data.url and data.dex.config and this contract remains inactive.",
		"No secret value is committed to Git.",
	)
}

func validateArgoCoreConfig(document map[string]any, rendered bool) error {
	metadata, ok := document["metadata"].(map[string]any)
	if document["apiVersion"] != "v1" || document["kind"] != "ConfigMap" || !ok || metadata["name"] != "argocd-cm" {
		return errors.New("Argo CD core ConfigMap identity must remain canonical")
	}
	data, ok := document["data"].(map[string]any)
	if !ok {
		return errors.New("Argo CD core ConfigMap data must be an object")
	}
	expected := map[string]string{
		"admin.enabled":           "false",
		"users.anonymous.enabled": "false",
		"exec.enabled":            "false",
		"statusbadge.enabled":     "false",
		"application.sync.requireOverridePrivilegeForRevisionSync": "true",
		"application.resourceTrackingMethod":                       "annotation+label",
		"resource.respectRBAC":                                     "strict",
		"resource.customizations.ignoreDifferences.all":            "jqPathExpressions:\n  - .metadata.managedFields\n",
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
		return errors.New("Argo CD RBAC policy.csv must be a string")
	}
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	for _, line := range lines {
		fields := strings.Split(line, ",")
		if len(fields) != 6 || strings.TrimSpace(fields[2]) != "applications" {
			continue
		}
		action := strings.TrimSpace(fields[3])
		if action == "override" || strings.HasPrefix(action, "action/") {
			return errors.New("Argo CD global RBAC must not grant application override or resource-action authority")
		}
	}
	if len(lines) != len(argoRBACPolicyLines) {
		return errors.New("Argo CD RBAC policy.csv must contain exactly the reviewed policy rules")
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
		return errors.New("Argo CD RBAC ConfigMap identity must remain canonical")
	}
	data, ok := document["data"].(map[string]any)
	if !ok || data["policy.default"] != "role:deny-all" || data["policy.matchMode"] != "glob" || data["scopes"] != "[groups]" {
		return errors.New("Argo CD RBAC ConfigMap fail-closed defaults must remain canonical")
	}
	if err := validateArgoRBACPolicyCSV(data["policy.csv"]); err != nil {
		return err
	}
	return nil
}

func validateInactiveAppProject(document map[string]any, expectedName string) error {
	metadata, ok := document["metadata"].(map[string]any)
	if document["apiVersion"] != "argoproj.io/v1alpha1" || document["kind"] != "AppProject" || !ok || metadata["name"] != expectedName || metadata["namespace"] != "argocd" {
		return fmt.Errorf("inactive project %s identity must remain canonical", expectedName)
	}
	spec, ok := document["spec"].(map[string]any)
	if !ok {
		return fmt.Errorf("inactive project %s spec must be an object", expectedName)
	}
	destinations, ok := spec["destinations"].([]any)
	if !ok || len(destinations) != 0 {
		return fmt.Errorf("inactive project %s must have no destinations", expectedName)
	}
	if err := requireExactStringArray(spec["sourceRepos"], "inactive project "+expectedName+" sourceRepos", "https://github.com/mindclade/gitops.git"); err != nil {
		return err
	}
	return validateReviewedAppProject(document, expectedName)
}

func validateDefaultAppProject(document map[string]any) error {
	metadata, ok := document["metadata"].(map[string]any)
	if document["apiVersion"] != "argoproj.io/v1alpha1" || document["kind"] != "AppProject" || !ok || metadata["name"] != "default" || metadata["namespace"] != "argocd" {
		return errors.New("default project identity must remain canonical")
	}
	spec, ok := document["spec"].(map[string]any)
	if !ok {
		return errors.New("default project spec must be an object")
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
	if err := validateAppProjectApplicationAuthority(document, name); err != nil {
		return err
	}
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

func validateAppProjectApplicationAuthority(document map[string]any, name string) error {
	spec, ok := document["spec"].(map[string]any)
	if !ok {
		return fmt.Errorf("AppProject %s spec must be an object", name)
	}
	rawRoles, exists := spec["roles"]
	if !exists {
		return nil
	}
	roles, ok := rawRoles.([]any)
	if !ok {
		return fmt.Errorf("AppProject %s roles must be an array", name)
	}
	for roleIndex, rawRole := range roles {
		role, ok := rawRole.(map[string]any)
		if !ok {
			return fmt.Errorf("AppProject %s role[%d] must be an object", name, roleIndex)
		}
		policies, ok := role["policies"].([]any)
		if !ok {
			return fmt.Errorf("AppProject %s role[%d] policies must be an array", name, roleIndex)
		}
		for policyIndex, rawPolicy := range policies {
			policy, ok := rawPolicy.(string)
			if !ok {
				return fmt.Errorf("AppProject %s role[%d] policy[%d] must be a string", name, roleIndex, policyIndex)
			}
			fields := strings.Split(policy, ",")
			if len(fields) != 6 {
				return fmt.Errorf("AppProject %s role[%d] policy[%d] must remain a canonical application allow rule", name, roleIndex, policyIndex)
			}
			for index := range fields {
				fields[index] = strings.TrimSpace(fields[index])
			}
			if fields[0] != "p" || !strings.HasPrefix(fields[1], "proj:"+name+":") || fields[2] != "applications" || fields[5] != "allow" {
				return fmt.Errorf("AppProject %s role[%d] policy[%d] must remain a canonical application allow rule", name, roleIndex, policyIndex)
			}
			if fields[3] != "get" && fields[3] != "sync" {
				return fmt.Errorf("AppProject %s role[%d] policy[%d] action %q exceeds reviewed get/sync authority", name, roleIndex, policyIndex, fields[3])
			}
			if fields[4] != name+"/*" {
				return fmt.Errorf("AppProject %s role[%d] policy[%d] must target only %s/*", name, roleIndex, policyIndex, name)
			}
		}
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
	defer func() { _ = file.Close() }()
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
		if resourceErr := compiler.AddResource(location, bytes.NewReader(content)); resourceErr != nil {
			return fmt.Errorf("load pinned %s CRD schema: %w", kind, resourceErr)
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
	inactiveProjects := map[string]bool{}
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
				inactiveProjects["default"] = true
			}
			for _, project := range []string{"platform", "services", "workers", "restricted"} {
				if name != project {
					continue
				}
				if err := validateInactiveAppProject(document, project); err != nil {
					return err
				}
				inactiveProjects[project] = true
			}
		}
	}
	if counts["Application"] != 0 || counts["ApplicationSet"] != 4 || counts["AppProject"] != 5 || counts["ExternalSecret"] != 0 {
		return fmt.Errorf("unexpected rendered custom-resource counts: Application=%d ApplicationSet=%d AppProject=%d ExternalSecret=%d", counts["Application"], counts["ApplicationSet"], counts["AppProject"], counts["ExternalSecret"])
	}
	if imageCount == 0 {
		return errors.New("bootstrap render contains no workload images")
	}
	if !coreConfigSeen || !rbacConfigSeen {
		return errors.New("bootstrap render lacks the semantically validated Argo CD core or RBAC ConfigMap")
	}
	for _, project := range []string{"default", "platform", "services", "workers", "restricted"} {
		if !inactiveProjects[project] {
			return fmt.Errorf("bootstrap render lacks semantically validated inactive project %s", project)
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
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse Argo CD Kustomization: multiple YAML documents are not allowed")
	}
	if document.APIVersion != "kustomize.config.k8s.io/v1beta1" || document.Kind != "Kustomization" {
		return nil, errors.New("invalid Argo CD Kustomization identity")
	}
	if document.Namespace != "argocd" || !document.GeneratorOptions.DisableNameSuffixHash || len(document.GeneratorOptions.Annotations) != 0 {
		return nil, errors.New("Argo CD Kustomization namespace and stable generator options must remain canonical")
	}
	if len(document.GeneratorOptions.Labels) != 1 || document.GeneratorOptions.Labels["app.kubernetes.io/part-of"] != "argocd" {
		return nil, errors.New("Argo CD Kustomization generator labels must remain canonical")
	}
	remoteResources := make([]string, 0, 1)
	for _, resource := range document.Resources {
		if strings.Contains(resource, "://") {
			remoteResources = append(remoteResources, resource)
		}
	}
	if len(remoteResources) != 1 {
		return nil, errors.New("Argo CD Kustomization must contain exactly one remote upstream resource")
	}
	if len(document.ConfigMapGenerator) != 1 {
		return nil, errors.New("Argo CD Kustomization must contain exactly one provenance generator and no other generated resources")
	}
	provenanceGenerators := 0
	values := map[string]string{}
	for _, generator := range document.ConfigMapGenerator {
		if generator.Name != "argocd-bootstrap-provenance" {
			continue
		}
		provenanceGenerators++
		if len(generator.Files) != 0 || len(generator.Envs) != 0 || generator.Behavior != "" || generator.Options != nil {
			return nil, errors.New("Argo CD bootstrap provenance must use literal values only")
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
		return nil, errors.New("Argo CD Kustomization must contain exactly one provenance generator")
	}
	for _, key := range bootstrapProvenanceKeys {
		if values[key] == "" {
			return nil, fmt.Errorf("bootstrap provenance lacks %s", key)
		}
	}
	if values["upstream-version"] != reviewedArgoVersion || values["upstream-revision"] != reviewedArgoRevision || values["upstream-sha256"] != reviewedArgoSHA256 {
		return nil, errors.New("Argo CD upstream version, revision, and checksum must equal the reviewed release contract")
	}
	if err := release.ValidateRevision(values["upstream-revision"]); err != nil {
		return nil, fmt.Errorf("Argo CD upstream revision: %w", err)
	}
	expectedURL := "https://raw.githubusercontent.com/argoproj/argo-cd/" + reviewedArgoRevision + "/manifests/install.yaml"
	if values["upstream-url"] != expectedURL || remoteResources[0] != expectedURL {
		return nil, errors.New("Argo CD Kustomization remote resource and provenance URL must equal the trusted revision-pinned manifest")
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
		return nil, errors.New("Argo CD Kustomization must contain exactly the reviewed bootstrap resources")
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
		return nil, errors.New("Argo CD Kustomization must contain exactly three provenance-bound image overrides")
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
		return nil, errors.New("Argo CD Kustomization contains an image override without matching provenance")
	}
	if err := validateBootstrapPatches(document.Patches); err != nil {
		return nil, err
	}
	return values, nil
}

func validateBootstrapPatches(patches []bootstrapPatch) error {
	if len(patches) != 4 {
		return errors.New("Argo CD Kustomization must contain exactly four reviewed patches")
	}
	for index, expectedPath := range []string{"notifications.yaml", "resource-customizations.yaml"} {
		patch := patches[index]
		if patch.Path != expectedPath || patch.Patch != "" || patch.Target.Group != "" || patch.Target.Version != "" || patch.Target.Kind != "" || patch.Target.Name != "" {
			return fmt.Errorf("Argo CD Kustomization patch[%d] must reference only %s", index, expectedPath)
		}
	}
	rbac := patches[2]
	if rbac.Path != "" || rbac.Target.Group != "" || rbac.Target.Version != "v1" || rbac.Target.Kind != "ConfigMap" || rbac.Target.Name != "argocd-rbac-cm" {
		return errors.New("Argo CD Kustomization must contain the canonical RBAC ConfigMap patch")
	}
	var rbacDocument map[string]any
	rbacDecoder := yaml.NewDecoder(strings.NewReader(rbac.Patch))
	if err := rbacDecoder.Decode(&rbacDocument); err != nil {
		return fmt.Errorf("parse Argo CD RBAC patch: %w", err)
	}
	var rbacTrailing any
	if err := rbacDecoder.Decode(&rbacTrailing); !errors.Is(err, io.EOF) {
		return errors.New("parse Argo CD RBAC patch: multiple YAML documents are not allowed")
	}
	if err := requireExactObjectKeys(rbacDocument, "Argo CD RBAC patch", "apiVersion", "kind", "metadata", "data"); err != nil {
		return err
	}
	metadata, ok := rbacDocument["metadata"].(map[string]any)
	if !ok || metadata["name"] != "argocd-rbac-cm" || len(metadata) != 1 || rbacDocument["apiVersion"] != "v1" || rbacDocument["kind"] != "ConfigMap" {
		return errors.New("Argo CD RBAC patch identity must remain canonical")
	}
	data, ok := rbacDocument["data"].(map[string]any)
	if !ok {
		return errors.New("Argo CD RBAC patch data must be an object")
	}
	if err := requireExactObjectKeys(data, "Argo CD RBAC patch data", "policy.default", "policy.matchMode", "scopes", "policy.csv"); err != nil {
		return err
	}
	if data["policy.default"] != "role:deny-all" || data["policy.matchMode"] != "glob" || data["scopes"] != "[groups]" {
		return errors.New("Argo CD RBAC patch fail-closed defaults must remain canonical")
	}
	if err := validateArgoRBACPolicyCSV(data["policy.csv"]); err != nil {
		return err
	}
	server := patches[3]
	if server.Path != "" || server.Target.Group != "apps" || server.Target.Version != "v1" || server.Target.Kind != "Deployment" || server.Target.Name != "argocd-server" {
		return errors.New("Argo CD Kustomization must contain the canonical server availability patch")
	}
	var operations []map[string]any
	serverDecoder := yaml.NewDecoder(strings.NewReader(server.Patch))
	if err := serverDecoder.Decode(&operations); err != nil {
		return fmt.Errorf("parse Argo CD server patch: %w", err)
	}
	var serverTrailing any
	if err := serverDecoder.Decode(&serverTrailing); !errors.Is(err, io.EOF) {
		return errors.New("parse Argo CD server patch: multiple YAML documents are not allowed")
	}
	if len(operations) != 1 {
		return errors.New("Argo CD server patch must only set two replicas")
	}
	replicas, replicasAreInteger := operations[0]["value"].(int)
	if len(operations[0]) != 3 || operations[0]["op"] != "replace" || operations[0]["path"] != "/spec/replicas" || !replicasAreInteger || replicas != 2 {
		return errors.New("Argo CD server patch must only set two replicas")
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
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
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
		kustomize, kustomizeOK := source["kustomize"].(map[string]any)
		if !kustomizeOK {
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
		kustomize, kustomizeOK := source["kustomize"].(map[string]any)
		if !kustomizeOK {
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
	if validationErr := validateArgoCoreConfig(coreConfig, false); validationErr != nil {
		return validationErr
	}
	kustomization, err := os.ReadFile(filepath.Join(root, "controllers", "argocd", "kustomization.yaml"))
	if err != nil {
		return err
	}
	if _, provenanceErr := BootstrapProvenance(kustomization); provenanceErr != nil {
		return provenanceErr
	}
	rbacText := string(rbac) + "\n" + string(kustomization)
	for _, invariant := range []string{`admin.enabled: "false"`, `users.anonymous.enabled: "false"`, "policy.default: role:deny-all"} {
		if !strings.Contains(rbacText, invariant) {
			return fmt.Errorf("Argo CD invariant %q is missing", invariant)
		}
	}
	if regexp.MustCompile(`(?m)^\s*p, role:deny-all,`).MatchString(rbacText) {
		return errors.New("the empty default RBAC role must not contain deny rules that override mapped roles")
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
	credentialContract, err := readSingleYAMLObject(filepath.Join(root, "controllers", "argocd", "repository-credentials-reference.yaml"), "controllers/argocd/repository-credentials-reference.yaml")
	if err != nil {
		return err
	}
	if validationErr := validateDormantArgoCredentialContract(credentialContract); validationErr != nil {
		return validationErr
	}
	credentialText := string(credentials)
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
		content, readErr := os.ReadFile(filepath.Join(root, "controllers", "applicationsets", name))
		if readErr != nil {
			return readErr
		}
		text := string(content)
		for _, invariant := range append([]string{"matrix:", "elementsYaml:", "if .active", "environments/*/" + contract.record}, contract.invariants...) {
			if !strings.Contains(text, invariant) {
				return fmt.Errorf("%s lacks dynamic release gating %q", name, invariant)
			}
		}
		if validationErr := validateApplicationSet(content, name, contract); validationErr != nil {
			return validationErr
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
		documents, readErr := readYAMLObjects(filepath.Join(root, relative), filepath.ToSlash(relative))
		if readErr != nil {
			return readErr
		}
		projectCount := 0
		defaultCount := 0
		for _, document := range documents {
			metadata, _ := document["metadata"].(map[string]any)
			name := fmt.Sprint(metadata["name"])
			switch name {
			case project:
				if validationErr := validateInactiveAppProject(document, project); validationErr != nil {
					return validationErr
				}
				projectCount++
			case "default":
				if project != "restricted" {
					return fmt.Errorf("unexpected default project in %s", filepath.ToSlash(relative))
				}
				if validationErr := validateDefaultAppProject(document); validationErr != nil {
					return validationErr
				}
				defaultCount++
			default:
				return fmt.Errorf("unexpected AppProject %q in %s", name, filepath.ToSlash(relative))
			}
		}
		if projectCount != 1 {
			return fmt.Errorf("%s must contain exactly one inactive project %s", filepath.ToSlash(relative), project)
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
		content, readErr := os.ReadFile(filepath.Join(root, ".github", "workflows", workflow))
		if readErr != nil {
			return readErr
		}
		text := string(content)
		for _, invariant := range []string{"CONNECTED_GOVERNANCE_READY", "PROMOTION_GOVERNANCE_EVIDENCE", "PROMOTION_TRUSTED_SIGNER", "PROMOTION_TRUSTED_ISSUER", "PROMOTION_TRUSTED_BUILDER", "PROMOTION_TRUSTED_KMS_KEY_VERSION", "PROMOTION_EVIDENCE_BASE_URL", "PROMOTION_EVIDENCE_AUDIENCE", "PROMOTION_EVIDENCE_PUBLIC_KEY_B64", "PROMOTION_VULNERABILITY_POLICY_DIGEST", "PROMOTION_JIT09_QUALIFICATION", "refs/heads/main", `!= qualified-v1`, "verify-transition --root ..", "verify-evidence", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "id-token: write", "--expected-envelope-digest", "--expected-artifact-reference", "--expected-builder-id", "--expected-key-version", "--expected-vulnerability-policy-digest", "ARTIFACT_SOURCE_REVISION", "AUTOMATION_REVISION", `[[ "$ARTIFACT_SOURCE_REVISION" =~ ^[0-9a-f]{40}$ ]]`, `[[ "$ATTESTATION_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]`, `[[ "$GOVERNANCE_EVIDENCE" =~ ^sha256:[0-9a-f]{64}$ ]]`, `[[ "$ARTIFACT_REFERENCE" =~ ^(oci://)?[a-z0-9]+([.-][a-z0-9]+)*(:[1-9][0-9]{0,4})?/[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*@sha256:[0-9a-f]{64}$ ]]`, `if [[ "$RELEASE_CLASS" = platform ]]`, `[[ "$ARTIFACT_REFERENCE" != oci://* ]]`} {
			if !strings.Contains(text, invariant) {
				return fmt.Errorf("%s lacks connected-governance preflight %q", workflow, invariant)
			}
		}
		for _, forbidden := range []string{"promotectl receipt", "promotectl rollback", "upload-artifact@", "promotion-receipt.json", "rollback-receipt.json"} {
			if strings.Contains(text, forbidden) {
				return fmt.Errorf("%s emits pre-merge completion evidence %q", workflow, forbidden)
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
	for _, workflow := range []string{"pull-request.yml", "promotion.yml", "drift-detection.yml", "rollback-verification.yml"} {
		content, readErr := os.ReadFile(filepath.Join(root, ".github", "workflows", workflow))
		if readErr != nil {
			return readErr
		}
		text := string(content)
		for _, invariant := range []string{
			"DeterminateSystems/nix-installer-action@ef8a148080ab6020fd15196c2084a2eea5ff2d25",
			"nix-2.31.2-x86_64-linux.tar.xz",
			"source-revision: 3477b9e591f27522d437d78b21cb857ce87dd6bb",
			"substituters = https://cache.nixos.org/", //nolint:misspell // Exact Nix configuration key.
			"trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=",
			"require-sigs = true",
			"accept-flake-config = false",
			"--no-accept-flake-config",
			"--no-update-lock-file",
		} {
			if !strings.Contains(text, invariant) {
				return fmt.Errorf("%s lacks locked Nix bootstrap %q", workflow, invariant)
			}
		}
		for _, forbidden := range []string{"actions/setup-go@", "actions/setup-python@", "bazel-contrib/setup-bazel@", "USE_BAZEL_VERSION", "--accept-flake-config", "--lockfile_mode=off"} {
			if strings.Contains(text, forbidden) {
				return fmt.Errorf("%s bypasses the Nix toolchain with %q", workflow, forbidden)
			}
		}
	}
	for _, invariant := range []string{
		"nix flake check --no-accept-flake-config --no-update-lock-file",
		"nix develop --no-accept-flake-config --no-update-lock-file .#ci --command just validate",
		"nix develop --no-accept-flake-config --no-update-lock-file .#ci --command just bazel-test",
		"git ls-files --error-unmatch .bazelignore .bazelrc .bazelversion flake.nix flake.lock MODULE.bazel MODULE.bazel.lock",
	} {
		if !strings.Contains(string(pullRequest), invariant) {
			return fmt.Errorf("pull-request workflow lacks Nix/Bazel validation %q", invariant)
		}
	}
	flake, err := os.ReadFile(filepath.Join(root, "flake.nix"))
	if err != nil {
		return err
	}
	for _, invariant := range []string{"policy = import ./generated/nix-bazel-policy.nix", "systems = policy.spec.systems", "toolchain", "devShells", "default", "ci", "formatter", "checks", "toolchainCheck", "vendorHash", "83199d0d373dd3ac2b9a1996b1d0263f76ab7a4c", "bazel_9", "toolchainManifest", "mindclade-toolchain.v2"} {
		if !strings.Contains(string(flake), invariant) {
			return fmt.Errorf("flake.nix lacks toolchain contract %q", invariant)
		}
	}
	justfile, err := os.ReadFile(filepath.Join(root, "justfile"))
	if err != nil {
		return err
	}
	for _, invariant := range []string{
		"MACOSX_DEPLOYMENT_TARGET",
		"bazel test --config=ci",
		// Guarded expansion: the recipe runs under bash -u, where bash 3.2 treats
		// an unguarded "${bazel_args[@]}" on an empty array as an unbound variable
		// and aborts before any test runs.
		`${bazel_args[@]+"${bazel_args[@]}"} //...`,
	} {
		if !strings.Contains(string(justfile), invariant) {
			return errors.New("just bazel-test does not use the locked Nix-provided Bazel CI configuration")
		}
	}
	if !strings.Contains(string(flake), "BAZEL_LINKOPTS") {
		return errors.New("the locked Nix Bazel wrapper does not provide platform linker options")
	}
	for _, forbidden := range []string{"bazelisk", "USE_BAZEL_VERSION", "--lockfile_mode=off"} {
		if strings.Contains(string(justfile), forbidden) {
			return fmt.Errorf("justfile bypasses the locked Bazel policy with %q", forbidden)
		}
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
