package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
	if err := validateSchemaSet(root); err != nil {
		return err
	}
	for _, environment := range release.Environments {
		if err := ValidateEnvironment(root, environment); err != nil {
			return err
		}
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
		"approvals": []any{"review:release", "review:security"}, "repository": "mindclade/gitops",
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
		if !safeClusterServer(server) {
			return nil, fmt.Errorf("cluster %s has an unsafe API server URI", name)
		}
		if clusters[name] || servers[server] {
			return nil, fmt.Errorf("cluster-set.yaml contains a duplicate cluster name or server")
		}
		clusters[name] = true
		servers[server] = true
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

func safeClusterServer(raw string) bool {
	if raw == "" || len(raw) > 2048 || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, " \r\n\t") {
		return false
	}
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Opaque == "" && parsed.Host != "" && parsed.Hostname() != "" && parsed.User == nil && parsed.RawQuery == "" && !parsed.ForceQuery && parsed.Fragment == "" && (parsed.Path == "" || parsed.Path == "/")
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
	}
	return nil
}

func safeIdentityURI(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && !parsed.ForceQuery && parsed.Fragment == "" && strings.TrimSpace(raw) == raw
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
	}
	if counts["Application"] != 0 || counts["ApplicationSet"] != 4 || counts["AppProject"] != 5 || counts["ExternalSecret"] != 0 {
		return fmt.Errorf("unexpected rendered custom-resource counts: Application=%d ApplicationSet=%d AppProject=%d ExternalSecret=%d", counts["Application"], counts["ApplicationSet"], counts["AppProject"], counts["ExternalSecret"])
	}
	if imageCount == 0 {
		return fmt.Errorf("bootstrap render contains no workload images")
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
	kustomization, err := os.ReadFile(filepath.Join(root, "controllers", "argocd", "kustomization.yaml"))
	if err != nil {
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
	for _, image := range []string{
		"quay.io/argoproj/argocd@sha256:e2aadfae709d904e87f46ba4aa49601d827b3022db22cd4d03aae816a2e7097b",
		"ghcr.io/dexidp/dex@sha256:8499afd690c437f52301efd2b05b2455da5bd2dfc20332cd697dc9937f808462",
		"public.ecr.aws/docker/library/redis@sha256:08ad0b1d280850169a790dba1393ff7a90aef951fc19632cf4d3ce4f78e679ba",
	} {
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
	applicationSets := map[string]struct {
		record     string
		invariants []string
	}{
		"environment-root.yaml": {
			record:     "cluster-set.yaml",
			invariants: []string{`name: '{{.environment}}.root.{{.name}}'`},
		},
		"platform-components.yaml": {
			record:     "platform-releases.yaml",
			invariants: []string{`name: '{{.environment}}.platform.{{.cluster}}.{{.component}}'`, "gitops.mindclade.io/release-class: platform"},
		},
		"control-plane-services.yaml": {
			record:     "service-releases.yaml",
			invariants: []string{`name: '{{.environment}}.service.{{.cluster}}.{{.component}}'`, "gitops.mindclade.io/release-class: service", `path: '{{.desiredStatePath}}'`, "images:", `- '{{.component}}={{.artifact}}'`},
		},
		"execution-workers.yaml": {
			record:     "worker-releases.yaml",
			invariants: []string{`name: '{{.environment}}.worker.{{.cluster}}.{{.component}}'`, "gitops.mindclade.io/release-class: worker", `path: '{{.desiredStatePath}}'`, "images:", `- '{{.component}}={{.artifact}}'`},
		},
	}
	for name, contract := range applicationSets {
		content, err := os.ReadFile(filepath.Join(root, "controllers", "applicationsets", name))
		if err != nil {
			return err
		}
		text := string(content)
		for _, invariant := range append([]string{"matrix:", "elementsYaml:", "if .active", "environments/*/" + contract.record, "desiredStateRevision"}, contract.invariants...) {
			if !strings.Contains(text, invariant) {
				return fmt.Errorf("%s lacks dynamic release gating %q", name, invariant)
			}
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
		content, err := os.ReadFile(filepath.Join(root, "projects", project+".appproject.yaml"))
		if err != nil {
			return err
		}
		if !strings.Contains(string(content), "destinations: []") {
			return fmt.Errorf("unbound project %s must have no destinations", project)
		}
	}
	for _, workflow := range []string{"promotion.yml", "rollback-verification.yml"} {
		content, err := os.ReadFile(filepath.Join(root, ".github", "workflows", workflow))
		if err != nil {
			return err
		}
		text := string(content)
		for _, invariant := range []string{"CONNECTED_GOVERNANCE_READY", "PROMOTION_GOVERNANCE_EVIDENCE", "PROMOTION_TRUSTED_SIGNER", "PROMOTION_TRUSTED_ISSUER", "refs/heads/main", `EVIDENCE_VERIFIER_IMPLEMENTATION: unbound`, `!= verified-v1`, "verify-transition --root ..", "ARTIFACT_SOURCE_REVISION", "AUTOMATION_REVISION", "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", "--checked-out-revision", "--workflow-run-id", "retention-days: 90", `[[ "$GOVERNANCE_EVIDENCE" =~ ^sha256:[0-9a-f]{64}$ ]]`, `[[ "$ARTIFACT_REFERENCE" =~ ^[^[:space:]]+@sha256:[0-9a-f]{64}$ ]]`} {
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
