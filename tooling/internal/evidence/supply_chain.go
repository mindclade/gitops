package evidence

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mindclade/gitops/tooling/internal/release"
)

const (
	supplyChainEnvelopeVersion = "mindclade.supply-chain-envelope.v1"
	supplyChainPayloadVersion  = "mindclade.supply-chain-evidence.v1"
	supplyChainPayloadType     = "application/vnd.mindclade.supply-chain-evidence.v1+json"
	supplyChainAlgorithm       = "ECDSA_P256_SHA256"
	supplyChainSigningPrefix   = "mindclade-supply-chain-evidence-v1\n"
	maxSupplyChainEvidenceAge  = 24 * time.Hour
)

var kmsKeyVersionPattern = regexp.MustCompile(`^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+/cryptoKeyVersions/[1-9][0-9]*$`)

type documentBinding struct {
	Digest    string `json:"digest"`
	MediaType string `json:"media_type"`
}

type vulnerabilityBinding struct {
	Digest       string `json:"digest"`
	MediaType    string `json:"media_type"`
	PolicyDigest string `json:"policy_digest"`
}

type supplyChainPayload struct {
	SchemaVersion       string               `json:"schema_version"`
	ArtifactReference   string               `json:"artifact_reference"`
	ArtifactDigest      string               `json:"artifact_digest"`
	SourceRevision      string               `json:"source_revision"`
	BuilderID           string               `json:"builder_id"`
	BuildID             string               `json:"build_id"`
	SignerIdentity      string               `json:"signer_identity"`
	IssuedAt            string               `json:"issued_at"`
	Provenance          documentBinding      `json:"provenance"`
	SBOM                documentBinding      `json:"sbom"`
	Dependencies        documentBinding      `json:"dependencies"`
	VulnerabilityReport vulnerabilityBinding `json:"vulnerability_report"`
}

type supplyChainSignature struct {
	Algorithm       string `json:"algorithm"`
	KeyVersion      string `json:"key_version"`
	SignatureBase64 string `json:"signature_base64"`
}

type supplyChainEnvelope struct {
	SchemaVersion string               `json:"schema_version"`
	PayloadType   string               `json:"payload_type"`
	Payload       supplyChainPayload   `json:"payload"`
	Signature     supplyChainSignature `json:"signature"`
}

type SupplyChainVerificationRequest struct {
	EnvelopePath                      string
	PublicKeyPath                     string
	ProvenancePath                    string
	SBOMPath                          string
	DependenciesPath                  string
	VulnerabilityPath                 string
	ExpectedEnvelopeDigest            string
	ExpectedArtifactReference         string
	ExpectedArtifactDigest            string
	ExpectedSourceRevision            string
	ExpectedBuilderID                 string
	ExpectedSignerIdentity            string
	ExpectedKeyVersion                string
	ExpectedVulnerabilityPolicyDigest string
	Now                               time.Time
}

func decodeStrict(data []byte, target any, description string) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%s is not strict JSON: %w", description, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s contains trailing JSON values", description)
	}
	return nil
}

func canonicalJSON(value any) ([]byte, error) {
	return json.Marshal(value)
}

func fileDigest(path string) (string, []byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:]), content, nil
}

func validateBinding(name string, binding documentBinding, path, mediaType string) ([]byte, error) {
	if binding.MediaType != mediaType {
		return nil, fmt.Errorf("%s media type must be %s", name, mediaType)
	}
	if err := release.ValidateDigest(binding.Digest); err != nil {
		return nil, fmt.Errorf("%s binding: %w", name, err)
	}
	digest, content, err := fileDigest(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if digest != binding.Digest {
		return nil, fmt.Errorf("%s digest mismatch", name)
	}
	return content, nil
}

func validateProvenance(content []byte, payload supplyChainPayload) error {
	var document struct {
		Type          string `json:"_type"`
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		Predicate struct {
			BuildDefinition struct {
				ExternalParameters struct {
					SourceRevision string `json:"source_revision"`
				} `json:"externalParameters"`
			} `json:"buildDefinition"`
			RunDetails struct {
				Builder struct {
					ID string `json:"id"`
				} `json:"builder"`
			} `json:"runDetails"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(content, &document); err != nil {
		return fmt.Errorf("provenance is invalid JSON: %w", err)
	}
	if document.Type != "https://in-toto.io/Statement/v1" || document.PredicateType != "https://slsa.dev/provenance/v1" {
		return errors.New("provenance must be an in-toto Statement with SLSA v1 predicate")
	}
	if document.Predicate.RunDetails.Builder.ID != payload.BuilderID {
		return errors.New("provenance builder identity mismatch")
	}
	if document.Predicate.BuildDefinition.ExternalParameters.SourceRevision != payload.SourceRevision {
		return errors.New("provenance source revision mismatch")
	}
	expectedDigest := strings.TrimPrefix(payload.ArtifactDigest, "sha256:")
	for _, subject := range document.Subject {
		if subject.Name == payload.ArtifactReference && subject.Digest["sha256"] == expectedDigest {
			return nil
		}
	}
	return errors.New("provenance lacks the exact artifact subject")
}

func validateSBOM(content []byte) error {
	var document struct {
		SPDXVersion       string            `json:"spdxVersion"`
		DocumentNamespace string            `json:"documentNamespace"`
		DocumentDescribes []string          `json:"documentDescribes"`
		Packages          []json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(content, &document); err != nil {
		return fmt.Errorf("SBOM is invalid JSON: %w", err)
	}
	if document.SPDXVersion != "SPDX-2.3" || !strings.HasPrefix(document.DocumentNamespace, "https://") {
		return errors.New("SBOM must be SPDX 2.3 with an HTTPS document namespace")
	}
	if len(document.DocumentDescribes) == 0 || len(document.Packages) == 0 {
		return errors.New("SBOM must describe at least one packaged subject")
	}
	return nil
}

func validateDependencies(content []byte, sourceRevision string) error {
	var document struct {
		SchemaVersion  string   `json:"schema_version"`
		SourceRevision string   `json:"source_revision"`
		Ecosystems     []string `json:"ecosystems"`
	}
	if err := decodeStrict(content, &document, "dependency snapshot"); err != nil {
		return err
	}
	if document.SchemaVersion != "mindclade.dependency-snapshot.v1" || document.SourceRevision != sourceRevision {
		return errors.New("dependency snapshot identity mismatch")
	}
	observed := append([]string(nil), document.Ecosystems...)
	sort.Strings(observed)
	expected := []string{"bazel", "go", "nix", "node", "python", "rust"}
	if strings.Join(observed, ",") != strings.Join(expected, ",") {
		return errors.New("dependency snapshot must cover Bazel, Nix, Go, Python, Rust, and Node exactly")
	}
	return nil
}

func validateVulnerability(content []byte, artifactDigest, policyDigest string) error {
	var document struct {
		SchemaVersion  string `json:"schema_version"`
		ArtifactDigest string `json:"artifact_digest"`
		PolicyDigest   string `json:"policy_digest"`
		Decision       string `json:"decision"`
	}
	if err := decodeStrict(content, &document, "vulnerability report"); err != nil {
		return err
	}
	if document.SchemaVersion != "mindclade.vulnerability-decision.v1" || document.Decision != "pass" {
		return errors.New("vulnerability report must carry a v1 pass decision")
	}
	if document.ArtifactDigest != artifactDigest || document.PolicyDigest != policyDigest {
		return errors.New("vulnerability report subject or policy mismatch")
	}
	return nil
}

func verifySupplyChainSignature(envelope supplyChainEnvelope, publicKeyPEM []byte) error {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New("evidence public key must be a PKIX PUBLIC KEY PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse evidence public key: %w", err)
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve.Params().Name != "P-256" {
		return errors.New("evidence public key must be ECDSA P-256")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature.SignatureBase64)
	if err != nil {
		return errors.New("evidence signature is not canonical base64")
	}
	payload, err := canonicalJSON(envelope.Payload)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(append([]byte(supplyChainSigningPrefix), payload...))
	if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		return errors.New("evidence signature verification failed")
	}
	return nil
}

func VerifySupplyChain(request SupplyChainVerificationRequest) error {
	envelopeDigest, envelopeContent, readEnvelopeErr := fileDigest(request.EnvelopePath)
	if readEnvelopeErr != nil {
		return fmt.Errorf("read evidence envelope: %w", readEnvelopeErr)
	}
	if envelopeDigest != request.ExpectedEnvelopeDigest {
		return errors.New("evidence envelope digest mismatch")
	}
	var envelope supplyChainEnvelope
	if err := decodeStrict(envelopeContent, &envelope, "evidence envelope"); err != nil {
		return err
	}
	canonicalEnvelope, canonicalEnvelopeErr := canonicalJSON(envelope)
	if canonicalEnvelopeErr != nil {
		return canonicalEnvelopeErr
	}
	if !bytes.Equal(bytes.TrimSpace(envelopeContent), canonicalEnvelope) {
		return errors.New("evidence envelope must use canonical JSON")
	}
	if envelope.SchemaVersion != supplyChainEnvelopeVersion || envelope.PayloadType != supplyChainPayloadType {
		return errors.New("unsupported supply-chain evidence envelope")
	}
	if envelope.Signature.Algorithm != supplyChainAlgorithm || envelope.Signature.KeyVersion != request.ExpectedKeyVersion || !kmsKeyVersionPattern.MatchString(envelope.Signature.KeyVersion) {
		return errors.New("evidence signing algorithm or KMS key version mismatch")
	}
	payload := envelope.Payload
	if !safeHTTPSIdentity(request.ExpectedBuilderID) || !safeHTTPSIdentity(request.ExpectedSignerIdentity) {
		return errors.New("trusted builder and signer identities must be protected canonical values")
	}
	if payload.SchemaVersion != supplyChainPayloadVersion || payload.ArtifactReference != request.ExpectedArtifactReference || payload.ArtifactDigest != request.ExpectedArtifactDigest || payload.SourceRevision != request.ExpectedSourceRevision || payload.BuilderID != request.ExpectedBuilderID || payload.SignerIdentity != request.ExpectedSignerIdentity {
		return errors.New("evidence payload identity mismatch")
	}
	if err := release.ValidateDigest(payload.ArtifactDigest); err != nil {
		return err
	}
	if err := release.ValidateRevision(payload.SourceRevision); err != nil {
		return err
	}
	if !strings.HasSuffix(payload.ArtifactReference, "@"+payload.ArtifactDigest) {
		return errors.New("evidence artifact reference does not bind its digest")
	}
	if payload.BuildID == "" || strings.TrimSpace(payload.BuildID) != payload.BuildID {
		return errors.New("evidence build ID must be nonempty and canonical")
	}
	issuedAt, parseIssuedAtErr := time.Parse(time.RFC3339, payload.IssuedAt)
	if parseIssuedAtErr != nil || issuedAt.Format(time.RFC3339) != payload.IssuedAt || !strings.HasSuffix(payload.IssuedAt, "Z") {
		return errors.New("evidence issued_at must be canonical RFC3339 UTC")
	}
	now := request.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if issuedAt.After(now.Add(maxFutureSkew)) || issuedAt.Before(now.Add(-maxSupplyChainEvidenceAge)) {
		return errors.New("evidence timestamp is outside the accepted window")
	}
	if payload.VulnerabilityReport.PolicyDigest != request.ExpectedVulnerabilityPolicyDigest {
		return errors.New("evidence vulnerability policy binding mismatch")
	}
	if err := release.ValidateDigest(request.ExpectedVulnerabilityPolicyDigest); err != nil {
		return err
	}
	publicKey, readPublicKeyErr := os.ReadFile(request.PublicKeyPath)
	if readPublicKeyErr != nil {
		return fmt.Errorf("read evidence public key: %w", readPublicKeyErr)
	}
	if err := verifySupplyChainSignature(envelope, publicKey); err != nil {
		return err
	}
	provenance, provenanceErr := validateBinding("provenance", payload.Provenance, request.ProvenancePath, "application/vnd.in-toto+json")
	if provenanceErr != nil {
		return provenanceErr
	}
	sbom, sbomErr := validateBinding("SBOM", payload.SBOM, request.SBOMPath, "application/spdx+json")
	if sbomErr != nil {
		return sbomErr
	}
	dependencies, dependenciesErr := validateBinding("dependency snapshot", payload.Dependencies, request.DependenciesPath, "application/vnd.mindclade.dependency-snapshot.v1+json")
	if dependenciesErr != nil {
		return dependenciesErr
	}
	vulnerabilityBinding := documentBinding{Digest: payload.VulnerabilityReport.Digest, MediaType: payload.VulnerabilityReport.MediaType}
	vulnerability, vulnerabilityErr := validateBinding("vulnerability report", vulnerabilityBinding, request.VulnerabilityPath, "application/vnd.mindclade.vulnerability-decision.v1+json")
	if vulnerabilityErr != nil {
		return vulnerabilityErr
	}
	if err := validateProvenance(provenance, payload); err != nil {
		return err
	}
	if err := validateSBOM(sbom); err != nil {
		return err
	}
	if err := validateDependencies(dependencies, payload.SourceRevision); err != nil {
		return err
	}
	return validateVulnerability(vulnerability, payload.ArtifactDigest, payload.VulnerabilityReport.PolicyDigest)
}
