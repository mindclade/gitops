package evidence

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFixture(t *testing.T, root, name string, value any) (string, string) {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return path, "sha256:" + hex.EncodeToString(digest[:])
}

func supplyChainFixture(t *testing.T) SupplyChainVerificationRequest {
	t.Helper()
	root := t.TempDir()
	artifactDigest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	artifactReference := "us-central1-docker.pkg.dev/mindclade/estate-ci/api@" + artifactDigest
	sourceRevision := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	builderID := "https://buildkite.com/mindclade/estate-ci"
	signerIdentity := "https://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/buildkite/subject/publisher"
	keyVersion := "projects/fixture-project/locations/global/keyRings/supply-chain/cryptoKeys/provenance/cryptoKeyVersions/1"
	policyDigest := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	provenancePath, provenanceDigest := writeFixture(t, root, "provenance.json", map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": []any{map[string]any{
			"name":   artifactReference,
			"digest": map[string]string{"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		}},
		"predicate": map[string]any{
			"buildDefinition": map[string]any{"externalParameters": map[string]string{"source_revision": sourceRevision}},
			"runDetails":      map[string]any{"builder": map[string]string{"id": builderID}},
		},
	})
	sbomPath, sbomDigest := writeFixture(t, root, "sbom.json", map[string]any{
		"spdxVersion":       "SPDX-2.3",
		"documentNamespace": "https://estate-ci.mindclade.com/sbom/fixture",
		"documentDescribes": []string{"SPDXRef-Package"},
		"packages":          []any{map[string]string{"SPDXID": "SPDXRef-Package", "name": "estate-ci"}},
	})
	dependenciesPath, dependenciesDigest := writeFixture(t, root, "dependencies.json", map[string]any{
		"schema_version":  "mindclade.dependency-snapshot.v1",
		"source_revision": sourceRevision,
		"ecosystems":      []string{"bazel", "go", "nix", "node", "python", "rust"},
	})
	vulnerabilityPath, vulnerabilityDigest := writeFixture(t, root, "vulnerability.json", map[string]any{
		"schema_version":  "mindclade.vulnerability-decision.v1",
		"artifact_digest": artifactDigest,
		"policy_digest":   policyDigest,
		"decision":        "pass",
	})

	payload := supplyChainPayload{
		SchemaVersion:     supplyChainPayloadVersion,
		ArtifactReference: artifactReference,
		ArtifactDigest:    artifactDigest,
		SourceRevision:    sourceRevision,
		BuilderID:         builderID,
		BuildID:           "fixture-build-1",
		SignerIdentity:    signerIdentity,
		IssuedAt:          "2026-09-02T10:00:00Z",
		Provenance:        documentBinding{Digest: provenanceDigest, MediaType: "application/vnd.in-toto+json"},
		SBOM:              documentBinding{Digest: sbomDigest, MediaType: "application/spdx+json"},
		Dependencies:      documentBinding{Digest: dependenciesDigest, MediaType: "application/vnd.mindclade.dependency-snapshot.v1+json"},
		VulnerabilityReport: vulnerabilityBinding{
			Digest:       vulnerabilityDigest,
			MediaType:    "application/vnd.mindclade.vulnerability-decision.v1+json",
			PolicyDigest: policyDigest,
		},
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	canonicalPayload, err := canonicalJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(append([]byte(supplyChainSigningPrefix), canonicalPayload...))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	envelope := supplyChainEnvelope{
		SchemaVersion: supplyChainEnvelopeVersion,
		PayloadType:   supplyChainPayloadType,
		Payload:       payload,
		Signature: supplyChainSignature{
			Algorithm:       supplyChainAlgorithm,
			KeyVersion:      keyVersion,
			SignatureBase64: base64.StdEncoding.EncodeToString(signature),
		},
	}
	envelopePath, envelopeDigest := writeFixture(t, root, "envelope.json", envelope)
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyPath := filepath.Join(root, "public-key.pem")
	if err := os.WriteFile(publicKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return SupplyChainVerificationRequest{
		EnvelopePath:                      envelopePath,
		PublicKeyPath:                     publicKeyPath,
		ProvenancePath:                    provenancePath,
		SBOMPath:                          sbomPath,
		DependenciesPath:                  dependenciesPath,
		VulnerabilityPath:                 vulnerabilityPath,
		ExpectedEnvelopeDigest:            envelopeDigest,
		ExpectedArtifactReference:         artifactReference,
		ExpectedArtifactDigest:            artifactDigest,
		ExpectedSourceRevision:            sourceRevision,
		ExpectedBuilderID:                 builderID,
		ExpectedSignerIdentity:            signerIdentity,
		ExpectedKeyVersion:                keyVersion,
		ExpectedVulnerabilityPolicyDigest: policyDigest,
		Now:                               time.Date(2026, 9, 2, 10, 5, 0, 0, time.UTC),
	}
}

func TestVerifySupplyChain(t *testing.T) {
	request := supplyChainFixture(t)
	if err := VerifySupplyChain(request); err != nil {
		t.Fatalf("expected valid evidence: %v", err)
	}
	request.ExpectedArtifactDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if err := VerifySupplyChain(request); err == nil {
		t.Fatal("expected an artifact-subject mismatch")
	}
	request = supplyChainFixture(t)
	request.ExpectedBuilderID = "https://buildkite.com/mindclade/estate-ci?mutable=true"
	if err := VerifySupplyChain(request); err == nil {
		t.Fatal("expected an unsafe builder identity rejection")
	}
}

func TestVerifySupplyChainRejectsTampering(t *testing.T) {
	request := supplyChainFixture(t)
	if err := os.WriteFile(request.SBOMPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifySupplyChain(request); err == nil {
		t.Fatal("expected tampered SBOM rejection")
	}
}
