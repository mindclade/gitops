package evidence

import (
	"strings"
	"testing"
	"time"
)

const (
	testRevision = "1111111111111111111111111111111111111111"
	testOther    = "2222222222222222222222222222222222222222"
	testDigest   = "sha256:" +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testKeyVersion = "projects/mindclade-signing/locations/us-central1/keyRings/" +
		"bootstrap-signing/cryptoKeys/supply-chain-provenance/cryptoKeyVersions/1"
)

var testNow = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

func validEnvelope() PromotionEnvelope {
	return PromotionEnvelope{
		SchemaVersion: "v1",
		Kind:          "GitOpsPromotionEnvelope",
		BuilderID:     "https://buildkite.com/mindclade/mindclade",
		Buildkite: BuildkiteIdentity{
			Organization: "mindclade",
			Pipeline:     "mindclade",
			BuildNumber:  "4271",
			BuildID:      "0f8b1d3e-2c4a-4b6d-9e1f-7a3c5d9b2e40",
			Commit:       testRevision,
		},
		SourceRevision:       testRevision,
		ArtifactReference:    "us-central1-docker.pkg.dev/mindclade/release/api",
		ArtifactDigest:       testDigest,
		EvidenceBundleDigest: testDigest,
		SBOM:                 PromotionDocument{Digest: testDigest, MediaType: "application/spdx+json"},
		Provenance: PromotionDocument{
			Digest: testDigest, MediaType: "application/vnd.in-toto+json",
		},
		Signature: PromotionSignature{
			Algorithm:       "ECDSA_P256_SHA256",
			KeyVersion:      testKeyVersion,
			SignatureBase64: "c2lnbmF0dXJl",
		},
		IssuedAt: testNow.Add(-time.Hour).Format(time.RFC3339),
	}
}

func TestValidEnvelopeIsAccepted(t *testing.T) {
	if err := validEnvelope().ValidateAt(testNow); err != nil {
		t.Fatalf("expected a valid envelope to be accepted, got %v", err)
	}
}

func TestEnvelopeRejectsEveryBrokenBinding(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*PromotionEnvelope)
		expects string
	}{
		{"wrong source revision", func(e *PromotionEnvelope) {
			e.SourceRevision = testOther
		}, "does not match source revision"},
		{"short source revision", func(e *PromotionEnvelope) {
			e.SourceRevision = "abc123"
			e.Buildkite.Commit = "abc123"
		}, "not a full commit SHA"},
		{"malformed artifact digest", func(e *PromotionEnvelope) {
			e.ArtifactDigest = "sha256:short"
		}, "artifact digest"},
		{"malformed evidence bundle digest", func(e *PromotionEnvelope) {
			e.EvidenceBundleDigest = "not-a-digest"
		}, "evidence bundle digest"},
		{"missing sbom digest", func(e *PromotionEnvelope) {
			e.SBOM.Digest = ""
		}, "sbom digest"},
		{"missing sbom media type", func(e *PromotionEnvelope) {
			e.SBOM.MediaType = "  "
		}, "sbom media type is empty"},
		{"missing provenance digest", func(e *PromotionEnvelope) {
			e.Provenance.Digest = ""
		}, "provenance digest"},
		{"wrong signature algorithm", func(e *PromotionEnvelope) {
			e.Signature.Algorithm = "RSA_SIGN_PSS_2048_SHA256"
		}, "unsupported signature algorithm"},
		{"signature key is not a KMS version", func(e *PromotionEnvelope) {
			e.Signature.KeyVersion = "some-local-key"
		}, "not a KMS key version"},
		{"empty signature", func(e *PromotionEnvelope) {
			e.Signature.SignatureBase64 = ""
		}, "signature is empty"},
		{"foreign buildkite organization", func(e *PromotionEnvelope) {
			e.Buildkite.Organization = "attacker"
		}, "not the estate organization"},
		{"builder disagrees with pipeline", func(e *PromotionEnvelope) {
			e.Buildkite.Pipeline = "other-pipeline"
		}, "does not identify pipeline"},
		{"malformed build number", func(e *PromotionEnvelope) {
			e.Buildkite.BuildNumber = "0"
		}, "build number"},
		{"malformed build id", func(e *PromotionEnvelope) {
			e.Buildkite.BuildID = "not-a-uuid"
		}, "build id"},
		{"expired envelope", func(e *PromotionEnvelope) {
			e.IssuedAt = testNow.Add(-48 * time.Hour).Format(time.RFC3339)
		}, "older than"},
		{"envelope from the future", func(e *PromotionEnvelope) {
			e.IssuedAt = testNow.Add(time.Hour).Format(time.RFC3339)
		}, "issued in the future"},
		{"unsupported schema", func(e *PromotionEnvelope) {
			e.SchemaVersion = "v2"
		}, "unsupported envelope schema"},
		{"unsupported kind", func(e *PromotionEnvelope) {
			e.Kind = "SomethingElse"
		}, "unsupported envelope kind"},
		{"empty artifact reference", func(e *PromotionEnvelope) {
			e.ArtifactReference = ""
		}, "artifact reference is empty"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			envelope := validEnvelope()
			testCase.mutate(&envelope)
			err := envelope.ValidateAt(testNow)
			if err == nil {
				t.Fatalf("expected rejection")
			}
			if !strings.Contains(err.Error(), testCase.expects) {
				t.Fatalf("expected error containing %q, got %v", testCase.expects, err)
			}
		})
	}
}

// The estate builds releases on Buildkite. An envelope must never be able to
// attest that a GitHub-hosted runner produced the artifact.
func TestEnvelopeRefusesToAttestAGitHubBuild(t *testing.T) {
	for _, builder := range []string{
		"https://github.com/mindclade/mindclade/actions/runs/1",
		"https://github.com/mindclade/mindclade",
		"https://token.actions.githubusercontent.com/mindclade",
		"https://buildkite.com/mindclade/actions/runner",
	} {
		t.Run(builder, func(t *testing.T) {
			envelope := validEnvelope()
			envelope.BuilderID = builder
			err := envelope.ValidateAt(testNow)
			if err == nil {
				t.Fatalf("expected a non-Buildkite builder to be rejected")
			}
			if !strings.Contains(err.Error(), "Buildkite") {
				t.Fatalf("expected a Buildkite-specific rejection, got %v", err)
			}
		})
	}
}
