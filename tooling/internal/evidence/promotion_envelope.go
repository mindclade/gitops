package evidence

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	promotionEnvelopeSchemaVersion = "v1"
	promotionEnvelopeKind          = "GitOpsPromotionEnvelope"
	promotionEnvelopeAlgorithm     = "ECDSA_P256_SHA256"
	promotionEnvelopeOrganization  = "mindclade"
	maxPromotionEnvelopeAge        = 24 * time.Hour
)

var (
	promotionDigestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	promotionRevisionPattern  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	promotionPipelinePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	promotionBuildNumberRegex = regexp.MustCompile(`^[1-9][0-9]*$`)
	promotionBuildIDPattern   = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	promotionBuilderPattern = regexp.MustCompile(
		`^https://buildkite\.com/mindclade/[a-z0-9][a-z0-9-]{0,63}$`)
)

// forbiddenBuilderFragments name build systems that must never appear as the
// builder of a promotion envelope. The estate builds releases on Buildkite; an
// envelope claiming a GitHub-hosted builder would attest something that did not
// happen, so it is rejected rather than normalised.
var forbiddenBuilderFragments = []string{
	"github.com",
	"githubusercontent.com",
	"actions/runner",
}

// BuildkiteIdentity is the build that produced the artifact.
type BuildkiteIdentity struct {
	Organization string `json:"organization"`
	Pipeline     string `json:"pipeline"`
	BuildNumber  string `json:"buildNumber"`
	BuildID      string `json:"buildID"`
	Commit       string `json:"commit"`
}

// PromotionDocument binds an evidence document by digest and media type.
type PromotionDocument struct {
	Digest    string `json:"digest"`
	MediaType string `json:"mediaType"`
}

// PromotionSignature is the KMS signature over the envelope payload.
type PromotionSignature struct {
	Algorithm       string `json:"algorithm"`
	KeyVersion      string `json:"keyVersion"`
	SignatureBase64 string `json:"signatureBase64"`
}

// PromotionEnvelope mirrors schemas/v1/gitops_promotion_envelope.schema.json.
//
// The envelope is a verification record, not an authority to build or deploy.
// Validating it proves that a named Buildkite build produced a named artifact
// from a named source revision, with SBOM, provenance and signature bound by
// digest. It never causes a rebuild or a deployment.
type PromotionEnvelope struct {
	SchemaVersion        string             `json:"schemaVersion"`
	Kind                 string             `json:"kind"`
	BuilderID            string             `json:"builderID"`
	Buildkite            BuildkiteIdentity  `json:"buildkite"`
	SourceRevision       string             `json:"sourceRevision"`
	ArtifactReference    string             `json:"artifactReference"`
	ArtifactDigest       string             `json:"artifactDigest"`
	EvidenceBundleDigest string             `json:"evidenceBundleDigest"`
	SBOM                 PromotionDocument  `json:"sbom"`
	Provenance           PromotionDocument  `json:"provenance"`
	Signature            PromotionSignature `json:"signature"`
	IssuedAt             string             `json:"issuedAt"`
}

// Validate checks the envelope against the current time.
func (envelope PromotionEnvelope) Validate() error {
	return envelope.ValidateAt(time.Now().UTC())
}

// ValidateAt checks every binding the envelope asserts. Time is injected so the
// freshness window is testable without a clock.
func (envelope PromotionEnvelope) ValidateAt(now time.Time) error {
	if envelope.SchemaVersion != promotionEnvelopeSchemaVersion {
		return fmt.Errorf("unsupported envelope schema %q", envelope.SchemaVersion)
	}
	if envelope.Kind != promotionEnvelopeKind {
		return fmt.Errorf("unsupported envelope kind %q", envelope.Kind)
	}
	if err := envelope.validateBuilder(); err != nil {
		return err
	}
	if err := envelope.validateBuildkite(); err != nil {
		return err
	}
	if !promotionRevisionPattern.MatchString(envelope.SourceRevision) {
		return fmt.Errorf("source revision %q is not a full commit SHA", envelope.SourceRevision)
	}
	// The source binding is the point of the envelope: the build must have been
	// taken from the revision being promoted.
	if envelope.Buildkite.Commit != envelope.SourceRevision {
		return fmt.Errorf(
			"buildkite commit %q does not match source revision %q",
			envelope.Buildkite.Commit, envelope.SourceRevision)
	}
	if strings.TrimSpace(envelope.ArtifactReference) == "" {
		return fmt.Errorf("artifact reference is empty")
	}
	for name, digest := range map[string]string{
		"artifact digest":        envelope.ArtifactDigest,
		"evidence bundle digest": envelope.EvidenceBundleDigest,
		"sbom digest":            envelope.SBOM.Digest,
		"provenance digest":      envelope.Provenance.Digest,
	} {
		if !promotionDigestPattern.MatchString(digest) {
			return fmt.Errorf("%s %q is not a sha256 digest", name, digest)
		}
	}
	for name, document := range map[string]PromotionDocument{
		"sbom":       envelope.SBOM,
		"provenance": envelope.Provenance,
	} {
		if strings.TrimSpace(document.MediaType) == "" {
			return fmt.Errorf("%s media type is empty", name)
		}
	}
	if err := envelope.validateSignature(); err != nil {
		return err
	}
	return envelope.validateFreshness(now)
}

func (envelope PromotionEnvelope) validateBuilder() error {
	for _, fragment := range forbiddenBuilderFragments {
		if strings.Contains(strings.ToLower(envelope.BuilderID), fragment) {
			return fmt.Errorf(
				"builder %q claims a non-Buildkite build system; releases are built on Buildkite",
				envelope.BuilderID)
		}
	}
	if !promotionBuilderPattern.MatchString(envelope.BuilderID) {
		return fmt.Errorf("builder %q is not a Buildkite pipeline identity", envelope.BuilderID)
	}
	return nil
}

func (envelope PromotionEnvelope) validateBuildkite() error {
	identity := envelope.Buildkite
	if identity.Organization != promotionEnvelopeOrganization {
		return fmt.Errorf("buildkite organization %q is not the estate organization", identity.Organization)
	}
	if !promotionPipelinePattern.MatchString(identity.Pipeline) {
		return fmt.Errorf("buildkite pipeline %q is malformed", identity.Pipeline)
	}
	// The builder identity and the recorded pipeline must be the same pipeline.
	if !strings.HasSuffix(envelope.BuilderID, "/"+identity.Pipeline) {
		return fmt.Errorf(
			"builder %q does not identify pipeline %q", envelope.BuilderID, identity.Pipeline)
	}
	if !promotionBuildNumberRegex.MatchString(identity.BuildNumber) {
		return fmt.Errorf("buildkite build number %q is malformed", identity.BuildNumber)
	}
	if !promotionBuildIDPattern.MatchString(identity.BuildID) {
		return fmt.Errorf("buildkite build id %q is malformed", identity.BuildID)
	}
	if !promotionRevisionPattern.MatchString(identity.Commit) {
		return fmt.Errorf("buildkite commit %q is not a full commit SHA", identity.Commit)
	}
	return nil
}

func (envelope PromotionEnvelope) validateSignature() error {
	if envelope.Signature.Algorithm != promotionEnvelopeAlgorithm {
		return fmt.Errorf("unsupported signature algorithm %q", envelope.Signature.Algorithm)
	}
	if !kmsKeyVersionPattern.MatchString(envelope.Signature.KeyVersion) {
		return fmt.Errorf("signature key version %q is not a KMS key version", envelope.Signature.KeyVersion)
	}
	if strings.TrimSpace(envelope.Signature.SignatureBase64) == "" {
		return fmt.Errorf("signature is empty")
	}
	return nil
}

func (envelope PromotionEnvelope) validateFreshness(now time.Time) error {
	issued, err := time.Parse(time.RFC3339, envelope.IssuedAt)
	if err != nil {
		return fmt.Errorf("issuedAt %q is not an RFC3339 timestamp", envelope.IssuedAt)
	}
	issued = issued.UTC()
	if issued.After(now.Add(maxFutureSkew)) {
		return fmt.Errorf("envelope was issued in the future")
	}
	if now.Sub(issued) > maxPromotionEnvelopeAge {
		return fmt.Errorf("envelope is older than the %s verification window", maxPromotionEnvelopeAge)
	}
	return nil
}
