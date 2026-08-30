package evidence

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mindclade/gitops/tooling/internal/release"
)

const (
	maxReceiptAge = 24 * time.Hour
	maxFutureSkew = 5 * time.Minute
)

var (
	positiveIntegerPattern = regexp.MustCompile(`^[1-9][0-9]*$`)
	requesterPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.\-\[\]]{0,127}$`)
	componentPattern       = regexp.MustCompile(`^[a-z][a-z0-9-]{2,62}$`)
)

type Receipt struct {
	SchemaVersion      string   `json:"schemaVersion"`
	Action             string   `json:"action"`
	Environment        string   `json:"environment"`
	ReleaseClass       string   `json:"releaseClass"`
	Component          string   `json:"component"`
	Cluster            string   `json:"cluster"`
	SourceRevision     string   `json:"sourceRevision"`
	ArtifactReference  string   `json:"artifactReference"`
	ArtifactDigest     string   `json:"artifactDigest"`
	PriorDigest        string   `json:"priorDigest"`
	AttestationDigest  string   `json:"attestationDigest"`
	Signer             string   `json:"signer"`
	Issuer             string   `json:"issuer"`
	IssuedAt           string   `json:"issuedAt"`
	Approvals          []string `json:"approvals"`
	Repository         string   `json:"repository"`
	WorkflowRunID      string   `json:"workflowRunID"`
	WorkflowRunAttempt string   `json:"workflowRunAttempt"`
	CheckedOutRevision string   `json:"checkedOutRevision"`
	Requester          string   `json:"requester"`
}

func (receipt Receipt) Validate() error {
	return receipt.ValidateAt(time.Now().UTC())
}

func (receipt Receipt) ValidateAt(now time.Time) error {
	if receipt.SchemaVersion != "v1" {
		return fmt.Errorf("unsupported receipt schema %q", receipt.SchemaVersion)
	}
	if receipt.Action != "promote" && receipt.Action != "rollback" {
		return fmt.Errorf("unsupported receipt action %q", receipt.Action)
	}
	if !release.ValidEnvironment(receipt.Environment) {
		return fmt.Errorf("unknown environment %q", receipt.Environment)
	}
	if receipt.ReleaseClass != "platform" && receipt.ReleaseClass != "service" && receipt.ReleaseClass != "worker" {
		return fmt.Errorf("unknown release class %q", receipt.ReleaseClass)
	}
	if !componentPattern.MatchString(receipt.Component) || !componentPattern.MatchString(receipt.Cluster) {
		return fmt.Errorf("component and cluster must be canonical identifiers")
	}
	if err := release.ValidateRevision(receipt.SourceRevision); err != nil {
		return err
	}
	for label, digest := range map[string]string{
		"artifact":    receipt.ArtifactDigest,
		"prior":       receipt.PriorDigest,
		"attestation": receipt.AttestationDigest,
	} {
		if err := release.ValidateDigest(digest); err != nil {
			return fmt.Errorf("%s digest: %w", label, err)
		}
	}
	if receipt.ArtifactDigest == receipt.PriorDigest {
		return fmt.Errorf("artifact and prior digests must differ")
	}
	if !strings.HasSuffix(receipt.ArtifactReference, "@"+receipt.ArtifactDigest) || strings.ContainsAny(receipt.ArtifactReference, " \r\n\t") {
		return fmt.Errorf("artifact reference must end in its immutable digest")
	}
	if !safeHTTPSIdentity(receipt.Signer) {
		return fmt.Errorf("signer must be an HTTPS workload identity URI")
	}
	if !safeHTTPSIdentity(receipt.Issuer) {
		return fmt.Errorf("issuer must be an HTTPS identity provider URI")
	}
	issuedAt, err := time.Parse(time.RFC3339, receipt.IssuedAt)
	if err != nil || !strings.HasSuffix(receipt.IssuedAt, "Z") || issuedAt.Format(time.RFC3339) != receipt.IssuedAt {
		return fmt.Errorf("issuedAt must be canonical RFC3339 UTC")
	}
	now = now.UTC()
	if issuedAt.After(now.Add(maxFutureSkew)) {
		return fmt.Errorf("issuedAt exceeds the five-minute future-skew allowance")
	}
	if issuedAt.Before(now.Add(-maxReceiptAge)) {
		return fmt.Errorf("receipt evidence is older than 24 hours")
	}
	if receipt.Repository != "mindclade/gitops" {
		return fmt.Errorf("receipt repository must be mindclade/gitops")
	}
	if !positiveIntegerPattern.MatchString(receipt.WorkflowRunID) || !positiveIntegerPattern.MatchString(receipt.WorkflowRunAttempt) {
		return fmt.Errorf("workflow run ID and attempt must be positive integers")
	}
	if err := release.ValidateRevision(receipt.CheckedOutRevision); err != nil {
		return fmt.Errorf("checked-out revision: %w", err)
	}
	if !requesterPattern.MatchString(receipt.Requester) {
		return fmt.Errorf("requester must be a nonempty workflow actor")
	}
	unique := map[string]bool{}
	for _, approval := range receipt.Approvals {
		approval = strings.TrimSpace(approval)
		if approval != "" {
			unique[approval] = true
		}
	}
	if len(unique) < 2 {
		return fmt.Errorf("at least two distinct approval records are required")
	}
	if receipt.Environment == "production" || receipt.Environment == "restricted" {
		contextPrefix := "github-environment:" + receipt.Environment + "-promotion"
		hasContext := false
		hasGovernanceEvidence := false
		for approval := range unique {
			if approval == contextPrefix {
				hasContext = true
			}
			if strings.HasPrefix(approval, "governance-evidence:") && release.ValidateDigest(strings.TrimPrefix(approval, "governance-evidence:")) == nil {
				hasGovernanceEvidence = true
			}
		}
		if !hasContext || !hasGovernanceEvidence {
			return fmt.Errorf("protected promotion requires environment context and immutable governance evidence")
		}
	}
	return nil
}

func safeHTTPSIdentity(raw string) bool {
	identity, err := url.Parse(raw)
	return err == nil && identity.Scheme == "https" && identity.Host != "" && identity.User == nil && identity.RawQuery == "" && !identity.ForceQuery && identity.Fragment == "" && strings.TrimSpace(raw) == raw
}
