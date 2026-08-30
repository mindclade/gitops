package rollback

import "github.com/mindclade/gitops/tooling/internal/evidence"

type Request struct {
	Environment        string
	ReleaseClass       string
	Component          string
	Cluster            string
	SourceRevision     string
	ArtifactReference  string
	CurrentDigest      string
	PreviousDigest     string
	AttestationDigest  string
	Signer             string
	Issuer             string
	IssuedAt           string
	Approvals          []string
	Repository         string
	WorkflowRunID      string
	WorkflowRunAttempt string
	CheckedOutRevision string
	Requester          string
}

func Receipt(request Request) (evidence.Receipt, error) {
	receipt := evidence.Receipt{
		SchemaVersion:      "v1",
		Action:             "rollback",
		Environment:        request.Environment,
		ReleaseClass:       request.ReleaseClass,
		Component:          request.Component,
		Cluster:            request.Cluster,
		SourceRevision:     request.SourceRevision,
		ArtifactReference:  request.ArtifactReference,
		ArtifactDigest:     request.PreviousDigest,
		PriorDigest:        request.CurrentDigest,
		AttestationDigest:  request.AttestationDigest,
		Signer:             request.Signer,
		Issuer:             request.Issuer,
		IssuedAt:           request.IssuedAt,
		Approvals:          request.Approvals,
		Repository:         request.Repository,
		WorkflowRunID:      request.WorkflowRunID,
		WorkflowRunAttempt: request.WorkflowRunAttempt,
		CheckedOutRevision: request.CheckedOutRevision,
		Requester:          request.Requester,
	}
	return receipt, receipt.Validate()
}
