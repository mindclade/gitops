# Mindclade GitOps Control Plane

This repository is the sole source of desired in-cluster state for Mindclade's
Argo CD-managed environments. It consumes immutable infrastructure exports and
signed release evidence; it does not build artifacts, provision Google Cloud
resources, contain credentials, or grant CI direct cluster access.

## Initial state

Development, staging, production, and restricted are deliberately inactive.
Every environment document carries `active: false`, has no cluster destination,
and contains no release. ApplicationSets read the authoritative cluster and
release arrays through fail-closed Git/list matrices; an inactive document or
empty array generates no Application. Activation requires a reviewed
infrastructure export, a registered destination, an immutable desired-state
revision and record digest, signed artifact evidence, and the protected
promotion workflow. Missing evidence is a denial, never a fallback.

The mapping is explicit: `cluster-set.yaml` drives the environment-root set;
`platform-releases.yaml`, `service-releases.yaml`, and `worker-releases.yaml`
drive their corresponding sets. Each active list item names its destination and
contains a 40-character `desiredStateRevision`; release items also carry
immutable release-record, promotion-receipt, and governance-evidence digests.
Those record values—not cluster labels or mutable artifact tags—become the
Application source revision and audit annotations.

## Authority boundary

- `infrastructure-live` creates cloud and cluster prerequisites and publishes
  schema-validated exports.
- This repository owns Argo CD configuration, AppProjects, ApplicationSets,
  environment desired state, digest promotion, and rollback evidence.
- Product CI builds and signs artifacts. GitOps only admits their immutable
  `sha256:` identities.
- The initial Argo credential file is an inactive, non-secret binding contract.
  External Secrets Operator may resolve credentials only after ESO and a
  reviewed SecretStore or ClusterSecretStore are qualified and that contract is
  replaced with an approved ExternalSecret binding. Secret values,
  service-account keys, kubeconfigs, and Argo admin tokens are forbidden.

## Connected activation prerequisites

Source activation is blocked until all of the following exist and have been
reviewed outside this repository:

- protected GitHub environments named `<environment>-promotion`, with required
  reviewer rules for the owning `release`, `platform`, and `security` teams;
- repository variable `CONNECTED_GOVERNANCE_READY=true`, set only after branch
  protection, required checks, merge-queue behavior, and environment rules are
  qualified;
- environment-scoped `PROMOTION_GOVERNANCE_EVIDENCE` containing the immutable
  `sha256:` digest of that qualification evidence;
- environment-scoped `PROMOTION_TRUSTED_SIGNER` and
  `PROMOTION_TRUSTED_ISSUER` identities, controlled with the same protected
  environment review rules;
- a digest-pinned Argo CD bootstrap, a qualified External Secrets Operator and
  secret store, registered Argo cluster credentials, and explicit AppProject
  destination allowlists; and
- matching `InfrastructureExport` records from `infrastructure-live`, including
  the admitted cluster membership and immutable plan/schema evidence.

Until then, AppProject destinations remain empty, all environment arrays remain
inactive, and the ApplicationSets emit zero Applications.

The initial source also contains a literal `unbound` evidence-verifier
implementation marker. Both workflows exit before receipt creation, and source
validation rejects every active environment, until a reviewed change adds
actual cryptographic signature/attestation verification. Setting repository or
environment variables alone cannot bypass this code-level activation blocker.

## Local validation

Required entry points are read-only with respect to repositories, clusters, and
cloud accounts:

```sh
just validate
just render development
just verify-bootstrap
just bazel-test
```

`just render` writes canonical JSON to standard output. `just validate` renders
the checksum-pinned Argo overlay, checks Kubernetes schemas, digest-only images,
Rego, strict JSON Schemas, and the exact source tree. `verify-bootstrap`
downloads the commit-pinned upstream Argo CD manifest and verifies its declared
SHA-256. Nothing in these commands connects to a cluster or promotes a release.
The canonical bootstrap is checked as Kubernetes 1.34 and the Argo namespace
pins restricted Pod Security admission enforcement, audit, and warning to
`v1.34` rather than a moving `latest` target.

A local or CI source `PASS` proves only those source contracts. It is not proof
that a cluster exists, GitHub protection is configured, reviewers approved an
operation, ESO can resolve credentials, Argo reconciled successfully, or live
governance is qualified.

## Promotion contract

Promotion and rollback run only after a fail-closed connected-governance
preflight and the required reviewers on `<environment>-promotion`. Before the
source-level verifier blocker, tooling proves the requested prior/current
digest against the exact component, cluster, and release class in the
checked-out environment record. A receipt separately binds the artifact source
revision and immutable artifact reference from product CI to the checked-out
GitOps revision (`GITHUB_SHA`), plus the attestation, protected-environment
signer and issuer, fresh UTC issuance time, repository, workflow run and
attempt, and requester. These two revisions are intentionally not conflated.
The workflow retains the validated non-secret receipt for 90 days under an
environment/run/attempt-specific artifact name. Desired-state release records
reference the receipt and governance evidence by digest. Automation does not
write desired state or contact a cluster; an approved source change remains a
separate reviewed action.
