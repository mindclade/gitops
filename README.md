# Mindclade GitOps Control Plane

This repository is the canonical target source for Mindclade's Argo CD-managed
environment state. It consumes immutable infrastructure exports and signed
release evidence; it does not build artifacts, provision Google Cloud
resources, contain credentials, or grant CI direct cluster access.

## Blueprint conformance status

The tracked source matches the governed 142-file `gitops/` tree derived from
`MINDCLADE_MONOREPO_BLUEPRINT_v3.4.3_OPTIMIZED.md` Appendix A3.13 exactly.
That structural result is not implementation qualification. The A3.13
production contract is currently **FAIL**: the repository is pre-production,
`production_authority` is false, and every live path is fail-closed. Platform
Operations owns this repository; Security co-owns its destination, source,
signature, secret-reference, and admission controls.

JIT-05 must ratify the GCP/GKE, deployment-package, policy, secret, and workload
identity boundaries. JIT-09 must ratify release signing, qualification,
promotion, rollback, revocation, and receipt signing. The repository cannot
manufacture those decisions or their connected evidence locally. Wave 5
production authority additionally requires non-production render, promotion,
rollback, drift, failure, rebootstrap, and isolated-recovery qualification.

## Initial state

Development, staging, production, and restricted are deliberately inactive.
Every environment document carries `active: false`, has no cluster destination,
and contains no release. ApplicationSets read the authoritative cluster and
release arrays through fail-closed Git/list matrices; an inactive document or
empty array generates no Application. Activation requires a reviewed
infrastructure export, a registered destination, an immutable desired-state
revision and record digest, signed artifact evidence, and the protected
promotion workflow. Missing evidence is a denial, never a fallback.

Activation is root-first. `cluster-set.yaml` and `infrastructure-exports.yaml`
form an atomic environment-root pair and must activate together. Once that root
is active, platform, service, worker, policy, and secret documents may be staged
independently; activating any of them before the root is invalid. The current
source has no approved service or worker package handoff. The ApplicationSets'
component paths therefore remain dormant. Resolving that boundary requires
JIT-05 ratification and a reviewed canonical-tree update; adding paths that are
absent from Appendix A3.13 would be source drift.

Platform packages, policy bindings, and secret references are contract-only in
this source revision. Each has an explicit `blocked-pending-jit-05` activation
gate, and validation rejects activation until a reviewed deployable platform
package, policy reconciler, or secret materializer replaces the corresponding
gate. Root activation and evidence qualification cannot implicitly activate
any of these independent modules.

The generated environment ConfigMap's `gitops.mindclade.io/activation` label
mirrors only that atomic cluster-set/infrastructure root state. It is not a
summary claiming that all seven environment documents are active. Platform,
service, worker, policy, and secret documents retain their independent staged
states after the root activates.

The mapping is explicit: `cluster-set.yaml` drives the environment-root set;
`platform-releases.yaml`, `service-releases.yaml`, and `worker-releases.yaml`
drive their corresponding sets. Each active list item names its destination and
contains a 40-character `desiredStateRevision`; release items also carry
immutable release-record, promotion-receipt, and governance-evidence digests.
Those record values—not cluster labels or mutable artifact tags—become the
Application source revision and audit annotations.

Every workload release selects exactly one canonical `desiredStatePath`:
`environments/<environment>/services/<component>` for services or
`environments/<environment>/workers/<component>` for workers. Its Application
renders only that path and binds the component image to the release's immutable
artifact with a Kustomize image override. Generated names are globally scoped
with dots: `<environment>.root.<cluster>`,
`<environment>.platform.<cluster>.<component>`,
`<environment>.service.<cluster>.<component>`, or
`<environment>.worker.<cluster>.<component>`.

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

- the protected GitHub environment named `production-promotion`, with the
  `release-engineering` reviewer and distinct-principal/code-owner separation
  declared by `github-config`;
- repository variable `CONNECTED_GOVERNANCE_READY=true`, set only after branch
  protection, required checks, merge-queue behavior, and environment rules are
  qualified;
- `production-promotion`-scoped `PROMOTION_GOVERNANCE_EVIDENCE` containing the
  immutable `sha256:` digest of that qualification evidence;
- environment-scoped `PROMOTION_TRUSTED_SIGNER` and
  `PROMOTION_TRUSTED_ISSUER` identities, controlled with the same protected
  environment review rules;
- protected `PROMOTION_TRUSTED_BUILDER`, `PROMOTION_TRUSTED_KMS_KEY_VERSION`,
  `PROMOTION_VULNERABILITY_POLICY_DIGEST`, and versioned public-key material;
- a private HTTPS evidence gateway bound through
  `PROMOTION_EVIDENCE_BASE_URL` and `PROMOTION_EVIDENCE_AUDIENCE` that accepts
  only the job's short-lived GitHub OIDC token; and
- `PROMOTION_JIT09_QUALIFICATION=qualified-v1`, set only after independent
  forged-signature, wrong-subject, stale-evidence, IAM-denial, and tamper tests;
- a digest-pinned Argo CD bootstrap, a qualified External Secrets Operator and
  secret store, registered Argo cluster credentials, and explicit AppProject
  destination allowlists; and
- matching `InfrastructureExport` records from `infrastructure-live`, including
  the admitted cluster membership and immutable plan/schema evidence.

Until then, AppProject destinations remain empty, all environment arrays remain
inactive, and the ApplicationSets emit zero Applications.

The manual promotion and rollback dispatch surfaces accept only `production`
and bind directly to `production-promotion`, the sole protected promotion
environment in the current governance catalog. That restriction grants no
production authority. The `source-ready-unqualified-jit09-v1`
evidence-verifier gate checks a canonical ECDSA P-256 envelope against the
protected Cloud KMS key version, exact
artifact/source/Buildkite identities, SLSA v1 provenance, SPDX 2.3 SBOM, all six
dependency ecosystems, and the vulnerability-policy decision. Both workflows
still exit without creating completion evidence, and source validation rejects
every active environment until connected qualification is independently
reviewed. Setting repository or environment variables alone cannot bypass the
cryptographic, subject, freshness, document-digest, or desired-state gates.

## Local validation

Required entry points are read-only with respect to repositories, clusters, and
cloud accounts:

```sh
nix build --no-accept-flake-config --no-link --no-update-lock-file .#toolchain
nix flake check --no-accept-flake-config --no-update-lock-file
nix develop --no-accept-flake-config --no-update-lock-file .#ci --command just validate
nix develop --no-accept-flake-config --no-update-lock-file .#ci --command just render development
nix develop --no-accept-flake-config --no-update-lock-file .#ci --command just verify-bootstrap
nix develop --no-accept-flake-config --no-update-lock-file .#ci --command just bazel-test
```

The root developer-quality interface is `just format`, `just format-check`,
`just lint`, and `just check`. Formatting is limited to handwritten source and
configuration; rendered or downloaded material and evidence remain under their
owning commands.

Pull requests and merge groups are qualified by the organization-required
workflow at the immutable `.github` policy revision. Its stable context remains
`Pull request / required`. The repository-local qualification workflow runs
only on protected `main` and manual dispatch, so it cannot create a competing
required-check context or cancel merge-queue qualification.

`flake.lock` is the system-tool supply-chain authority for Linux x86-64 and
Apple Silicon. The `packages.toolchain`, `devShells.default`, `devShells.ci`,
`formatter`, and `checks.toolchain` outputs use one reviewed package set. Go
modules remain owned by `tooling/go.mod` and `tooling/go.sum`; Bazel modules,
toolchains, and action inputs remain owned by `MODULE.bazel` and BUILD files.
Nix pins the tools that execute those native dependency graphs and does not
replace them. Lock updates are isolated changes; normal checks always use
`--no-update-lock-file`.

`just render` writes canonical JSON to standard output. `just validate` renders
the checksum-pinned Argo overlay, checks Kubernetes schemas, digest-only images,
Rego, strict JSON Schemas, and the exact source tree. `verify-bootstrap`
downloads the commit-pinned upstream Argo CD manifest and verifies its declared
SHA-256. `just bazel-test` uses Bazel 9.1.1 from the Nix toolchain and enforces
the committed `MODULE.bazel.lock` without updating it. Nothing in these commands
connects to a cluster or promotes a release.

Remote Bazel execution and remote caching are intentionally disabled. They may
be enabled only for workers with the exact reviewed Nix store paths or an
immutable, digest-pinned image built from this toolchain closure.

The canonical bootstrap is checked as Kubernetes 1.34 and the Argo namespace
pins restricted Pod Security admission enforcement, audit, and warning to
`v1.34` rather than a moving `latest` target.

A local or CI source `PASS` proves only those source contracts. It is not proof
that a cluster exists, GitHub protection is configured, reviewers approved an
operation, ESO can resolve credentials, Argo reconciled successfully, or live
governance is qualified.

The scheduled drift workflow is currently a source-contract and pinned-upstream
integrity preflight. It has no cluster credentials and does not perform a live
object comparison. Live drift qualification remains a connected activation
preflight and must not be inferred from its result.

## Operational runbooks

- [Argo CD unavailable](runbooks/argocd-unavailable.md)
- [Cluster rebootstrap](runbooks/cluster-rebootstrap.md)
- [Compromised release](runbooks/compromised-release.md)
- [Deployment drift](runbooks/deployment-drift.md)
- [Emergency rollback](runbooks/emergency-rollback.md)
- [Failed synchronization](runbooks/failed-synchronization.md)

## Promotion contract

The current production-only promotion and rollback workflows are source gates,
not operational promotion implementations. They validate immutable input
grammar and the requested prior/current digest against the exact component,
cluster, and release class in the checked-out production record, require the
connected JIT-09 qualification gate, acquire a short-lived OIDC credential,
and verify the complete signed Buildkite evidence set. They neither write
desired state nor emit a promotion or rollback receipt.

The `promotectl receipt` and `promotectl rollback` commands validate the current
v1 receipt payload contract for source testing only. A blueprint-authoritative
receipt must instead be produced after a protected desired-state commit merges,
Argo reconciles it, and observed sync and health succeed; it must be signed and
linked to that Git commit and the subject digests. Until the live observer and
receipt signer are connected and qualified, no command or workflow in this
repository may label a pre-merge payload as completion evidence.

`GitOpsPromotionEnvelope/v1`
(`schemas/v1/gitops_promotion_envelope.schema.json`, validated by
`tooling/internal/evidence/promotion_envelope.go`) binds a released artifact to
the Buildkite build that produced it: the build number and identifier, the
source revision, the OCI digest, the evidence-bundle digest, and the SBOM,
provenance and signature bound by digest and media type.

The envelope is a verification record, not an authority. Validating one proves a
named Buildkite build produced a named artifact from a named revision. It never
rebuilds, never deploys, and never asserts that GitHub Actions performed the
build. Releases are produced on Buildkite, so a builder identity naming
`github.com`, `githubusercontent.com`, or `actions/runner` is rejected outright,
and the builder must name the same pipeline the Buildkite identity records. The
source binding is the point of the envelope, so the Buildkite commit must equal
the source revision even when both are well formed.

## Tracked implementation blockers

- [#1](https://github.com/mindclade/gitops/issues/1): connected qualification
  of the source-ready signed evidence verifier and post-sync receipt observer.
- [#2](https://github.com/mindclade/gitops/issues/2): component-scoped workload
  package handoff.
- [#4](https://github.com/mindclade/gitops/issues/4): digest-bound deployable
  platform packages.
- [#5](https://github.com/mindclade/gitops/issues/5): policy and secret
  materialization.
- [#6](https://github.com/mindclade/gitops/issues/6): live drift, observed Argo
  health, and durable signed evidence.
- [#8](https://github.com/mindclade/gitops/issues/8): A3.8 thin, pinned reusable
  workflow callers.
- [#9](https://github.com/mindclade/gitops/issues/9): ReleaseManifest-bound,
  stale-base-safe candidate promotion and rollback transitions.
