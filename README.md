# Mindclade GitOps Control Plane

This repository is the canonical target source for Mindclade's Argo CD-managed
environment state. It consumes immutable infrastructure exports and signed
release evidence; it does not build artifacts, provision Google Cloud
resources, contain credentials, or grant CI direct cluster access.

## Blueprint conformance status

The tracked source matches the 126-file `gitops/` tree in
`MINDCLADE_MONOREPO_BLUEPRINT_v3.4.0_OPTIMIZED.md` Appendix A3.13 exactly.
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

- protected GitHub environments named `<environment>-promotion`, with required
  reviewer rules for `release-engineering`, `platform-operations`, and
  `security` as applicable to the release unit;
- repository variable `CONNECTED_GOVERNANCE_READY=true`, set only after branch
  protection, required checks, merge-queue behavior, and environment rules are
  qualified;
- environment-scoped `PROMOTION_GOVERNANCE_EVIDENCE` containing the immutable
  `sha256:` digest of that qualification evidence in every environment,
  including development and staging;
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

The initial source carries a `blocked-pending-jit-09` evidence-verifier gate.
Both protected workflows exit without creating completion evidence, and source
validation rejects every active environment, until a reviewed change adds and
qualifies actual cryptographic signature/attestation verification. Setting
repository or environment variables alone cannot bypass this code-level gate.

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
SHA-256. `just bazel-test` selects Bazel 9.2.0 through Bazelisk. Nothing in these
commands connects to a cluster or promotes a release.

The canonical Bazel recipe and CI deliberately pass `--lockfile_mode=off` because
the current authoritative 126-file blueprint does not include
`MODULE.bazel.lock`. A direct default Bzlmod command can generate that untracked
audit byproduct and make exact-tree validation fail. Use `just bazel-test` for
blueprint-conformant checks; do not interpret the lockfile exception as a claim
that unpinned Bazel versions are acceptable.

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

The current promotion and rollback workflows are pre-production gates, not
operational promotion implementations. They validate immutable input grammar
and the requested prior/current digest against the exact component, cluster,
and release class in the checked-out environment record, then stop at JIT-09.
They neither write desired state nor emit a promotion or rollback receipt.

The `promotectl receipt` and `promotectl rollback` commands validate the current
v1 receipt payload contract for source testing only. A blueprint-authoritative
receipt must instead be produced after a protected desired-state commit merges,
Argo reconciles it, and observed sync and health succeed; it must be signed and
linked to that Git commit and the subject digests. Until JIT-09 defines and
qualifies that signed envelope and the live observer, no command or workflow in
this repository may label a pre-merge payload as completion evidence.

## Tracked implementation blockers

- [#1](https://github.com/mindclade/gitops/issues/1): authoritative signed
  ReleaseManifest and evidence verification.
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
