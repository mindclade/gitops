# Cluster rebootstrap

Owner: `@mindclade/platform`
Last reviewed: `2026-08-30`

## Authority boundary

Infrastructure Live restores the cluster, network, identities, and External
Secrets prerequisites. This repository restores Argo CD and in-cluster desired
state. Neither repository silently takes ownership of the other's resources.

## Preconditions

- A reviewed infrastructure export identifies the rebuilt cluster and immutable
  source commit.
- The Argo CD upstream revision and SHA-256 in the controller Kustomization pass
  `just verify-bootstrap`.
- Repository and SSO credentials exist in the approved external secret store.
- AppProject destinations remain empty until the new cluster identity is
  independently verified and explicitly reviewed.

## Sequence

1. Platform operators install the checksummed Argo payload through the protected
   bootstrap path; never use a moving release URL.
2. Reconcile namespace, strict configuration, the inactive credential-binding
   contract, projects, and ApplicationSets. Confirm local admin and anonymous
   access remain disabled. Activate ExternalSecret bindings only after ESO and
   its reviewed store are independently ready.
3. Bind the exact cluster destination and 40-character desired-state revision.
4. Activate one non-production environment root without prune, verify health and
   drift, then proceed through staged protected promotions.
5. Production and restricted require separate evidence and approval; they are
   never inferred active from development success.

## Completion evidence

Retain infrastructure export digest, cluster identity, upstream checksum, Git
revision, RBAC verification, secret-reference readiness, policy results,
environment activation receipt, restore timing, and rollback test.
