# Failed synchronization

Owner: `@mindclade/platform-operations`
Last reviewed: `2026-08-30`

## Trigger

Use this runbook when an Argo Application reports `Failed`, `Error`, degraded
health, or an incomplete sync wave.

## Procedure

1. Freeze further promotion for the affected environment and release class.
2. Identify the immutable Git revision, artifact digest, configuration digest,
   sync wave, and first failing resource. Ignore cascading errors until the
   earliest failure is understood.
3. Classify the failure as render/schema, policy denial, missing external
   secret, destination authorization, admission failure, health timeout, or
   runtime regression.
4. Correct desired state in Git or invoke the reviewed previous-digest rollback.
   Do not use force sync, ad-hoc live edits, blanket prune, or policy bypass.
5. Reconcile only after required checks and protected approval succeed.

## Verification

Verify the application revision and digest, resource health, policy results,
rollout SLOs, and absence of unexpected deletions. If an ExternalSecret binding
has been activated, verify ESO and store readiness without viewing references
or payloads. Attach the non-secret comparison and rollback receipt to the
incident or change record.
