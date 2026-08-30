# Emergency rollback

Owner: `@mindclade/platform-operations`
Last reviewed: `2026-08-30`

## Preconditions

Emergency urgency does not permit mutable tags, missing evidence, plaintext
secrets, direct CI cluster credentials, or disabling admission controls. Obtain
Incident Command, Release, Platform, and Security authorization through the
protected environment.

## Procedure

1. Freeze new promotions and identify the current and previous immutable
   artifact digests plus their source and evidence digests.
2. Run the rollback-verification workflow on `main`. Its connected-governance
   preflight must pass and its protected environment must approve execution.
3. Review the emitted receipt checksum. Commit the previous digest and receipt
   reference through the normal Git review path.
4. Reconcile without broad prune. Observe health, correctness, safety, latency,
   and dependent queues before declaring recovery.

## Failure path

If prior evidence is invalid, the environment is inactive, or connected
governance is unavailable, stop. Use the independently authorized cluster
recovery path to suspend service safely, then reconstruct every action in Git.

## Exit evidence

Capture incident ID, current and previous digests, source revision, attestation
digest, protected approval record, Git commit, sync result, and SLO verification.
