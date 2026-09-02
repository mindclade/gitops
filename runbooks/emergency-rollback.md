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
3. Confirm that source validation reaches the fail-closed JIT-09 qualification gate, then
   stop. The current workflow does not change desired state, reconcile Argo CD,
   emit a rollback receipt, or prove recovery.

## Failure path

If prior evidence is invalid, the environment is inactive, connected governance
is unavailable, or the workflow stops at JIT-09 as designed, record the attempt
as blocked. Use the independently authorized cluster recovery path to suspend
service safely, then reconstruct every action in Git.

## Exit evidence

Before JIT-09 is connected and qualified, capture the incident ID, current and
previous digests, source revision, attestation digest, and protected approval
record only as incident working records. They are not a rollback receipt, sync
result, SLO verification, or recovery evidence.
