# Argo CD unavailable

## Trigger

Use this runbook when the Argo API/UI or reconciliation controllers are
unavailable. A source check alone is not proof of cluster health.

## Containment

1. Declare the incident and assign Incident Command and Platform owners.
2. Freeze promotion workflows; do not disable policy, widen AppProjects, enable
   local admin, or distribute kubeconfigs.
3. Preserve the failing Git revision, controller events, and non-secret logs.
4. Confirm whether the failure is DNS, identity, API reachability, controller
   availability, repository access, or an invalid desired-state revision.

## Recovery

Recover through the protected cluster access path. Compare the deployed Argo CD
revision and SHA-256 with `controllers/argocd/kustomization.yaml`; restore only
the reviewed payload. Reconcile the last known-good Git commit without pruning,
then verify projects, RBAC, the inactive credential-binding contract, and all
ApplicationSets before unfreezing promotions. If a credential binding had been
activated, independently verify ESO and store readiness first.

## Exit evidence

Record incident ID, source commit, upstream checksum, controller health,
repository connectivity, reconciliation result, and approving owners. Never
copy tokens, Secret data, or kubeconfigs into the record.
