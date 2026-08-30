# Deployment drift

Owner: `@mindclade/platform`
Last reviewed: `2026-08-30`

## Scope

Drift is any live object difference not explained by declared desired state,
approved controller mutation, or an explicitly ignored non-authoritative field.

## Procedure

1. Freeze promotions for the affected project; do not automatically prune.
2. Capture the application, desired Git revision, live resource identity,
   managed fields, and redacted diff.
3. Determine whether drift came from emergency access, a controller default,
   compromised credentials, a failed sync, or an invalid ignore rule.
4. If Git is correct, use the protected Argo reconciliation path. If the live
   state is the approved recovery state, reconstruct it in Git first and review
   the resulting diff.
5. Treat unauthorized drift in Argo RBAC, projects, repository credentials,
   policy controllers, admission webhooks, or release digests as a security
   incident.

## Closure

Evidence must identify owner, root cause, affected interval, objects, reviewed
commit, reconciliation outcome, and any new prevention test. Secret payloads and
kubeconfigs are excluded from evidence.
