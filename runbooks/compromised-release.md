# Compromised release

## Immediate actions

1. Declare a security incident and freeze the affected digest across every
   environment. Do not rebuild under the same identity.
2. Preserve signature, provenance, SBOM, vulnerability, evaluation, promotion,
   and deployment evidence without fetching or exposing protected payloads.
3. Revoke or suspend the compromised signer through its owning security system;
   GitOps does not rotate keys.
4. Identify every desired-state record and live Application admitting the
   digest, including canaries and rollback histories.

## Recovery

Select a previously verified digest with intact evidence and follow
`emergency-rollback.md`. If no safe digest exists, suspend the workload rather
than admit an unsigned rebuild. Product CI must issue a new artifact digest and
complete evidence chain before normal promotion resumes.

## Closure

Record affected digests, signer identity, source revisions, environments,
containment times, rollback receipts, and verification results. Add policy or
contract tests for the failed control and recertify the protected promotion
environment before unfreezing.
