# Security policy

Report suspected vulnerabilities or control-plane compromise through GitHub
private vulnerability reporting or an approved private Mindclade security
channel. Do not open a public issue or include credentials, secret payloads,
partner data, restricted biological data, kubeconfigs, or production logs in a
report.

## Security invariants

- Argo CD local admin and anonymous access remain disabled.
- Human access is group-mapped to current Mindclade teams and defaults to deny.
- Repository and SSO credentials may be activated only through reviewed
  ExternalSecret references after ESO and a store are qualified; the initial
  binding contract is inactive and contains neither store nor remote-key names.
  This repository never contains credential values.
- Production and restricted releases use immutable `sha256:` digests with
  signed provenance, SBOM, vulnerability, approval, and rollback evidence.
- GitHub workflows have read-only source permissions and no cloud or cluster
  credentials. They validate evidence but cannot deploy.
- Emergency action follows the protected runbooks and is reconstructed in Git
  immediately after containment.

If a secret is discovered, stop validation, preserve minimal non-secret evidence,
notify Security, revoke it through its owning system, and purge it from Git
history using the separately approved incident process.
