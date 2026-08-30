## Change intent

Describe the desired-state, policy, tooling, or runbook change and its owner.

## Authority and evidence

- [ ] The change stays within GitOps authority and creates no cloud resource.
- [ ] Every release reference is an immutable `sha256:` digest.
- [ ] No plaintext secret, kubeconfig, token, private key, or partner data appears.
- [ ] Infrastructure exports identify an immutable source commit.
- [ ] Every activated or changed release references its protected promotion receipt and immutable governance evidence.
- [ ] Production/restricted rollout and rollback evidence is attached when applicable.

## Validation

- [ ] `nix flake check --no-update-lock-file`
- [ ] `nix develop --no-update-lock-file .#ci --command just validate`
- [ ] `nix develop --no-update-lock-file .#ci --command just bazel-test`
- [ ] Deterministic render checked for every affected environment.
- [ ] Upstream bootstrap checksum checked when Argo CD provenance changed.

## Rollback

Identify the prior digest or desired-state commit and the verification performed.
