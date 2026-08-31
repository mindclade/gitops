# Contributing

Platform Operations owns desired state; Security co-owns destination, source,
signature, secret-reference, and admission policy. Changes must preserve Git as
the sole desired-state authority.

Use the repository-root commands from the pinned Nix shell:

```text
just format
just format-check
just lint
just check
```

`just format` edits only handwritten source and configuration. Rendered or
downloaded manifests, distribution output, receipts, and other evidence remain
under their owning commands. Lint suppressions must name the exact rule and
explain why the exception is safe.

Pyright is strict by default. Existing dynamic YAML, JSON, and release-contract
modules carry an explicit file-level `basic` migration directive with only the
named dynamic checks disabled; newly added Python modules inherit strict
checking.

Passing local checks proves source qualification only. It does not qualify a
cluster, Argo CD reconciliation, promotion, rollback, or production state.
