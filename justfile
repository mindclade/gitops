set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

toolchain:
    nix build --no-accept-flake-config --no-link --no-update-lock-file .#toolchain

nix-validate:
    nix flake check --no-accept-flake-config --no-update-lock-file
    nix develop --no-accept-flake-config --no-update-lock-file .#ci --command just check
    nix develop --no-accept-flake-config --no-update-lock-file .#ci --command just bazel-test

format:
    biome check --write .
    ruff format .
    cd tooling && golangci-lint fmt --config ../.golangci.yml
    opa fmt -w policy
    git ls-files 'BUILD.bazel' 'MODULE.bazel' '*.bzl' | xargs buildifier -mode=fix
    nixfmt flake.nix
    just --fmt

format-check:
    biome check .
    ruff format --check .
    cd tooling && golangci-lint fmt --config ../.golangci.yml --diff
    opa fmt --fail policy >/dev/null
    git ls-files 'BUILD.bazel' 'MODULE.bazel' '*.bzl' | xargs buildifier -mode=check -lint=warn
    nixfmt --check flake.nix
    just --fmt --check

fmt-check: format-check

lint:
    biome lint .
    ruff check .
    pyright
    cd tooling && golangci-lint run --config ../.golangci.yml ./...
    actionlint .github/workflows/*.yml
    zizmor --no-progress --offline .github/workflows/*.yml
    yamllint --config-file .yamllint.yaml .
    markdownlint-cli2

go-test:
    cd tooling && go test ./...

python-test:
    while IFS= read -r test_file; do python3 "$test_file"; done < <(find tests -type f -name 'test_*.py' | sort)

policy-test:
    if command -v opa >/dev/null; then opa test policy; elif command -v conftest >/dev/null; then conftest verify --policy policy; else echo 'opa or conftest is required' >&2; exit 1; fi

bootstrap-check:
    #!/usr/bin/env bash
    set -euo pipefail
    command -v kustomize >/dev/null
    command -v kubeconform >/dev/null
    (cd tooling && go run ./cmd/promotectl verify-bootstrap --root .. --fetch)
    render_dir=$(mktemp -d)
    trap 'rm -rf "$render_dir"' EXIT
    render_file="$render_dir/bootstrap.yaml"
    kustomize build --load-restrictor=LoadRestrictionsNone controllers/argocd > "$render_file"
    kubeconform -strict -summary -ignore-missing-schemas -kubernetes-version 1.34.0 "$render_file"
    (cd tooling && go run ./cmd/promotectl validate-bootstrap --file "$render_file")
    test "$(awk '$0 == "kind: Application" {n++} END {print n+0}' "$render_file")" = 0
    test "$(awk '$0 == "kind: ApplicationSet" {n++} END {print n+0}' "$render_file")" = 4
    test "$(awk '$0 == "kind: ExternalSecret" {n++} END {print n+0}' "$render_file")" = 0
    awk '/^[[:space:]]*image:/ {seen++; if ($2 !~ /@sha256:[0-9a-f]{64}$/) bad=1} END {exit !(seen > 0 && !bad)}' "$render_file"
    if command -v conftest >/dev/null; then
      conftest test "$render_file" --policy policy --namespace mindclade.gitops.secret_reference
    elif command -v opa >/dev/null; then
      mkdir "$render_dir/objects"
      csplit -s -f "$render_dir/objects/object-" "$render_file" '/^---$/' '{*}'
      while IFS= read -r object_file; do
        test "$(opa eval --format raw --data policy/secret_reference.rego --input "$object_file" 'count(data.mindclade.gitops.secret_reference.deny)')" = 0
      done < <(find "$render_dir/objects" -type f -size +0c | sort)
    else
      echo 'opa or conftest is required' >&2
      exit 1
    fi

lint-ci:
    actionlint .github/workflows/*.yml
    zizmor --no-progress --offline .github/workflows/*.yml

validate-source:
    cd tooling && go run ./cmd/promotectl validate --root ..

flake-check:
    nix flake check --no-accept-flake-config --no-build --no-update-lock-file

test: go-test python-test policy-test bootstrap-check bazel-test

# Vulnerability scan of declared dependencies. Requires network access to the
# OSV database, so it is deliberately separate from the hermetic lint recipe.
security:
    osv-scanner scan source --recursive .

check: format-check lint validate-source test security flake-check

validate: check

ci: check

render environment:
    cd tooling && go run ./cmd/promotectl render --root .. --environment {{ environment }}

verify-bootstrap:
    cd tooling && go run ./cmd/promotectl verify-bootstrap --root .. --fetch

bazel-test:
    @bazel_args=(); if test -n "${MACOSX_DEPLOYMENT_TARGET:-}"; then bazel_args+=("--repo_env=MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET}" "--action_env=MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET}" "--copt=-mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET}" "--linkopt=-mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET}"); fi; bazel test --config=ci ${bazel_args[@]+"${bazel_args[@]}"} //...
