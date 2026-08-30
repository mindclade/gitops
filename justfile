set shell := ["bash", "-euo", "pipefail", "-c"]

default: validate

fmt-check:
    test -z "$(gofmt -l tooling)"

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

validate: fmt-check go-test python-test policy-test bootstrap-check
    cd tooling && go run ./cmd/promotectl validate --root ..

render environment:
    cd tooling && go run ./cmd/promotectl render --root .. --environment {{environment}}

verify-bootstrap:
    cd tooling && go run ./cmd/promotectl verify-bootstrap --root .. --fetch

bazel-test:
    USE_BAZEL_VERSION=9.2.0 bazelisk --output_base=/tmp/mindclade-gitops-bazel-output test --lockfile_mode=off --symlink_prefix=/tmp/mindclade-gitops-bazel- //...
