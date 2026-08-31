{
  description = "Pinned GitOps validation and operations toolchain";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      perSystem =
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          biomeTarget =
            {
              aarch64-darwin = {
                asset = "biome-darwin-arm64";
                hash = "sha256-UA/Ij/QJJe1CKtzKa4o+kFJu6QTSuhCw7eDNBl/KPSs=";
              };
              x86_64-linux = {
                asset = "biome-linux-x64";
                hash = "sha256-klh/rBAuM8v4qx/bSIT49Ny/ERcln8bezVy1tfXkjmc=";
              };
            }
            .${system};
          biome = pkgs.runCommand "biome-2.3.11" { } ''
            install -D -m 0755 ${
              pkgs.fetchurl {
                url = "https://github.com/biomejs/biome/releases/download/%40biomejs/biome%402.3.11/${biomeTarget.asset}";
                inherit (biomeTarget) hash;
              }
            } "$out/bin/biome"
          '';
          toolchainPackages = with pkgs; [
            act
            actionlint
            bash
            bazelisk
            biome
            buildifier
            cacert
            conftest
            coreutils
            diffutils
            findutils
            gawk
            git
            gnugrep
            gnused
            gnutar
            go_1_26
            golangci-lint
            gzip
            jq
            just
            markdownlint-cli2
            kubeconform
            kustomize
            nixfmt
            open-policy-agent
            pre-commit

            pyright

            python312

            ruff
            shellcheck
            shfmt
            stdenv.cc
            yq-go
          ];
          promotectl = pkgs.buildGoModule {
            pname = "promotectl";
            version = "0.1.0";
            src = ./tooling;
            vendorHash = "sha256-UVaaiY1gDpx3/Le2N7Qmf2WzH8MCM5MtlxuMKKaZtM0=";
            subPackages = [ "cmd/promotectl" ];
          };
          toolchain = pkgs.buildEnv {
            name = "mindclade-gitops-toolchain";
            paths = toolchainPackages;
            ignoreCollisions = true;
          };
          toolchainCheck =
            pkgs.runCommand "mindclade-gitops-toolchain-check"
              {
                nativeBuildInputs = toolchainPackages;
              }
              ''
                      set -euo pipefail
                test "$(biome --version)" = "Version: 2.3.11"
                test "${pkgs.buildifier.version}" = "8.5.1"
                test "${pkgs.golangci-lint.version}" = "2.13.1"
                test "${pkgs.markdownlint-cli2.version}" = "0.23.2"
                test "$(pre-commit --version)" = "pre-commit 4.5.1"
                test "$(pyright --version)" = "pyright 1.1.412"
                test "$(ruff --version)" = "ruff 0.16.4"
                test "$(shfmt --version)" = "v3.13.1"
                    command -v act actionlint bazelisk cc conftest go gofmt jq just kubeconform kustomize nixfmt opa python3 shellcheck yq >/dev/null
                      go version | grep -E '^go version go1\.26\.' >/dev/null
                      python3 --version | grep -E '^Python 3\.12\.' >/dev/null
                    test "$(opa version | awk '/^Version:/ { print $2 }')" = "${pkgs.open-policy-agent.version}"
                      test "$(kustomize version)" = "v${pkgs.kustomize.version}"
                      kubeconform -v | grep -F "v${pkgs.kubeconform.version}" >/dev/null
                      mkdir -p "$out"
                      {
                        printf 'act=%s\n' "${pkgs.act.version}"
                        printf 'actionlint=%s\n' "${pkgs.actionlint.version}"
                        printf 'bazelisk=%s\n' "${pkgs.bazelisk.version}"
                        printf 'conftest=%s\n' "${pkgs.conftest.version}"
                        printf 'go=%s\n' "${pkgs.go_1_26.version}"
                        printf 'kubeconform=%s\n' "${pkgs.kubeconform.version}"
                        printf 'kustomize=%s\n' "${pkgs.kustomize.version}"
                        printf 'nixfmt=%s\n' "${pkgs.nixfmt.version}"
                        printf 'opa=%s\n' "${pkgs.open-policy-agent.version}"
                        printf 'python=%s\n' "${pkgs.python312.version}"
                      } > "$out/versions.txt"
              '';
          sourceCheck =
            pkgs.runCommand "mindclade-gitops-source-check"
              {
                nativeBuildInputs = toolchainPackages ++ [ promotectl ];
              }
              ''
                  set -euo pipefail
                export HOME="$TMPDIR/home"
                export PROMOTECTL_RUNFILE="${promotectl}/bin/promotectl"
                mkdir -p "$HOME" "$out" "$TMPDIR/source"
                cp -R ${self}/. "$TMPDIR/source/"
                chmod -R u+w "$TMPDIR/source"
                cd "$TMPDIR/source"
                  test -z "$(gofmt -l tooling)"
                  promotectl validate --root .
                  opa test policy
                  while IFS= read -r test_file; do
                    python3 "$test_file"
                  done < <(find tests -type f -name 'test_*.py' ! -path 'tests/drift/test_live_object_diff.py' | sort)
                  touch "$out/passed"
              '';
        in
        {
          inherit
            pkgs
            promotectl
            sourceCheck
            toolchain
            toolchainCheck
            toolchainPackages
            ;
        };
    in
    {
      packages = forAllSystems (
        system:
        let
          current = perSystem system;
        in
        {
          inherit (current) promotectl toolchain;
          default = current.toolchain;
        }
      );

      devShells = forAllSystems (
        system:
        let
          current = perSystem system;
          common = {
            packages = current.toolchainPackages;
            LANG = "C";
            LC_ALL = "C";
            TZ = "UTC";
            USE_BAZEL_VERSION = "9.2.0";
          };
        in
        {
          default = current.pkgs.mkShellNoCC common;
          ci = current.pkgs.mkShellNoCC common;
        }
      );

      checks = forAllSystems (
        system:
        let
          current = perSystem system;
        in
        {
          inherit (current) promotectl;
          source = current.sourceCheck;
          toolchain = current.toolchainCheck;
        }
      );

      formatter = forAllSystems (system: (perSystem system).pkgs.nixfmt);
    };
}
