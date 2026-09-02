{
  description = "Pinned GitOps validation and operations toolchain";

  nixConfig = {
    substituters = [ "https://cache.nixos.org/" ];
    trusted-public-keys = [ "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=" ];
    require-sigs = true;
  };

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/83199d0d373dd3ac2b9a1996b1d0263f76ab7a4c";

  outputs =
    { self, nixpkgs }:
    let
      policy = import ./generated/nix-bazel-policy.nix;
      systems = policy.spec.systems;
      forAllSystems = nixpkgs.lib.genAttrs systems;
      perSystem =
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          bazelRuntimeInputs =
            with pkgs;
            [
              bash
              bazel_9
              bzip2
              cacert
              coreutils
              curl
              diffutils
              file
              findutils
              gawk
              git
              gnugrep
              gnumake
              gnused
              gnutar
              gzip
              jdk21_headless
              jq
              openssl.bin
              openssh
              patch
              stdenv.cc
              unzip
              which
              xz
              zip
            ]
            ++ lib.optionals stdenv.hostPlatform.isDarwin [ darwin.cctools ];
          bazel = pkgs.writeShellApplication {
            name = "bazel";
            runtimeInputs = bazelRuntimeInputs;
            text = ''
              export PATH=${pkgs.lib.makeBinPath bazelRuntimeInputs}
              export JAVA_HOME=${pkgs.jdk21_headless}
              export CC=${pkgs.stdenv.cc}/bin/cc
              export CXX=${pkgs.stdenv.cc}/bin/c++
              export BAZEL_LINKOPTS=${pkgs.lib.escapeShellArg (pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isDarwin "-L${pkgs.darwin.libresolv}/lib")}
              export LANG=C
              export LC_ALL=C
              export TZ=UTC
              if [[ "''${1:-}" == "--version" ]]; then
                printf 'bazel %s\n' '${pkgs.bazel_9.version}'
                exit 0
              fi
              startup_flags=(--nosystem_rc --nohome_rc --server_javabase=${pkgs.jdk21_headless})
              if [[ -n "''${BAZEL_OUTPUT_USER_ROOT:-}" ]]; then
                startup_flags+=(--output_user_root="''${BAZEL_OUTPUT_USER_ROOT}")
              fi
              exec ${pkgs.bazel_9}/bin/bazel "''${startup_flags[@]}" "$@"
            '';
          };
          toolchainManifest =
            pkgs.runCommand "mindclade-gitops-toolchain-manifest-v2"
              {
                nativeBuildInputs = [
                  pkgs.coreutils
                  pkgs.jq
                ];
              }
              ''
                set -euo pipefail
                mkdir -p "$out/share/mindclade"
                record() {
                  local path="$1" store_path="$2" version="$3"
                  local sha256
                  sha256="$(sha256sum "$path" | cut -d' ' -f1)"
                  jq -cn \
                    --arg path "$path" \
                    --arg sha256 "sha256:$sha256" \
                    --arg store_path "$store_path" \
                    --arg version "$version" \
                    '{path:$path,sha256:$sha256,store_path:$store_path,version:$version}'
                }
                bazel_json="$(record ${pkgs.bazel_9}/bin/bazel ${pkgs.bazel_9} ${pkgs.bazel_9.version})"
                cc_json="$(record ${pkgs.stdenv.cc}/bin/cc ${pkgs.stdenv.cc} ${pkgs.stdenv.cc.version})"
                cxx_json="$(record ${pkgs.stdenv.cc}/bin/c++ ${pkgs.stdenv.cc} ${pkgs.stdenv.cc.version})"
                go_json="$(record ${pkgs.go_1_26}/bin/go ${pkgs.go_1_26} ${pkgs.go_1_26.version})"
                java_json="$(record ${pkgs.jdk21_headless}/bin/java ${pkgs.jdk21_headless} ${pkgs.jdk21_headless.version})"
                python_json="$(record ${pkgs.python312}/bin/python3 ${pkgs.python312} ${pkgs.python312.version})"
                unsigned="$TMPDIR/unsigned.json"
                jq -Scn \
                  --arg repository mindclade/gitops \
                  --arg system ${system} \
                  --arg revision ${nixpkgs.rev} \
                  --arg nar_hash ${nixpkgs.narHash} \
                  --arg policy_digest ${policy.generated.policy_digest} \
                  --arg policy_revision ${policy.generated.authority_revision} \
                  --arg flake "sha256:${builtins.hashFile "sha256" "${self}/flake.lock"}" \
                  --arg module "sha256:${builtins.hashFile "sha256" "${self}/MODULE.bazel.lock"}" \
                  --argjson bazel "$bazel_json" \
                  --argjson cc "$cc_json" \
                  --argjson cxx "$cxx_json" \
                  --argjson go "$go_json" \
                  --argjson java "$java_json" \
                  --argjson python "$python_json" \
                  '{schema_version:"mindclade-toolchain.v2",repository:$repository,system:$system,nixpkgs:{revision:$revision,nar_hash:$nar_hash},policy:{digest:$policy_digest,revision:$policy_revision},locks:{flake:$flake,module:$module},executables:{bazel:$bazel,cc:$cc,cxx:$cxx,go:$go,java:$java,python:$python}}' \
                  > "$unsigned"
                digest="sha256:$(jq -jSc . "$unsigned" | sha256sum | cut -d' ' -f1)"
                jq -Sc --arg digest "$digest" '. + {toolchain_digest:$digest}' "$unsigned" \
                  > "$out/share/mindclade/toolchain-manifest.json"
              '';
          biomeTarget = policy.spec.tools.biome.targets.${system};
          biomeVersion = policy.spec.tools.biome.version;
          biome = pkgs.runCommand "biome-${biomeVersion}" { } ''
            install -D -m 0755 ${
              pkgs.fetchurl {
                url = "https://github.com/biomejs/biome/releases/download/%40biomejs/biome%40${biomeVersion}/${biomeTarget.asset}";
                inherit (biomeTarget) hash;
              }
            } "$out/bin/biome"
          '';
          toolchainPackages =
            with pkgs;
            [
              act
              actionlint
              bash
              bazel
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
              jdk21_headless
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
              toolchainManifest
              yq-go
            ]
            ++ lib.optionals stdenv.hostPlatform.isDarwin [ darwin.libresolv ];
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
            pathsToLink = [
              "/bin"
              "/share/mindclade"
            ];
            ignoreCollisions = false;
          };
          toolchainCheck =
            pkgs.runCommand "mindclade-gitops-toolchain-check"
              {
                nativeBuildInputs = [ toolchain ];
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
                test "$(shfmt --version)" = "3.13.1"
                    command -v act actionlint bazel cc conftest go gofmt jq just kubeconform kustomize nixfmt opa python3 shellcheck yq >/dev/null
                      test "$(bazel --version)" = "bazel 9.1.1"
                      go version | grep -E '^go version go1\.26\.' >/dev/null
                      python3 --version | grep -E '^Python 3\.12\.' >/dev/null
                    test "$(opa version | awk '/^Version:/ { print $2 }')" = "${pkgs.open-policy-agent.version}"
                      test "$(kustomize version)" = "v${pkgs.kustomize.version}"
                      kubeconform -v | grep -F "v${pkgs.kubeconform.version}" >/dev/null
                      mkdir -p "$out"
                      {
                        printf 'act=%s\n' "${pkgs.act.version}"
                        printf 'actionlint=%s\n' "${pkgs.actionlint.version}"
                        printf 'bazel=%s\n' "${pkgs.bazel_9.version}"
                        printf 'conftest=%s\n' "${pkgs.conftest.version}"
                        printf 'go=%s\n' "${pkgs.go_1_26.version}"
                        printf 'kubeconform=%s\n' "${pkgs.kubeconform.version}"
                        printf 'kustomize=%s\n' "${pkgs.kustomize.version}"
                        printf 'nixfmt=%s\n' "${pkgs.nixfmt.version}"
                        printf 'opa=%s\n' "${pkgs.open-policy-agent.version}"
                        printf 'python=%s\n' "${pkgs.python312.version}"
                      } > "$out/versions.txt"
                      jq -e '.schema_version == "mindclade-toolchain.v2" and .executables.bazel.version == "9.1.1" and (.toolchain_digest | test("^sha256:[0-9a-f]{64}$"))' \
                        ${toolchain}/share/mindclade/toolchain-manifest.json >/dev/null
              '';
          sourceCheck =
            pkgs.runCommand "mindclade-gitops-source-check"
              {
                nativeBuildInputs = [
                  promotectl
                  toolchain
                ];
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
            toolchainManifest
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
          "toolchain-manifest" = current.toolchainManifest;
          default = current.toolchain;
        }
      );

      devShells = forAllSystems (
        system:
        let
          current = perSystem system;
          darwinDeploymentTarget = current.pkgs.lib.optionalString current.pkgs.stdenv.hostPlatform.isDarwin "14.0";
          locale = if current.pkgs.stdenv.hostPlatform.isDarwin then "en_US.UTF-8" else "C.UTF-8";
          common = {
            packages = [ current.toolchain ];
            MACOSX_DEPLOYMENT_TARGET = darwinDeploymentTarget;
            JAVA_HOME = "${current.pkgs.jdk21_headless}";
            CC = "${current.pkgs.stdenv.cc}/bin/cc";
            CXX = "${current.pkgs.stdenv.cc}/bin/c++";
            LANG = locale;
            LC_ALL = locale;
            TZ = "UTC";
            shellHook = ''
              export PATH="${current.toolchain}/bin:$PATH"
              export GOROOT="${current.pkgs.go_1_26}/share/go"
              export MINDCLADE_TOOLCHAIN_MANIFEST="${current.toolchainManifest}/share/mindclade/toolchain-manifest.json"
            '';
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
