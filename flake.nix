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
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
      ];
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
            ++ lib.optionals stdenv.hostPlatform.isDarwin [
              darwin.cctools
              darwin.cctools.libtool
            ];
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
          moduleLock = "${self}/MODULE.bazel.lock";
          toolchainManifest = pkgs.writeTextDir "share/mindclade/toolchain-manifest.json" (
            builtins.toJSON {
              schema_version = "mindclade-toolchain.v1";
              repository = "mindclade/gitops";
              inherit system;
              nixpkgs = {
                revision = nixpkgs.rev;
                nar_hash = nixpkgs.narHash;
              };
              flake_lock_sha256 = builtins.hashFile "sha256" "${self}/flake.lock";
              module_lock_sha256 =
                if builtins.pathExists moduleLock then builtins.hashFile "sha256" moduleLock else null;
              bazel = {
                version = pkgs.bazel_9.version;
                store_path = "${pkgs.bazel_9}";
              };
              startup_jdk = {
                version = pkgs.jdk21_headless.version;
                store_path = "${pkgs.jdk21_headless}";
              };
              native_cc_store_path = "${pkgs.stdenv.cc}";
            }
          );
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
                      jq -e '.schema_version == "mindclade-toolchain.v1" and .bazel.version == "9.1.1"' \
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
