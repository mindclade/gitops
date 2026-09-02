# pyright: basic, reportArgumentType=false, reportAttributeAccessIssue=false, reportCallIssue=false, reportOperatorIssue=false, reportOptionalMemberAccess=false, reportOptionalSubscript=false
import json
import os
import re
import subprocess
import tempfile
import unittest
from datetime import date
from pathlib import Path


def _repository_root():
    if "TEST_SRCDIR" not in os.environ:
        return Path(__file__).resolve().parents[2], None
    runfiles_root = Path(os.environ["TEST_SRCDIR"]) / os.environ["TEST_WORKSPACE"]
    temporary = tempfile.TemporaryDirectory()
    root = Path(temporary.name)
    for relative in os.environ["GITOPS_SOURCE_RUNFILES"].split():
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise RuntimeError(f"unsafe source runfile path: {relative}")
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((runfiles_root / relative_path).read_bytes())
    return root, temporary


ROOT, _ROOT_TEMPORARY = _repository_root()
RUNBOOKS = {
    "Argo CD unavailable": "runbooks/argocd-unavailable.md",
    "Cluster rebootstrap": "runbooks/cluster-rebootstrap.md",
    "Compromised release": "runbooks/compromised-release.md",
    "Deployment drift": "runbooks/deployment-drift.md",
    "Emergency rollback": "runbooks/emergency-rollback.md",
    "Failed synchronization": "runbooks/failed-synchronization.md",
}
ALLOWED_OWNER_TEAMS = {
    "@mindclade/platform-operations",
    "@mindclade/release-engineering",
    "@mindclade/security",
}
EXPECTED_ARGO_SSO_TEAMS = [
    "platform-operations",
    "release-engineering",
    "security",
]


class LiveObjectDiffTest(unittest.TestCase):
    def assert_dormant_argo_sso_contract(self, core_config, credential_contract):
        core_data = re.search(r"(?ms)^data:\n(?P<body>.*)\Z", core_config)
        self.assertIsNotNone(core_data, "argocd-cm lacks data")
        effective_keys = set(re.findall(r"(?m)^  ([A-Za-z0-9_.-]+):", core_data["body"]))
        self.assertNotIn("url", effective_keys)
        self.assertNotIn("dex.config", effective_keys)

        self.assertIn("gitops.mindclade.io/activation: inactive", credential_contract)
        self.assertIn("  status: inactive", credential_contract)
        self.assertIn(
            "  activation-gate: blocked-pending-jit-05",
            credential_contract,
        )
        self.assertNotRegex(credential_contract, r"(?m)^kind:\s+ExternalSecret\s*$")

        sso = re.search(
            r"(?m)^  sso-contract: \|\n(?P<body>(?:^    .*\n?)*)",
            credential_contract,
        )
        self.assertIsNotNone(sso, "inactive credential contract lacks SSO intent")
        self.assertIn("    provider: github", sso["body"])
        self.assertIn("    org: mindclade", sso["body"])
        self.assertIn("    teamNameField: slug", sso["body"])
        self.assertIn("    callbackPath: /api/dex/callback", sso["body"])
        self.assertEqual(
            re.findall(r"(?m)^      - ([a-z-]+)$", sso["body"]),
            EXPECTED_ARGO_SSO_TEAMS,
        )

        requirements = re.search(
            r"(?m)^  activation-requirements: \|\n(?P<body>(?:^    .*\n?)*)",
            credential_contract,
        )
        self.assertIsNotNone(requirements, "credential contract lacks activation requirements")
        self.assertIn("JIT-05 ratifies", requirements["body"])
        self.assertIn("/api/dex/callback exactly", requirements["body"])
        self.assertIn("activated atomically in one reviewed change", requirements["body"])
        self.assertIn(
            "argocd-cm omits data.url and data.dex.config",
            requirements["body"],
        )

    def test_exact_blueprint_file_count(self):
        files = [
            path
            for path in ROOT.rglob("*")
            if path.is_file() and ".git" not in path.parts and ".ruff_cache" not in path.parts
        ]
        self.assertEqual(len(files), 142)

    def test_no_plaintext_secret_or_mutable_release(self):
        for path in ROOT.rglob("*"):
            if not path.is_file() or ".git" in path.parts:
                continue
            if path.suffix not in {".yaml", ".yml", ".json"}:
                continue
            text = path.read_text()
            self.assertIsNone(re.search(r"(?m)^kind:\s+Secret\s*$", text), str(path))
            self.assertIsNone(re.search(r"(?m)^\s*stringData:\s*$", text), str(path))
            self.assertNotIn(":latest", text, str(path))

    def test_projects_are_inactive_until_connected_qualification(self):
        expected_documents = {"default", "platform", "services", "workers", "restricted"}
        names = set()
        for path in (ROOT / "projects").glob("*.yaml"):
            text = path.read_text()
            names.update(re.findall(r"(?m)^  name: ([a-z-]+)$", text))
            self.assertIn("destinations: []", text)
        self.assertEqual(names, expected_documents)

    def test_default_rbac_grants_nothing_without_blocking_mapped_roles(self):
        kustomization = (ROOT / "controllers/argocd/kustomization.yaml").read_text()
        self.assertIn("policy.default: role:deny-all", kustomization)
        self.assertIsNone(re.search(r"(?m)^\s*p, role:deny-all,", kustomization))
        for role in ("security-auditor", "release-promoter", "platform-operator"):
            self.assertIn(f"p, role:{role}", kustomization)

    def test_revision_sync_requires_ungranted_override_privilege(self):
        core_config = (ROOT / "controllers/argocd/resource-customizations.yaml").read_text()
        self.assertIn(
            'application.sync.requireOverridePrivilegeForRevisionSync: "true"',
            core_config,
        )
        authority_sources = [
            (ROOT / "controllers/argocd/kustomization.yaml").read_text(),
        ] + [path.read_text() for path in sorted((ROOT / "projects").glob("*.yaml"))]
        for source in authority_sources:
            self.assertNotIn(", applications, override,", source)
            self.assertNotIn(", applications, action/", source)

    def test_bootstrap_images_are_digest_pinned(self):
        kustomization = (ROOT / "controllers/argocd/kustomization.yaml").read_text()
        expected = {
            "quay.io/argoproj/argocd": "e2aadfae709d904e87f46ba4aa49601d827b3022db22cd4d03aae816a2e7097b",
            "ghcr.io/dexidp/dex": "8499afd690c437f52301efd2b05b2455da5bd2dfc20332cd697dc9937f808462",
            "public.ecr.aws/docker/library/redis": "08ad0b1d280850169a790dba1393ff7a90aef951fc19632cf4d3ce4f78e679ba",
        }
        for image, digest in expected.items():
            self.assertIn(f"{image}@sha256:{digest}", kustomization)
            self.assertIn(f"digest: sha256:{digest}", kustomization)
        self.assertNotIn("newTag:", kustomization)

    def test_credential_binding_is_inactive_and_non_materializing(self):
        contract = (ROOT / "controllers/argocd/repository-credentials-reference.yaml").read_text()
        self.assertIn("kind: ConfigMap", contract)
        self.assertIn("status: inactive", contract)
        self.assertIn("provider: ExternalSecret", contract)
        self.assertNotIn("kind: ExternalSecret", contract)
        self.assertNotIn("secretStoreRef:", contract)
        self.assertNotIn("remoteRef:", contract)

    def test_argo_sso_is_dormant_until_atomic_activation(self):
        core_config = (ROOT / "controllers/argocd/resource-customizations.yaml").read_text()
        credential_contract = (
            ROOT / "controllers/argocd/repository-credentials-reference.yaml"
        ).read_text()
        self.assert_dormant_argo_sso_contract(core_config, credential_contract)

    def test_argo_sso_contract_assertions_reject_unsafe_mutations(self):
        core_config = (ROOT / "controllers/argocd/resource-customizations.yaml").read_text()
        credential_contract = (
            ROOT / "controllers/argocd/repository-credentials-reference.yaml"
        ).read_text()
        cases = {
            "effective-url": (
                core_config.replace(
                    "\ndata:\n",
                    "\ndata:\n  url: https://argocd.example.invalid\n",
                    1,
                ),
                credential_contract,
            ),
            "effective-dex-config": (
                core_config.replace(
                    "\ndata:\n",
                    "\ndata:\n  dex.config: |\n    connectors: []\n",
                    1,
                ),
                credential_contract,
            ),
            "wrong-org": (
                core_config,
                credential_contract.replace("    org: mindclade", "    org: lookalike"),
            ),
            "login-instead-of-slug": (
                core_config,
                credential_contract.replace(
                    "    teamNameField: slug",
                    "    teamNameField: login",
                ),
            ),
            "broadened-team-set": (
                core_config,
                credential_contract.replace(
                    "      - security",
                    "      - security\n      - contractors",
                ),
            ),
            "wrong-callback": (
                core_config,
                credential_contract.replace(
                    "/api/dex/callback",
                    "/oauth/callback",
                ),
            ),
            "missing-jit-gate": (
                core_config,
                credential_contract.replace(
                    "  activation-gate: blocked-pending-jit-05\n",
                    "",
                ),
            ),
            "non-atomic-activation": (
                core_config,
                credential_contract.replace(
                    "activated atomically in one reviewed change",
                    "activated independently",
                ),
            ),
        }
        for mutation, (mutated_core, mutated_contract) in cases.items():
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                self.assert_dormant_argo_sso_contract(
                    mutated_core,
                    mutated_contract,
                )

    def test_namespace_pss_version_matches_validated_kubernetes_minor(self):
        namespace = (ROOT / "controllers/argocd/namespace.yaml").read_text()
        self.assertNotIn("pod-security.kubernetes.io/enforce-version: latest", namespace)
        for mode in ("enforce", "audit", "warn"):
            self.assertIn(f"pod-security.kubernetes.io/{mode}-version: v1.34", namespace)

    def test_source_validation_covers_main_and_merge_queue(self):
        workflow = (ROOT / ".github/workflows/pull-request.yml").read_text()
        justfile = (ROOT / "justfile").read_text()
        self.assertTrue(workflow.startswith("name: Pull request\n"))
        self.assertIn("\n  required:\n    name: required\n", workflow)
        self.assertIn("push:\n    branches: [main]", workflow)
        self.assertIn("merge_group:\n    types: [checks_requested]", workflow)
        self.assertIn(
            "nix develop --no-accept-flake-config --no-update-lock-file .#ci --command just validate",
            workflow,
        )
        self.assertIn("kubeconform -strict", justfile)
        self.assertIn("kustomize build", justfile)

    def test_all_workflows_use_the_organization_approved_checkout_pin(self):
        expected = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
        stale = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
        workflow_directory = ROOT / ".github" / "workflows"
        workflows = sorted(workflow_directory.glob("*.yml"))
        self.assertEqual(len(workflows), 4)
        for path in workflows:
            with self.subTest(workflow=path.name):
                source = path.read_text()
                self.assertIn(expected, source)
                self.assertNotIn(stale, source)

    def test_all_workflows_use_the_locked_nix_toolchain(self):
        installer = (
            "DeterminateSystems/nix-installer-action@ef8a148080ab6020fd15196c2084a2eea5ff2d25 # v22"
        )
        workflow_directory = ROOT / ".github" / "workflows"
        for path in sorted(workflow_directory.glob("*.yml")):
            with self.subTest(workflow=path.name):
                source = path.read_text()
                self.assertIn(installer, source)
                self.assertIn("--no-update-lock-file", source)
                self.assertIn("nix-2.31.2-x86_64-linux.tar.xz", source)
                self.assertIn(
                    "source-revision: 3477b9e591f27522d437d78b21cb857ce87dd6bb",
                    source,
                )
                self.assertIn("substituters = https://cache.nixos.org/", source)
                self.assertIn(
                    "trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=",
                    source,
                )
                self.assertIn("require-sigs = true", source)
                self.assertIn("accept-flake-config = false", source)
                self.assertIn("--no-accept-flake-config", source)
                self.assertNotIn("--accept-flake-config", source)
                self.assertNotIn("actions/setup-go@", source)
                self.assertNotIn("actions/setup-python@", source)
                self.assertNotIn("bazel-contrib/setup-bazel@", source)

    def test_flake_exposes_the_cross_platform_toolchain_contract(self):
        flake = (ROOT / "flake.nix").read_text()
        lock = (ROOT / "flake.lock").read_text()
        for invariant in (
            '"aarch64-darwin"',
            '"x86_64-linux"',
            "toolchain = pkgs.buildEnv",
            "devShells = forAllSystems",
            "default = current.pkgs.mkShellNoCC common",
            "ci = current.pkgs.mkShellNoCC common",
            "checks = forAllSystems",
            "formatter = forAllSystems",
        ):
            self.assertIn(invariant, flake)
        self.assertIn('"nixpkgs"', lock)
        self.assertIn('"narHash"', lock)

    def test_nix_toolchain_uses_pinned_bazel_release(self):
        workflow = (ROOT / ".github/workflows/pull-request.yml").read_text()
        justfile = (ROOT / "justfile").read_text()
        readme = (ROOT / "README.md").read_text()
        flake = (ROOT / "flake.nix").read_text()
        self.assertIn("nix build --no-accept-flake-config", workflow)
        self.assertIn("BAZEL_LINKOPTS", flake)
        self.assertIn("MACOSX_DEPLOYMENT_TARGET", justfile)
        self.assertIn('bazel test --config=ci "${bazel_args[@]}" //...', justfile)
        self.assertIn("83199d0d373dd3ac2b9a1996b1d0263f76ab7a4c", flake)
        self.assertIn("bazel_9", flake)
        self.assertEqual((ROOT / ".bazelversion").read_text().strip(), "9.1.1")
        self.assertIn("`MODULE.bazel.lock`", readme)
        self.assertTrue((ROOT / "MODULE.bazel.lock").is_file())
        for source in (workflow, justfile, readme):
            self.assertNotIn("bazelisk", source.lower())
            self.assertNotIn("USE_BAZEL_VERSION", source)
            self.assertNotIn("--lockfile_mode=off", source)

    def test_nix_config_guard_accepts_wrapped_and_scalar_values(self):
        workflow = (ROOT / ".github/workflows/pull-request.yml").read_text()
        jq_filter = workflow.split("nix config show --json | jq -e '\n", 1)[1].split(
            "\n          ' >/dev/null", 1
        )[0]
        approved = {
            "substituters": ["https://cache.nixos.org/"],
            "trusted-public-keys": [
                "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
            ],
            "require-sigs": True,
            "accept-flake-config": False,
        }
        fixtures = (
            approved,
            {key: {"value": value, "source": "workflow"} for key, value in approved.items()},
        )
        for fixture in fixtures:
            with self.subTest(shape=type(fixture["substituters"])):
                result = subprocess.run(
                    ["jq", "-e", jq_filter],
                    input=json.dumps(fixture),
                    capture_output=True,
                    check=False,
                    text=True,
                )
                self.assertEqual(0, result.returncode, result.stderr)
        rejected = {**approved, "accept-flake-config": True}
        result = subprocess.run(
            ["jq", "-e", jq_filter],
            input=json.dumps(rejected),
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertNotEqual(0, result.returncode)

    def test_local_bootstrap_provenance_is_checked_before_remote_render(self):
        justfile = (ROOT / "justfile").read_text()
        provenance = "go run ./cmd/promotectl verify-bootstrap --root .."
        render = "kustomize build --load-restrictor=LoadRestrictionsNone"
        self.assertIn(provenance, justfile)
        self.assertIn(render, justfile)
        self.assertLess(justfile.index(provenance), justfile.index(render))

    def test_runbooks_are_indexed_owned_and_recently_reviewed(self):
        readme = (ROOT / "README.md").read_text()
        section = re.search(
            r"(?ms)^## Operational runbooks\n+(?P<body>.*?)(?=^## |\Z)",
            readme,
        )
        self.assertIsNotNone(section, "README lacks the operational runbook index")
        indexed = dict(re.findall(r"(?m)^- \[([^]]+)\]\((runbooks/[^)]+\.md)\)$", section["body"]))
        self.assertEqual(indexed, RUNBOOKS)

        runbook_root = (ROOT / "runbooks").resolve()
        actual = {path.relative_to(ROOT).as_posix() for path in (ROOT / "runbooks").glob("*.md")}
        self.assertEqual(actual, set(RUNBOOKS.values()))

        codeowners = {}
        for raw_line in (ROOT / ".github/CODEOWNERS").read_text().splitlines():
            fields = raw_line.strip().split()
            if fields and not fields[0].startswith("#"):
                codeowners[fields[0]] = set(fields[1:])

        for title, relative in RUNBOOKS.items():
            with self.subTest(runbook=relative):
                target = (ROOT / relative).resolve()
                self.assertEqual(target.parent, runbook_root)
                self.assertTrue(target.is_file())
                text = target.read_text()
                self.assertTrue(text.startswith(f"# {title}\n"))

                owner = re.search(r"(?m)^Owner: `([^`]+)`$", text)
                self.assertIsNotNone(owner, f"{relative} lacks owner metadata")
                self.assertIn(owner.group(1), ALLOWED_OWNER_TEAMS)

                specific_pattern = f"/{relative}"
                effective_owners = codeowners.get(
                    specific_pattern,
                    codeowners["/runbooks/"],
                )
                self.assertIn(
                    owner.group(1),
                    effective_owners,
                    f"{relative} owner is not an effective CODEOWNER",
                )

                reviewed = re.search(
                    r"(?m)^Last reviewed: `(\d{4}-\d{2}-\d{2})`$",
                    text,
                )
                self.assertIsNotNone(
                    reviewed,
                    f"{relative} lacks an ISO last-reviewed date",
                )
                review_date = date.fromisoformat(reviewed.group(1))
                age = (date.today() - review_date).days
                self.assertGreaterEqual(age, 0, f"{relative} review date is in the future")
                self.assertLessEqual(age, 366, f"{relative} review is stale")

    def test_codeowners_cover_blueprint_authority_boundaries(self):
        entries = {}
        patterns = []
        for raw_line in (ROOT / ".github/CODEOWNERS").read_text().splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split()
            self.assertGreaterEqual(len(fields), 2, raw_line)
            pattern, teams = fields[0], set(fields[1:])
            self.assertNotIn(pattern, entries, f"duplicate CODEOWNERS pattern {pattern}")
            self.assertTrue(teams <= ALLOWED_OWNER_TEAMS, raw_line)
            entries[pattern] = teams
            patterns.append(pattern)

        expected = {
            "*": {"@mindclade/platform-operations"},
            "/.github/": {"@mindclade/platform-operations", "@mindclade/security"},
            "/controllers/": {"@mindclade/platform-operations", "@mindclade/security"},
            "/projects/": {"@mindclade/platform-operations", "@mindclade/security"},
            "/platform/": {
                "@mindclade/platform-operations",
                "@mindclade/release-engineering",
                "@mindclade/security",
            },
            "/environments/development/": {
                "@mindclade/platform-operations",
                "@mindclade/release-engineering",
            },
            "/environments/staging/": {
                "@mindclade/platform-operations",
                "@mindclade/release-engineering",
                "@mindclade/security",
            },
            "/environments/production/": ALLOWED_OWNER_TEAMS,
            "/environments/restricted/": ALLOWED_OWNER_TEAMS,
            "/policy/": {"@mindclade/platform-operations", "@mindclade/security"},
            "/schemas/": ALLOWED_OWNER_TEAMS,
            "/tooling/": ALLOWED_OWNER_TEAMS,
            "/runbooks/": {"@mindclade/platform-operations", "@mindclade/security"},
            "/runbooks/emergency-rollback.md": ALLOWED_OWNER_TEAMS,
            "/SECURITY.md": {"@mindclade/platform-operations", "@mindclade/security"},
            "/LICENSE": {"@mindclade/platform-operations", "@mindclade/security"},
            "/README.md": {"@mindclade/platform-operations", "@mindclade/release-engineering"},
            "/component.yaml": {"@mindclade/platform-operations", "@mindclade/security"},
            "/BUILD.bazel": {"@mindclade/platform-operations", "@mindclade/release-engineering"},
            "/MODULE.bazel": {"@mindclade/platform-operations", "@mindclade/security"},
            "/justfile": {"@mindclade/platform-operations", "@mindclade/release-engineering"},
        }
        self.assertEqual(entries, expected)
        self.assertEqual(patterns[0], "*", "catch-all CODEOWNERS rule must be first")
        self.assertLess(
            patterns.index("/runbooks/"),
            patterns.index("/runbooks/emergency-rollback.md"),
            "file-specific runbook ownership must override the directory rule",
        )

    def test_dependabot_covers_declared_dependency_ecosystems(self):
        text = (ROOT / ".github/dependabot.yml").read_text()
        self.assertRegex(text, r"(?m)^version: 2$")
        matches = list(re.finditer(r"(?m)^  - package-ecosystem: ([a-z-]+)$", text))
        configured = {}
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            block = text[match.end() : end]
            directory = re.search(r"(?m)^    directory: (\S+)$", block)
            interval = re.search(r"(?m)^      interval: (\S+)$", block)
            limit = re.search(
                r"(?m)^    open-pull-requests-limit: ([1-9][0-9]*)$",
                block,
            )
            reviewers = set(re.findall(r"(?m)^      - (mindclade/[a-z-]+)$", block))
            self.assertIsNotNone(directory, match.group(1))
            self.assertIsNotNone(interval, match.group(1))
            self.assertIsNotNone(limit, match.group(1))
            self.assertEqual(interval.group(1), "weekly")
            self.assertEqual(
                reviewers,
                {"mindclade/platform-operations", "mindclade/security"},
            )
            self.assertNotIn(match.group(1), configured)
            configured[match.group(1)] = directory.group(1)

        self.assertEqual(
            configured,
            {"github-actions": "/", "gomod": "/tooling", "bazel": "/"},
        )
        module = (ROOT / "MODULE.bazel").read_text(encoding="utf-8")
        for required in (
            'go_mod_from_file = "//tooling:go.mod"',
            'go_sum_from_file = "//tooling:go.sum"',
            "go_deps.from_file(go_mod = go_mod_from_file)",
        ):
            self.assertIn(required, module)

    def test_component_metadata_has_a_coherent_authority_contract(self):
        text = (ROOT / "component.yaml").read_text()
        for required in (
            "apiVersion: mindclade.io/v1alpha1",
            "kind: Component",
            "  name: gitops",
            "    github.com/project-slug: mindclade/gitops",
            "    mindclade.dev/security-owner: security",
            "    mindclade.dev/trust-tier: deployment-control",
            "    mindclade.dev/recovery-tier: isolated-git",
            "    mindclade.io/qualification-status: FAIL",
            "  type: deployment-control-plane",
            "  lifecycle: pre-production",
            "  maturity: pre-production",
            "  owner: platform-operations",
            "  security_reviewers:",
            "    - security",
            "  repository_class: deployment-source",
            "  data_classification: public",
            "  production_authority: false",
            "    strategy: protected-digest-promotion",
            "    artifact: source-commit",
            "    immutable: true",
        ):
            self.assertIn(required, text)

        dependencies = re.search(
            r"(?ms)^  dependencies:\n(?P<body>(?:    - [^\n]+\n)+)^  provides:",
            text,
        )
        self.assertIsNotNone(dependencies)
        self.assertEqual(
            set(re.findall(r"(?m)^    - component:([^\n]+)$", dependencies["body"])),
            {"infrastructure-live", "mindclade"},
        )

        evidence = re.search(
            r"(?ms)^    evidence:\n(?P<body>(?:      - [^\n]+\n?)+)\Z",
            text,
        )
        self.assertIsNotNone(evidence)
        self.assertEqual(
            set(re.findall(r"(?m)^      - ([^\n]+)$", evidence["body"])),
            {
                "signed-release",
                "immutable-artifact-digest",
                "policy-verification",
                "protected-environment-approval",
            },
        )

    def test_governance_docs_match_source_only_qualification_boundary(self):
        readme = re.sub(r"\s+", " ", (ROOT / "README.md").read_text())
        template = (ROOT / ".github/pull_request_template.md").read_text()
        self.assertIn("does not perform a live object comparison", readme)
        self.assertIn("Live drift qualification remains a connected activation preflight", readme)
        for blocker in (
            "Platform packages",
            "policy bindings",
            "secret references",
            "`blocked-pending-jit-05` activation gate",
            "`blocked-pending-jit-09` evidence-verifier gate",
        ):
            self.assertIn(blocker, readme)
        self.assertIn(
            "Every activated or changed release references its protected promotion receipt and immutable governance evidence.",
            template,
        )
        self.assertNotIn(
            "Production/restricted approval and rollback evidence",
            template,
        )


if __name__ == "__main__":
    unittest.main()
