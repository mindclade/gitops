import re
import unittest
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNBOOKS = {
    "Argo CD unavailable": "runbooks/argocd-unavailable.md",
    "Cluster rebootstrap": "runbooks/cluster-rebootstrap.md",
    "Compromised release": "runbooks/compromised-release.md",
    "Deployment drift": "runbooks/deployment-drift.md",
    "Emergency rollback": "runbooks/emergency-rollback.md",
    "Failed synchronization": "runbooks/failed-synchronization.md",
}
ALLOWED_OWNER_TEAMS = {
    "@mindclade/platform",
    "@mindclade/release",
    "@mindclade/security",
}


class LiveObjectDiffTest(unittest.TestCase):
    def test_exact_blueprint_file_count(self):
        files = [path for path in ROOT.rglob("*") if path.is_file() and ".git" not in path.parts]
        self.assertEqual(len(files), 126)

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

    def test_projects_are_unbound_until_connected_qualification(self):
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

    def test_credential_binding_is_inactive_and_unbound(self):
        contract = (ROOT / "controllers/argocd/repository-credentials-reference.yaml").read_text()
        self.assertIn("kind: ConfigMap", contract)
        self.assertIn("status: inactive", contract)
        self.assertIn("provider: ExternalSecret", contract)
        self.assertNotIn("kind: ExternalSecret", contract)
        self.assertNotIn("secretStoreRef:", contract)
        self.assertNotIn("remoteRef:", contract)

    def test_namespace_pss_version_matches_validated_kubernetes_minor(self):
        namespace = (ROOT / "controllers/argocd/namespace.yaml").read_text()
        self.assertNotIn("pod-security.kubernetes.io/enforce-version: latest", namespace)
        for mode in ("enforce", "audit", "warn"):
            self.assertIn(f"pod-security.kubernetes.io/{mode}-version: v1.34", namespace)

    def test_source_validation_covers_main_and_merge_queue(self):
        workflow = (ROOT / ".github/workflows/pull-request.yml").read_text()
        self.assertIn("push:\n    branches: [main]", workflow)
        self.assertIn("merge_group:\n    types: [checks_requested]", workflow)
        self.assertIn("kubeconform -strict", workflow)
        self.assertIn("kustomize build", workflow)

    def test_bazelisk_uses_pinned_bazel_release(self):
        workflow = (ROOT / ".github/workflows/pull-request.yml").read_text()
        justfile = (ROOT / "justfile").read_text()
        readme = (ROOT / "README.md").read_text()
        self.assertIn('USE_BAZEL_VERSION: "9.2.0"', workflow)
        self.assertIn("USE_BAZEL_VERSION=9.2.0 bazelisk", justfile)
        self.assertIn("`--lockfile_mode=off`", readme)
        self.assertIn("`MODULE.bazel.lock`", readme)
        self.assertFalse((ROOT / ".bazelversion").exists())

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
        indexed = dict(
            re.findall(r"(?m)^- \[([^]]+)\]\((runbooks/[^)]+\.md)\)$", section["body"])
        )
        self.assertEqual(indexed, RUNBOOKS)

        runbook_root = (ROOT / "runbooks").resolve()
        actual = {
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "runbooks").glob("*.md")
        }
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
            "*": {"@mindclade/release"},
            "/.github/": {"@mindclade/release", "@mindclade/security"},
            "/controllers/": {"@mindclade/platform", "@mindclade/security"},
            "/projects/": {"@mindclade/platform", "@mindclade/security"},
            "/platform/": {"@mindclade/platform", "@mindclade/release"},
            "/environments/development/": {"@mindclade/release"},
            "/environments/staging/": {
                "@mindclade/platform",
                "@mindclade/release",
            },
            "/environments/production/": ALLOWED_OWNER_TEAMS,
            "/environments/restricted/": ALLOWED_OWNER_TEAMS,
            "/policy/": {"@mindclade/release", "@mindclade/security"},
            "/schemas/": {"@mindclade/platform", "@mindclade/release"},
            "/tooling/": {"@mindclade/platform", "@mindclade/release"},
            "/runbooks/": {"@mindclade/platform", "@mindclade/security"},
            "/runbooks/emergency-rollback.md": ALLOWED_OWNER_TEAMS,
            "/SECURITY.md": {"@mindclade/release", "@mindclade/security"},
            "/LICENSE": {"@mindclade/release", "@mindclade/security"},
            "/README.md": {"@mindclade/platform", "@mindclade/release"},
            "/component.yaml": {"@mindclade/platform", "@mindclade/release"},
            "/BUILD.bazel": {"@mindclade/platform", "@mindclade/release"},
            "/MODULE.bazel": {"@mindclade/platform", "@mindclade/security"},
            "/justfile": {"@mindclade/platform", "@mindclade/release"},
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
        matches = list(
            re.finditer(r"(?m)^  - package-ecosystem: ([a-z-]+)$", text)
        )
        configured = {}
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            block = text[match.end():end]
            directory = re.search(r"(?m)^    directory: (\S+)$", block)
            interval = re.search(r"(?m)^      interval: (\S+)$", block)
            limit = re.search(
                r"(?m)^    open-pull-requests-limit: ([1-9][0-9]*)$",
                block,
            )
            reviewers = set(
                re.findall(r"(?m)^      - (mindclade/[a-z-]+)$", block)
            )
            self.assertIsNotNone(directory, match.group(1))
            self.assertIsNotNone(interval, match.group(1))
            self.assertIsNotNone(limit, match.group(1))
            self.assertEqual(interval.group(1), "weekly")
            self.assertEqual(
                reviewers,
                {"mindclade/platform", "mindclade/security"},
            )
            self.assertNotIn(match.group(1), configured)
            configured[match.group(1)] = directory.group(1)

        self.assertEqual(
            configured,
            {"github-actions": "/", "gomod": "/tooling", "bazel": "/"},
        )

    def test_component_metadata_has_a_coherent_authority_contract(self):
        text = (ROOT / "component.yaml").read_text()
        for required in (
            "apiVersion: mindclade.io/v1alpha1",
            "kind: Component",
            "  name: gitops",
            "    github.com/project-slug: mindclade/gitops",
            "  type: deployment-control-plane",
            "  lifecycle: production",
            "  maturity: production",
            "  owner: release",
            "  repository_class: deployment-source",
            "  data_classification: confidential",
            "  production_authority: true",
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
            "code-level `unbound` implementation marker",
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
