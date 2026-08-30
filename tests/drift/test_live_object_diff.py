import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


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
        self.assertIn('USE_BAZEL_VERSION: "9.2.0"', workflow)
        self.assertIn("USE_BAZEL_VERSION=9.2.0 bazelisk", justfile)
        self.assertFalse((ROOT / ".bazelversion").exists())


if __name__ == "__main__":
    unittest.main()
