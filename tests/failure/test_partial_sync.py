import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class PartialSyncTest(unittest.TestCase):
    def test_inactive_release_sets_produce_zero_applications(self):
        active_clusters = 0
        active_release_sets = 0
        for environment in ("development", "staging", "production", "restricted"):
            directory = ROOT / "environments" / environment
            cluster_set = json.loads((directory / "cluster-set.yaml").read_text())
            active_clusters += len(cluster_set["clusters"]) if cluster_set["active"] else 0
            for name in ("platform-releases.yaml", "service-releases.yaml", "worker-releases.yaml"):
                release_set = json.loads((directory / name).read_text())
                active_release_sets += len(release_set["releases"]) if release_set["active"] else 0
        concrete_applications = 0
        for path in ROOT.rglob("*.yaml"):
            concrete_applications += len(re.findall(r"(?m)^kind:\s+Application\s*$", path.read_text()))
        self.assertEqual(active_clusters, 0)
        self.assertEqual(active_release_sets, 0)
        self.assertEqual(concrete_applications, 0)

    def test_applicationsets_preserve_on_partial_failure(self):
        files = sorted((ROOT / "controllers/applicationsets").glob("*.yaml"))
        self.assertEqual(len(files), 4)
        expected_sources = {
            "environment-root.yaml": "cluster-set.yaml",
            "platform-components.yaml": "platform-releases.yaml",
            "control-plane-services.yaml": "service-releases.yaml",
            "execution-workers.yaml": "worker-releases.yaml",
        }
        for path in files:
            text = path.read_text()
            self.assertIn("matrix:", text)
            self.assertIn("git:", text)
            self.assertIn(f"environments/*/{expected_sources[path.name]}", text)
            self.assertIn("elementsYaml:", text)
            self.assertIn("if .active", text)
            self.assertNotIn("elements: []", text)
            self.assertIn("desiredStateRevision", text)
            self.assertRegex(text, r"gitops\.mindclade\.io/(?:release|activation)-record-digest")
            if path.name != "environment-root.yaml":
                self.assertIn("promotion-receipt-digest", text)
                self.assertIn("governance-evidence-digest", text)
            self.assertIn("applicationsSync: create-update", text)
            self.assertIn("preserveResourcesOnDeletion: true", text)
            self.assertNotIn("prune: true", text)
            self.assertNotRegex(text, r"targetRevision:\s*(?:main|HEAD|master)")


if __name__ == "__main__":
    unittest.main()
