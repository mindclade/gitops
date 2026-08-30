import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class StagingRenderTest(unittest.TestCase):
    def test_staging_requires_explicit_activation(self):
        directory = ROOT / "environments/staging"
        documents = [json.loads(path.read_text()) for path in sorted(directory.glob("*.yaml")) if path.name != "kustomization.yaml"]
        self.assertEqual(len(documents), 7)
        self.assertTrue(all(document["environment"] == "staging" for document in documents))
        self.assertTrue(all(document["active"] is False for document in documents))
        self.assertEqual(json.loads((directory / "cluster-set.yaml").read_text())["clusters"], [])

    def test_staging_has_no_artifact_or_destination(self):
        directory = ROOT / "environments/staging"
        combined = "\n".join(path.read_text() for path in directory.glob("*.yaml"))
        self.assertNotIn("sha256:", combined)
        self.assertNotIn("https://", combined)


if __name__ == "__main__":
    unittest.main()
