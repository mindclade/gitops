import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ProductionRenderTest(unittest.TestCase):
    def test_production_is_inactive_without_release_records(self):
        directory = ROOT / "environments/production"
        for path in directory.glob("*.yaml"):
            if path.name == "kustomization.yaml":
                continue
            document = json.loads(path.read_text())
            self.assertIs(document["active"], False)
            self.assertEqual(document["environment"], "production")
        self.assertEqual(json.loads((directory / "cluster-set.yaml").read_text())["clusters"], [])
        self.assertEqual(json.loads((directory / "platform-releases.yaml").read_text())["releases"], [])
        self.assertEqual(json.loads((directory / "service-releases.yaml").read_text())["releases"], [])
        self.assertEqual(json.loads((directory / "worker-releases.yaml").read_text())["releases"], [])

    def test_no_mutable_production_reference(self):
        text = "\n".join(path.read_text() for path in ROOT.rglob("*.yaml"))
        self.assertIsNone(re.search(r"targetRevision:\s*(?:HEAD|main|master|refs/heads/)", text))
        self.assertNotIn(":latest", text)


if __name__ == "__main__":
    unittest.main()
