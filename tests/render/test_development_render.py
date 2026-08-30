import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DOCUMENTS = (
    "cluster-set.yaml",
    "infrastructure-exports.yaml",
    "platform-releases.yaml",
    "service-releases.yaml",
    "worker-releases.yaml",
    "policy-bindings.yaml",
    "secret-references.yaml",
)


class DevelopmentRenderTest(unittest.TestCase):
    def test_development_is_inactive_and_empty(self):
        for name in DOCUMENTS:
            document = json.loads((ROOT / "environments/development" / name).read_text())
            self.assertEqual(document["schemaVersion"], "v1")
            self.assertEqual(document["environment"], "development")
            self.assertIs(document["active"], False)
            for field in ("clusters", "exports", "releases", "bindings", "references"):
                if field in document:
                    self.assertEqual(document[field], [], f"{name} unexpectedly activates {field}")

    def test_render_inputs_have_a_stable_order(self):
        rendered = []
        for name in DOCUMENTS:
            rendered.append((name, json.loads((ROOT / "environments/development" / name).read_text())))
        first = json.dumps(rendered, sort_keys=True, separators=(",", ":"))
        second = json.dumps(rendered, sort_keys=True, separators=(",", ":"))
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
