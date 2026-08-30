import json
import os
import tempfile
import unittest
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
