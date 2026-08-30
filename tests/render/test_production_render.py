import json
import os
import re
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
