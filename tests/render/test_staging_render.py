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
