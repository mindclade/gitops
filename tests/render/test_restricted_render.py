# pyright: basic, reportArgumentType=false, reportAttributeAccessIssue=false, reportCallIssue=false, reportOperatorIssue=false, reportOptionalMemberAccess=false, reportOptionalSubscript=false
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


class RestrictedRenderTest(unittest.TestCase):
    def test_restricted_is_inactive_and_deny_all(self):
        directory = ROOT / "environments/restricted"
        documents = [
            json.loads(path.read_text())
            for path in sorted(directory.glob("*.yaml"))
            if path.name != "kustomization.yaml"
        ]
        self.assertEqual(len(documents), 7)
        self.assertTrue(all(document["environment"] == "restricted" for document in documents))
        self.assertTrue(all(document["active"] is False for document in documents))
        self.assertTrue(
            all(
                not document.get(field)
                for document in documents
                for field in ("clusters", "exports", "releases", "bindings", "references")
                if field in document
            )
        )

    def test_default_project_and_restricted_project_deny_sync(self):
        project = (ROOT / "projects/restricted.appproject.yaml").read_text()
        self.assertIn("name: default", project)
        self.assertIn("gitops.mindclade.io/authority: deny-all", project)
        self.assertGreaterEqual(project.count("destinations: []"), 2)
        self.assertIn("kind: deny", project)
        self.assertIn("duration: 24h", project)


if __name__ == "__main__":
    unittest.main()
