import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class EvidenceChainTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._build_directory = tempfile.TemporaryDirectory()
        cls.promotectl = Path(cls._build_directory.name) / "promotectl"
        runfile = os.environ.get("PROMOTECTL_RUNFILE")
        if runfile:
            candidate = Path(runfile)
            if not candidate.is_absolute():
                candidate = Path(os.environ["TEST_SRCDIR"]) / os.environ["TEST_WORKSPACE"] / candidate
            if candidate.is_file():
                cls.promotectl = candidate
                return
        if shutil.which("go") is None or not (ROOT / "tooling/go.mod").exists():
            cls.promotectl = None
            return
        subprocess.run(
            ["go", "build", "-o", str(cls.promotectl), "./cmd/promotectl"],
            cwd=ROOT / "tooling",
            check=True,
            capture_output=True,
            text=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls._build_directory.cleanup()

    def test_receipt_schema_requires_complete_immutable_chain(self):
        schema = json.loads((ROOT / "schemas/v1/promotion_receipt.schema.json").read_text())
        required = set(schema["required"])
        self.assertTrue({"releaseClass", "component", "cluster", "sourceRevision", "artifactReference", "artifactDigest", "priorDigest", "attestationDigest", "signer", "issuer", "issuedAt", "approvals", "repository", "workflowRunID", "workflowRunAttempt", "checkedOutRevision", "requester"} <= required)
        self.assertEqual(schema["properties"]["approvals"]["minItems"], 2)
        self.assertTrue(DIGEST_PATTERN.fullmatch("sha256:" + "a" * 64))
        self.assertFalse(DIGEST_PATTERN.fullmatch("latest"))

    def test_protected_workflow_evidence_is_not_user_supplied(self):
        workflow = (ROOT / ".github/workflows/promotion.yml").read_text()
        self.assertIn("CONNECTED_GOVERNANCE_READY", workflow)
        self.assertIn("PROMOTION_GOVERNANCE_EVIDENCE", workflow)
        self.assertIn("PROMOTION_TRUSTED_SIGNER", workflow)
        self.assertIn("PROMOTION_TRUSTED_ISSUER", workflow)
        self.assertIn("github-environment:${{ inputs.environment }}-promotion", workflow)
        self.assertNotIn("approvals:\n        description:", workflow)
        self.assertNotIn("signer:\n        description:", workflow)
        self.assertNotIn("issued_at:\n        description:", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertNotIn("id-token: write", workflow)
        self.assertIn('test "$AUTOMATION_REVISION" = "$GITHUB_SHA"', workflow)
        self.assertIn("verify-transition --root ..", workflow)
        self.assertIn("EVIDENCE_VERIFIER_IMPLEMENTATION: unbound", workflow)
        self.assertIn('!= verified-v1', workflow)
        self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", workflow)

    def _receipt(self, **overrides):
        issued_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        values = {
            "environment": "development",
            "release-class": "service",
            "component": "api-service",
            "cluster": "dev-cluster",
            "source-revision": "e" * 40,
            "artifact-reference": "registry.example/api@sha256:" + "b" * 64,
            "artifact-digest": "sha256:" + "b" * 64,
            "prior-digest": "sha256:" + "c" * 64,
            "attestation-digest": "sha256:" + "d" * 64,
            "signer": "https://issuer.example/workload/release",
            "issuer": "https://issuer.example",
            "issued-at": issued_at,
            "approvals": "review:release,review:security",
            "repository": "mindclade/gitops",
            "workflow-run-id": "12345",
            "workflow-run-attempt": "2",
            "checked-out-revision": "a" * 40,
            "requester": "release-operator",
        }
        values.update(overrides)
        command = [str(self.promotectl), "receipt"]
        for name, value in values.items():
            command.extend((f"--{name}", value))
        return subprocess.run(command, capture_output=True, text=True)

    def test_receipt_rejects_unsafe_identity_stale_time_and_unbound_context(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")
        accepted = self._receipt()
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        receipt = json.loads(accepted.stdout)
        self.assertNotEqual(receipt["sourceRevision"], receipt["checkedOutRevision"])
        self.assertEqual(receipt["repository"], "mindclade/gitops")

        future = (datetime.now(timezone.utc) + timedelta(minutes=6)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        expired = (datetime.now(timezone.utc) - timedelta(hours=25)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        invalid = (
            {"signer": "https://user@issuer.example/workload"},
            {"signer": "https://issuer.example/workload?token=secret"},
            {"signer": "https://issuer.example/workload#mutable"},
            {"signer": "https:///missing-host"},
            {"issuer": "https://user@issuer.example"},
            {"issuer": "https://issuer.example?tenant=mutable"},
            {"artifact-reference": "registry.example/api:latest"},
            {"release-class": "unknown"},
            {"issued-at": future},
            {"issued-at": expired},
            {"issued-at": datetime.now(timezone.utc).replace(microsecond=0).isoformat()},
            {"repository": "fork/gitops"},
            {"workflow-run-id": "0"},
            {"checked-out-revision": "mutable"},
            {"requester": "invalid actor"},
        )
        for override in invalid:
            with self.subTest(override=override):
                result = self._receipt(**override)
                self.assertNotEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
