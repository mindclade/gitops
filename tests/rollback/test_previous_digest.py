import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class PreviousDigestTest(unittest.TestCase):
    def test_rollback_contract_requires_previous_digest_and_evidence(self):
        schema = json.loads((ROOT / "schemas/v1/promotion_receipt.schema.json").read_text())
        self.assertIn("priorDigest", schema["required"])
        self.assertIn("attestationDigest", schema["required"])
        self.assertEqual(schema["properties"]["action"]["enum"], ["promote", "rollback"])
        source = (ROOT / "tooling/internal/evidence/receipt.go").read_text()
        self.assertIn("artifact and prior digests must differ", source)

    def test_rollback_workflow_is_validation_only_and_governed(self):
        workflow = (ROOT / ".github/workflows/rollback-verification.yml").read_text()
        self.assertIn("CONNECTED_GOVERNANCE_READY", workflow)
        self.assertIn("PROMOTION_GOVERNANCE_EVIDENCE", workflow)
        self.assertIn("PROMOTION_TRUSTED_SIGNER", workflow)
        self.assertIn("PROMOTION_TRUSTED_ISSUER", workflow)
        self.assertIn("previous_digest:", workflow)
        self.assertIn('--artifact-digest "$PREVIOUS_DIGEST"', workflow)
        self.assertIn('test "$AUTOMATION_REVISION" = "$GITHUB_SHA"', workflow)
        self.assertIn('[[ "$GOVERNANCE_EVIDENCE" =~ ^sha256:[0-9a-f]{64}$ ]]', workflow)
        self.assertIn(
            '[[ "$ARTIFACT_REFERENCE" =~ ^(oci://)?[a-z0-9]+([.-][a-z0-9]+)*',
            workflow,
        )
        self.assertIn('if [[ "$RELEASE_CLASS" = platform ]]', workflow)
        self.assertIn('[[ "$ARTIFACT_REFERENCE" != oci://* ]]', workflow)
        self.assertIn('[[ "$ARTIFACT_REFERENCE" == *@"$PREVIOUS_DIGEST" ]]', workflow)
        self.assertIn("verify-transition --root ..", workflow)
        self.assertIn("EVIDENCE_VERIFIER_GATE: blocked-pending-jit-09", workflow)
        self.assertIn('!= qualified-v1', workflow)
        self.assertIn('[[ "$ARTIFACT_SOURCE_REVISION" =~ ^[0-9a-f]{40}$ ]]', workflow)
        self.assertIn('[[ "$ATTESTATION_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]', workflow)
        self.assertNotIn("signer:\n        description:", workflow)
        self.assertNotIn("promotectl rollback", workflow)
        self.assertNotIn("upload-artifact@", workflow)
        self.assertNotIn("rollback-receipt.json", workflow)
        self.assertNotIn("kubectl", workflow)
        self.assertNotIn("argocd app", workflow)
        self.assertNotIn("contents: write", workflow)


if __name__ == "__main__":
    unittest.main()
