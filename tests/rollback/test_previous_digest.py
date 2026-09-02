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
        self.assertIn("options: [production]", workflow)
        self.assertNotIn("options: [development, staging, production, restricted]", workflow)
        self.assertIn("name: production-promotion", workflow)
        self.assertNotIn("name: ${{ inputs.environment }}-promotion", workflow)
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
        self.assertIn("PROMOTION_JIT09_QUALIFICATION", workflow)
        self.assertIn("go run ./cmd/promotectl verify-evidence", workflow)
        self.assertIn("ACTIONS_ID_TOKEN_REQUEST_TOKEN", workflow)
        self.assertIn("!= qualified-v1", workflow)
        self.assertIn('[[ "$ARTIFACT_SOURCE_REVISION" =~ ^[0-9a-f]{40}$ ]]', workflow)
        self.assertIn('[[ "$ATTESTATION_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]', workflow)
        self.assertNotIn("signer:\n        description:", workflow)
        self.assertNotIn("promotectl rollback", workflow)
        self.assertNotIn("upload-artifact@", workflow)
        self.assertNotIn("rollback-receipt.json", workflow)
        self.assertNotIn("kubectl", workflow)
        self.assertNotIn("argocd app", workflow)
        self.assertNotIn("contents: write", workflow)

        promotion_workflow = (ROOT / ".github/workflows/promotion.yml").read_text()
        self.assertIn("options: [production]", promotion_workflow)
        self.assertNotIn(
            "options: [development, staging, production, restricted]",
            promotion_workflow,
        )
        self.assertIn("name: production-promotion", promotion_workflow)
        self.assertNotIn("name: ${{ inputs.environment }}-promotion", promotion_workflow)

    def test_emergency_runbook_requires_qualified_jit_09_without_claiming_a_receipt(self):
        runbook = (ROOT / "runbooks/emergency-rollback.md").read_text()
        self.assertIn("fail-closed JIT-09 qualification gate", runbook)
        self.assertIn("does not change desired state", runbook)
        self.assertIn("not a rollback receipt", runbook)
        self.assertNotIn("Review the emitted receipt checksum", runbook)
        self.assertNotIn("before declaring recovery", runbook)


if __name__ == "__main__":
    unittest.main()
