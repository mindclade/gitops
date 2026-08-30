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
ENVIRONMENTS = ("development", "staging", "production", "restricted")
GOVERNANCE_DIGEST = "sha256:" + "f" * 64


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
        artifact_reference_pattern = re.compile(schema["properties"]["artifactReference"]["pattern"])
        self.assertTrue(artifact_reference_pattern.fullmatch("registry.example/api@sha256:" + "a" * 64))
        self.assertFalse(artifact_reference_pattern.fullmatch("@sha256:" + "a" * 64))
        approvals = schema["properties"]["approvals"]
        self.assertEqual(
            approvals["contains"]["pattern"],
            "^governance-evidence:sha256:[0-9a-f]{64}$",
        )
        self.assertEqual(approvals["minContains"], 1)
        self.assertEqual(approvals["maxContains"], 1)
        contexts = {
            condition["if"]["properties"]["environment"]["const"]:
            condition["then"]["properties"]["approvals"]["contains"]["const"]
            for condition in schema["allOf"]
            if "environment" in condition["if"].get("properties", {})
        }
        self.assertEqual(
            contexts,
            {
                environment: f"github-environment:{environment}-promotion"
                for environment in ENVIRONMENTS
            },
        )

    def test_protected_workflow_evidence_is_not_user_supplied(self):
        workflow = (ROOT / ".github/workflows/promotion.yml").read_text()
        self.assertIn("CONNECTED_GOVERNANCE_READY", workflow)
        self.assertIn("PROMOTION_GOVERNANCE_EVIDENCE", workflow)
        self.assertIn("PROMOTION_TRUSTED_SIGNER", workflow)
        self.assertIn("PROMOTION_TRUSTED_ISSUER", workflow)
        self.assertNotIn("approvals:\n        description:", workflow)
        self.assertNotIn("signer:\n        description:", workflow)
        self.assertNotIn("issued_at:\n        description:", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertNotIn("id-token: write", workflow)
        self.assertIn('test "$AUTOMATION_REVISION" = "$GITHUB_SHA"', workflow)
        self.assertIn('[[ "$GOVERNANCE_EVIDENCE" =~ ^sha256:[0-9a-f]{64}$ ]]', workflow)
        self.assertIn('[[ "$ARTIFACT_REFERENCE" =~ ^(oci://)?[a-z0-9]+([.-][a-z0-9]+)*', workflow)
        self.assertIn('if [[ "$RELEASE_CLASS" = platform ]]', workflow)
        self.assertIn('[[ "$ARTIFACT_REFERENCE" != oci://* ]]', workflow)
        self.assertIn('[[ "$ARTIFACT_REFERENCE" == *@"$ARTIFACT_DIGEST" ]]', workflow)
        self.assertIn("verify-transition --root ..", workflow)
        self.assertIn("EVIDENCE_VERIFIER_GATE: blocked-pending-jit-09", workflow)
        self.assertIn('!= qualified-v1', workflow)
        self.assertIn('[[ "$ARTIFACT_SOURCE_REVISION" =~ ^[0-9a-f]{40}$ ]]', workflow)
        self.assertIn('[[ "$ATTESTATION_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]', workflow)
        self.assertNotIn("upload-artifact@", workflow)
        self.assertNotIn("promotectl receipt", workflow)
        self.assertNotIn("promotion-receipt.json", workflow)

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
            "repository": "mindclade/gitops",
            "workflow-run-id": "12345",
            "workflow-run-attempt": "2",
            "checked-out-revision": "a" * 40,
            "requester": "release-operator",
        }
        values.update(overrides)
        if "approvals" not in overrides:
            values["approvals"] = (
                f"github-environment:{values['environment']}-promotion,"
                f"governance-evidence:{GOVERNANCE_DIGEST}"
            )
        command = [str(self.promotectl), "receipt"]
        for name, value in values.items():
            command.extend((f"--{name}", value))
        return subprocess.run(command, capture_output=True, text=True)

    def test_receipt_accepts_governed_evidence_in_every_environment(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")
        for environment in ENVIRONMENTS:
            with self.subTest(environment=environment):
                accepted = self._receipt(environment=environment)
                self.assertEqual(accepted.returncode, 0, accepted.stderr)
                receipt = json.loads(accepted.stdout)
                self.assertEqual(receipt["environment"], environment)
                self.assertNotEqual(receipt["sourceRevision"], receipt["checkedOutRevision"])
                self.assertEqual(receipt["repository"], "mindclade/gitops")

    def test_receipt_accepts_canonical_artifact_reference_for_each_release_class(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")
        digest = "sha256:" + "b" * 64
        cases = (
            ("platform", f"oci://registry.example:5443/platform/kueue@{digest}"),
            ("service", f"registry.example:5443/mindclade/api-service@{digest}"),
            ("worker", f"registry.example/mindclade/training-worker@{digest}"),
        )
        for release_class, artifact_reference in cases:
            with self.subTest(release_class=release_class):
                result = self._receipt(**{
                    "release-class": release_class,
                    "artifact-reference": artifact_reference,
                })
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_receipt_rejects_missing_malformed_or_mismatched_governance_in_every_environment(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")
        for environment in ENVIRONMENTS:
            context = f"github-environment:{environment}-promotion"
            other_environment = "staging" if environment == "development" else "development"
            invalid_approvals = (
                f"{context},review:security",
                f"{context},governance-evidence:not-a-digest",
                f"github-environment:{other_environment}-promotion,governance-evidence:{GOVERNANCE_DIGEST}",
                f"{context},github-environment:{other_environment}-promotion,governance-evidence:{GOVERNANCE_DIGEST}",
                f"{context},governance-evidence:not-a-digest,governance-evidence:{GOVERNANCE_DIGEST}",
                f"{context},governance-evidence:{GOVERNANCE_DIGEST},governance-evidence:{GOVERNANCE_DIGEST}",
                f"{context},governance-evidence:{GOVERNANCE_DIGEST},governance-evidence:{'sha256:' + 'e' * 64}",
                f"{context},governance-evidence:{GOVERNANCE_DIGEST},xx",
                f"{context},governance-evidence:{GOVERNANCE_DIGEST},{'x' * 257}",
                f"{context},review:security\napproval,governance-evidence:{GOVERNANCE_DIGEST}",
                f"{context},review:security\rapproval,governance-evidence:{GOVERNANCE_DIGEST}",
            )
            for approvals in invalid_approvals:
                with self.subTest(environment=environment, approvals=approvals):
                    result = self._receipt(environment=environment, approvals=approvals)
                    self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_receipt_rejects_artifact_references_outside_the_schema_contract(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")
        digest = "sha256:" + "b" * 64
        invalid_references = (
            "@" + digest,
            "registry.example/api @" + digest,
            "registry.example/api\t@" + digest,
            "registry.example/api@" + digest + " ",
            "registry.example/api@sha256:" + "a" * 64,
            "registry.example/api:latest",
            "registry.example/api@latest",
            "registry.example/api@path@" + digest,
            "https://registry.example/api@" + digest,
            "registry.example/user:password@api@" + digest,
            "registry.example/api?channel=stable@" + digest,
            "registry.example/api#fragment@" + digest,
            "Registry.example/api@" + digest,
            "oci://registry.example/api@" + digest,
            "registry.example/api_@" + digest,
        )
        for artifact_reference in invalid_references:
            with self.subTest(artifact_reference=artifact_reference):
                result = self._receipt(**{"artifact-reference": artifact_reference})
                self.assertNotEqual(result.returncode, 0, result.stdout)

        platform_without_oci = self._receipt(**{
            "release-class": "platform",
            "artifact-reference": "registry.example/platform/kueue@" + digest,
        })
        self.assertNotEqual(platform_without_oci.returncode, 0, platform_without_oci.stdout)

    def test_receipt_rejects_unsafe_identity_stale_time_and_invalid_metadata(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        future = (datetime.now(timezone.utc) + timedelta(minutes=6)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        expired = (datetime.now(timezone.utc) - timedelta(hours=25)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        invalid = (
            {"signer": "https://user@issuer.example/workload"},
            {"signer": "https://issuer.example/workload?token=secret"},
            {"signer": "https://issuer.example/workload#mutable"},
            {"signer": "https:///missing-host"},
            {"issuer": "https://user@issuer.example"},
            {"issuer": "https://issuer.example?tenant=mutable"},
            {"release-class": "unknown"},
            {"component": "invalid-component-"},
            {"cluster": "invalid-cluster-"},
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
