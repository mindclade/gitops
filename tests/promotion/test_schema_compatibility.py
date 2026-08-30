import copy
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class SchemaCompatibilityTest(unittest.TestCase):
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

    def test_v1_schemas_are_strict_and_identified(self):
        schemas = sorted((ROOT / "schemas/v1").glob("*.schema.json"))
        self.assertEqual(len(schemas), 7)
        identifiers = set()
        for path in schemas:
            schema = json.loads(path.read_text())
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertEqual(schema["type"], "object")
            self.assertIs(schema["additionalProperties"], False)
            self.assertIn("schemaVersion", schema["required"])
            self.assertNotIn(schema["$id"], identifiers)
            identifiers.add(schema["$id"])

    def test_environment_documents_have_only_declared_top_level_fields(self):
        schema_for_file = {
            "cluster-set.yaml": "cluster_set.schema.json",
            "infrastructure-exports.yaml": "infrastructure_exports.schema.json",
            "platform-releases.yaml": "platform_releases.schema.json",
            "service-releases.yaml": "workload_releases.schema.json",
            "worker-releases.yaml": "workload_releases.schema.json",
            "policy-bindings.yaml": "policy_bindings.schema.json",
            "secret-references.yaml": "secret_references.schema.json",
        }
        for environment in ("development", "staging", "production", "restricted"):
            for filename, schema_name in schema_for_file.items():
                document = json.loads((ROOT / "environments" / environment / filename).read_text())
                schema = json.loads((ROOT / "schemas/v1" / schema_name).read_text())
                self.assertTrue(set(document) <= set(schema["properties"]), filename)
                self.assertTrue(set(schema["required"]) <= set(document), filename)

    def test_workload_evidence_matches_policy_and_receipt_contract(self):
        workload = json.loads((ROOT / "schemas/v1/workload_releases.schema.json").read_text())
        release_item = workload["properties"]["releases"]["items"]
        evidence = release_item["properties"]["evidence"]
        self.assertTrue({"signature", "sbom", "provenance", "vulnerabilityScan", "evaluation", "signer", "issuer"} <= set(evidence["required"]))
        self.assertTrue({"releaseRecordDigest", "promotionReceiptDigest", "governanceEvidenceDigest", "desiredStateRevision", "desiredStatePath"} <= set(release_item["required"]))
        signed_policy = (ROOT / "policy/signed_release.rego").read_text()
        self.assertIn('"vulnerabilityScan"', signed_policy)
        self.assertIn('"promotionReceiptDigest"', signed_policy)
        self.assertIn('"governanceEvidenceDigest"', signed_policy)

    @staticmethod
    def _digest(character):
        return "sha256:" + character * 64

    def _active_environment(self, root, environment="development", initial_percent=0):
        directory = root / "environments" / environment
        source_revision = "c" * 40
        desired_revision = "d" * 40
        digest = self._digest("a")
        prior = self._digest("b")
        evidence = {
            "signature": self._digest("c"),
            "sbom": self._digest("d"),
            "provenance": self._digest("e"),
            "vulnerabilityScan": self._digest("f"),
            "signer": "https://issuer.example/workload/release",
            "issuer": "https://issuer.example",
        }
        cluster = {
            "name": "dev-cluster",
            "server": "https://cluster.example",
            "desiredStateRevision": desired_revision,
            "activationRecordDigest": self._digest("1"),
            "labels": {
                "gitops.mindclade.io/active": "true",
                "gitops.mindclade.io/environment": environment,
            },
        }
        infrastructure_export = {
            "apiVersion": "infrastructure.mindclade.dev/v1",
            "kind": "InfrastructureExport",
            "metadata": {
                "environment": environment,
                "stack": "clusters",
                "sourceRepository": "mindclade/infrastructure-live",
                "sourceCommit": "e" * 40,
                "root": f"opentofu/live/{environment}/clusters",
                "planDigest": self._digest("2"),
                "schemaDigest": self._digest("3"),
                "generatedAt": "2026-08-29T12:00:00Z",
            },
            "spec": {
                "resources": [{
                    "kind": "cluster-membership",
                    "name": "dev-cluster",
                    "uri": "//gkehub.googleapis.com/projects/dev/locations/global/memberships/dev-cluster",
                }],
                "evidence": {
                    "signature": {"uri": "https://evidence.example/signature", "digest": self._digest("4")},
                    "provenance": {"uri": "https://evidence.example/provenance", "digest": self._digest("5")},
                },
            },
        }
        platform_release = {
            "component": "kueue",
            "cluster": "dev-cluster",
            "namespace": "kueue-system",
            "artifact": f"oci://registry.example/kueue@{digest}",
            "digest": digest,
            "priorDigest": prior,
            "sourceRevision": source_revision,
            "desiredStateRevision": desired_revision,
            "releaseRecordDigest": self._digest("6"),
            "promotionReceiptDigest": self._digest("7"),
            "governanceEvidenceDigest": self._digest("8"),
            "evidence": evidence,
        }
        workload_release = {
            "component": "api-service",
            "cluster": "dev-cluster",
            "namespace": "services",
            "desiredStatePath": f"environments/{environment}/services/api-service",
            "artifact": f"registry.example/api@{digest}",
            "digest": digest,
            "priorDigest": prior,
            "sourceRevision": source_revision,
            "desiredStateRevision": desired_revision,
            "releaseRecordDigest": self._digest("9"),
            "promotionReceiptDigest": self._digest("0"),
            "governanceEvidenceDigest": self._digest("1"),
            "configurationDigest": self._digest("2"),
            "evidence": {**evidence, "evaluation": self._digest("3")},
            "rollout": {"strategy": "manual", "initialPercent": initial_percent, "automaticPromotion": False},
        }
        documents = {
            "cluster-set.yaml": {"schemaVersion": "v1", "environment": environment, "active": True, "clusters": [cluster]},
            "infrastructure-exports.yaml": {"schemaVersion": "v1", "environment": environment, "active": True, "exports": [infrastructure_export]},
            "platform-releases.yaml": {"schemaVersion": "v1", "environment": environment, "active": True, "releases": [platform_release]},
            "service-releases.yaml": {"schemaVersion": "v1", "environment": environment, "active": True, "releaseClass": "service", "releases": [workload_release]},
            "worker-releases.yaml": {"schemaVersion": "v1", "environment": environment, "active": True, "releaseClass": "worker", "releases": [{**workload_release, "component": "gpu-worker", "namespace": "workers", "desiredStatePath": f"environments/{environment}/workers/gpu-worker"}]},
            "policy-bindings.yaml": {"schemaVersion": "v1", "environment": environment, "active": True, "bindings": [{"name": "baseline", "policyDigest": self._digest("4"), "enforcement": "deny", "namespaces": ["services", "workers"]}]},
            "secret-references.yaml": {"schemaVersion": "v1", "environment": environment, "active": True, "references": [{"name": "service-runtime", "namespace": "services", "externalSecret": "service-runtime", "storeRef": "qualified-store", "purpose": "Runtime credential reference only"}]},
        }
        for name, document in documents.items():
            (directory / name).write_text(json.dumps(document, separators=(",", ":")) + "\n")
        return infrastructure_export

    def _repository_copy(self):
        directory = tempfile.TemporaryDirectory()
        target = Path(directory.name) / "gitops"
        shutil.copytree(ROOT, target, ignore=shutil.ignore_patterns(".git"))
        return directory, target

    def _validate(self, root):
        return subprocess.run(
            [str(self.promotectl), "validate", "--root", str(root)],
            capture_output=True,
            text=True,
        )

    def test_infrastructure_export_wire_contract_active_blocker(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            self._active_environment(repository)
            result = self._validate(repository)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("external signature and attestation verifier implementation is unbound", result.stderr)
        finally:
            directory.cleanup()

    def test_cluster_server_rejects_credentials_and_mutable_components(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        invalid_servers = (
            "https://user:password@cluster.example",
            "https://cluster.example/path",
            "https://cluster.example?token=secret",
            "https://cluster.example#mutable",
            "http://cluster.example",
            "https:///missing-host",
            "https://cluster.example/" + "a" * 2049,
        )
        for server in invalid_servers:
            with self.subTest(server=server):
                directory, repository = self._repository_copy()
                try:
                    self._active_environment(repository)
                    path = repository / "environments/development/cluster-set.yaml"
                    document = json.loads(path.read_text())
                    document["clusters"][0]["server"] = server
                    path.write_text(json.dumps(document, separators=(",", ":")) + "\n")
                    result = self._validate(repository)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertNotIn("external signature and attestation verifier implementation is unbound", result.stderr)
                finally:
                    directory.cleanup()

    def test_infrastructure_export_wire_contract_negative_mutations(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        mutations = {
            "cross-environment": lambda wrapper: wrapper["exports"][0]["metadata"].update(environment="staging"),
            "secret-bearing-query": lambda wrapper: wrapper["exports"][0]["spec"]["resources"][0].update(uri="https://cluster.example/path?token=secret"),
            "duplicate-stack": lambda wrapper: wrapper["exports"].append({**copy.deepcopy(wrapper["exports"][0]), "metadata": {**wrapper["exports"][0]["metadata"], "planDigest": self._digest("a")}}),
            "duplicate-resource": lambda wrapper: wrapper["exports"].append({**copy.deepcopy(wrapper["exports"][0]), "metadata": {**wrapper["exports"][0]["metadata"], "stack": "network", "root": "opentofu/live/development/network"}}),
            "unknown-nested-field": lambda wrapper: wrapper["exports"][0]["spec"]["evidence"]["signature"].update(token="forbidden"),
            "missing-membership": lambda wrapper: wrapper["exports"][0]["spec"]["resources"][0].update(name="different-cluster"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                directory, repository = self._repository_copy()
                try:
                    self._active_environment(repository)
                    path = repository / "environments/development/infrastructure-exports.yaml"
                    wrapper = json.loads(path.read_text())
                    mutate(wrapper)
                    path.write_text(json.dumps(wrapper, separators=(",", ":")) + "\n")
                    result = self._validate(repository)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                finally:
                    directory.cleanup()

    def test_downstream_contracts_can_be_staged_independently_after_root(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            self._active_environment(repository)
            path = repository / "environments/development/secret-references.yaml"
            document = json.loads(path.read_text())
            document["active"] = False
            document["references"] = []
            path.write_text(json.dumps(document, separators=(",", ":")) + "\n")
            result = self._validate(repository)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("external signature and attestation verifier implementation is unbound", result.stderr)
            self.assertNotIn("active state", result.stderr)
        finally:
            directory.cleanup()

    def test_environment_root_can_be_activated_before_downstream_contracts(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            self._active_environment(repository)
            downstream = {
                "platform-releases.yaml": "releases",
                "service-releases.yaml": "releases",
                "worker-releases.yaml": "releases",
                "policy-bindings.yaml": "bindings",
                "secret-references.yaml": "references",
            }
            for filename, collection in downstream.items():
                path = repository / "environments/development" / filename
                document = json.loads(path.read_text())
                document["active"] = False
                document[collection] = []
                path.write_text(json.dumps(document, separators=(",", ":")) + "\n")

            result = self._validate(repository)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("external signature and attestation verifier implementation is unbound", result.stderr)
            self.assertNotIn("active state", result.stderr)
        finally:
            directory.cleanup()

    def test_environment_root_documents_must_activate_as_an_atomic_pair(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        cases = (
            ("cluster-set.yaml", "clusters"),
            ("infrastructure-exports.yaml", "exports"),
        )
        for filename, collection in cases:
            with self.subTest(inactive=filename):
                directory, repository = self._repository_copy()
                try:
                    self._active_environment(repository)
                    path = repository / "environments/development" / filename
                    document = json.loads(path.read_text())
                    document["active"] = False
                    document[collection] = []
                    path.write_text(json.dumps(document, separators=(",", ":")) + "\n")

                    result = self._validate(repository)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("cluster-set.yaml and infrastructure-exports.yaml active states must match", result.stderr)
                finally:
                    directory.cleanup()

    def test_downstream_contracts_cannot_activate_before_environment_root(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        downstream = {
            "platform-releases.yaml": "releases",
            "service-releases.yaml": "releases",
            "worker-releases.yaml": "releases",
            "policy-bindings.yaml": "bindings",
            "secret-references.yaml": "references",
        }
        for selected in downstream:
            with self.subTest(selected=selected):
                directory, repository = self._repository_copy()
                try:
                    self._active_environment(repository)
                    for filename, collection in (("cluster-set.yaml", "clusters"), ("infrastructure-exports.yaml", "exports")):
                        path = repository / "environments/development" / filename
                        document = json.loads(path.read_text())
                        document["active"] = False
                        document[collection] = []
                        path.write_text(json.dumps(document, separators=(",", ":")) + "\n")
                    for filename, collection in downstream.items():
                        if filename == selected:
                            continue
                        path = repository / "environments/development" / filename
                        document = json.loads(path.read_text())
                        document["active"] = False
                        document[collection] = []
                        path.write_text(json.dumps(document, separators=(",", ":")) + "\n")

                    result = self._validate(repository)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(f"{selected} cannot be active before the development environment root", result.stderr)
                finally:
                    directory.cleanup()

    def test_workload_release_class_must_match_its_filename(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        cases = (
            ("service-releases.yaml", "worker", "service"),
            ("worker-releases.yaml", "service", "worker"),
        )
        for filename, declared, required in cases:
            with self.subTest(filename=filename):
                directory, repository = self._repository_copy()
                try:
                    path = repository / "environments/development" / filename
                    document = json.loads(path.read_text())
                    document["releaseClass"] = declared
                    path.write_text(json.dumps(document, separators=(",", ":")) + "\n")

                    result = self._validate(repository)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(f'required class is "{required}"', result.stderr)
                finally:
                    directory.cleanup()

    def test_transition_verification_enforces_workload_file_release_class(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            self._active_environment(repository)
            path = repository / "environments/development/service-releases.yaml"
            document = json.loads(path.read_text())
            document["releaseClass"] = "worker"
            path.write_text(json.dumps(document, separators=(",", ":")) + "\n")

            result = subprocess.run(
                [
                    str(self.promotectl),
                    "verify-transition",
                    "--root", str(repository),
                    "--action", "promote",
                    "--environment", "development",
                    "--release-class", "service",
                    "--component", "api-service",
                    "--cluster", "dev-cluster",
                    "--artifact-digest", self._digest("f"),
                    "--prior-digest", self._digest("a"),
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn('required class is "service"', result.stderr)
        finally:
            directory.cleanup()

    def test_workload_desired_state_path_is_component_scoped(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            self._active_environment(repository)
            path = repository / "environments/development/service-releases.yaml"
            document = json.loads(path.read_text())
            document["releases"][0]["desiredStatePath"] = "environments/development/services/another-service"
            path.write_text(json.dumps(document, separators=(",", ":")) + "\n")

            result = self._validate(repository)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("desiredStatePath", result.stderr)
            self.assertIn("environments/development/services/api-service", result.stderr)
        finally:
            directory.cleanup()

    def test_protected_canary_policy_is_enforced_by_source_validator(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")
        directory, repository = self._repository_copy()
        try:
            self._active_environment(repository, environment="production", initial_percent=25)
            result = self._validate(repository)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("protected canary may not begin above 10 percent", result.stderr)
        finally:
            directory.cleanup()


if __name__ == "__main__":
    unittest.main()
