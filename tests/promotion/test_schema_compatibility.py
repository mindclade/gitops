import base64
import copy
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from functools import lru_cache
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
INFRASTRUCTURE_EXPORT_PRODUCER_COMMIT = "e80be3f354e61c518ae347bf393f35fb368fc158"
INFRASTRUCTURE_EXPORT_SCHEMA_DIGEST = "sha256:12fddd3a67b663499a8f5d3972cce56343da0c43795ac5caf8891c176957648a"
BOOTSTRAP_TEST_REVISION = "b" * 40
PREVIOUS_TEST_REVISION = "a" * 40
TEST_VALIDATION_TIME = datetime.now(timezone.utc).replace(microsecond=0)


def _canonical_time(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


@lru_cache(maxsize=None)
def _p256_sign(
    message,
    key_seed=b"mindclade-test-p256-key",
    nonce_seed=b"mindclade-test-p256-nonce",
):
    # Deterministic test-only P-256 arithmetic, matching the producer fixture.
    field = int("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
    order = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
    base = (
        int("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
        int("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
    )

    def add(left, right):
        if left is None:
            return right
        if right is None:
            return left
        x1, y1 = left
        x2, y2 = right
        if x1 == x2 and (y1 + y2) % field == 0:
            return None
        if left == right:
            slope = (3 * x1 * x1 - 3) * pow(2 * y1, field - 2, field) % field
        else:
            slope = (y2 - y1) * pow(x2 - x1, field - 2, field) % field
        x3 = (slope * slope - x1 - x2) % field
        return x3, (slope * (x1 - x3) - y1) % field

    def multiply(point, scalar):
        result = None
        addend = point
        while scalar:
            if scalar & 1:
                result = add(result, addend)
            addend = add(addend, addend)
            scalar >>= 1
        return result

    def integer(value):
        encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if encoded[0] & 0x80:
            encoded = b"\x00" + encoded
        return b"\x02" + bytes([len(encoded)]) + encoded

    scalar = int.from_bytes(hashlib.sha256(key_seed).digest(), "big") % (order - 1) + 1
    public_x, public_y = multiply(base, scalar)
    uncompressed = b"\x04" + public_x.to_bytes(32, "big") + public_y.to_bytes(32, "big")
    public_key = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200") + uncompressed
    digest = hashlib.sha256(message).digest()
    nonce = int.from_bytes(hashlib.sha256(nonce_seed + digest).digest(), "big") % (order - 1) + 1
    nonce_x, _ = multiply(base, nonce)
    r = nonce_x % order
    s = (pow(nonce, -1, order) * (int.from_bytes(digest, "big") + r * scalar)) % order
    encoded = integer(r) + integer(s)
    return public_key, b"\x30" + bytes([len(encoded)]) + encoded


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

    def test_policy_and_secret_resource_names_use_dns_label_grammar(self):
        fields = {
            "policy_bindings.schema.json": ("name", "namespaces"),
            "secret_references.schema.json": ("name", "namespace", "externalSecret", "storeRef"),
        }
        for schema_name, names in fields.items():
            schema = json.loads((ROOT / "schemas/v1" / schema_name).read_text())
            collection = "bindings" if schema_name.startswith("policy") else "references"
            properties = schema["properties"][collection]["items"]["properties"]
            for name in names:
                specification = properties[name]
                if specification.get("type") == "array":
                    specification = specification["items"]
                pattern = re.compile(specification["pattern"])
                for valid in ("a", "0", "a-b", "a" * 63):
                    self.assertTrue(pattern.fullmatch(valid), (schema_name, name, valid))
                for invalid in ("-a", "a-", "Upper", "a" * 64):
                    self.assertFalse(pattern.fullmatch(invalid), (schema_name, name, invalid))

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

    def test_infrastructure_export_schema_matches_reviewed_producer_contract(self):
        schema = json.loads((ROOT / "schemas/v1/infrastructure_exports.schema.json").read_text())
        self.assertIn(INFRASTRUCTURE_EXPORT_PRODUCER_COMMIT, schema["$comment"])
        export = schema["$defs"]["infrastructureExport"]
        metadata = export["properties"]["metadata"]
        self.assertFalse(metadata["additionalProperties"])
        self.assertTrue({
            "providerLockDigest", "backendStateDigest", "backendLineage", "backendSerial",
        } <= set(metadata["required"]))
        self.assertEqual(metadata["properties"]["schemaDigest"]["const"], INFRASTRUCTURE_EXPORT_SCHEMA_DIGEST)
        self.assertIn("pattern", metadata["properties"]["sourceCommit"])
        self.assertNotIn("const", metadata["properties"]["sourceCommit"])
        resources = export["properties"]["spec"]["properties"]["resources"]
        self.assertIn("gke-cluster", resources["items"]["properties"]["kind"]["enum"])
        evidence = export["properties"]["spec"]["properties"]["evidence"]
        signature = evidence["properties"]["signature"]
        self.assertEqual(signature["properties"]["algorithm"]["const"], "EC_SIGN_P256_SHA256")
        self.assertEqual(
            set(signature["required"]),
            {"algorithm", "keyVersion", "publicKey", "publicKeyDigest", "value", "payloadDigest"},
        )
        provenance = schema["$defs"]["evidenceReference"]["properties"]["uri"]["pattern"]
        self.assertEqual(
            provenance,
            r"^https://github\.com/mindclade/infrastructure-live/actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*$",
        )

    @staticmethod
    def _digest(character):
        return "sha256:" + character * 64

    @staticmethod
    def _sign_infrastructure_export(
        export,
        key_seed=b"mindclade-test-p256-key",
        key_version="projects/mindclade-bootstrap/locations/us-central1/keyRings/bootstrap-signing/cryptoKeys/infrastructure-export/cryptoKeyVersions/7",
    ):
        resources = sorted(
            export["spec"]["resources"],
            key=lambda resource: (resource["kind"], resource["name"], resource["uri"]),
        )
        export["spec"]["resources"] = resources
        metadata = export["metadata"]
        canonical_metadata = {
            field: metadata[field]
            for field in (
                "environment", "stack", "sourceRepository", "sourceCommit", "root",
                "planDigest", "providerLockDigest", "backendStateDigest", "backendLineage",
                "backendSerial", "schemaDigest", "generatedAt",
            )
        }
        provenance = export["spec"]["evidence"]["provenance"]
        payload = {
            "apiVersion": export["apiVersion"],
            "kind": export["kind"],
            "metadata": canonical_metadata,
            "spec": {"resources": resources, "provenance": provenance},
        }
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        public_key, signature_value = _p256_sign(encoded, key_seed)
        signature = {
            "algorithm": "EC_SIGN_P256_SHA256",
            "keyVersion": key_version,
            "publicKey": base64.b64encode(public_key).decode("ascii"),
            "publicKeyDigest": "sha256:" + hashlib.sha256(public_key).hexdigest(),
            "value": base64.b64encode(signature_value).decode("ascii"),
            "payloadDigest": "sha256:" + hashlib.sha256(encoded).hexdigest(),
        }
        export["spec"]["evidence"] = {"signature": signature, "provenance": provenance}
        return export

    @staticmethod
    def _write_infrastructure_trust_bundle(root, signatures, repin=True):
        keys = []
        active_start = TEST_VALIDATION_TIME.replace(
            hour=0, minute=0, second=0, microsecond=0,
        ) - timedelta(days=1)
        for index, signature in enumerate(signatures):
            valid_from = active_start - timedelta(days=89 * (len(signatures) - index - 1))
            public_key_der = base64.b64decode(signature["publicKey"])
            encoded_der = base64.b64encode(public_key_der).decode("ascii")
            public_key_pem = (
                "-----BEGIN PUBLIC KEY-----\n"
                + "\n".join(encoded_der[offset:offset + 64] for offset in range(0, len(encoded_der), 64))
                + "\n-----END PUBLIC KEY-----\n"
            )
            keys.append({
                "algorithm": "EC_SIGN_P256_SHA256",
                "keyVersion": signature["keyVersion"],
                "publicKey": signature["publicKey"],
                "publicKeyDigest": signature["publicKeyDigest"],
                "publicKeyPEM": public_key_pem,
                "publicKeyPEMSHA256": hashlib.sha256(public_key_pem.encode("utf-8")).hexdigest(),
                "validFrom": _canonical_time(valid_from),
                "validUntil": _canonical_time(valid_from + timedelta(days=90)),
                "revoked": False,
            })
        bundle = {
            "schemaVersion": "v1",
            "sourceRepository": "mindclade/bootstrap",
            "sourceRevision": BOOTSTRAP_TEST_REVISION,
            "purpose": "infrastructure-export-signing",
            "keys": keys,
        }
        path = root.parent / "infrastructure-export-trust-bundle.json"
        path.write_text(json.dumps(bundle, separators=(",", ":")) + "\n")
        (root.parent / "bootstrap-source-revision.txt").write_text(BOOTSTRAP_TEST_REVISION + "\n")
        if repin:
            SchemaCompatibilityTest._pin_infrastructure_trust_bundle(root)
        return path

    @staticmethod
    def _pin_infrastructure_trust_bundle(root):
        path = root.parent / "infrastructure-export-trust-bundle.json"
        digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        (root.parent / "infrastructure-export-trust-bundle-digest.txt").write_text(digest + "\n")

    @staticmethod
    def _pin_previous_infrastructure_state(previous_root):
        revision_path = previous_root.parent / "previous-repository-revision.txt"
        if not revision_path.exists():
            revision_path.write_text(PREVIOUS_TEST_REVISION + "\n")
        revision = revision_path.read_text().strip()
        hasher = hashlib.sha256()
        hasher.update(b"mindclade.gitops.previous-infrastructure-state.v1\x00")

        def write_field(label, value):
            encoded_label = label.encode("utf-8")
            hasher.update(struct.pack(">Q", len(encoded_label)))
            hasher.update(encoded_label)
            hasher.update(struct.pack(">Q", len(value)))
            hasher.update(value)

        write_field("previousRepositoryRevision", revision.encode("ascii"))
        for environment in ("development", "staging", "production", "restricted"):
            relative = f"environments/{environment}/infrastructure-exports.yaml"
            write_field(relative, (previous_root / relative).read_bytes())
        digest = "sha256:" + hasher.hexdigest()
        (previous_root.parent / "previous-infrastructure-state-digest.txt").write_text(digest + "\n")
        return digest

    @staticmethod
    def _trust_arguments(root):
        parent = root.parent
        return [
            "--infrastructure-export-trust-bundle", str(parent / "infrastructure-export-trust-bundle.json"),
            "--infrastructure-export-trust-bundle-digest", (parent / "infrastructure-export-trust-bundle-digest.txt").read_text().strip(),
            "--bootstrap-source-revision", (parent / "bootstrap-source-revision.txt").read_text().strip(),
            "--previous-repository-root", str(parent / "previous-gitops"),
            "--previous-repository-revision", (parent / "previous-repository-revision.txt").read_text().strip(),
            "--previous-infrastructure-state-digest", (parent / "previous-infrastructure-state-digest.txt").read_text().strip(),
        ]

    @staticmethod
    def _set_rotation_overlap(keys, overlap):
        new_start = datetime.fromisoformat(keys[1]["validFrom"].replace("Z", "+00:00"))
        old_until = new_start + overlap
        keys[0]["validFrom"] = _canonical_time(old_until - timedelta(days=90))
        keys[0]["validUntil"] = _canonical_time(old_until)

    def _active_environment(self, root, environment="development", initial_percent=0):
        previous_root = root.parent / "previous-gitops"
        if not previous_root.exists():
            shutil.copytree(
                ROOT,
                previous_root,
                ignore=shutil.ignore_patterns(
                    ".git",
                    ".cache",
                    "__pycache__",
                    "bazel-*",
                    "result",
                ),
            )
            self._pin_previous_infrastructure_state(previous_root)
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
                "sourceCommit": INFRASTRUCTURE_EXPORT_PRODUCER_COMMIT,
                "root": f"opentofu/live/{environment}/clusters",
                "planDigest": self._digest("2"),
                "providerLockDigest": self._digest("3"),
                "backendStateDigest": self._digest("4"),
                "backendLineage": "123e4567-e89b-42d3-a456-426614174000",
                "backendSerial": 17,
                "schemaDigest": INFRASTRUCTURE_EXPORT_SCHEMA_DIGEST,
                "generatedAt": _canonical_time(TEST_VALIDATION_TIME),
            },
            "spec": {
                "resources": [
                    {
                        "kind": "gke-cluster",
                        "name": "dev-cluster",
                        "uri": "//container.googleapis.com/projects/dev/locations/us-central1/clusters/dev-cluster",
                    },
                    {
                        "kind": "cluster-membership",
                        "name": "dev-cluster",
                        "uri": "//gkehub.googleapis.com/projects/dev/locations/global/memberships/dev-cluster",
                    },
                ],
                "evidence": {
                    "provenance": {
                        "uri": "https://github.com/mindclade/infrastructure-live/actions/runs/123456/attempts/1",
                        "digest": self._digest("5"),
                    },
                },
            },
        }
        self._sign_infrastructure_export(infrastructure_export)
        self._write_infrastructure_trust_bundle(
            root,
            [infrastructure_export["spec"]["evidence"]["signature"]],
        )
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
        kustomization = directory / "kustomization.yaml"
        kustomization.write_text(
            kustomization.read_text().replace(
                "gitops.mindclade.io/activation: inactive",
                "gitops.mindclade.io/activation: active",
            )
        )
        if root.resolve() == previous_root.resolve():
            self._pin_previous_infrastructure_state(previous_root)
        return infrastructure_export

    def _repository_copy(self):
        directory = tempfile.TemporaryDirectory()
        target = Path(directory.name) / "gitops"
        shutil.copytree(
            ROOT,
            target,
            ignore=shutil.ignore_patterns(
                ".git",
                ".cache",
                "__pycache__",
                "bazel-*",
                "result",
            ),
        )
        return directory, target

    def _validate(self, root):
        command = [str(self.promotectl), "validate", "--root", str(root)]
        trust_bundle = root.parent / "infrastructure-export-trust-bundle.json"
        previous_root = root.parent / "previous-gitops"
        if trust_bundle.exists() or previous_root.exists():
            command.extend(self._trust_arguments(root))
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
        )

    @staticmethod
    def _set_inactive(repository, environment, filename, collection):
        path = repository / "environments" / environment / filename
        document = json.loads(path.read_text())
        document["active"] = False
        document[collection] = []
        path.write_text(json.dumps(document, separators=(",", ":")) + "\n")

    @staticmethod
    def _set_kustomization_activation(repository, environment, activation):
        path = repository / "environments" / environment / "kustomization.yaml"
        text = path.read_text()
        text = text.replace(
            "gitops.mindclade.io/activation: active",
            f"gitops.mindclade.io/activation: {activation}",
        ).replace(
            "gitops.mindclade.io/activation: inactive",
            f"gitops.mindclade.io/activation: {activation}",
        )
        path.write_text(text)

    def _transition(self, repository, **overrides):
        values = {
            "action": "promote",
            "environment": "development",
            "release-class": "service",
            "component": "api-service",
            "cluster": "dev-cluster",
            "artifact-digest": self._digest("f"),
            "prior-digest": self._digest("a"),
        }
        values.update(overrides)
        command = [str(self.promotectl), "verify-transition", "--root", str(repository)]
        trust_bundle = repository.parent / "infrastructure-export-trust-bundle.json"
        previous_root = repository.parent / "previous-gitops"
        if trust_bundle.exists() or previous_root.exists():
            command.extend(self._trust_arguments(repository))
        for name, value in values.items():
            command.extend((f"--{name}", value))
        return subprocess.run(command, capture_output=True, text=True)

    def test_bootstrap_resource_and_provenance_are_bound_in_both_validators(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            path = repository / "controllers/argocd/kustomization.yaml"
            text = path.read_text()
            resource_prefix = "  - https://raw.githubusercontent.com/argoproj/argo-cd/"
            lines = text.splitlines()
            resource_index = next(
                index for index, line in enumerate(lines)
                if line.startswith(resource_prefix)
            )
            lines[resource_index] = lines[resource_index].replace(
                "/manifests/install.yaml",
                "/manifests/namespace-install.yaml",
            )
            path.write_text("\n".join(lines) + "\n")

            commands = (
                [str(self.promotectl), "validate", "--root", str(repository)],
                [str(self.promotectl), "verify-bootstrap", "--root", str(repository)],
            )
            for command in commands:
                with self.subTest(command=command[1]):
                    result = subprocess.run(command, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("provenance", result.stderr)
                    self.assertIn("remote", result.stderr)
        finally:
            directory.cleanup()

    def test_bootstrap_image_provenance_is_bound_to_exact_effective_overrides(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            path = repository / "controllers/argocd/kustomization.yaml"
            text = path.read_text()
            marker = (
                "  - name: quay.io/argoproj/argocd\n"
                "    digest: sha256:e2aadfae709d904e87f46ba4aa49601d827b3022db22cd4d03aae816a2e7097b\n"
            )
            duplicate = marker + (
                "  - name: quay.io/argoproj/argocd\n"
                f"    digest: {self._digest('9')}\n"
            )
            self.assertEqual(text.count(marker), 1)
            path.write_text(text.replace(marker, duplicate))

            commands = (
                [str(self.promotectl), "validate", "--root", str(repository)],
                [str(self.promotectl), "verify-bootstrap", "--root", str(repository)],
            )
            for command in commands:
                with self.subTest(command=command[1]):
                    result = subprocess.run(command, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("image override", result.stderr)
        finally:
            directory.cleanup()

    def test_bootstrap_version_label_is_bound_to_the_reviewed_release(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            path = repository / "controllers/argocd/kustomization.yaml"
            path.write_text(
                path.read_text().replace(
                    "upstream-version=v3.5.2",
                    "upstream-version=v999.0.0",
                )
            )
            for command in (
                [str(self.promotectl), "validate", "--root", str(repository)],
                [str(self.promotectl), "verify-bootstrap", "--root", str(repository)],
            ):
                with self.subTest(command=command[1]):
                    result = subprocess.run(command, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("upstream version, revision, and checksum must equal", result.stderr)
        finally:
            directory.cleanup()

    def test_bootstrap_image_keys_are_bound_to_reviewed_upstream_repositories(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            path = repository / "controllers/argocd/kustomization.yaml"
            text = path.read_text()
            for original, replacement in (
                ("quay.io/argoproj/argocd", "registry.invalid/fake/argocd"),
                ("ghcr.io/dexidp/dex", "registry.invalid/fake/dex"),
                ("public.ecr.aws/docker/library/redis", "registry.invalid/fake/redis"),
            ):
                self.assertEqual(text.count(original), 2)
                text = text.replace(original, replacement)
            path.write_text(text)
            for command in (
                [str(self.promotectl), "validate", "--root", str(repository)],
                [str(self.promotectl), "verify-bootstrap", "--root", str(repository)],
            ):
                with self.subTest(command=command[1]):
                    result = subprocess.run(command, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("reviewed immutable image reference", result.stderr)
        finally:
            directory.cleanup()

    def test_bootstrap_reviewed_image_digest_cannot_be_replaced_consistently(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            path = repository / "controllers/argocd/kustomization.yaml"
            text = path.read_text()
            original = "sha256:e2aadfae709d904e87f46ba4aa49601d827b3022db22cd4d03aae816a2e7097b"
            replacement = self._digest("9")
            self.assertEqual(text.count(original), 2)
            path.write_text(text.replace(original, replacement))
            for command in (
                [str(self.promotectl), "validate", "--root", str(repository)],
                [str(self.promotectl), "verify-bootstrap", "--root", str(repository)],
            ):
                with self.subTest(command=command[1]):
                    result = subprocess.run(command, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("reviewed immutable image reference", result.stderr)
        finally:
            directory.cleanup()

    def test_argo_fail_closed_configuration_is_semantic_not_comment_based(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        cases = (
            (
                "admin",
                "controllers/argocd/resource-customizations.yaml",
                '  admin.enabled: "false"',
                '  # admin.enabled: "false"\n  admin.enabled: "true"',
                "admin.enabled must equal",
            ),
            (
                "destination",
                "projects/platform.appproject.yaml",
                "  destinations: []",
                "  # destinations: []\n"
                "  destinations:\n"
                '    - namespace: "*"\n'
                '      server: "*"',
                "must have no destinations",
            ),
            (
                "project-role-broadening",
                "projects/services.appproject.yaml",
                "p, proj:services:promoter, applications, sync, services/*, allow",
                "p, proj:services:promoter, applications, sync, */*, allow",
                "must target only services/*",
            ),
            (
                "project-resource-action",
                "projects/services.appproject.yaml",
                "p, proj:services:promoter, applications, sync, services/*, allow",
                "p, proj:services:promoter, applications, sync, services/*, allow\n"
                "        - p, proj:services:promoter, applications, action/*, services/*, allow",
                "exceeds reviewed get/sync authority",
            ),
            (
                "local-account",
                "controllers/argocd/resource-customizations.yaml",
                '  statusbadge.enabled: "false"',
                '  statusbadge.enabled: "false"\n'
                "  accounts.backdoor: apiKey, login",
                'contains undeclared field "accounts.backdoor"',
            ),
            (
                "revision-sync-override-control",
                "controllers/argocd/resource-customizations.yaml",
                '  application.sync.requireOverridePrivilegeForRevisionSync: "true"',
                '  application.sync.requireOverridePrivilegeForRevisionSync: "false"',
                "application.sync.requireOverridePrivilegeForRevisionSync must equal",
            ),
            (
                "premature-sso-url",
                "controllers/argocd/resource-customizations.yaml",
                '  statusbadge.enabled: "false"',
                '  statusbadge.enabled: "false"\n'
                "  url: https://argocd.example.invalid",
                'contains undeclared field "url"',
            ),
            (
                "premature-dex-configuration",
                "controllers/argocd/resource-customizations.yaml",
                '  statusbadge.enabled: "false"',
                '  statusbadge.enabled: "false"\n'
                '  dex.config: "{}"',
                'contains undeclared field "dex.config"',
            ),
            (
                "sso-team-contract",
                "controllers/argocd/repository-credentials-reference.yaml",
                "      - platform-operations",
                "      - platform",
                "sso-contract.teams[0] must equal",
            ),
            (
                "sso-callback-contract",
                "controllers/argocd/repository-credentials-reference.yaml",
                "    callbackPath: /api/dex/callback",
                "    callbackPath: /oauth2/callback",
                "sso-contract identity must remain canonical",
            ),
            (
                "sso-activation-gate",
                "controllers/argocd/repository-credentials-reference.yaml",
                "  activation-gate: blocked-pending-jit-05",
                "  activation-gate: active",
                "must remain inactive behind JIT-05",
            ),
            (
                "rbac-escalation",
                "controllers/argocd/kustomization.yaml",
                "          g, mindclade:platform-operations, role:platform-operator",
                "          g, mindclade:platform-operations, role:platform-operator\n"
                "          p, role:release-promoter, clusters, *, *, allow",
                "policy.csv must contain exactly the reviewed policy rules",
            ),
            (
                "rbac-resource-action",
                "controllers/argocd/kustomization.yaml",
                "          p, role:platform-operator, applications, sync, platform/*, allow",
                "          p, role:platform-operator, applications, sync, platform/*, allow\n"
                "          p, role:platform-operator, applications, action/*, platform/*, allow",
                "must not grant application override or resource-action authority",
            ),
            (
                "rbac-multiple-documents",
                "controllers/argocd/kustomization.yaml",
                "          g, mindclade:platform-operations, role:platform-operator",
                "          g, mindclade:platform-operations, role:platform-operator\n"
                "      ---\n"
                "      apiVersion: v1\n"
                "      kind: ConfigMap",
                "RBAC patch: multiple YAML documents",
            ),
            (
                "server-patch-multiple-documents",
                "controllers/argocd/kustomization.yaml",
                "      - op: replace\n"
                "        path: /spec/replicas\n"
                "        value: 2",
                "      - op: replace\n"
                "        path: /spec/replicas\n"
                "        value: 2\n"
                "      ---\n"
                "      - op: add\n"
                "        path: /metadata/annotations/backdoor\n"
                "        value: enabled",
                "server patch: multiple YAML documents",
            ),
            (
                "server-replicas-string-type",
                "controllers/argocd/kustomization.yaml",
                "        value: 2",
                '        value: "2"',
                "server patch must only set two replicas",
            ),
        )
        for name, relative, original, replacement, expected in cases:
            with self.subTest(name=name):
                directory, repository = self._repository_copy()
                try:
                    path = repository / relative
                    text = path.read_text()
                    self.assertEqual(text.count(original), 1)
                    path.write_text(text.replace(original, replacement))
                    result = self._validate(repository)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(expected, result.stderr)
                finally:
                    directory.cleanup()

    def test_project_source_files_reject_duplicate_documents(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            path = repository / "projects/platform.appproject.yaml"
            document = path.read_text()
            path.write_text(document + "---\n" + document)
            result = self._validate(repository)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("must contain exactly one inactive project platform", result.stderr)
        finally:
            directory.cleanup()

    def test_applicationset_security_fields_are_parsed_not_satisfied_by_comments(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        cases = (
            (
                "project",
                "      project: '{{ if eq .environment \"restricted\" }}restricted{{ else }}services{{ end }}'",
                "      # project: '{{ if eq .environment \"restricted\" }}restricted{{ else }}services{{ end }}'\n"
                "      project: services-shadow",
                "template project must equal",
            ),
            (
                "target-revision",
                "        targetRevision: '{{.desiredStateRevision}}'",
                "        # targetRevision: '{{.desiredStateRevision}}'\n"
                "        targetRevision: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
                "source repoURL, targetRevision, and path must remain canonical",
            ),
            (
                "fail-on-shared-resource",
                "          - FailOnSharedResource=true",
                "          # - FailOnSharedResource=true\n"
                "          - Replace=true",
                "syncPolicy.syncOptions",
            ),
            (
                "component-path",
                "        path: '{{.desiredStatePath}}'",
                "        # path: '{{.desiredStatePath}}'\n"
                "        path: 'environments/development'",
                "source repoURL, targetRevision, and path must remain canonical",
            ),
            (
                "image-binding",
                "          images:\n"
                "            - '{{.component}}={{.artifact}}'",
                "          # images:\n"
                "          #   - '{{.component}}={{.artifact}}'\n"
                "          images: []",
                "source.kustomize.images",
            ),
            (
                "superseding-multi-source",
                "      source:\n",
                "      sources:\n"
                "        - repoURL: https://github.com/mindclade/gitops.git\n"
                "          targetRevision: main\n"
                "          path: environments/development\n"
                "      source:\n",
                'contains undeclared field "sources"',
            ),
        )
        for name, original, replacement, expected in cases:
            with self.subTest(name=name):
                directory, repository = self._repository_copy()
                try:
                    path = repository / "controllers/applicationsets/control-plane-services.yaml"
                    text = path.read_text()
                    self.assertEqual(text.count(original), 1)
                    path.write_text(text.replace(original, replacement))
                    result = self._validate(repository)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(expected, result.stderr)
                finally:
                    directory.cleanup()

    def test_component_manifest_is_strict_and_semantically_complete(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        cases = {
            "wrong-identity": lambda text: text.replace("  name: gitops", "  name: another-component"),
            "wrong-repository": lambda text: text.replace("mindclade/gitops", "fork/gitops"),
            "wrong-type": lambda text: text.replace("  type: deployment-control-plane", "  type: service"),
            "wrong-lifecycle": lambda text: text.replace("  lifecycle: pre-production", "  lifecycle: production"),
            "wrong-owner": lambda text: text.replace("  owner: platform-operations", "  owner: release-engineering"),
            "wrong-maturity": lambda text: text.replace("  maturity: pre-production", "  maturity: production"),
            "wrong-repository-class": lambda text: text.replace("  repository_class: deployment-source", "  repository_class: product-source"),
            "wrong-data-classification": lambda text: text.replace("  data_classification: confidential", "  data_classification: public"),
            "premature-production-authority": lambda text: text.replace("  production_authority: false", "  production_authority: true"),
            "wrong-trust-tier": lambda text: text.replace("mindclade.dev/trust-tier: deployment-control", "mindclade.dev/trust-tier: application"),
            "wrong-recovery-tier": lambda text: text.replace("mindclade.dev/recovery-tier: isolated-git", "mindclade.dev/recovery-tier: none"),
            "missing-security-reviewer": lambda text: text.replace("  security_reviewers:\n    - security\n", ""),
            "empty-dependencies": lambda text: text.replace(
                "  dependencies:\n    - component:infrastructure-live\n    - component:mindclade",
                "  dependencies: []",
            ),
            "invalid-dependency": lambda text: text.replace("    - component:mindclade", "    - mindclade"),
            "wrong-dependency": lambda text: text.replace("component:mindclade", "component:untrusted-source"),
            "empty-provides": lambda text: text.replace(
                "  provides:\n    - cluster-desired-state-v1\n    - promotion-receipt-v1\n    - rollback-evidence-v1",
                "  provides: []",
            ),
            "wrong-provided-contract": lambda text: text.replace("rollback-evidence-v1", "mutable-tags-v1"),
            "wrong-consumer": lambda text: text.replace("component:argocd", "component:untrusted-controller"),
            "wrong-release-strategy": lambda text: text.replace("    strategy: protected-digest-promotion", "    strategy: tag-promotion"),
            "wrong-release-artifact": lambda text: text.replace("    artifact: source-commit", "    artifact: image-tag"),
            "mutable-release": lambda text: text.replace("    immutable: true", "    immutable: false"),
            "missing-evidence": lambda text: text.replace("      - policy-verification\n", ""),
            "unknown-field": lambda text: text.replace("  owner: platform-operations", "  owner: platform-operations\n  undocumented: true"),
            "multiple-documents": lambda text: text + "---\napiVersion: v1\nkind: ConfigMap\n",
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                directory, repository = self._repository_copy()
                try:
                    path = repository / "component.yaml"
                    original = path.read_text()
                    mutated = mutate(original)
                    self.assertNotEqual(mutated, original)
                    path.write_text(mutated)
                    result = self._validate(repository)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("component.yaml", result.stderr)
                finally:
                    directory.cleanup()

    def test_infrastructure_export_wire_contract_active_blocker(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            self._active_environment(repository)
            for filename, collection in {
                "platform-releases.yaml": "releases",
                "service-releases.yaml": "releases",
                "worker-releases.yaml": "releases",
                "policy-bindings.yaml": "bindings",
                "secret-references.yaml": "references",
            }.items():
                self._set_inactive(repository, "development", filename, collection)
            result = self._validate(repository)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("external signature and attestation verification is pending JIT-09 ratification and qualification", result.stderr)
        finally:
            directory.cleanup()

    def test_infrastructure_export_preserves_backend_serial_above_float_precision(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            self._active_environment(repository)
            path = repository / "environments/development/infrastructure-exports.yaml"
            wrapper = json.loads(path.read_text())
            wrapper["exports"][0]["metadata"]["backendSerial"] = 2**53 + 1
            self._sign_infrastructure_export(wrapper["exports"][0])
            path.write_text(json.dumps(wrapper, separators=(",", ":")) + "\n")
            for filename, collection in {
                "platform-releases.yaml": "releases",
                "service-releases.yaml": "releases",
                "worker-releases.yaml": "releases",
                "policy-bindings.yaml": "bindings",
                "secret-references.yaml": "references",
            }.items():
                self._set_inactive(repository, "development", filename, collection)
            result = self._validate(repository)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("external signature and attestation verification is pending JIT-09", result.stderr)
            self.assertNotIn("payloadDigest", result.stderr)
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
            "https://cluster.example:0",
            "https://cluster.example:65536",
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
                    self.assertNotIn("external signature and attestation verification is pending JIT-09", result.stderr)
                finally:
                    directory.cleanup()

    def test_cluster_names_and_servers_are_globally_unique_across_environments(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        for duplicate in ("name", "server", "equivalent-server"):
            with self.subTest(duplicate=duplicate):
                directory, repository = self._repository_copy()
                try:
                    self._active_environment(repository, environment="development")
                    self._active_environment(repository, environment="staging")
                    cluster_path = repository / "environments/staging/cluster-set.yaml"
                    cluster_set = json.loads(cluster_path.read_text())
                    if duplicate == "name":
                        cluster_set["clusters"][0]["server"] = "https://staging-cluster.example"
                    else:
                        cluster_set["clusters"][0]["name"] = "staging-cluster"
                        if duplicate == "equivalent-server":
                            cluster_set["clusters"][0]["server"] = "https://CLUSTER.example.:443"
                        export_path = repository / "environments/staging/infrastructure-exports.yaml"
                        exports = json.loads(export_path.read_text())
                        exports["exports"][0]["spec"]["resources"][0]["name"] = "staging-cluster"
                        self._sign_infrastructure_export(exports["exports"][0])
                        export_path.write_text(json.dumps(exports, separators=(",", ":")) + "\n")
                        for filename in (
                            "platform-releases.yaml",
                            "service-releases.yaml",
                            "worker-releases.yaml",
                        ):
                            release_path = repository / "environments/staging" / filename
                            release_set = json.loads(release_path.read_text())
                            release_set["releases"][0]["cluster"] = "staging-cluster"
                            release_path.write_text(json.dumps(release_set, separators=(",", ":")) + "\n")
                    cluster_path.write_text(json.dumps(cluster_set, separators=(",", ":")) + "\n")

                    result = self._validate(repository)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    expected_field = "server" if duplicate == "equivalent-server" else duplicate
                    self.assertIn(f"cluster {expected_field}", result.stderr)
                    self.assertIn("reused across environments", result.stderr)
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
            "old-signature-reference": lambda wrapper: wrapper["exports"][0]["spec"]["evidence"].update(signature={"uri": "https://evidence.example/signature", "digest": self._digest("4")}),
            "generic-provenance": lambda wrapper: wrapper["exports"][0]["spec"]["evidence"]["provenance"].update(uri="https://evidence.example/provenance"),
            "wrong-gke-provider": lambda wrapper: wrapper["exports"][0]["spec"]["resources"][1].update(uri="//gkehub.googleapis.com/projects/dev/locations/us-central1/clusters/dev-cluster"),
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

    def test_infrastructure_export_signature_consistency_rejects_tampering(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        mutations = {
            "signed-backend-state": (
                lambda export: export["metadata"].update(backendStateDigest=self._digest("9")),
                "signature payloadDigest does not match the canonical export payload",
            ),
            "payload-digest": (
                lambda export: export["spec"]["evidence"]["signature"].update(payloadDigest=self._digest("9")),
                "signature payloadDigest does not match the canonical export payload",
            ),
            "public-key-digest": (
                lambda export: export["spec"]["evidence"]["signature"].update(publicKeyDigest=self._digest("9")),
                "signature publicKeyDigest does not match the embedded public key",
            ),
            "signature-value": (
                lambda export: export["spec"]["evidence"]["signature"].update(
                    value="A" + export["spec"]["evidence"]["signature"]["value"][1:]
                ),
                "GCP KMS ECDSA P-256 signature verification failed",
            ),
        }
        for name, (mutate, expected) in mutations.items():
            with self.subTest(name=name):
                directory, repository = self._repository_copy()
                try:
                    self._active_environment(repository)
                    path = repository / "environments/development/infrastructure-exports.yaml"
                    wrapper = json.loads(path.read_text())
                    mutate(wrapper["exports"][0])
                    path.write_text(json.dumps(wrapper, separators=(",", ":")) + "\n")
                    result = self._validate(repository)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(expected, result.stderr)
                    self.assertNotIn("pending JIT-09", result.stderr)
                finally:
                    directory.cleanup()

    def test_active_infrastructure_exports_require_independent_trust_inputs(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            self._active_environment(repository)
            result = subprocess.run(
                [str(self.promotectl), "validate", "--root", str(repository)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("require independently protected", result.stderr)
            self.assertIn("--infrastructure-export-trust-bundle", result.stderr)
            self.assertIn("--infrastructure-export-trust-bundle-digest", result.stderr)
            self.assertIn("--bootstrap-source-revision", result.stderr)
            self.assertIn("--previous-repository-root", result.stderr)
            self.assertIn("--previous-repository-revision", result.stderr)
            self.assertIn("--previous-infrastructure-state-digest", result.stderr)
        finally:
            directory.cleanup()

    def test_infrastructure_export_previous_root_must_be_independent(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            self._active_environment(repository)
            trust_arguments = self._trust_arguments(repository)
            previous_root_index = trust_arguments.index("--previous-repository-root") + 1
            trust_arguments[previous_root_index] = str(repository)
            result = subprocess.run(
                [
                    str(self.promotectl), "validate", "--root", str(repository),
                    *trust_arguments,
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("independently supplied snapshot", result.stderr)
        finally:
            directory.cleanup()

    def test_previous_state_checkpoint_binds_revision_files_and_root(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        cases = {
            "wrong-revision": "does not equal protected digest",
            "mutated-export": "does not equal protected digest",
            "nested-directory": "read previous repository environments/development/infrastructure-exports.yaml",
        }
        for case, expected in cases.items():
            with self.subTest(case=case):
                directory, repository = self._repository_copy()
                try:
                    self._active_environment(repository)
                    trust_arguments = self._trust_arguments(repository)
                    if case == "wrong-revision":
                        revision_index = trust_arguments.index("--previous-repository-revision") + 1
                        trust_arguments[revision_index] = "f" * 40
                    elif case == "mutated-export":
                        previous_export = repository.parent / "previous-gitops/environments/development/infrastructure-exports.yaml"
                        previous_export.write_bytes(previous_export.read_bytes() + b" ")
                    else:
                        root_index = trust_arguments.index("--previous-repository-root") + 1
                        trust_arguments[root_index] = str(repository.parent / "previous-gitops/environments")

                    result = subprocess.run(
                        [str(self.promotectl), "validate", "--root", str(repository), *trust_arguments],
                        capture_output=True,
                        text=True,
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(expected, result.stderr)
                finally:
                    directory.cleanup()

    def test_infrastructure_export_trust_bundle_rejects_untrusted_keys(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        cases = ("arbitrary-key", "substituted-key-version", "revoked-key", "expired-key")
        for case in cases:
            with self.subTest(case=case):
                directory, repository = self._repository_copy()
                try:
                    self._active_environment(repository)
                    export_path = repository / "environments/development/infrastructure-exports.yaml"
                    wrapper = json.loads(export_path.read_text())
                    export = wrapper["exports"][0]
                    bundle_path = repository.parent / "infrastructure-export-trust-bundle.json"
                    bundle = json.loads(bundle_path.read_text())
                    if case == "arbitrary-key":
                        self._sign_infrastructure_export(export, key_seed=b"attacker-controlled-key")
                        expected = "does not match keyVersion"
                    elif case == "substituted-key-version":
                        self._sign_infrastructure_export(
                            export,
                            key_version="projects/mindclade-bootstrap/locations/us-central1/keyRings/bootstrap-signing/cryptoKeys/infrastructure-export/cryptoKeyVersions/8",
                        )
                        expected = "is absent from the independently supplied bootstrap trust bundle"
                    elif case == "revoked-key":
                        bundle["keys"][0]["revoked"] = True
                        bundle_path.write_text(json.dumps(bundle, separators=(",", ":")) + "\n")
                        self._pin_infrastructure_trust_bundle(repository)
                        expected = "is revoked by the bootstrap trust bundle"
                    else:
                        bundle["keys"][0]["validFrom"] = "2020-01-01T00:00:00Z"
                        bundle["keys"][0]["validUntil"] = "2020-03-31T00:00:00Z"
                        bundle_path.write_text(json.dumps(bundle, separators=(",", ":")) + "\n")
                        self._pin_infrastructure_trust_bundle(repository)
                        expected = "outside its current bootstrap trust validity window"
                    export_path.write_text(json.dumps(wrapper, separators=(",", ":")) + "\n")

                    result = self._validate(repository)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(expected, result.stderr)
                finally:
                    directory.cleanup()

    def test_replacing_export_and_bundle_requires_a_protected_digest_rotation(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            self._active_environment(repository)
            export_path = repository / "environments/development/infrastructure-exports.yaml"
            wrapper = json.loads(export_path.read_text())
            export = wrapper["exports"][0]
            self._sign_infrastructure_export(export, key_seed=b"attacker-controlled-key")
            export_path.write_text(json.dumps(wrapper, separators=(",", ":")) + "\n")
            self._write_infrastructure_trust_bundle(
                repository,
                [export["spec"]["evidence"]["signature"]],
                repin=False,
            )

            rejected = self._transition(repository)
            self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
            self.assertIn("raw digest", rejected.stderr)
            self.assertIn("does not equal protected digest", rejected.stderr)

            self._pin_infrastructure_trust_bundle(repository)
            accepted_after_protected_rotation = self._transition(repository)
            self.assertEqual(
                accepted_after_protected_rotation.returncode,
                0,
                accepted_after_protected_rotation.stderr,
            )
        finally:
            directory.cleanup()

    def test_trust_bundle_is_bound_to_bootstrap_revision_and_pem_bytes(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        cases = {
            "bootstrap-revision": "does not equal protected bootstrap revision",
            "pem-byte-digest": "publicKeyPEMSHA256 does not match",
            "pem-der-cross-check": "publicKeyPEM SPKI DER does not match",
        }
        for case, expected in cases.items():
            with self.subTest(case=case):
                directory, repository = self._repository_copy()
                try:
                    self._active_environment(repository)
                    bundle_path = repository.parent / "infrastructure-export-trust-bundle.json"
                    bundle = json.loads(bundle_path.read_text())
                    if case == "bootstrap-revision":
                        bundle["sourceRevision"] = "c" * 40
                    elif case == "pem-byte-digest":
                        bundle["keys"][0]["publicKeyPEM"] = bundle["keys"][0]["publicKeyPEM"].replace(
                            "BEGIN PUBLIC KEY", "BEGIN  PUBLIC KEY",
                        )
                    else:
                        export_path = repository / "environments/development/infrastructure-exports.yaml"
                        wrapper = json.loads(export_path.read_text())
                        attacker_export = copy.deepcopy(wrapper["exports"][0])
                        self._sign_infrastructure_export(attacker_export, key_seed=b"different-pem-key")
                        attacker_signature = attacker_export["spec"]["evidence"]["signature"]
                        attacker_der = base64.b64decode(attacker_signature["publicKey"])
                        attacker_encoded = base64.b64encode(attacker_der).decode("ascii")
                        attacker_pem = (
                            "-----BEGIN PUBLIC KEY-----\n"
                            + "\n".join(attacker_encoded[offset:offset + 64] for offset in range(0, len(attacker_encoded), 64))
                            + "\n-----END PUBLIC KEY-----\n"
                        )
                        bundle["keys"][0]["publicKeyPEM"] = attacker_pem
                        bundle["keys"][0]["publicKeyPEMSHA256"] = hashlib.sha256(attacker_pem.encode()).hexdigest()
                    bundle_path.write_text(json.dumps(bundle, separators=(",", ":")) + "\n")
                    self._pin_infrastructure_trust_bundle(repository)

                    result = self._validate(repository)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(expected, result.stderr)
                finally:
                    directory.cleanup()

    def test_infrastructure_export_trust_bundle_supports_rotation_overlap(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            self._active_environment(repository)
            export_path = repository / "environments/development/infrastructure-exports.yaml"
            wrapper = json.loads(export_path.read_text())
            export = wrapper["exports"][0]
            original_signature = copy.deepcopy(export["spec"]["evidence"]["signature"])
            self._sign_infrastructure_export(
                export,
                key_seed=b"mindclade-test-rotated-p256-key",
                key_version="projects/mindclade-bootstrap/locations/us-central1/keyRings/bootstrap-signing/cryptoKeys/infrastructure-export/cryptoKeyVersions/8",
            )
            export_path.write_text(json.dumps(wrapper, separators=(",", ":")) + "\n")
            self._write_infrastructure_trust_bundle(
                repository,
                [original_signature, export["spec"]["evidence"]["signature"]],
            )

            result = self._transition(repository)
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            directory.cleanup()

    def test_infrastructure_export_rotation_overlap_is_bounded_and_ordered(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        cases = {
            "zero-overlap": (
                lambda keys: self._set_rotation_overlap(keys, timedelta(0)),
                "must be greater than zero and no more than 24 hours",
            ),
            "excessive-overlap": (
                lambda keys: self._set_rotation_overlap(keys, timedelta(hours=48)),
                "must be greater than zero and no more than 24 hours",
            ),
            "noncanonical-window-duration": (
                lambda keys: keys[0].update(validUntil=keys[0]["validFrom"]),
                "exact reviewed 90-day bootstrap rotation window",
            ),
            "different-crypto-key": (
                lambda keys: keys[1].update(
                    keyVersion=keys[1]["keyVersion"].replace(
                        "projects/mindclade-bootstrap/",
                        "projects/mindclade-secondary/",
                    )
                ),
                "must retain the same bootstrap CryptoKey prefix",
            ),
            "non-increasing-version": (
                lambda keys: keys.reverse(),
                "numeric key version must increase monotonically",
            ),
        }
        for case, (mutate, expected) in cases.items():
            with self.subTest(case=case):
                directory, repository = self._repository_copy()
                try:
                    self._active_environment(repository)
                    export_path = repository / "environments/development/infrastructure-exports.yaml"
                    wrapper = json.loads(export_path.read_text())
                    export = wrapper["exports"][0]
                    original_signature = copy.deepcopy(export["spec"]["evidence"]["signature"])
                    self._sign_infrastructure_export(
                        export,
                        key_seed=b"mindclade-test-rotated-p256-key",
                        key_version="projects/mindclade-bootstrap/locations/us-central1/keyRings/bootstrap-signing/cryptoKeys/infrastructure-export/cryptoKeyVersions/8",
                    )
                    export_path.write_text(json.dumps(wrapper, separators=(",", ":")) + "\n")
                    bundle_path = self._write_infrastructure_trust_bundle(
                        repository,
                        [original_signature, export["spec"]["evidence"]["signature"]],
                    )
                    bundle = json.loads(bundle_path.read_text())
                    mutate(bundle["keys"])
                    bundle_path.write_text(json.dumps(bundle, separators=(",", ":")) + "\n")
                    self._pin_infrastructure_trust_bundle(repository)

                    result = self._validate(repository)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(expected, result.stderr)
                finally:
                    directory.cleanup()

    def test_infrastructure_export_backend_state_replay_is_rejected(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        cases = {
            "serial-regression": (
                lambda metadata: metadata.update(backendSerial=16),
                "backend serial regressed from 17 to 16",
            ),
            "same-serial-different-state": (
                lambda metadata: metadata.update(backendStateDigest=self._digest("9")),
                "reused backend serial 17 with a different backend state digest",
            ),
            "lineage-replacement": (
                lambda metadata: metadata.update(
                    backendLineage="223e4567-e89b-42d3-a456-426614174000",
                    backendSerial=18,
                ),
                "no reviewed recovery contract authorizes lineage replacement",
            ),
        }
        for case, (mutate, expected) in cases.items():
            with self.subTest(case=case):
                directory, repository = self._repository_copy()
                try:
                    self._active_environment(repository)
                    self._active_environment(repository.parent / "previous-gitops")
                    path = repository / "environments/development/infrastructure-exports.yaml"
                    wrapper = json.loads(path.read_text())
                    mutate(wrapper["exports"][0]["metadata"])
                    self._sign_infrastructure_export(wrapper["exports"][0])
                    path.write_text(json.dumps(wrapper, separators=(",", ":")) + "\n")

                    result = self._transition(repository)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(expected, result.stderr)
                finally:
                    directory.cleanup()

    def test_previous_state_mutation_after_checkpoint_cannot_hide_a_regression(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            self._active_environment(repository)
            previous = repository.parent / "previous-gitops"
            self._active_environment(previous)

            relative = Path("environments/development/infrastructure-exports.yaml")
            previous_path = previous / relative
            previous_wrapper = json.loads(previous_path.read_text())
            previous_wrapper["exports"][0]["metadata"]["backendSerial"] = 16
            self._sign_infrastructure_export(previous_wrapper["exports"][0])
            previous_path.write_text(json.dumps(previous_wrapper, separators=(",", ":")) + "\n")

            current_path = repository / relative
            current_wrapper = json.loads(current_path.read_text())
            current_wrapper["exports"][0]["metadata"]["backendSerial"] = 16
            self._sign_infrastructure_export(current_wrapper["exports"][0])
            current_path.write_text(json.dumps(current_wrapper, separators=(",", ":")) + "\n")

            result = self._transition(repository)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("previous infrastructure state digest", result.stderr)
            self.assertIn("does not equal protected digest", result.stderr)
        finally:
            directory.cleanup()

    def test_equal_backend_serial_allows_a_same_state_evidence_refresh(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            self._active_environment(repository)
            self._active_environment(repository.parent / "previous-gitops")
            path = repository / "environments/development/infrastructure-exports.yaml"
            wrapper = json.loads(path.read_text())
            export = wrapper["exports"][0]
            export["metadata"].update(
                planDigest=self._digest("9"),
                generatedAt=_canonical_time(TEST_VALIDATION_TIME - timedelta(minutes=1)),
            )
            export["spec"]["evidence"]["provenance"] = {
                "uri": "https://github.com/mindclade/infrastructure-live/actions/runs/123457/attempts/1",
                "digest": self._digest("9"),
            }
            self._sign_infrastructure_export(export)
            path.write_text(json.dumps(wrapper, separators=(",", ":")) + "\n")

            result = self._transition(repository)
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            directory.cleanup()

    def test_stack_removal_cannot_reset_the_backend_high_water_mark(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            self._active_environment(repository)
            self._active_environment(repository.parent / "previous-gitops")
            for filename, collection in {
                "cluster-set.yaml": "clusters",
                "infrastructure-exports.yaml": "exports",
                "platform-releases.yaml": "releases",
                "service-releases.yaml": "releases",
                "worker-releases.yaml": "releases",
                "policy-bindings.yaml": "bindings",
                "secret-references.yaml": "references",
            }.items():
                self._set_inactive(repository, "development", filename, collection)
            self._set_kustomization_activation(repository, "development", "inactive")

            removed = self._validate(repository)
            self.assertNotEqual(removed.returncode, 0, removed.stdout)
            self.assertIn("stack clusters disappeared", removed.stderr)
            self.assertIn("tombstone contract", removed.stderr)

            self._active_environment(repository)
            path = repository / "environments/development/infrastructure-exports.yaml"
            wrapper = json.loads(path.read_text())
            wrapper["exports"][0]["metadata"]["backendSerial"] = 16
            self._sign_infrastructure_export(wrapper["exports"][0])
            path.write_text(json.dumps(wrapper, separators=(",", ":")) + "\n")

            reintroduced = self._transition(repository)
            self.assertNotEqual(reintroduced.returncode, 0, reintroduced.stdout)
            self.assertIn("backend serial regressed from 17 to 16", reintroduced.stderr)
        finally:
            directory.cleanup()

    def test_infrastructure_export_backend_state_can_advance_monotonically(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            self._active_environment(repository)
            self._active_environment(repository.parent / "previous-gitops")
            equal_result = self._transition(repository)
            self.assertEqual(equal_result.returncode, 0, equal_result.stderr)
            path = repository / "environments/development/infrastructure-exports.yaml"
            wrapper = json.loads(path.read_text())
            wrapper["exports"][0]["metadata"].update(
                backendSerial=18,
                backendStateDigest=self._digest("9"),
            )
            self._sign_infrastructure_export(wrapper["exports"][0])
            path.write_text(json.dumps(wrapper, separators=(",", ":")) + "\n")

            result = self._transition(repository)
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            directory.cleanup()

    def test_downstream_contracts_can_be_staged_independently_after_root(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            self._active_environment(repository)
            for filename, collection in {
                "platform-releases.yaml": "releases",
                "worker-releases.yaml": "releases",
                "policy-bindings.yaml": "bindings",
                "secret-references.yaml": "references",
            }.items():
                self._set_inactive(repository, "development", filename, collection)
            result = self._validate(repository)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("external signature and attestation verification is pending JIT-09 ratification and qualification", result.stderr)
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
            self.assertIn("external signature and attestation verification is pending JIT-09 ratification and qualification", result.stderr)
            self.assertNotIn("active state", result.stderr)
        finally:
            directory.cleanup()

    def test_environment_kustomization_must_match_root_activation_and_environment(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        cases = (
            "inactive-active-root",
            "wrong-environment",
            "unstable-generator-name",
            "undeclared-resource",
        )
        for case in cases:
            with self.subTest(case=case):
                directory, repository = self._repository_copy()
                try:
                    self._active_environment(repository)
                    path = repository / "environments/development/kustomization.yaml"
                    text = path.read_text()
                    if case == "inactive-active-root":
                        text = text.replace(
                            "gitops.mindclade.io/activation: active",
                            "gitops.mindclade.io/activation: inactive",
                        )
                    elif case == "wrong-environment":
                        text = text.replace(
                            "gitops.mindclade.io/environment: development",
                            "gitops.mindclade.io/environment: staging",
                        )
                    elif case == "unstable-generator-name":
                        text = text.replace("disableNameSuffixHash: true", "disableNameSuffixHash: false")
                    else:
                        text += "resources:\n  - https://attacker.example/arbitrary-cluster-state.yaml\n"
                    path.write_text(text)
                    result = self._validate(repository)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("kustomization.yaml", result.stderr)
                finally:
                    directory.cleanup()

        directory, repository = self._repository_copy()
        try:
            path = repository / "environments/development/kustomization.yaml"
            path.write_text(
                path.read_text().replace(
                    "gitops.mindclade.io/activation: inactive",
                    "gitops.mindclade.io/activation: active",
                )
            )
            result = self._validate(repository)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn('activation must equal "inactive"', result.stderr)
        finally:
            directory.cleanup()

    def test_contract_only_platform_kustomizations_reject_deployable_inputs(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            path = repository / "platform/kueue/kustomization.yaml"
            path.write_text(
                path.read_text()
                + "resources:\n  - https://attacker.example/arbitrary-platform-state.yaml\n"
            )
            result = self._validate(repository)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn('contains undeclared field "resources"', result.stderr)
        finally:
            directory.cleanup()

    def test_contract_only_modules_have_independent_activation_blockers(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        downstream = {
            "platform-releases.yaml": "releases",
            "service-releases.yaml": "releases",
            "worker-releases.yaml": "releases",
            "policy-bindings.yaml": "bindings",
            "secret-references.yaml": "references",
        }
        blockers = {
            "platform-releases.yaml": "platform deployment boundary is pending JIT-05 ratification and qualification",
            "policy-bindings.yaml": "policy binding reconciliation boundary is pending JIT-05 ratification and qualification",
            "secret-references.yaml": "secret reference materialization boundary is pending JIT-05 ratification and qualification",
        }
        for selected, expected in blockers.items():
            with self.subTest(selected=selected):
                directory, repository = self._repository_copy()
                try:
                    self._active_environment(repository)
                    for filename, collection in downstream.items():
                        if filename != selected:
                            self._set_inactive(repository, "development", filename, collection)
                    result = self._validate(repository)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(expected, result.stderr)
                    self.assertNotIn("external signature and attestation verification", result.stderr)
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
                    self._set_kustomization_activation(repository, "development", "inactive")
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
                    *self._trust_arguments(repository),
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

    def test_transition_verification_validates_the_complete_checked_out_environment(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            self._active_environment(repository)
            accepted = self._transition(repository)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
        finally:
            directory.cleanup()

        cases = (
            "inactive-root",
            "wrong-wrapper-environment",
            "missing-cluster",
            "admitted-artifact-digest-mismatch",
        )
        for case in cases:
            with self.subTest(case=case):
                directory, repository = self._repository_copy()
                try:
                    self._active_environment(repository)
                    transition_overrides = {}
                    service_path = repository / "environments/development/service-releases.yaml"
                    service_set = json.loads(service_path.read_text())
                    if case == "inactive-root":
                        self._set_inactive(repository, "development", "cluster-set.yaml", "clusters")
                        self._set_inactive(repository, "development", "infrastructure-exports.yaml", "exports")
                        self._set_kustomization_activation(repository, "development", "inactive")
                    elif case == "wrong-wrapper-environment":
                        service_set["environment"] = "staging"
                        service_path.write_text(json.dumps(service_set, separators=(",", ":")) + "\n")
                    elif case == "missing-cluster":
                        service_set["releases"][0]["cluster"] = "ghost-cluster"
                        service_path.write_text(json.dumps(service_set, separators=(",", ":")) + "\n")
                        transition_overrides["cluster"] = "ghost-cluster"
                    else:
                        service_set["releases"][0]["artifact"] = (
                            "registry.example/api@" + self._digest("e")
                        )
                        service_path.write_text(json.dumps(service_set, separators=(",", ":")) + "\n")

                    result = self._transition(repository, **transition_overrides)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("validate checked-out development environment", result.stderr)
                finally:
                    directory.cleanup()

    def test_promotion_cannot_relabel_the_checked_out_rollback_digest(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            self._active_environment(repository)
            rejected = self._transition(
                repository,
                **{"artifact-digest": self._digest("b")},
            )
            self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
            self.assertIn("use the rollback transition", rejected.stderr)

            rollback = self._transition(
                repository,
                action="rollback",
                **{"artifact-digest": self._digest("b")},
            )
            self.assertEqual(rollback.returncode, 0, rollback.stderr)
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

    def test_release_artifact_references_use_canonical_class_specific_grammar(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        digest = self._digest("a")
        cases = (
            ("service-releases.yaml", "registry.example/api@path@" + digest),
            ("service-releases.yaml", "https://registry.example/api@" + digest),
            ("service-releases.yaml", "oci://registry.example/api@" + digest),
            ("service-releases.yaml", "registry.example/api?channel=stable@" + digest),
            ("platform-releases.yaml", "registry.example/platform/kueue@" + digest),
            ("platform-releases.yaml", "oci://user:password@registry.example/kueue@" + digest),
        )
        for filename, artifact in cases:
            with self.subTest(filename=filename, artifact=artifact):
                directory, repository = self._repository_copy()
                try:
                    self._active_environment(repository)
                    path = repository / "environments/development" / filename
                    document = json.loads(path.read_text())
                    document["releases"][0]["artifact"] = artifact
                    path.write_text(json.dumps(document, separators=(",", ":")) + "\n")
                    result = self._validate(repository)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("artifact", result.stderr)
                finally:
                    directory.cleanup()

    def test_policy_and_secret_identifiers_are_dns_labels(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        cases = (
            ("policy-bindings.yaml", "bindings", "name"),
            ("policy-bindings.yaml", "bindings", "namespaces"),
            ("secret-references.yaml", "references", "name"),
            ("secret-references.yaml", "references", "namespace"),
            ("secret-references.yaml", "references", "externalSecret"),
            ("secret-references.yaml", "references", "storeRef"),
        )
        for filename, collection, field in cases:
            with self.subTest(filename=filename, field=field):
                directory, repository = self._repository_copy()
                try:
                    self._active_environment(repository)
                    path = repository / "environments/development" / filename
                    document = json.loads(path.read_text())
                    record = document[collection][0]
                    if field == "namespaces":
                        record[field] = ["services-"]
                    else:
                        record[field] = "invalid-"
                    path.write_text(json.dumps(document, separators=(",", ":")) + "\n")
                    result = self._validate(repository)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(filename, result.stderr)
                    self.assertNotIn("pending JIT-05", result.stderr)
                finally:
                    directory.cleanup()

    def test_policy_and_secret_resource_identities_must_be_unique(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        cases = (
            ("policy-binding-name", "policy-bindings.yaml", "bindings"),
            ("secret-name", "secret-references.yaml", "references"),
            ("external-secret", "secret-references.yaml", "references"),
        )
        for case, filename, collection in cases:
            with self.subTest(case=case):
                directory, repository = self._repository_copy()
                try:
                    self._active_environment(repository)
                    path = repository / "environments/development" / filename
                    document = json.loads(path.read_text())
                    duplicate = copy.deepcopy(document[collection][0])
                    if case == "secret-name":
                        duplicate["externalSecret"] = "another-external-secret"
                    elif case == "external-secret":
                        duplicate["name"] = "another-reference"
                    document[collection].append(duplicate)
                    path.write_text(json.dumps(document, separators=(",", ":")) + "\n")
                    result = self._validate(repository)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("duplicate", result.stderr)
                    self.assertNotIn("pending JIT-05", result.stderr)
                finally:
                    directory.cleanup()

    def test_secret_store_reference_is_intentionally_shareable(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        directory, repository = self._repository_copy()
        try:
            self._active_environment(repository)
            self._set_inactive(repository, "development", "platform-releases.yaml", "releases")
            self._set_inactive(repository, "development", "policy-bindings.yaml", "bindings")
            path = repository / "environments/development/secret-references.yaml"
            document = json.loads(path.read_text())
            duplicate = copy.deepcopy(document["references"][0])
            duplicate.update(
                name="worker-runtime",
                namespace="workers",
                externalSecret="worker-runtime",
            )
            document["references"].append(duplicate)
            path.write_text(json.dumps(document, separators=(",", ":")) + "\n")
            result = self._validate(repository)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("secret reference materialization boundary is pending JIT-05 ratification and qualification", result.stderr)
            self.assertNotIn("duplicate", result.stderr)
        finally:
            directory.cleanup()

    def test_workload_rollout_strategy_remains_manual_until_controller_activation(self):
        if self.promotectl is None:
            self.skipTest("Go toolchain is unavailable")

        for strategy in ("canary", "blue-green"):
            with self.subTest(strategy=strategy):
                directory, repository = self._repository_copy()
                try:
                    self._active_environment(repository)
                    path = repository / "environments/development/service-releases.yaml"
                    document = json.loads(path.read_text())
                    document["releases"][0]["rollout"]["strategy"] = strategy
                    path.write_text(json.dumps(document, separators=(",", ":")) + "\n")
                    result = self._validate(repository)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("strategy", result.stderr)
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
