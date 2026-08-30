import copy
import json
import os
import re
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
        kustomization = directory / "kustomization.yaml"
        kustomization.write_text(
            kustomization.read_text().replace(
                "gitops.mindclade.io/activation: inactive",
                "gitops.mindclade.io/activation: active",
            )
        )
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
                "differs from its reviewed semantic contract",
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
                "rbac-escalation",
                "controllers/argocd/kustomization.yaml",
                "          g, mindclade:platform, role:platform-operator",
                "          g, mindclade:platform, role:platform-operator\n"
                "          p, role:release-promoter, clusters, *, *, allow",
                "policy.csv must contain exactly the reviewed policy rules",
            ),
            (
                "rbac-multiple-documents",
                "controllers/argocd/kustomization.yaml",
                "          g, mindclade:platform, role:platform-operator",
                "          g, mindclade:platform, role:platform-operator\n"
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
            self.assertIn("must contain exactly one unbound project platform", result.stderr)
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
            "wrong-lifecycle": lambda text: text.replace("  lifecycle: production", "  lifecycle: experimental"),
            "wrong-owner": lambda text: text.replace("  owner: release", "  owner: application"),
            "wrong-maturity": lambda text: text.replace("  maturity: production", "  maturity: beta"),
            "wrong-repository-class": lambda text: text.replace("  repository_class: deployment-source", "  repository_class: product-source"),
            "wrong-data-classification": lambda text: text.replace("  data_classification: confidential", "  data_classification: public"),
            "no-production-authority": lambda text: text.replace("  production_authority: true", "  production_authority: false"),
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
            "unknown-field": lambda text: text.replace("  owner: release", "  owner: release\n  undocumented: true"),
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
                    self.assertNotIn("external signature and attestation verifier implementation is unbound", result.stderr)
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
            for filename, collection in {
                "platform-releases.yaml": "releases",
                "worker-releases.yaml": "releases",
                "policy-bindings.yaml": "bindings",
                "secret-references.yaml": "references",
            }.items():
                self._set_inactive(repository, "development", filename, collection)
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
            "platform-releases.yaml": "platform deployment implementation is unbound",
            "policy-bindings.yaml": "policy binding reconciler implementation is unbound",
            "secret-references.yaml": "secret reference materializer implementation is unbound",
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
                    self.assertNotIn("external signature and attestation verifier implementation", result.stderr)
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
                    self.assertNotIn("implementation is unbound", result.stderr)
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
                    self.assertNotIn("implementation is unbound", result.stderr)
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
            self.assertIn("secret reference materializer implementation is unbound", result.stderr)
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
