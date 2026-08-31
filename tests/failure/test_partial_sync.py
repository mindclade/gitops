# pyright: basic, reportArgumentType=false, reportAttributeAccessIssue=false, reportCallIssue=false, reportOperatorIssue=false, reportOptionalMemberAccess=false, reportOptionalSubscript=false
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


class PartialSyncTest(unittest.TestCase):
    def test_inactive_release_sets_produce_zero_applications(self):
        active_clusters = 0
        active_release_sets = 0
        for environment in ("development", "staging", "production", "restricted"):
            directory = ROOT / "environments" / environment
            cluster_set = json.loads((directory / "cluster-set.yaml").read_text())
            active_clusters += len(cluster_set["clusters"]) if cluster_set["active"] else 0
            for name in ("platform-releases.yaml", "service-releases.yaml", "worker-releases.yaml"):
                release_set = json.loads((directory / name).read_text())
                active_release_sets += len(release_set["releases"]) if release_set["active"] else 0
        concrete_applications = 0
        for path in ROOT.rglob("*.yaml"):
            concrete_applications += len(
                re.findall(r"(?m)^kind:\s+Application\s*$", path.read_text())
            )
        self.assertEqual(active_clusters, 0)
        self.assertEqual(active_release_sets, 0)
        self.assertEqual(concrete_applications, 0)

    def test_applicationsets_preserve_on_partial_failure(self):
        files = sorted((ROOT / "controllers/applicationsets").glob("*.yaml"))
        self.assertEqual(len(files), 4)
        expected_sources = {
            "environment-root.yaml": "cluster-set.yaml",
            "platform-components.yaml": "platform-releases.yaml",
            "control-plane-services.yaml": "service-releases.yaml",
            "execution-workers.yaml": "worker-releases.yaml",
        }
        for path in files:
            text = path.read_text()
            self.assertIn("matrix:", text)
            self.assertIn("git:", text)
            self.assertIn(f"environments/*/{expected_sources[path.name]}", text)
            self.assertIn("elementsYaml:", text)
            self.assertIn("if .active", text)
            self.assertNotIn("elements: []", text)
            self.assertIn("desiredStateRevision", text)
            self.assertRegex(text, r"gitops\.mindclade\.io/(?:release|activation)-record-digest")
            if path.name != "environment-root.yaml":
                self.assertIn("promotion-receipt-digest", text)
                self.assertIn("governance-evidence-digest", text)
            self.assertIn("applicationsSync: create-update", text)
            self.assertIn("preserveResourcesOnDeletion: true", text)
            self.assertIn("FailOnSharedResource=true", text)
            self.assertNotIn("prune: true", text)
            self.assertNotRegex(text, r"targetRevision:\s*(?:main|HEAD|master)")

    def test_restricted_workloads_use_the_restricted_project(self):
        expected_projects = {
            "control-plane-services.yaml": (
                '{{ if eq .environment "restricted" }}restricted{{ else }}services{{ end }}'
            ),
            "execution-workers.yaml": (
                '{{ if eq .environment "restricted" }}restricted{{ else }}workers{{ end }}'
            ),
        }
        for filename, project in expected_projects.items():
            text = (ROOT / "controllers/applicationsets" / filename).read_text()
            self.assertIn(f"project: '{project}'", text)

    def test_contract_config_maps_have_stable_names(self):
        kustomizations = [
            *(ROOT / "environments").glob("*/kustomization.yaml"),
            *(ROOT / "platform").glob("*/kustomization.yaml"),
        ]
        self.assertEqual(len(kustomizations), 11)
        for path in kustomizations:
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertIn("disableNameSuffixHash: true", path.read_text())

    def test_application_names_partition_environment_and_release_class(self):
        expected_templates = {
            "environment-root.yaml": "{{.environment}}.root.{{.name}}",
            "platform-components.yaml": "{{.environment}}.platform.{{.cluster}}.{{.component}}",
            "control-plane-services.yaml": "{{.environment}}.service.{{.cluster}}.{{.component}}",
            "execution-workers.yaml": "{{.environment}}.worker.{{.cluster}}.{{.component}}",
        }
        for filename, template in expected_templates.items():
            text = (ROOT / "controllers/applicationsets" / filename).read_text()
            self.assertIn(f"name: '{template}'", text)

        applications = {
            f"{environment}.{release_class}.shared-cluster.shared-component"
            for environment in ("development", "staging")
            for release_class in ("platform", "service", "worker")
        }
        applications.update(
            f"{environment}.root.shared-cluster" for environment in ("development", "staging")
        )
        self.assertEqual(len(applications), 8)

    def test_release_applications_have_canonical_labels(self):
        expected_classes = {
            "platform-components.yaml": "platform",
            "control-plane-services.yaml": "service",
            "execution-workers.yaml": "worker",
        }
        for filename, release_class in expected_classes.items():
            text = (ROOT / "controllers/applicationsets" / filename).read_text()
            self.assertIn(
                f"gitops.mindclade.io/release-class: {release_class}",
                text,
            )
            self.assertIn(
                "gitops.mindclade.io/component: '{{.component}}'",
                text,
            )

    def test_workload_applications_select_one_component_and_artifact(self):
        schema = json.loads((ROOT / "schemas/v1/workload_releases.schema.json").read_text())
        release = schema["properties"]["releases"]["items"]
        self.assertIn("desiredStatePath", release["required"])
        path_pattern = re.compile(release["properties"]["desiredStatePath"]["pattern"])
        self.assertIsNotNone(
            path_pattern.fullmatch("environments/development/services/control-plane")
        )
        self.assertIsNotNone(
            path_pattern.fullmatch("environments/restricted/workers/training-worker")
        )
        self.assertIsNone(path_pattern.fullmatch("environments/development"))
        self.assertIsNone(path_pattern.fullmatch("environments/development/services/component-"))

        for filename in ("control-plane-services.yaml", "execution-workers.yaml"):
            text = (ROOT / "controllers/applicationsets" / filename).read_text()
            self.assertIn("path: '{{.desiredStatePath}}'", text)
            self.assertIn("images:", text)
            self.assertIn("- '{{.component}}={{.artifact}}'", text)
            self.assertNotIn("path: 'environments/{{.environment}}'", text)
            self.assertNotIn("namePrefix:", text)

    def test_generated_name_segments_reject_trailing_hyphens(self):
        locations = (
            ("workload_releases.schema.json", ("component", "cluster")),
            ("platform_releases.schema.json", ("cluster",)),
            ("cluster_set.schema.json", ("name",)),
            ("promotion_receipt.schema.json", ("component", "cluster")),
        )
        for filename, fields in locations:
            schema = json.loads((ROOT / "schemas/v1" / filename).read_text())
            if filename == "cluster_set.schema.json":
                properties = schema["properties"]["clusters"]["items"]["properties"]
            elif filename in (
                "workload_releases.schema.json",
                "platform_releases.schema.json",
            ):
                properties = schema["properties"]["releases"]["items"]["properties"]
            else:
                properties = schema["properties"]
            for field in fields:
                pattern = re.compile(properties[field]["pattern"])
                with self.subTest(schema=filename, field=field):
                    self.assertIsNotNone(pattern.fullmatch("valid-name"))
                    self.assertIsNone(pattern.fullmatch("invalid-name-"))


if __name__ == "__main__":
    unittest.main()
