package mindclade.gitops.rollout_safety

import rego.v1

protected_environment contains "production"
protected_environment contains "restricted"

workload_release if {
	input.releaseClass in {"service", "worker"}
}

deny contains "protected environments cannot use automatic promotion" if {
	input.environment in protected_environment
	some release in input.releases
	object.get(object.get(release, "rollout", {}), "automaticPromotion", false) == true
}

deny contains "protected environments cannot prune without explicit receipt evidence" if {
	input.environment in protected_environment
	some release in input.releases
	object.get(object.get(release, "rollout", {}), "prune", false) == true
	object.get(release, "pruneEvidence", "") == ""
}

deny contains "protected canaries may not begin above 10 percent" if {
	input.environment in protected_environment
	some release in input.releases
	object.get(object.get(release, "rollout", {}), "initialPercent", 0) > 10
}

deny contains sprintf("release %s rollout requires an immutable rollback digest", [release.component]) if {
	some release in input.releases
	not regex.match(`^sha256:[0-9a-f]{64}$`, object.get(release, "priorDigest", ""))
}

deny contains sprintf("release %s rollout strategy must remain manual until a rollout controller is implemented", [release.component]) if {
	workload_release
	some release in input.releases
	object.get(object.get(release, "rollout", {}), "strategy", "") != "manual"
}
