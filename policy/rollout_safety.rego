package mindclade.gitops.rollout_safety

import rego.v1

protected_environment contains "production"
protected_environment contains "restricted"

deny contains "protected environments cannot use automatic promotion" if {
  input.environment in protected_environment
  object.get(input.rollout, "automaticPromotion", false) == true
}

deny contains "protected environments cannot prune without explicit receipt evidence" if {
  input.environment in protected_environment
  object.get(input.rollout, "prune", false) == true
  object.get(input, "pruneEvidence", "") == ""
}

deny contains "protected canaries may not begin above 10 percent" if {
  input.environment in protected_environment
  object.get(input.rollout, "initialPercent", 0) > 10
}

deny contains "rollout requires an immutable rollback digest" if {
  not regex.match(`^sha256:[0-9a-f]{64}$`, object.get(input, "priorDigest", ""))
}
