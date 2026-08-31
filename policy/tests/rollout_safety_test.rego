package mindclade.gitops.rollout_safety

import rego.v1

prior := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

test_rejects_unsafe_production_rollout if {
	result := deny with input as {"environment": "production", "releaseClass": "service", "releases": [{"component": "api", "priorDigest": prior, "rollout": {"strategy": "canary", "automaticPromotion": true, "prune": true, "initialPercent": 50}}]}
	count(result) == 4
}

test_accepts_manual_canary if {
	result := deny with input as {"environment": "production", "releaseClass": "service", "releases": [{"component": "api", "priorDigest": prior, "rollout": {"strategy": "manual", "automaticPromotion": false, "prune": false, "initialPercent": 5}}]}
	count(result) == 0
}

test_rejects_nonimmutable_release_prior_digest if {
	result := deny with input as {"environment": "development", "releases": [{"component": "api", "priorDigest": "latest", "rollout": {"strategy": "manual", "automaticPromotion": false, "initialPercent": 0}}]}
	count(result) == 1
}

test_accepts_platform_release_without_workload_rollout if {
	result := deny with input as {"environment": "production", "releaseClass": "platform", "releases": [{"component": "kueue", "priorDigest": prior}]}
	count(result) == 0
}
