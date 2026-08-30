package mindclade.gitops.rollout_safety

import rego.v1

prior := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

test_rejects_unsafe_production_rollout if {
  result := deny with input as {"environment": "production", "priorDigest": prior, "rollout": {"automaticPromotion": true, "prune": true, "initialPercent": 50}}
  count(result) == 3
}

test_accepts_manual_canary if {
  result := deny with input as {"environment": "production", "priorDigest": prior, "rollout": {"automaticPromotion": false, "prune": false, "initialPercent": 5}}
  count(result) == 0
}
