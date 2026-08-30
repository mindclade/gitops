package mindclade.gitops.approved_environment

import rego.v1

test_rejects_unapproved_production if {
  result := deny with input as {"environment": "production", "active": true, "releases": [{"desiredStateRevision": "mutable"}]}
  count(result) == 3
}

test_accepts_inactive_environment if {
  result := deny with input as {"environment": "restricted", "active": false}
  count(result) == 0
}

test_accepts_protected_release_with_immutable_record_evidence if {
  result := deny with input as {"environment": "production", "active": true, "releases": [{
    "desiredStateRevision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "promotionReceiptDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "governanceEvidenceDigest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  }]}
  count(result) == 0
}
