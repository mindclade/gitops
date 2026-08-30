package mindclade.gitops.signed_release

import rego.v1

digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

test_rejects_missing_evidence if {
  result := deny with input as {"active": true, "releases": [{"component": "api", "evidence": {}}]}
  count(result) == 8
}

test_accepts_complete_evidence if {
  result := deny with input as {
    "active": true,
    "releases": [{
      "component": "api",
      "promotionReceiptDigest": digest,
      "governanceEvidenceDigest": digest,
      "evidence": {
        "signature": digest,
        "sbom": digest,
        "provenance": digest,
        "vulnerabilityScan": digest,
        "signer": "https://issuer.example/workload/release",
        "issuer": "https://issuer.example"
      }
    }]
  }
  count(result) == 0
}
