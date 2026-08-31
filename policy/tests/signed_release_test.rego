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
				"issuer": "https://issuer.example",
			},
		}],
	}
	count(result) == 0
}

test_workload_requires_immutable_evaluation_evidence if {
	result := deny with input as {
		"active": true,
		"releaseClass": "service",
		"releases": [{
			"component": "api",
			"promotionReceiptDigest": digest,
			"governanceEvidenceDigest": digest,
			"evidence": {
				"signature": digest,
				"sbom": digest,
				"provenance": digest,
				"vulnerabilityScan": digest,
				"evaluation": "latest",
				"signer": "https://issuer.example/workload/release",
				"issuer": "https://issuer.example",
			},
		}],
	}
	count(result) == 1
}

test_rejects_mutable_or_credential_bearing_identities if {
	result := deny with input as {
		"active": true,
		"releaseClass": "service",
		"releases": [{
			"component": "api",
			"promotionReceiptDigest": digest,
			"governanceEvidenceDigest": digest,
			"evidence": {
				"signature": digest,
				"sbom": digest,
				"provenance": digest,
				"vulnerabilityScan": digest,
				"evaluation": digest,
				"signer": "https://user@issuer.example/workload/release",
				"issuer": "https://issuer.example?tenant=mutable",
			},
		}],
	}
	count(result) == 2
}

test_accepts_complete_workload_evidence if {
	result := deny with input as {
		"active": true,
		"releaseClass": "worker",
		"releases": [{
			"component": "worker",
			"promotionReceiptDigest": digest,
			"governanceEvidenceDigest": digest,
			"evidence": {
				"signature": digest,
				"sbom": digest,
				"provenance": digest,
				"vulnerabilityScan": digest,
				"evaluation": digest,
				"signer": "https://issuer.example/workload/release",
				"issuer": "https://issuer.example",
			},
		}],
	}
	count(result) == 0
}
