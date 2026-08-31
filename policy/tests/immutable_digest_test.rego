package mindclade.gitops.immutable_digest

import rego.v1

digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
prior := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

test_rejects_mutable_reference if {
	result := deny with input as {"releases": [{"component": "api", "artifact": "registry/api:latest", "digest": "latest", "priorDigest": prior}]}
	count(result) == 1
}

test_accepts_digest_reference if {
	result := deny with input as {"releases": [{"component": "api", "artifact": concat("@", ["registry/api", digest]), "digest": digest, "priorDigest": prior}]}
	count(result) == 0
}
