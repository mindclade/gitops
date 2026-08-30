package mindclade.gitops.secret_reference

import rego.v1

test_rejects_plaintext_secret if {
  result := deny with input as {"apiVersion": "v1", "kind": "Secret", "data": {"token": "c2VjcmV0"}}
  count(result) == 2
}

test_accepts_external_secret if {
  result := deny with input as {"apiVersion": "external-secrets.io/v1", "kind": "ExternalSecret", "credentialBearing": true, "spec": {"data": [{"remoteRef": {"key": "gitops-token"}}]}}
  count(result) == 0
}

test_accepts_noncredential_configmap_data if {
  result := deny with input as {"apiVersion": "v1", "kind": "ConfigMap", "data": {"policy.csv": "p, role:auditor, applications, get, */*, allow"}}
  count(result) == 0
}

test_accepts_empty_upstream_secret_stub if {
  result := deny with input as {"apiVersion": "v1", "kind": "Secret", "type": "Opaque"}
  count(result) == 0
}
