package mindclade.gitops.destination_allowlist

import rego.v1

test_rejects_wildcard_destination if {
  result := deny with input as {"bound": true, "destinations": [{"name": "*", "namespace": "argocd"}], "allowedDestinations": []}
  count(result) == 2
}

test_accepts_unbound_project if {
  result := deny with input as {"bound": false, "destinations": [], "allowedDestinations": []}
  count(result) == 0
}
