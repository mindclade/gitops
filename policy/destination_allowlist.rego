package mindclade.gitops.destination_allowlist

import rego.v1

deny contains "wildcard destination names are forbidden" if {
  some destination in input.destinations
  destination.name == "*"
}

deny contains "wildcard destination servers are forbidden" if {
  some destination in input.destinations
  destination.server == "*"
}

deny contains sprintf("destination %s/%s is not explicitly allowed", [object.get(destination, "name", object.get(destination, "server", "")), destination.namespace]) if {
  some destination in input.destinations
  not destination in object.get(input, "allowedDestinations", [])
}

deny contains "unbound projects must have no destinations" if {
  input.bound == false
  count(input.destinations) != 0
}
