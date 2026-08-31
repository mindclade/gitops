package mindclade.gitops.secret_reference

import rego.v1

deny contains "plaintext Kubernetes Secret resources are forbidden" if {
	some _, value in walk(input)
	is_object(value)
	object.get(value, "kind", "") == "Secret"
	object.get(value, "data", null) != null
}

deny contains "inline secret data fields are forbidden" if {
	some _, value in walk(input)
	is_object(value)
	object.get(value, "kind", "") == "Secret"
	object.get(value, "data", null) != null
}

deny contains "inline stringData fields are forbidden" if {
	some _, value in walk(input)
	is_object(value)
	object.get(value, "kind", "") == "Secret"
	object.get(value, "stringData", null) != null
}

deny contains "credential-bearing objects cannot contain inline data" if {
	some _, value in walk(input)
	is_object(value)
	object.get(value, "credentialBearing", false) == true
	object.get(value, "kind", "") != "ExternalSecret"
	object.get(value, "data", null) != null
}

deny contains "credential references must use ExternalSecret" if {
	object.get(input, "credentialBearing", false) == true
	object.get(input, "kind", "") != "ExternalSecret"
}
