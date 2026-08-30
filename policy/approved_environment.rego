package mindclade.gitops.approved_environment

import rego.v1

protected_environment contains "production"
protected_environment contains "restricted"

deny contains "environment is not approved" if {
  not input.environment in {"development", "staging", "production", "restricted"}
}

deny contains "active desired state requires a reviewed source revision" if {
  input.active == true
  some record in object.get(input, "releases", object.get(input, "clusters", []))
  not regex.match(`^[0-9a-f]{40}$`, object.get(record, "desiredStateRevision", ""))
}

deny contains "protected release requires an immutable promotion receipt" if {
  input.active == true
  input.environment in protected_environment
  some release in object.get(input, "releases", [])
  not regex.match(`^sha256:[0-9a-f]{64}$`, object.get(release, "promotionReceiptDigest", ""))
}

deny contains "protected activation requires connected governance evidence" if {
  input.active == true
  input.environment in protected_environment
  some release in object.get(input, "releases", [])
  not regex.match(`^sha256:[0-9a-f]{64}$`, object.get(release, "governanceEvidenceDigest", ""))
}
