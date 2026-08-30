package mindclade.gitops.signed_release

import rego.v1

required_evidence := {"signature", "sbom", "provenance", "vulnerabilityScan", "signer", "issuer"}

valid_digest(value) if {
  regex.match(`^sha256:[0-9a-f]{64}$`, value)
}

deny contains sprintf("release %s lacks an immutable promotion receipt", [release.component]) if {
  input.active == true
  some release in input.releases
  not valid_digest(object.get(release, "promotionReceiptDigest", ""))
}

deny contains sprintf("release %s lacks immutable governance evidence", [release.component]) if {
  input.active == true
  some release in input.releases
  not valid_digest(object.get(release, "governanceEvidenceDigest", ""))
}

deny contains sprintf("release %s is missing %s evidence", [release.component, field]) if {
  input.active == true
  some release in input.releases
  some field in required_evidence
  value := object.get(object.get(release, "evidence", {}), field, "")
  value == ""
}

deny contains sprintf("release %s has non-immutable %s evidence", [release.component, field]) if {
  input.active == true
  some release in input.releases
  some field in required_evidence - {"signer", "issuer"}
  value := object.get(object.get(release, "evidence", {}), field, "")
  value != ""
  not valid_digest(value)
}

deny contains sprintf("release %s has an invalid signer identity", [release.component]) if {
  input.active == true
  some release in input.releases
  signer := object.get(object.get(release, "evidence", {}), "signer", "")
  signer != ""
  not startswith(signer, "https://")
}

deny contains sprintf("release %s has an invalid issuer identity", [release.component]) if {
  input.active == true
  some release in input.releases
  issuer := object.get(object.get(release, "evidence", {}), "issuer", "")
  issuer != ""
  not startswith(issuer, "https://")
}
