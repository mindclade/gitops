package mindclade.gitops.immutable_digest

import rego.v1

valid_digest(value) if {
	regex.match(`^sha256:[0-9a-f]{64}$`, value)
}

deny contains sprintf("release %s must use an immutable digest", [release.component]) if {
	some release in input.releases
	not valid_digest(object.get(release, "digest", ""))
}

deny contains sprintf("release %s artifact must end in its declared digest", [release.component]) if {
	some release in input.releases
	digest := object.get(release, "digest", "")
	artifact := object.get(release, "artifact", "")
	valid_digest(digest)
	not endswith(artifact, concat("@", [digest]))
}

deny contains sprintf("release %s lacks an immutable rollback digest", [release.component]) if {
	some release in input.releases
	not valid_digest(object.get(release, "priorDigest", ""))
}
