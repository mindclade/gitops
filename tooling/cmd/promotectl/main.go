package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mindclade/gitops/tooling/internal/policy"
	"github.com/mindclade/gitops/tooling/internal/promotion"
	"github.com/mindclade/gitops/tooling/internal/release"
	"github.com/mindclade/gitops/tooling/internal/rendering"
	"github.com/mindclade/gitops/tooling/internal/rollback"
)

const version = "0.1.0"

func fail(err error) {
	fmt.Fprintln(os.Stderr, "promotectl:", err)
	os.Exit(1)
}

func approvals(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func writeJSON(value any) error {
	content, err := release.CanonicalJSON(value)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(content)
	return err
}

func receiptCommand(arguments []string) error {
	flags := flag.NewFlagSet("receipt", flag.ContinueOnError)
	environment := flags.String("environment", "", "target environment")
	releaseClass := flags.String("release-class", "", "platform, service, or worker")
	component := flags.String("component", "", "release component")
	cluster := flags.String("cluster", "", "target cluster")
	revision := flags.String("source-revision", "", "artifact source revision")
	artifactReference := flags.String("artifact-reference", "", "immutable artifact reference")
	artifact := flags.String("artifact-digest", "", "artifact digest")
	prior := flags.String("prior-digest", "", "prior artifact digest")
	attestation := flags.String("attestation-digest", "", "evidence digest")
	signer := flags.String("signer", "", "signer identity")
	issuer := flags.String("issuer", "", "signer issuer")
	issuedAt := flags.String("issued-at", "", "RFC3339 issuance time")
	approvalList := flags.String("approvals", "", "comma-separated approval records")
	repository := flags.String("repository", "", "workflow repository")
	workflowRunID := flags.String("workflow-run-id", "", "GitHub workflow run ID")
	workflowRunAttempt := flags.String("workflow-run-attempt", "", "GitHub workflow run attempt")
	checkedOutRevision := flags.String("checked-out-revision", "", "checked-out Git revision")
	requester := flags.String("requester", "", "workflow requester")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	receipt, err := promotion.Receipt(promotion.Request{
		Environment: *environment, ReleaseClass: *releaseClass, Component: *component,
		Cluster: *cluster, SourceRevision: *revision, ArtifactReference: *artifactReference, ArtifactDigest: *artifact,
		PriorDigest: *prior, AttestationDigest: *attestation, Signer: *signer,
		Issuer:   *issuer,
		IssuedAt: *issuedAt, Approvals: approvals(*approvalList),
		Repository: *repository, WorkflowRunID: *workflowRunID,
		WorkflowRunAttempt: *workflowRunAttempt, CheckedOutRevision: *checkedOutRevision,
		Requester: *requester,
	})
	if err != nil {
		return err
	}
	return writeJSON(receipt)
}

func rollbackCommand(arguments []string) error {
	flags := flag.NewFlagSet("rollback", flag.ContinueOnError)
	environment := flags.String("environment", "", "target environment")
	releaseClass := flags.String("release-class", "", "platform, service, or worker")
	component := flags.String("component", "", "release component")
	cluster := flags.String("cluster", "", "target cluster")
	revision := flags.String("source-revision", "", "artifact source revision")
	artifactReference := flags.String("artifact-reference", "", "immutable artifact reference")
	current := flags.String("current-digest", "", "current artifact digest")
	previous := flags.String("previous-digest", "", "previous artifact digest")
	attestation := flags.String("attestation-digest", "", "previous evidence digest")
	signer := flags.String("signer", "", "signer identity")
	issuer := flags.String("issuer", "", "signer issuer")
	issuedAt := flags.String("issued-at", "", "RFC3339 authorization time")
	approvalList := flags.String("approvals", "", "comma-separated approval records")
	repository := flags.String("repository", "", "workflow repository")
	workflowRunID := flags.String("workflow-run-id", "", "GitHub workflow run ID")
	workflowRunAttempt := flags.String("workflow-run-attempt", "", "GitHub workflow run attempt")
	checkedOutRevision := flags.String("checked-out-revision", "", "checked-out Git revision")
	requester := flags.String("requester", "", "workflow requester")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	receipt, err := rollback.Receipt(rollback.Request{
		Environment: *environment, ReleaseClass: *releaseClass, Component: *component,
		Cluster: *cluster, SourceRevision: *revision, ArtifactReference: *artifactReference, CurrentDigest: *current,
		PreviousDigest: *previous, AttestationDigest: *attestation, Signer: *signer,
		Issuer:   *issuer,
		IssuedAt: *issuedAt, Approvals: approvals(*approvalList),
		Repository: *repository, WorkflowRunID: *workflowRunID,
		WorkflowRunAttempt: *workflowRunAttempt, CheckedOutRevision: *checkedOutRevision,
		Requester: *requester,
	})
	if err != nil {
		return err
	}
	return writeJSON(receipt)
}

func transitionCommand(arguments []string) error {
	flags := flag.NewFlagSet("verify-transition", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	trustBundle := flags.String("infrastructure-export-trust-bundle", "", "independently supplied bootstrap infrastructure-export trust bundle")
	trustBundleDigest := flags.String("infrastructure-export-trust-bundle-digest", "", "protected sha256 digest of the raw infrastructure-export trust bundle")
	bootstrapRevision := flags.String("bootstrap-source-revision", "", "protected bootstrap source revision that emitted the trust bundle")
	previousRoot := flags.String("previous-repository-root", "", "independently supplied previous GitOps repository snapshot")
	previousRevision := flags.String("previous-repository-revision", "", "protected previous GitOps revision bound to the replay checkpoint")
	previousStateDigest := flags.String("previous-infrastructure-state-digest", "", "protected digest of the previous InfrastructureExport replay checkpoint")
	action := flags.String("action", "", "promote or rollback")
	environment := flags.String("environment", "", "target environment")
	releaseClass := flags.String("release-class", "", "platform, service, or worker")
	component := flags.String("component", "", "release component")
	cluster := flags.String("cluster", "", "target cluster")
	artifact := flags.String("artifact-digest", "", "requested artifact digest")
	prior := flags.String("prior-digest", "", "currently admitted digest")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	return policy.VerifyTransitionWithOptions(
		*root, *action, *environment, *releaseClass, *component, *cluster, *artifact, *prior,
		policy.ValidationOptions{
			InfrastructureExportTrustBundle:       *trustBundle,
			InfrastructureExportTrustBundleDigest: *trustBundleDigest,
			BootstrapSourceRevision:               *bootstrapRevision,
			PreviousRepositoryRoot:                *previousRoot,
			PreviousRepositoryRevision:            *previousRevision,
			PreviousInfrastructureStateDigest:     *previousStateDigest,
		},
	)
}

func bootstrapProvenance(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return policy.BootstrapProvenance(data)
}

func verifyBootstrap(root string, fetch bool) error {
	provenance, err := bootstrapProvenance(filepath.Join(root, "controllers", "argocd", "kustomization.yaml"))
	if err != nil {
		return err
	}
	if !fetch {
		return nil
	}
	client := &http.Client{Timeout: 30 * time.Second}
	response, err := client.Get(provenance["upstream-url"])
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("bootstrap fetch returned %s", response.Status)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.LimitReader(response.Body, 64<<20)); err != nil {
		return err
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if actual != provenance["upstream-sha256"] {
		return fmt.Errorf("bootstrap checksum mismatch: got %s", actual)
	}
	fmt.Printf("verified Argo CD %s at %s (%s)\n", provenance["upstream-version"], provenance["upstream-revision"], actual)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fail(fmt.Errorf("expected validate, validate-bootstrap, render, receipt, rollback, verify-bootstrap, verify-transition, or version"))
	}
	switch os.Args[1] {
	case "validate":
		flags := flag.NewFlagSet("validate", flag.ExitOnError)
		root := flags.String("root", ".", "repository root")
		trustBundle := flags.String("infrastructure-export-trust-bundle", "", "independently supplied bootstrap infrastructure-export trust bundle")
		trustBundleDigest := flags.String("infrastructure-export-trust-bundle-digest", "", "protected sha256 digest of the raw infrastructure-export trust bundle")
		bootstrapRevision := flags.String("bootstrap-source-revision", "", "protected bootstrap source revision that emitted the trust bundle")
		previousRoot := flags.String("previous-repository-root", "", "independently supplied previous GitOps repository snapshot")
		previousRevision := flags.String("previous-repository-revision", "", "protected previous GitOps revision bound to the replay checkpoint")
		previousStateDigest := flags.String("previous-infrastructure-state-digest", "", "protected digest of the previous InfrastructureExport replay checkpoint")
		_ = flags.Parse(os.Args[2:])
		if err := policy.ValidateRepositoryWithOptions(*root, policy.ValidationOptions{
			InfrastructureExportTrustBundle:       *trustBundle,
			InfrastructureExportTrustBundleDigest: *trustBundleDigest,
			BootstrapSourceRevision:               *bootstrapRevision,
			PreviousRepositoryRoot:                *previousRoot,
			PreviousRepositoryRevision:            *previousRevision,
			PreviousInfrastructureStateDigest:     *previousStateDigest,
		}); err != nil {
			fail(err)
		}
		fmt.Println("gitops source validation passed")
	case "render":
		flags := flag.NewFlagSet("render", flag.ExitOnError)
		root := flags.String("root", ".", "repository root")
		environment := flags.String("environment", "", "environment to render")
		_ = flags.Parse(os.Args[2:])
		content, err := rendering.Environment(*root, *environment)
		if err != nil {
			fail(err)
		}
		_, _ = os.Stdout.Write(content)
	case "validate-bootstrap":
		flags := flag.NewFlagSet("validate-bootstrap", flag.ExitOnError)
		path := flags.String("file", "", "canonical rendered bootstrap YAML")
		_ = flags.Parse(os.Args[2:])
		if *path == "" {
			fail(fmt.Errorf("--file is required"))
		}
		if err := policy.ValidateArgoRender(*path); err != nil {
			fail(err)
		}
		fmt.Println("pinned Argo CD custom resources and image digests passed")
	case "receipt":
		if err := receiptCommand(os.Args[2:]); err != nil {
			fail(err)
		}
	case "rollback":
		if err := rollbackCommand(os.Args[2:]); err != nil {
			fail(err)
		}
	case "verify-transition":
		if err := transitionCommand(os.Args[2:]); err != nil {
			fail(err)
		}
		fmt.Println("checked-out release transition passed")
	case "verify-bootstrap":
		flags := flag.NewFlagSet("verify-bootstrap", flag.ExitOnError)
		root := flags.String("root", ".", "repository root")
		fetch := flags.Bool("fetch", false, "download and hash the pinned payload")
		_ = flags.Parse(os.Args[2:])
		if err := verifyBootstrap(*root, *fetch); err != nil {
			fail(err)
		}
	case "version":
		fmt.Println(version)
	default:
		fail(fmt.Errorf("unknown command %q", os.Args[1]))
	}
}
