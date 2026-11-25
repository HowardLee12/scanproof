package policy

import (
	"testing"

	"github.com/HowardLee12/scanproof/internal/model"
)

const scopedStdlib = `
exceptions:
  - id: EX-GO
    finding: CVE-1
    package: stdlib
    artifact: cr.example.com/mirror/coredns/coredns
    reason: Vendor image; the vendor ships the Go fix.
    expires: 2027-01-31
`

func imageResult(ref string) model.ScanResult {
	v := vuln("CVE-1", model.SeverityCritical, "1.1")
	v.Package = "stdlib"
	return model.ScanResult{Image: model.Image{Reference: ref}, Vulnerabilities: []model.Vulnerability{v}}
}

func TestScopedExceptionOnlyAcceptsItsImage(t *testing.T) {
	excs := mustExceptions(t, scopedStdlib)
	vendor := Evaluate(imageResult("cr.example.com/mirror/coredns/coredns:v1.11.1@sha256:"+sha64), Default(), excs, now)
	if vendor.Verdict != VerdictPass || vendor.Vulnerabilities[0].ExceptionID != "EX-GO" || len(vendor.Applied) != 1 {
		t.Fatalf("the vendor image should be accepted: %+v", vendor)
	}
	ours := Evaluate(imageResult("cr.example.com/team/api:2.0"), Default(), excs, now)
	if ours.Verdict != VerdictWarn || ours.Vulnerabilities[0].Accepted() || !ours.Vulnerabilities[0].Violation {
		t.Fatalf("the same CVE in another image is still a violation: %+v", ours.Vulnerabilities)
	}
	// An exception for other artifacts is not "unused" in this one: it is
	// out of scope, and a central file would otherwise flood every report.
	if len(ours.Applied)+len(ours.Expired)+len(ours.Unused) != 0 {
		t.Errorf("out-of-scope exception listed: applied %v, expired %v, unused %v", ours.Applied, ours.Expired, ours.Unused)
	}
}

const sha64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func directoryResult(ref string) model.ScanResult {
	res := imageResult(ref)
	res.ArtifactType = model.ArtifactDirectory
	return res
}

func TestScopedExceptionForADirectory(t *testing.T) {
	excs := mustExceptions(t, `
exceptions:
  - {id: EX-D, finding: CVE-1, artifact: "dir:acme-vllm", reason: r, expires: 2027-01-31}
`)
	if ev := Evaluate(directoryResult("dir:acme-vllm:0.9.1"), Default(), excs, now); !ev.Vulnerabilities[0].Accepted() {
		t.Error("every version of the directory is in scope")
	}
	if ev := Evaluate(directoryResult("dir:acme-vllm"), Default(), excs, now); !ev.Vulnerabilities[0].Accepted() {
		t.Error("a directory without a version is in scope")
	}
	if ev := Evaluate(imageResult("acme-vllm:0.9.1"), Default(), excs, now); ev.Vulnerabilities[0].Accepted() {
		t.Error("an image with the directory's name is not the directory")
	}
	if ev := Evaluate(directoryResult("dir:other"), Default(), excs, now); ev.Vulnerabilities[0].Accepted() {
		t.Error("another directory is out of scope")
	}
}

func TestScopedExceptionListAndPrefix(t *testing.T) {
	excs := mustExceptions(t, `
exceptions:
  - id: EX-L
    finding: CVE-1
    artifact: [example-api, "cr.example.com/mirror/*"]
    reason: r
    expires: 2027-01-31
`)
	for ref, want := range map[string]bool{
		"example-api:1.0":                          true,
		"cr.example.com/mirror/coredns/coredns:v1": true,
		"cr.example.com/mirror2/app:1":             false,
		"example-api-worker:1.0":                   false,
	} {
		if got := Evaluate(imageResult(ref), Default(), excs, now).Vulnerabilities[0].Accepted(); got != want {
			t.Errorf("%s: accepted = %v, want %v", ref, got, want)
		}
	}
}

func TestScopedSecretAndMalwareExceptions(t *testing.T) {
	excs := mustExceptions(t, `
exceptions:
  - {id: EX-S, finding: github-pat, path: tests/token.txt, artifact: example-api, reason: r, expires: 2027-01-31}
  - {id: EX-M, finding: Eicar-Test-Signature, path: tests/eicar.com, artifact: example-api, reason: r, expires: 2027-01-31}
`)
	result := func(ref string) model.ScanResult {
		return model.ScanResult{
			Image:   model.Image{Reference: ref},
			Secrets: []model.Secret{{RuleID: "github-pat", Target: "tests/token.txt"}},
			Malware: &model.MalwareScan{Detections: []model.MalwareDetection{{Path: "tests/eicar.com", Signature: "Eicar-Test-Signature"}}},
		}
	}
	in := Evaluate(result("example-api:1.0"), Default(), excs, now)
	if !in.Secrets[0].Accepted() || !in.Malware[0].Accepted() || in.Verdict != VerdictPass {
		t.Errorf("in scope: secrets %+v, malware %+v", in.Secrets, in.Malware)
	}
	out := Evaluate(result("example-worker:1.0"), Default(), excs, now)
	if out.Secrets[0].Accepted() || out.Malware[0].Accepted() || out.Verdict != VerdictWarn {
		t.Errorf("out of scope: secrets %+v, malware %+v", out.Secrets, out.Malware)
	}
}

func TestGlobalExceptionsStillApplyEverywhere(t *testing.T) {
	excs := mustExceptions(t, "exceptions:\n  - {id: EX-1, finding: CVE-1, reason: r, expires: 2027-01-31}\n")
	for _, res := range []model.ScanResult{imageResult("example-api:1.0"), directoryResult("dir:acme-vllm:1"), {}} {
		if len(res.Vulnerabilities) > 0 && !Evaluate(res, Default(), excs, now).Vulnerabilities[0].Accepted() {
			t.Errorf("%s: a global exception applies everywhere", res.Image.Reference)
		}
	}
	if ev := Evaluate(model.ScanResult{}, Default(), excs, now); len(ev.Unused) != 1 {
		t.Error("a global exception that matched nothing is still listed as unused")
	}
}

// Whether an artifact is a directory comes from the scan, not from its
// name: an image from a registry host named "dir" is not a directory.
func TestADirScopeNeverMatchesAnImage(t *testing.T) {
	excs := mustExceptions(t, `
exceptions:
  - {id: EX-D, finding: CVE-1, artifact: "dir:*", reason: r, expires: 2027-01-31}
`)
	if Evaluate(imageResult("dir:5000/app:1"), Default(), excs, now).Vulnerabilities[0].Accepted() {
		t.Error("an image named dir:5000/app is still an image")
	}
	if !Evaluate(directoryResult("dir:acme-vllm:1"), Default(), excs, now).Vulnerabilities[0].Accepted() {
		t.Error("dir:* covers every directory")
	}
}

func TestOutOfScopeExceptionsAreCounted(t *testing.T) {
	ev := Evaluate(imageResult("cr.example.com/team/api:2.0"), Default(), mustExceptions(t, scopedStdlib), now)
	if len(ev.OutOfScope) != 1 || ev.OutOfScope[0].ID != "EX-GO" {
		t.Fatalf("out of scope = %+v", ev.OutOfScope)
	}
	if ev := Evaluate(imageResult("cr.example.com/mirror/coredns/coredns:1"), Default(), mustExceptions(t, scopedStdlib), now); len(ev.OutOfScope) != 0 {
		t.Errorf("an exception in scope is not out of scope: %+v", ev.OutOfScope)
	}
}
