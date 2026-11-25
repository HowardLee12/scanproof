package app

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// exceptionIDs maps "package" to the exception ID that accepted
// CVE-2022-48174 in it, or "violation".
func exceptionIDs(t *testing.T, doc map[string]any) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, v := range doc["vulnerabilities"].([]any) {
		f := v.(map[string]any)
		if f["id"] != "CVE-2022-48174" {
			continue
		}
		id, _ := f["exception_id"].(string)
		if id == "" && f["violation"] == true {
			id = "violation"
		}
		out[f["package"].(string)] = id
	}
	return out
}

func appliedIDs(doc map[string]any) string {
	ids := []string{}
	for _, list := range []string{"applied", "expired", "unused"} {
		for _, ex := range doc["exceptions"].(map[string]any)[list].([]any) {
			ids = append(ids, list+":"+ex.(map[string]any)["id"].(string))
		}
	}
	return strings.Join(ids, ",")
}

func TestScanAppliesOnlyExceptionsForTheScannedImage(t *testing.T) {
	for artifact, want := range map[string]string{"alpine": "EX-1", "example-api": "violation", `"alpi*"`: "EX-1"} {
		excs := filepath.Join(t.TempDir(), "exceptions.yaml")
		writeFile(t, excs, "exceptions:\n  - {id: EX-1, finding: CVE-2022-48174, artifact: "+artifact+", reason: r, expires: 2027-02-28}\n")
		out := t.TempDir()
		h := newHarness()
		if code := h.run("scan", "--trivy-results", fixture, "--exceptions", excs, "--out", out, "--pdf=false"); code != 0 {
			t.Fatalf("%s: code %d: %s", artifact, code, h.stderr.String())
		}
		var doc map[string]any
		readJSON(t, filepath.Join(out, "results.json"), &doc)
		if got := exceptionIDs(t, doc)["busybox"]; got != want {
			t.Errorf("artifact %s: busybox is %q, want %q", artifact, got, want)
		}
	}
}

func TestScanRefusesABadArtifactScope(t *testing.T) {
	excs := filepath.Join(t.TempDir(), "exceptions.yaml")
	writeFile(t, excs, "exceptions:\n  - {id: EX-1, finding: CVE-1, artifact: alpine:3.18.0, reason: r, expires: 2027-02-28}\n")
	h := newHarness()
	code := h.run("scan", "--trivy-results", fixture, "--exceptions", excs, "--out", t.TempDir(), "--pdf=false")
	if code != ExitError || !strings.Contains(h.stderr.String(), `exception EX-1: artifact "alpine:3.18.0": drop the tag`) {
		t.Fatalf("code %d, stderr %q", code, h.stderr.String())
	}
}

const centralExceptions = `
exceptions:
  - id: EX-ALPINE
    finding: CVE-2022-48174
    artifact: alpine
    reason: Vendor base image; tracked upstream.
    expires: 2027-02-28
  - id: EX-REPO
    finding: CVE-2022-48174
    package: ssl_client
    artifact: ["repo/*", "dir:acme-vllm"]
    reason: ssl_client is not used.
    expires: 2027-02-28
  - id: EX-GONE
    finding: CVE-2022-48174
    artifact: cr.example.com/retired/app
    reason: The image was retired.
    expires: 2027-02-28
`

func TestRescanScopesACentralExceptionsFilePerImage(t *testing.T) {
	storeDir := t.TempDir()
	trivyBin := fakeTrivy(t)
	seed := newHarness()
	seed.now = time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC)
	if code := seed.run("scan", "--trivy", trivyBin, "--out", t.TempDir(), "--pdf=false",
		"--store", "file://"+storeDir, "--", "alpine:3.18.0"); code != 0 {
		t.Fatalf("seed scan: %d %s", code, seed.stderr.String())
	}
	images := filepath.Join(t.TempDir(), "images.txt")
	writeFile(t, images, "alpine:3.18.0@"+fixtureDigest+"\nrepo/new:1@sha256:"+strings.Repeat("c", 64)+"\n")
	excs := filepath.Join(t.TempDir(), "exceptions.yaml")
	writeFile(t, excs, centralExceptions)

	h := newHarness()
	code := h.run("rescan", "--store", "file://"+storeDir, "--inventory", "file", "--images-file", images,
		"--trivy", trivyBin, "--exceptions", excs, "--out", t.TempDir(), "--notify", "never")
	if code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}
	warning := "scanproof: warning: exception EX-GONE is limited to cr.example.com/retired/app, which matched no running image or directory"
	if stderr := h.stderr.String(); !strings.Contains(stderr, warning) || strings.Count(stderr, "matched no running") != 1 {
		t.Errorf("a scoped exception that matches nothing running should be named once: %q", stderr)
	}
	byRef := map[string]map[string]any{}
	for _, doc := range storedResults(t, storeDir)["rescan"] {
		byRef[doc["image"].(map[string]any)["reference"].(string)] = doc
	}
	alpine, repo := byRef["alpine:3.18.0"], byRef["repo/new:1"]
	if alpine == nil || repo == nil {
		t.Fatalf("rescans = %v", byRef)
	}
	want := map[string]string{"busybox": "EX-ALPINE", "busybox-binsh": "EX-ALPINE", "ssl_client": "EX-ALPINE"}
	if got := exceptionIDs(t, alpine); !equalMaps(got, want) || appliedIDs(alpine) != "applied:EX-ALPINE" {
		t.Errorf("alpine: %v, exceptions %s", got, appliedIDs(alpine))
	}
	want = map[string]string{"busybox": "violation", "busybox-binsh": "violation", "ssl_client": "EX-REPO"}
	if got := exceptionIDs(t, repo); !equalMaps(got, want) || appliedIDs(repo) != "applied:EX-REPO" {
		t.Errorf("repo/new: %v, exceptions %s", got, appliedIDs(repo))
	}
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestScanDirAppliesOnlyExceptionsForTheDirectory(t *testing.T) {
	root := makeSoftwareDir(t)
	for artifact, want := range map[string]string{`"dir:acme-vllm"`: "EX-1", `"dir:acme-*"`: "EX-1", "acme-vllm": "violation", `"dir:other"`: "violation"} {
		excs := filepath.Join(t.TempDir(), "exceptions.yaml")
		writeFile(t, excs, "exceptions:\n  - {id: EX-1, finding: CVE-2022-48174, artifact: "+artifact+", reason: r, expires: 2027-02-28}\n")
		out := t.TempDir()
		h := newHarness()
		code := h.run("scan", "--dir", "--name", "acme-vllm", "--version", "0.9.1", "--trivy", fakeTrivy(t),
			"--exceptions", excs, "--out", out, "--pdf=false", "--sbom=false", root)
		if code != 0 {
			t.Fatalf("%s: code %d: %s", artifact, code, h.stderr.String())
		}
		var doc map[string]any
		readJSON(t, filepath.Join(out, "results.json"), &doc)
		if got := exceptionIDs(t, doc)["busybox"]; got != want {
			t.Errorf("artifact %s: busybox is %q, want %q", artifact, got, want)
		}
	}
}

// When an inventory source failed, its images were never listed, so an
// exception for them is not "unmatched".
func TestNoScopeWarningWhenAnInventoryFailed(t *testing.T) {
	images := filepath.Join(t.TempDir(), "images.txt")
	writeFile(t, images, "repo/x@not-a-digest\n")
	excs := filepath.Join(t.TempDir(), "exceptions.yaml")
	writeFile(t, excs, centralExceptions)
	h := newHarness()
	h.run("rescan", "--store", "file://"+t.TempDir(), "--inventory", "file", "--images-file", images,
		"--trivy", fakeTrivy(t), "--exceptions", excs, "--out", t.TempDir(), "--notify", "never")
	if strings.Contains(h.stderr.String(), "matched no running") {
		t.Errorf("no scope warning while an inventory could not be read: %q", h.stderr.String())
	}
}

func TestResultsNameTheExceptionsFile(t *testing.T) {
	excs := filepath.Join(t.TempDir(), "exceptions.yaml")
	writeFile(t, excs, centralExceptions)
	out := t.TempDir()
	h := newHarness()
	if code := h.run("scan", "--trivy-results", fixture, "--exceptions", excs, "--out", out, "--pdf=false"); code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}
	var doc map[string]any
	readJSON(t, filepath.Join(out, "results.json"), &doc)
	e := doc["exceptions"].(map[string]any)
	sum := sha256.Sum256([]byte(centralExceptions))
	oos, _ := e["out_of_scope"].(map[string]any)
	if e["source"] != excs || e["sha256"] != hex.EncodeToString(sum[:]) || oos["count"] != float64(2) {
		t.Fatalf("exceptions = %v", e)
	}
}

// The two files a review used to widen a scoped exception to every image:
// an alias as the artifact key, and a merge key around the whole file.
func TestScanRefusesExceptionsFilesThatHideTheirScope(t *testing.T) {
	files := map[string]string{
		"alias key": `exceptions:
  - id: SCOPED
    finding: CVE-2000-0001
    reason: r
    expires: 2099-01-01
    &k artifact: cr.example.com/team/api
  - id: LOOKS-SCOPED
    finding: CVE-2022-48174
    reason: accepted for cr.example.com/team/api only
    expires: 2099-01-01
    *k :
`,
		"merge key": `<<:
  exceptions:
    - {id: EX-1, finding: CVE-2022-48174, reason: r, expires: 2099-01-01, artifact: }
`,
	}
	for name, content := range files {
		excs := filepath.Join(t.TempDir(), "exceptions.yaml")
		writeFile(t, excs, content)
		h := newHarness()
		code := h.run("scan", "--trivy-results", fixture, "--exceptions", excs, "--out", t.TempDir(), "--pdf=false")
		if code != ExitError || !strings.Contains(h.stderr.String(), "are not supported in an exceptions file") {
			t.Errorf("%s: code %d, stderr %q", name, code, h.stderr.String())
		}
	}
}
