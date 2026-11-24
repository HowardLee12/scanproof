package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixtureDigest = "sha256:02bb6f428431fbc2809c5d1b41eab5a68350194fb508869a33cb1af4444c9b11"

// storedResults returns the results.json documents in a file store, by trigger.
func storedResults(t *testing.T, storeDir string) map[string][]map[string]any {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(storeDir, "scans", "*", "*", "*", "*", "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]map[string]any{}
	for _, f := range files {
		var doc map[string]any
		readJSON(t, f, &doc)
		trigger, _ := doc["trigger"].(string)
		out[trigger] = append(out[trigger], doc)
	}
	return out
}

func TestRescanUsesStoredSBOMAndPullsTheRest(t *testing.T) {
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

	received := make(chan []byte, 4)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- body
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	h := newHarness()
	h.client = srv.Client()
	h.env["SCANPROOF_DISCORD_WEBHOOK_URL"] = srv.URL + "/hook"
	h.now = time.Date(2026, 11, 24, 6, 0, 0, 0, time.UTC)
	code := h.run("rescan", "--store", "file://"+storeDir, "--inventory", "file", "--images-file", images,
		"--trivy", trivyBin, "--out", t.TempDir())
	if code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}

	byTrigger := storedResults(t, storeDir)
	if len(byTrigger["ci"])+len(byTrigger["manual"]) != 1 || len(byTrigger["rescan"]) != 2 {
		t.Fatalf("stored scans = %v", map[string]int{"rescan": len(byTrigger["rescan"]), "ci": len(byTrigger["ci"]), "manual": len(byTrigger["manual"])})
	}
	methods := map[string]string{}
	for _, doc := range byTrigger["rescan"] {
		img := doc["image"].(map[string]any)
		rt := doc["runtime"].(map[string]any)
		methods[img["reference"].(string)] = rt["method"].(string)
		if img["reference"] == "repo/new:1" && img["digest"] != "sha256:"+strings.Repeat("c", 64) {
			t.Errorf("the running digest must be recorded, got %v", img["digest"])
		}
	}
	if methods["alpine:3.18.0"] != "sbom" || methods["repo/new:1"] != "image" {
		t.Errorf("methods = %v", methods)
	}

	select {
	case body := <-received:
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil || !strings.Contains(string(body), "2 running images") {
			t.Errorf("unexpected notification %s", body)
		}
	default:
		t.Fatal("expected one summary notification")
	}
	if len(received) != 0 {
		t.Error("a rescan sends one notification, not one per image")
	}
	if !strings.Contains(h.stdout.String(), "2 images rescanned") {
		t.Errorf("stdout = %q", h.stdout.String())
	}
}

func TestRescanWithoutPullSkipsImagesWithoutSBOM(t *testing.T) {
	storeDir := t.TempDir()
	images := filepath.Join(t.TempDir(), "images.txt")
	writeFile(t, images, "repo/new:1@sha256:"+strings.Repeat("c", 64)+"\n")
	h := newHarness()
	code := h.run("rescan", "--store", "file://"+storeDir, "--inventory", "file", "--images-file", images,
		"--trivy", fakeTrivy(t), "--out", t.TempDir(), "--pull-missing=false")
	if code != 0 || !strings.Contains(h.stderr.String(), "no stored SBOM") {
		t.Fatalf("code %d, stderr %q", code, h.stderr.String())
	}
	if len(storedResults(t, storeDir)["rescan"]) != 0 {
		t.Fatal("nothing should be stored")
	}
}

func TestRescanReportsFailedImages(t *testing.T) {
	dir := t.TempDir()
	failing := filepath.Join(dir, "trivy")
	writeFile(t, failing, "#!/bin/sh\necho 'registry says no' >&2\nexit 1\n")
	if err := os.Chmod(failing, 0o755); err != nil {
		t.Fatal(err)
	}
	images := filepath.Join(dir, "images.txt")
	writeFile(t, images, "repo/new:1\n")
	h := newHarness()
	code := h.run("rescan", "--store", "file://"+t.TempDir(), "--inventory", "file", "--images-file", images,
		"--trivy", failing, "--out", t.TempDir())
	if code != ExitError || !strings.Contains(h.stderr.String(), "registry says no") {
		t.Fatalf("code %d, stderr %q", code, h.stderr.String())
	}
}

func TestRescanUsageErrors(t *testing.T) {
	cases := [][]string{
		{"rescan", "--inventory", "file", "--images-file", "x"},
		{"rescan", "--store", "file:///tmp/x"},
		{"rescan", "--store", "file:///tmp/x", "--inventory", "docker"},
		{"rescan", "--store", "file:///tmp/x", "--inventory", "file"},
		{"rescan", "--store", "file:///tmp/x", "--inventory", "kubernetes"},
	}
	for _, args := range cases {
		h := newHarness()
		if code := h.run(args...); code != ExitError {
			t.Errorf("%v: code %d", args, code)
		}
	}
}

func TestRescanFallsBackWhenTheStoredSBOMWasChanged(t *testing.T) {
	storeDir := t.TempDir()
	trivyBin := fakeTrivy(t)
	seed := newHarness()
	seed.now = time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC)
	if code := seed.run("scan", "--trivy", trivyBin, "--out", t.TempDir(), "--pdf=false",
		"--store", "file://"+storeDir, "--", "alpine:3.18.0"); code != 0 {
		t.Fatalf("seed scan: %d %s", code, seed.stderr.String())
	}
	sboms, _ := filepath.Glob(filepath.Join(storeDir, "scans", "*", "*", "*", "*", "sbom.cdx.json"))
	if len(sboms) != 1 {
		t.Fatalf("expected one stored SBOM, got %v", sboms)
	}
	if err := os.WriteFile(sboms[0], []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	images := filepath.Join(t.TempDir(), "images.txt")
	writeFile(t, images, "alpine:3.18.0@"+fixtureDigest+"\n")
	h := newHarness()
	h.now = time.Date(2026, 11, 24, 6, 0, 0, 0, time.UTC)
	if code := h.run("rescan", "--store", "file://"+storeDir, "--inventory", "file", "--images-file", images,
		"--trivy", trivyBin, "--out", t.TempDir()); code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}
	if !strings.Contains(h.stderr.String(), "does not match the SHA-256") {
		t.Errorf("expected a warning about the changed SBOM, got %q", h.stderr.String())
	}
	rescans := storedResults(t, storeDir)["rescan"]
	if len(rescans) != 1 || rescans[0]["runtime"].(map[string]any)["method"] != "image" {
		t.Fatalf("the image should have been pulled instead: %+v", rescans)
	}
}

func TestImportedResultsDoNotCreateAnSBOM(t *testing.T) {
	storeDir := t.TempDir()
	h := newHarness()
	if code := h.run("scan", "--trivy-results", fixture, "--trivy", fakeTrivy(t), "--out", t.TempDir(),
		"--pdf=false", "--store", "file://"+storeDir); code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}
	if sboms, _ := filepath.Glob(filepath.Join(storeDir, "scans", "*", "*", "*", "*", "sbom.cdx.json")); len(sboms) != 0 {
		t.Fatalf("an imported report must not produce an SBOM: %v", sboms)
	}
	if _, err := os.Stat(filepath.Join(storeDir, "index")); err == nil {
		t.Fatal("scans without an SBOM must not be indexed")
	}
}
