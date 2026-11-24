package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HowardLee12/scanproof/internal/store"
)

// seedImageScan stores a scan of alpine:3.18.0 with its SBOM and returns the
// stored SBOM's path.
func seedImageScan(t *testing.T, storeDir, trivyBin string) string {
	t.Helper()
	seed := newHarness()
	seed.now = time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC)
	if code := seed.run("scan", "--trivy", trivyBin, "--out", t.TempDir(), "--pdf=false",
		"--store", "file://"+storeDir, "--", "alpine:3.18.0"); code != 0 {
		t.Fatalf("seed: %d %s", code, seed.stderr.String())
	}
	sboms, _ := filepath.Glob(filepath.Join(storeDir, "scans", "*", "*", "*", "*", "sbom.cdx.json"))
	if len(sboms) != 1 {
		t.Fatalf("stored SBOMs = %v", sboms)
	}
	return sboms[0]
}

func TestRescanWithoutPullReportsAStoredImageScanItCannotUse(t *testing.T) {
	storeDir, trivyBin := t.TempDir(), fakeTrivy(t)
	sbom := seedImageScan(t, storeDir, trivyBin)
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	images := filepath.Join(t.TempDir(), "images.txt")
	writeFile(t, images, "alpine:3.18.0@"+fixtureDigest+"\n")
	h := newHarness()
	code := h.run("rescan", "--store", "file://"+storeDir, "--inventory", "file", "--images-file", images,
		"--trivy", trivyBin, "--out", t.TempDir(), "--pull-missing=false")
	stderr := h.stderr.String()
	reportID := filepath.Base(filepath.Dir(sbom))
	if code != ExitError || !strings.Contains(stderr, reportID) || !strings.Contains(stderr, "does not match the SHA-256") ||
		strings.Contains(stderr, "skipping") {
		t.Fatalf("a tampered stored scan must fail, not be skipped: code %d, stderr %q", code, stderr)
	}
}

func TestRescanReportsIndexEntriesItCannotRead(t *testing.T) {
	storeDir := t.TempDir()
	digest := "sha256:" + strings.Repeat("e", 64)
	prefix, _ := store.DigestIndexPrefix(digest)
	if err := os.MkdirAll(filepath.Join(storeDir, filepath.FromSlash(prefix)), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(storeDir, filepath.FromSlash(prefix), "SR-20261101-AAAAAA.json"), "{broken")
	images := filepath.Join(t.TempDir(), "images.txt")
	writeFile(t, images, "dir:acme-vllm:1@"+digest+"\nrepo/app:1@"+digest+"\n")
	h := newHarness()
	code := h.run("rescan", "--store", "file://"+storeDir, "--inventory", "file", "--images-file", images,
		"--trivy", fakeTrivy(t), "--out", t.TempDir(), "--pull-missing=false")
	stderr := h.stderr.String()
	if code != ExitError || strings.Count(stderr, "1 stored index entry for this digest could not be read") != 2 ||
		strings.Contains(stderr, "no stored scan") {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
}

func TestRescanFailsForAnImagesFileItDoesNotRead(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	h := newHarness()
	code := h.run("rescan", "--store", "file://"+t.TempDir(), "--inventory", "kubernetes", "--images-file", "images.txt", "--out", t.TempDir())
	if code != ExitError || !strings.Contains(h.stderr.String(), "--images-file: it is only read with --inventory file") {
		t.Fatalf("code %d, stderr %q", code, h.stderr.String())
	}
}
