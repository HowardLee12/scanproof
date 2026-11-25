package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// When Trivy reaches its own --timeout on a stored SBOM, the rescan of that
// image is out of time: it must not try older SBOMs or pull the image, and
// the message names the SBOM scan.
func TestRescanStopsWhenTrivyTimesOutOnTheStoredSBOM(t *testing.T) {
	storeDir := t.TempDir()
	seed := newHarness()
	seed.now = time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC)
	if code := seed.run("scan", "--trivy", fakeTrivy(t), "--out", t.TempDir(), "--pdf=false",
		"--store", "file://"+storeDir, "--", "alpine:3.18.0"); code != 0 {
		t.Fatalf("seed scan: %d %s", code, seed.stderr.String())
	}
	images := filepath.Join(t.TempDir(), "images.txt")
	writeFile(t, images, "alpine:3.18.0@"+fixtureDigest+"\n")
	calls := filepath.Join(t.TempDir(), "calls.log")
	trivyBin := trivyScript(t, `echo "$1" >> '`+calls+`'
if [ "$1" = sbom ]; then sleep 1.5; echo 'FATAL scan error: context deadline exceeded' >&2; exit 1; fi`)

	h := newHarness()
	code := h.run("rescan", "--store", "file://"+storeDir, "--inventory", "file", "--images-file", images,
		"--trivy", trivyBin, "--out", t.TempDir(), "--timeout", "1s", "--notify", "never")
	want := "the rescan of this image stopped at its --timeout of 1s during the Trivy SBOM scan; raise --timeout"
	if code != ExitError || !strings.Contains(h.stderr.String(), want) {
		t.Fatalf("code %d, stderr %q", code, h.stderr.String())
	}
	data, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "image") {
		t.Errorf("the image must not be pulled after the timeout; trivy ran: %q", data)
	}
}
