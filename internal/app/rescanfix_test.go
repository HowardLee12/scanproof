package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// notifyServer collects chat messages.
func notifyServer(t *testing.T, h *harness) chan []byte {
	t.Helper()
	received := make(chan []byte, 4)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- body
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	h.client = srv.Client()
	h.env["SCANPROOF_DISCORD_WEBHOOK_URL"] = srv.URL + "/hook"
	return received
}

func TestRescanGoesOnAfterABadLineAndAFailedSource(t *testing.T) {
	storeDir, trivyBin := t.TempDir(), fakeTrivy(t)
	digest := seedDirectoryScan(t, storeDir, trivyBin, makeSoftwareDir(t))
	images := filepath.Join(t.TempDir(), "images.txt")
	writeFile(t, images, "dir:acme-vllm:0.9.1@"+digest+"\ndir:broken-line\n")
	t.Setenv("KUBERNETES_SERVICE_HOST", "") // the kubernetes inventory fails here

	h := newHarness()
	received := notifyServer(t, h)
	h.now = time.Date(2026, 11, 24, 6, 0, 0, 0, time.UTC)
	code := h.run("rescan", "--store", "file://"+storeDir, "--inventory", "kubernetes,file", "--images-file", images,
		"--trivy", trivyBin, "--out", t.TempDir())
	if code != ExitError {
		t.Fatalf("code %d, want %d", code, ExitError)
	}
	if len(storedResults(t, storeDir)["rescan"]) != 1 {
		t.Fatal("the good line must still be rescanned")
	}
	stderr := h.stderr.String()
	if !strings.Contains(stderr, "line 2") || !strings.Contains(stderr, "kubernetes inventory") {
		t.Errorf("stderr = %q", stderr)
	}
	if out := h.stdout.String(); !strings.Contains(out, "1 directory rescanned, 2 failed") {
		t.Errorf("stdout = %q", out)
	}
	body := string(next(t, received))
	if !strings.Contains(body, "line 2") || !strings.Contains(body, "kubernetes inventory") {
		t.Errorf("the chat message must list the failures: %s", body)
	}
}

func TestRescanWarnsAboutAnImagesFileItDoesNotRead(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	h := newHarness()
	h.run("rescan", "--store", "file://"+t.TempDir(), "--inventory", "kubernetes", "--images-file", "images.txt", "--out", t.TempDir())
	if !strings.Contains(h.stderr.String(), "warning: --images-file is only read with --inventory file") {
		t.Fatalf("stderr = %q", h.stderr.String())
	}
}

func TestRescanNamesTheStoredScanItCouldNotUse(t *testing.T) {
	storeDir, trivyBin := t.TempDir(), fakeTrivy(t)
	digest := seedDirectoryScan(t, storeDir, trivyBin, makeSoftwareDir(t))
	sboms, _ := filepath.Glob(filepath.Join(storeDir, "scans", "*", "*", "*", "*", "sbom.cdx.json"))
	if err := os.WriteFile(sboms[0], []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	reportID := filepath.Base(filepath.Dir(sboms[0]))
	images := filepath.Join(t.TempDir(), "images.txt")
	writeFile(t, images, "dir:acme-vllm:0.9.1@"+digest+"\n")

	h := newHarness()
	received := notifyServer(t, h)
	code := h.run("rescan", "--store", "file://"+storeDir, "--inventory", "file", "--images-file", images,
		"--trivy", trivyBin, "--out", t.TempDir())
	stderr := h.stderr.String()
	if code != ExitError || !strings.Contains(stderr, reportID) || !strings.Contains(stderr, "does not match the SHA-256") ||
		strings.Contains(stderr, "no stored scan") {
		t.Fatalf("a tampered SBOM must be named, not reported as missing: code %d, stderr %q", code, stderr)
	}
	if body := string(next(t, received)); !strings.Contains(body, reportID) {
		t.Errorf("the chat message must name the stored scan: %s", body)
	}
}
