package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// seedDirectoryScan stores a scan --dir of root on 1 November and returns
// its tree digest.
func seedDirectoryScan(t *testing.T, storeDir, trivyBin, root string) string {
	t.Helper()
	h := newHarness()
	h.now = time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC)
	code := h.run("scan", "--dir", "--name", "acme-vllm", "--version", "0.9.1", "--trivy", trivyBin,
		"--out", t.TempDir(), "--pdf=false", "--store", "file://"+storeDir, root)
	if code != 0 {
		t.Fatalf("seed scan: %d %s", code, h.stderr.String())
	}
	return treeDigestOf(t, root)
}

func TestRescanChecksADirectoryFromItsStoredSBOM(t *testing.T) {
	storeDir, trivyBin := t.TempDir(), fakeTrivy(t)
	digest := seedDirectoryScan(t, storeDir, trivyBin, makeSoftwareDir(t))
	images := filepath.Join(t.TempDir(), "images.txt")
	writeFile(t, images, "# deployed outside images\ndir:acme-vllm:0.9.1@"+digest+"   gpu-cluster/inference/vllm\n")

	received := make(chan []byte, 2)
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
		"--trivy", trivyBin, "--out", t.TempDir(), "--notify", "always")
	if code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}
	rescans := storedResults(t, storeDir)["rescan"]
	if len(rescans) != 1 {
		t.Fatalf("stored rescans = %d", len(rescans))
	}
	doc := rescans[0]
	rt := doc["runtime"].(map[string]any)
	dir := doc["directory"].(map[string]any)
	if doc["artifact_type"] != "directory" || rt["method"] != "sbom" || dir["name"] != "acme-vllm" || dir["tree_digest"] != digest ||
		!reflect.DeepEqual(rt["locations"], []any{"gpu-cluster/inference/vllm"}) {
		t.Errorf("rescan = artifact %v, runtime %v, directory %v", doc["artifact_type"], rt, dir)
	}
	if len(doc["vulnerabilities"].([]any)) == 0 {
		t.Error("the stored SBOM's vulnerabilities must be reported")
	}
	if out := h.stdout.String(); !strings.Contains(out, "directory acme-vllm:0.9.1") || !strings.Contains(out, "1 directory rescanned") {
		t.Errorf("stdout = %q", out)
	}
	if body := string(next(t, received)); !strings.Contains(body, "1 directory") || !strings.Contains(body, "directory acme-vllm:0.9.1") {
		t.Errorf("notification = %s", body)
	}
}

func TestRescanNeverPullsADirectory(t *testing.T) {
	storeDir := t.TempDir()
	images := filepath.Join(t.TempDir(), "images.txt")
	writeFile(t, images, "dir:example-worker:2@sha256:"+strings.Repeat("d", 64)+"\n")
	for _, pull := range []string{"--pull-missing=true", "--pull-missing=false"} {
		received := make(chan []byte, 1)
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			received <- body
			w.WriteHeader(http.StatusNoContent)
		}))
		h := newHarness()
		h.client = srv.Client()
		h.env["SCANPROOF_SLACK_WEBHOOK_URL"] = srv.URL + "/hook"
		code := h.run("rescan", "--store", "file://"+storeDir, "--inventory", "file", "--images-file", images,
			"--trivy", fakeTrivy(t), "--out", t.TempDir(), pull)
		srv.Close()
		want := "no stored scan for this directory; run scanproof scan --dir on a host that has it"
		if code != ExitError || !strings.Contains(h.stderr.String(), want) {
			t.Errorf("%s: code %d, stderr %q", pull, code, h.stderr.String())
		}
		if body := string(next(t, received)); !strings.Contains(body, "directory example-worker:2") || !strings.Contains(body, "no stored scan") {
			t.Errorf("%s: notification = %s", pull, body)
		}
		if len(storedResults(t, storeDir)["rescan"]) != 0 {
			t.Fatalf("%s: nothing may be stored for a directory that was not checked", pull)
		}
	}
}

func TestRescanDoesNotUseAnImageScanForADirectory(t *testing.T) {
	storeDir, trivyBin := t.TempDir(), fakeTrivy(t)
	seed := newHarness()
	if code := seed.run("scan", "--trivy", trivyBin, "--out", t.TempDir(), "--pdf=false",
		"--store", "file://"+storeDir, "--", "alpine:3.18.0"); code != 0 {
		t.Fatalf("seed: %d %s", code, seed.stderr.String())
	}
	images := filepath.Join(t.TempDir(), "images.txt")
	// The image's digest listed as a directory must not match the image scan.
	writeFile(t, images, "dir:impostor@"+fixtureDigest+"\n")
	h := newHarness()
	code := h.run("rescan", "--store", "file://"+storeDir, "--inventory", "file", "--images-file", images,
		"--trivy", trivyBin, "--out", t.TempDir())
	if code != ExitError || !strings.Contains(h.stderr.String(), "not a directory scan") {
		t.Fatalf("code %d, stderr %q", code, h.stderr.String())
	}
}

func TestRescanInventoryList(t *testing.T) {
	opts, err := parseRescanOptions([]string{"--store", "file:///x", "--inventory", " kubernetes, file,kubernetes", "--images-file", "i.txt"}, io.Discard)
	if err != nil || !reflect.DeepEqual(opts.Inventories, []string{"kubernetes", "file"}) {
		t.Fatalf("got %v, %v", opts.Inventories, err)
	}
	for _, bad := range [][]string{
		{"--store", "file:///x", "--inventory", "kubernetes,docker"},
		{"--store", "file:///x", "--inventory", "kubernetes,"},
		{"--store", "file:///x", "--inventory", "kubernetes,file"},
	} {
		if _, err := parseRescanOptions(bad, io.Discard); err == nil {
			t.Errorf("%v should be rejected", bad)
		}
	}
}

func TestRescanMergesCopiesOfADirectoryByTreeDigest(t *testing.T) {
	storeDir, trivyBin := t.TempDir(), fakeTrivy(t)
	digest := seedDirectoryScan(t, storeDir, trivyBin, makeSoftwareDir(t))
	images := filepath.Join(t.TempDir(), "images.txt")
	writeFile(t, images, "dir:acme-vllm:0.9.1@"+digest+" node-a\ndir:acme-vllm:0.9.1@"+digest+" node-b\n")
	h := newHarness()
	code := h.run("rescan", "--store", "file://"+storeDir, "--inventory", "file,file", "--images-file", images,
		"--trivy", trivyBin, "--out", t.TempDir())
	if code != 0 || !strings.Contains(h.stdout.String(), "1 directory rescanned") {
		t.Fatalf("code %d, stdout %q, stderr %q", code, h.stdout.String(), h.stderr.String())
	}
	rt := storedResults(t, storeDir)["rescan"][0]["runtime"].(map[string]any)
	if !reflect.DeepEqual(rt["locations"], []any{"node-a", "node-b"}) {
		t.Errorf("copies of one directory are merged by tree digest: %v", rt["locations"])
	}
}

// next returns the notification the run already sent, or fails.
func next(t *testing.T, received chan []byte) []byte {
	t.Helper()
	select {
	case body := <-received:
		return body
	default:
		t.Fatal("no notification was sent")
		return nil
	}
}
