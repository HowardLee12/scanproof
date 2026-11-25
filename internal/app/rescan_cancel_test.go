package app

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// After SIGINT or SIGTERM the rescan stops, and says so once, instead of
// reporting every remaining image as cancelled.
func TestRescanStopsWhenCancelled(t *testing.T) {
	images := filepath.Join(t.TempDir(), "images.txt")
	writeFile(t, images, "repo/a:1\nrepo/b:1\ndir:acme-vllm:0.9.1@"+fixtureDigest+"\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h := newHarness()
	h.ctx = ctx
	code := h.run("rescan", "--store", "file://"+t.TempDir(), "--inventory", "file", "--images-file", images,
		"--trivy", fakeTrivy(t), "--out", t.TempDir(), "--notify", "never")
	stderr := h.stderr.String()
	want := "scanproof: the rescan was cancelled; not rescanned: 2 images and 1 directory\n"
	if code != ExitError || !strings.Contains(stderr, want) || strings.Count(stderr, "cancelled") != 1 {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
	// The totals add up: nothing failed, three were never reached.
	totals := "ScanProof rescan: 0 images rescanned, 0 failed, 2 images and 1 directory not rescanned, 2 running images and 1 directory found\n"
	if h.stdout.String() != totals {
		t.Errorf("stdout %q, want %q", h.stdout.String(), totals)
	}
}
