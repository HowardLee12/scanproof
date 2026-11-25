package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A scan stopped while it writes its evidence (here: cancelled while making
// the PDF) must not leave the manifest of an earlier run next to its new
// results.json: the manifest would vouch for files it does not describe.
func TestAStoppedScanLeavesNoOldManifest(t *testing.T) {
	out := t.TempDir()
	writeFile(t, filepath.Join(out, manifestFile), `{"files":[]}`)
	typst := filepath.Join(t.TempDir(), "typst")
	writeFile(t, typst, "#!/bin/sh\nsleep 30\n")
	if err := os.Chmod(typst, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h := newHarness()
	h.ctx = ctx
	code := h.run("scan", "--trivy-results", fixture, "--out", out, "--typst", typst)
	if code != ExitError || !strings.Contains(h.stderr.String(), "was cancelled while making the PDF") {
		t.Fatalf("code %d, stderr %q", code, h.stderr.String())
	}
	if _, err := os.Stat(filepath.Join(out, manifestFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the old manifest is still there: %v", err)
	}
}
