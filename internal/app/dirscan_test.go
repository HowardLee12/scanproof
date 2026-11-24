package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HowardLee12/scanproof/internal/tree"
)

// makeSoftwareDir builds a small directory like a virtualenv with a Go
// worker binary next to it.
func makeSoftwareDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"venv/lib/python3.12/site-packages/requests-2.25.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: requests\nVersion: 2.25.0\n",
		"worker/bin/example-worker": "\x7fELF fake worker binary",
		"tests/eicar.com":           "EICAR-TEST",
	}
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, p, content)
	}
	if err := os.Symlink("lib", filepath.Join(root, "venv", "lib64")); err != nil {
		t.Fatal(err)
	}
	return root
}

func treeDigestOf(t *testing.T, root string) string {
	t.Helper()
	res, err := tree.Digest(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	return res.Digest
}

func TestScanDirUsageErrors(t *testing.T) {
	dir := t.TempDir()
	cases := map[string][]string{
		"no name":            {"scan", "--dir", dir},
		"no path":            {"scan", "--dir", "--name", "acme-vllm"},
		"two paths":          {"scan", "--dir", "--name", "acme-vllm", dir, dir},
		"bad name":           {"scan", "--dir", "--name", "acme vllm", dir},
		"bad version":        {"scan", "--dir", "--name", "acme-vllm", "--version", "1:2", dir},
		"platform":           {"scan", "--dir", "--name", "acme-vllm", "--platform", "linux/arm64", dir},
		"docker-daemon":      {"scan", "--dir", "--name", "acme-vllm", "--docker-daemon=false", dir},
		"trivy-results":      {"scan", "--dir", "--name", "acme-vllm", "--trivy-results", fixture, dir},
		"name without --dir": {"scan", "--name", "acme-vllm", "alpine:3.18.0"},
		"version only":       {"scan", "--version", "1.0", "alpine:3.18.0"},
		"missing directory":  {"scan", "--dir", "--name", "acme-vllm", "--trivy", fakeTrivy(t), "--out", t.TempDir(), filepath.Join(dir, "nope")},
		"a file":             {"scan", "--dir", "--name", "acme-vllm", "--trivy", fakeTrivy(t), "--out", t.TempDir(), fixture},
	}
	wants := map[string]string{
		"no name": "--name", "platform": "--platform", "docker-daemon": "--docker-daemon",
		"trivy-results": "--trivy-results", "name without --dir": "--dir", "version only": "--dir",
		"bad name": "invalid directory name", "bad version": "invalid directory version", "a file": "not a directory",
	}
	for name, args := range cases {
		h := newHarness()
		code := h.run(args...)
		if code != ExitError {
			t.Errorf("%s: code %d, want %d", name, code, ExitError)
		}
		if want := wants[name]; want != "" && !strings.Contains(h.stderr.String(), want) {
			t.Errorf("%s: stderr %q should mention %q", name, h.stderr.String(), want)
		}
	}
}

func TestScanDirWritesDirectoryEvidence(t *testing.T) {
	root := makeSoftwareDir(t)
	storeDir, out := t.TempDir(), t.TempDir()
	h := newHarness()
	h.env["GITHUB_ACTIONS"] = "true"
	h.env["GITHUB_REPOSITORY"] = "example-org/inference"
	code := h.run("scan", "--dir", "--name", "acme-vllm", "--version", "0.9.1", "--trivy", fakeTrivy(t),
		"--out", out, "--pdf=false", "--store", "file://"+storeDir, root)
	if code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}
	digest := treeDigestOf(t, root)
	resolved, _ := filepath.EvalSymlinks(root)

	var doc map[string]any
	readJSON(t, filepath.Join(out, "results.json"), &doc)
	img := doc["image"].(map[string]any)
	dir := doc["directory"].(map[string]any)
	if doc["artifact_type"] != "directory" || img["reference"] != "dir:acme-vllm:0.9.1" || img["digest"] != digest {
		t.Errorf("artifact = %v, image = %v", doc["artifact_type"], img)
	}
	if dir["name"] != "acme-vllm" || dir["version"] != "0.9.1" || dir["tree_digest"] != digest ||
		dir["path"] != resolved || dir["files"] != float64(3) || dir["symlinks"] != float64(1) {
		t.Errorf("directory = %v", dir)
	}
	if doc["trigger"] != "ci" || doc["context"].(map[string]any)["repository"] != "example-org/inference" {
		t.Errorf("the CI context must be recorded: %v %v", doc["trigger"], doc["context"])
	}
	if md := readFile(t, filepath.Join(out, "summary.md")); !strings.Contains(md, "Directory `acme-vllm:0.9.1`") {
		t.Errorf("summary.md = %s", md)
	}
	if !strings.Contains(h.stdout.String(), "directory acme-vllm:0.9.1") ||
		!strings.Contains(h.stdout.String(), "Rescan inventory line: dir:acme-vllm:0.9.1@"+digest+"\n") {
		t.Errorf("stdout = %q", h.stdout.String())
	}

	hex := strings.TrimPrefix(digest, "sha256:")
	entries, _ := filepath.Glob(filepath.Join(storeDir, "index", "digests", "sha256", hex, "SR-*.json"))
	if len(entries) != 1 {
		t.Fatalf("the scan must be indexed by its tree digest, got %v", entries)
	}
	manifests, _ := filepath.Glob(filepath.Join(storeDir, "scans", "*", "*", "*", "*", "manifest.json"))
	var manifest map[string]any
	readJSON(t, manifests[0], &manifest)
	if manifest["artifact_type"] != "directory" || manifest["image_digest"] != digest {
		t.Errorf("manifest = %v", manifest)
	}
}

func TestScanDirWithMalwareCheck(t *testing.T) {
	root := makeSoftwareDir(t)
	out := t.TempDir()
	h := newHarness()
	code := h.run("scan", "--dir", "--name", "acme-vllm", "--trivy", fakeTrivy(t), "--out", out, "--pdf=false",
		"--sbom=false", "--malware", "--clamscan", fakeClamscan(t), "--malware-workdir", t.TempDir(), root)
	if code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}
	var doc map[string]any
	readJSON(t, filepath.Join(out, "results.json"), &doc)
	m := doc["malware"].(map[string]any)
	findings := m["findings"].([]any)
	if m["files_scanned"] != float64(3) || m["tree_digest"] != treeDigestOf(t, root) || len(findings) != 1 ||
		findings[0].(map[string]any)["path"] != "tests/eicar.com" {
		t.Fatalf("malware = %v", m)
	}
	if !strings.Contains(readFile(t, filepath.Join(out, "summary.md")), "No malware detections | 1 | ❌") {
		t.Error("the malware rule should fail in the job summary")
	}
}

func TestScanDirFailsWhenTheDirectoryChanges(t *testing.T) {
	root := makeSoftwareDir(t)
	abs, _ := filepath.Abs(fixture)
	bin := filepath.Join(t.TempDir(), "trivy")
	// This Trivy changes the directory while it "scans" it.
	writeFile(t, bin, `#!/bin/sh
case "$1" in
  version) echo '{"Version":"0.76.2"}' ;;
  rootfs) for last; do :; done; echo changed >> "$last/worker/bin/example-worker"; cat '`+abs+`' ;;
  *) cat '`+abs+`' ;;
esac
`)
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	h := newHarness()
	code := h.run("scan", "--dir", "--name", "acme-vllm", "--trivy", bin, "--out", t.TempDir(), "--pdf=false", root)
	if code != ExitError || !strings.Contains(h.stderr.String(), "changed while it was being scanned") {
		t.Fatalf("code %d, stderr %q", code, h.stderr.String())
	}
}

func TestScanDirRefusesSymlinkedRootsSafely(t *testing.T) {
	root := makeSoftwareDir(t)
	link := filepath.Join(t.TempDir(), "current")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	h := newHarness()
	if code := h.run("scan", "--dir", "--name", "acme-vllm", "--trivy", fakeTrivy(t), "--out", out, "--pdf=false", "--sbom=false", link); code != 0 {
		t.Fatalf("a symlink to the directory is resolved once: code %d %s", code, h.stderr.String())
	}
	var doc map[string]any
	readJSON(t, filepath.Join(out, "results.json"), &doc)
	resolved, _ := filepath.EvalSymlinks(root)
	if doc["directory"].(map[string]any)["path"] != resolved {
		t.Errorf("the evidence must record the directory that was read: %v", doc["directory"])
	}
}

func TestScanDirWithoutSBOMWarnsThatRescansCannotCheckIt(t *testing.T) {
	h := newHarness()
	code := h.run("scan", "--dir", "--name", "acme-vllm", "--trivy", fakeTrivy(t), "--out", t.TempDir(), "--pdf=false",
		"--sbom=false", makeSoftwareDir(t))
	if code != 0 || !strings.Contains(h.stderr.String(), "rescans cannot check this directory") {
		t.Fatalf("code %d, stderr %q", code, h.stderr.String())
	}
}
