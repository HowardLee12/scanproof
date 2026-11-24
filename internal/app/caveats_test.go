package app

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// versionedTrivy is a fake Trivy that reports itself as version.
func versionedTrivy(t *testing.T, version string) string {
	t.Helper()
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(t.TempDir(), "report.json")
	writeFile(t, report, strings.Replace(string(data), `"Version": "0.76.2"`, `"Version": "`+version+`"`, 1))
	bin := filepath.Join(t.TempDir(), "trivy")
	writeFile(t, bin, `#!/bin/sh
case "$1" in
  version) echo '{"Version":"`+version+`"}' ;;
  convert)
    out=""
    while [ $# -gt 0 ]; do
      if [ "$1" = "--output" ]; then out="$2"; fi
      shift
    done
    echo '{"bomFormat":"CycloneDX"}' > "$out" ;;
  *) cat '`+report+`' ;;
esac
`)
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestScanDirWarnsWhenTrivyIsAnotherVersion(t *testing.T) {
	out := t.TempDir()
	h := newHarness()
	code := h.run("scan", "--dir", "--name", "acme-vllm", "--trivy", versionedTrivy(t, "0.77.0"), "--out", out, "--pdf=false",
		"--sbom=false", makeSoftwareDir(t))
	if code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}
	want := "modelled for Trivy 0.76.2; this scan used Trivy 0.77.0"
	if !strings.Contains(h.stderr.String(), "warning: "+"What Trivy skips is "+want) {
		t.Errorf("stderr = %q", h.stderr.String())
	}
	var doc map[string]any
	readJSON(t, filepath.Join(out, "results.json"), &doc)
	cov := doc["directory"].(map[string]any)["coverage"].(map[string]any)
	if cov["modelled_for"] != "0.76.2" || !strings.Contains(strings.Join(toStrings(cov["caveats"]), " "), want) {
		t.Errorf("coverage = %v", cov)
	}
	if md := readFile(t, filepath.Join(out, "summary.md")); !strings.Contains(md, want) {
		t.Errorf("summary.md = %s", md)
	}
}

func TestImageScanWarnsWhenTrivyIsAnotherVersion(t *testing.T) {
	out := t.TempDir()
	h := newHarness()
	if code := h.run("scan", "--trivy", versionedTrivy(t, "0.80.1"), "--out", out, "--pdf=false", "--sbom=false", "--", "alpine:3.18.0"); code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}
	want := "this scan used Trivy 0.80.1"
	if !strings.Contains(h.stderr.String(), want) || !strings.Contains(readFile(t, filepath.Join(out, "summary.md")), want) {
		t.Errorf("stderr %q", h.stderr.String())
	}
}

func TestScanDirWarnsAboutAParentOthersCanChange(t *testing.T) {
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(shared, "venv")
	if err := os.Rename(makeSoftwareDir(t), root); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	h := newHarness()
	if code := h.run("scan", "--dir", "--name", "acme-vllm", "--trivy", fakeTrivy(t), "--out", out, "--pdf=false", "--sbom=false", root); code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}
	resolved, _ := filepath.EvalSymlinks(shared)
	if !strings.Contains(h.stderr.String(), resolved+" can be written by its group or others") {
		t.Errorf("stderr = %q", h.stderr.String())
	}
	var doc map[string]any
	readJSON(t, filepath.Join(out, "results.json"), &doc)
	caveats := toStrings(doc["directory"].(map[string]any)["coverage"].(map[string]any)["caveats"])
	if len(caveats) != 1 || !strings.Contains(caveats[0], resolved) {
		t.Errorf("caveats = %v", caveats)
	}
}

func TestAncestorWarnings(t *testing.T) {
	const me = 1000
	got := ancestorWarnings([]ancestor{
		{path: "/srv/shared", mode: fs.ModeDir | 0o775, uid: me, owned: true},
		{path: "/tmp", mode: fs.ModeDir | fs.ModeSticky | 0o777, uid: 0, owned: true},
		{path: "/srv", mode: fs.ModeDir | 0o755, uid: 2000, owned: true},
		{path: "/", mode: fs.ModeDir | 0o755, uid: 0, owned: true},
		{path: "/c", mode: fs.ModeDir | 0o755},
	}, me)
	if len(got) != 2 || !strings.Contains(got[0], "/srv/shared can be written by its group or others (mode 0775") ||
		!strings.Contains(got[1], "/srv is owned by uid 2000") {
		t.Fatalf("got %q", got)
	}
}

func toStrings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, x := range list {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}
