package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// trivyScript writes a fake Trivy that behaves like fakeTrivy and runs
// extra shell code first for the subcommand in $1.
func trivyScript(t *testing.T, extra string) string {
	t.Helper()
	abs, _ := filepath.Abs(fixture)
	bin := filepath.Join(t.TempDir(), "trivy")
	writeFile(t, bin, `#!/bin/sh
for last; do :; done
`+extra+`
case "$1" in
  version) echo '{"Version":"0.76.2"}' ;;
  convert)
    out=""
    while [ $# -gt 0 ]; do
      if [ "$1" = "--output" ]; then out="$2"; fi
      shift
    done
    echo '{"bomFormat":"CycloneDX"}' > "$out" ;;
  *) cat '`+abs+`' ;;
esac
`)
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestScanDirRecordsWhatTrivyDoesNotRead(t *testing.T) {
	root := makeSoftwareDir(t)
	for name, content := range map[string]string{
		"src/pkg/.git/config": "[remote]\n\turl = https://example.com/pkg.git\n",
		"dev/notes.txt":       "not read by trivy\n",
		"lib/libx.so":         "\x7fELF\x02\x01\x01\x00 shared library",
		"app/model.bin":       "weights weights weights",
	} {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, p, content)
	}
	out := t.TempDir()
	h := newHarness()
	if code := h.run("scan", "--dir", "--name", "acme-vllm", "--trivy", fakeTrivy(t), "--out", out, "--pdf=false", root); code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}
	var doc map[string]any
	readJSON(t, filepath.Join(out, "results.json"), &doc)
	cov := doc["directory"].(map[string]any)["coverage"].(map[string]any)
	notScanned := cov["not_scanned"].(map[string]any)
	secrets := cov["secrets_not_checked"].(map[string]any)
	if notScanned["files"] != float64(2) || secrets["files"] != float64(3) {
		t.Fatalf("coverage = %v", cov)
	}
	reasons := secrets["by_reason"].(map[string]any)
	if reasons["binary file"] != float64(2) || reasons["file type .bin"] != float64(1) {
		t.Errorf("reasons = %v (the worker binary and libx.so are binary)", reasons)
	}
	if md := readFile(t, filepath.Join(out, "summary.md")); !strings.Contains(md, "2 files were not checked for vulnerabilities or secrets") {
		t.Errorf("summary.md = %s", md)
	}
}

func TestScanDirDetectsAChangeThatWasReverted(t *testing.T) {
	root := makeSoftwareDir(t)
	worker := "$last/worker/bin/example-worker"
	// While "scanning", write the file and put the same bytes back.
	bin := trivyScript(t, `if [ "$1" = rootfs ]; then cp "`+worker+`" "$last/../saved"; sleep 0.05; `+
		`echo x >> "`+worker+`"; cp "$last/../saved" "`+worker+`"; fi`)
	h := newHarness()
	code := h.run("scan", "--dir", "--name", "acme-vllm", "--trivy", bin, "--out", t.TempDir(), "--pdf=false", root)
	if code != ExitError || !strings.Contains(h.stderr.String(), "changed while it was being scanned") {
		t.Fatalf("code %d, stderr %q", code, h.stderr.String())
	}
}

func TestScanDirWithStoreNeedsItsSBOM(t *testing.T) {
	storeDir := t.TempDir()
	bin := trivyScript(t, `if [ "$1" = convert ]; then echo "convert broke" >&2; exit 1; fi`)
	h := newHarness()
	code := h.run("scan", "--dir", "--name", "acme-vllm", "--trivy", bin, "--out", t.TempDir(), "--pdf=false",
		"--store", "file://"+storeDir, makeSoftwareDir(t))
	if code != ExitError || !strings.Contains(h.stderr.String(), "SBOM") {
		t.Fatalf("code %d, stderr %q", code, h.stderr.String())
	}
	if _, err := os.Stat(filepath.Join(storeDir, "scans")); !os.IsNotExist(err) {
		t.Fatal("a directory scan that rescans could not use must not be stored")
	}
}

func TestScanDirPrintsTheInventoryLineOnlyWhenRescannable(t *testing.T) {
	cases := map[string][]string{
		"no store":   {},
		"no SBOM":    {"--store", "file://" + t.TempDir(), "--sbom=false"},
		"stored too": {"--store", "file://" + t.TempDir()},
	}
	for name, extra := range cases {
		h := newHarness()
		args := append([]string{"scan", "--dir", "--name", "acme-vllm", "--trivy", fakeTrivy(t), "--out", t.TempDir(), "--pdf=false"}, extra...)
		if code := h.run(append(args, makeSoftwareDir(t))...); code != 0 {
			t.Fatalf("%s: code %d: %s", name, code, h.stderr.String())
		}
		hasLine := strings.Contains(h.stdout.String(), "Rescan inventory line:")
		if hasLine != (name == "stored too") {
			t.Errorf("%s: stdout = %q", name, h.stdout.String())
		}
		if name != "stored too" && !strings.Contains(h.stdout.String(), "cannot check this directory") {
			t.Errorf("%s: say why it cannot be rescanned: %q", name, h.stdout.String())
		}
	}
}

func TestScanDirRefusesToWriteInsideTheScannedDirectory(t *testing.T) {
	root := makeSoftwareDir(t)
	cases := map[string]struct {
		args []string
		env  map[string]string
	}{
		"--out":             {args: []string{"--out", filepath.Join(root, "evidence")}},
		"--malware-workdir": {args: []string{"--malware", "--clamscan", "true", "--malware-workdir", filepath.Join(root, "tests")}},
		"TRIVY_CACHE_DIR":   {env: map[string]string{"TRIVY_CACHE_DIR": filepath.Join(root, "cache")}},
		"Trivy's cache":     {env: map[string]string{"HOME": root}},
	}
	for name, c := range cases {
		h := newHarness()
		for k, v := range c.env {
			h.env[k] = v
		}
		args := append([]string{"scan", "--dir", "--name", "acme-vllm", "--trivy", fakeTrivy(t), "--out", t.TempDir(), "--pdf=false"}, c.args...)
		code := h.run(append(args, root)...)
		if code != ExitError || !strings.Contains(h.stderr.String(), "inside the scanned directory") {
			t.Errorf("%s: code %d, stderr %q", name, code, h.stderr.String())
		}
	}
}

func TestMalwareScanOfAnImagePinsOnePlatform(t *testing.T) {
	ref, config := pushImage(t, map[string][]byte{"app/main": []byte("binary")})
	log := filepath.Join(t.TempDir(), "args")
	bin := fakeTrivyFor(t, config)
	wrapper := filepath.Join(t.TempDir(), "trivy")
	writeFile(t, wrapper, "#!/bin/sh\necho \"$@\" >> '"+log+"'\nexec '"+bin+"' \"$@\"\n")
	if err := os.Chmod(wrapper, 0o755); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	h := newHarness()
	code := h.run("scan", "--trivy", wrapper, "--out", out, "--pdf=false", "--sbom=false",
		"--malware", "--clamscan", fakeClamscan(t), "--docker-daemon=false", "--", ref)
	if code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}
	want := "--platform linux/" + runtime.GOARCH
	if args := readFile(t, log); !strings.Contains(args, want) {
		t.Errorf("Trivy must scan the same platform as the malware scan (%s): %s", want, args)
	}
	var doc map[string]any
	readJSON(t, filepath.Join(out, "results.json"), &doc)
	// The evidence records the platform in the config of the image that was
	// read, not the one asked for; this test image's config has none.
	if p, ok := doc["malware"].(map[string]any)["platform"]; ok {
		t.Errorf("malware platform = %v, want none", p)
	}
}
