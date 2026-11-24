package trivy

import (
	"os"
	"strings"
	"testing"

	"github.com/HowardLee12/scanproof/internal/tree"
)

func file(p string, size int64) tree.Entry { return tree.Entry{Path: p, Type: tree.File, Size: size} }
func dir(p string) tree.Entry              { return tree.Entry{Path: p, Type: tree.Dir} }

// The expectations below were measured with the real Trivy 0.76.2 (the
// version the image pins): see docs/directories.md#limits.
func TestCoverageFollowsTrivysSkipRules(t *testing.T) {
	entries := []tree.Entry{
		dir("dev"), file("dev/creds.txt", 50),
		dir("lib"), dir("lib/dev"), file("lib/dev/creds.txt", 50),
		dir("src"), dir("src/pkg"), dir("src/pkg/.git"), file("src/pkg/.git/config", 80), file("src/pkg/.git/HEAD", 30),
		file("wt/.git", 20),
		file("app/settings.ini", 50), file("app/tiny", 5),
		file("app/model.bin", 5000), file("app/photo.jpg", 50), file("app/photo.JPG", 50), file("app/x.pyc", 50),
		file("app/go.sum", 50), file("app/package-lock.json", 50),
		file("web/node_modules/a/index.js", 50), file("go/vendor/b/b.go", 50),
		file("lib/libx.so", 9000),
	}
	binary := func(p string) bool { return p == "lib/libx.so" }
	c := Coverage(entries, binary)

	if c.NotScanned.Files != 4 {
		t.Errorf("not scanned files = %d, want dev/creds.txt, two files in src/pkg/.git and wt/.git", c.NotScanned.Files)
	}
	roots := map[string]int{}
	for _, p := range c.NotScanned.Paths {
		roots[p.Path] = p.Files
	}
	if roots["dev"] != 1 || roots["src/pkg/.git"] != 2 || roots["wt/.git"] != 1 || len(roots) != 3 {
		t.Errorf("not scanned paths = %+v", c.NotScanned.Paths)
	}

	skipped := map[string]string{}
	for _, p := range c.SecretsNotChecked.Paths {
		skipped[p.Path] = p.Reason
	}
	for _, want := range []string{"app/model.bin", "app/photo.jpg", "app/go.sum", "app/package-lock.json",
		"web/node_modules/a/index.js", "go/vendor/b/b.go", "lib/libx.so"} {
		if skipped[want] == "" {
			t.Errorf("%s should not be checked for secrets: %+v", want, c.SecretsNotChecked.Paths)
		}
	}
	for _, scanned := range []string{"app/settings.ini", "app/photo.JPG", "app/x.pyc", "lib/dev/creds.txt", "app/tiny"} {
		if skipped[scanned] != "" {
			t.Errorf("%s is read by the secret scanner (or too small to hold a secret)", scanned)
		}
	}
	if c.SecretsNotChecked.Files != 7 || c.SecretsNotChecked.ByReason["binary file"] != 1 {
		t.Errorf("secrets not checked = %+v", c.SecretsNotChecked)
	}
}

func TestCoverageListsAreBounded(t *testing.T) {
	entries := []tree.Entry{}
	for i := 0; i < maxCoveragePaths+7; i++ {
		entries = append(entries, file("data/"+strings.Repeat("x", i+1)+".bin", 100))
	}
	c := Coverage(entries, func(string) bool { return false })
	if c.SecretsNotChecked.Files != maxCoveragePaths+7 || len(c.SecretsNotChecked.Paths) != maxCoveragePaths || c.SecretsNotChecked.Omitted != 7 {
		t.Fatalf("got %d files, %d paths, %d omitted", c.SecretsNotChecked.Files, len(c.SecretsNotChecked.Paths), c.SecretsNotChecked.Omitted)
	}
}

func TestIsBinaryMatchesTrivy(t *testing.T) {
	for _, b := range []byte{0x00, 0x01, 0x06, 0x0b, 0x0e, 0x1a, 0x1c, 0x1f, 0x7f} {
		if !IsBinary([]byte{'a', b, 'a'}) {
			t.Errorf("0x%02x makes a file binary", b)
		}
	}
	for _, b := range []byte{0x07, 0x08, 0x09, 0x0a, 0x0c, 0x0d, 0x1b, 0x20, 0x80, 0xff} {
		if IsBinary([]byte{'a', b, 'a'}) {
			t.Errorf("0x%02x does not make a file binary", b)
		}
	}
	late := append([]byte(strings.Repeat("a", BinaryHeadBytes)), 0)
	if IsBinary(late) {
		t.Errorf("only the first %d bytes count", BinaryHeadBytes)
	}
}

func TestScansPinTheSecretConfig(t *testing.T) {
	var path string
	exec := func(_ string, args []string) {
		path = ""
		for i, a := range args {
			if a == "--secret-config" {
				path = args[i+1]
			}
		}
		if args[0] == "sbom" {
			if path != "" {
				t.Errorf("trivy sbom has no --secret-config flag (Trivy 0.76.2 rejects it): %v", args)
			}
			return
		}
		if path == "" {
			t.Fatalf("no --secret-config in %v", args)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("the pinned secret config %s must not exist, got %v", path, err)
		}
		if info, err := os.Stat(strings.TrimSuffix(path, "/trivy-secret.yaml")); err != nil || info.Mode().Perm() != 0o700 {
			t.Errorf("its directory must be a fresh private one: %v %v", info, err)
		}
	}
	for _, scan := range scanFuncs(t, exec) {
		scan()
		if path != "" {
			if _, err := os.Stat(strings.TrimSuffix(path, "/trivy-secret.yaml")); !os.IsNotExist(err) {
				t.Errorf("the temporary directory must be removed")
			}
		}
	}
}
