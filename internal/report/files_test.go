package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestNewReportIDFormat(t *testing.T) {
	id, err := NewReportID(testNow, bytes.NewReader([]byte{0x7f, 0x3a, 0x9c}))
	if err != nil {
		t.Fatal(err)
	}
	if id != "SR-20261124-7F3A9C" {
		t.Fatalf("got %q", id)
	}
	random, err := NewReportID(testNow, nil)
	if err != nil || !regexp.MustCompile(`^SR-20261124-[0-9A-F]{6}$`).MatchString(random) {
		t.Fatalf("got %q, %v", random, err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func TestNewReportIDReportsRandomFailure(t *testing.T) {
	if _, err := NewReportID(testNow, failingReader{}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestWriteJSONAndHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.json")
	if err := WriteJSON(path, map[string]int{"a": 1}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{\n  \"a\": 1\n}\n" {
		t.Fatalf("unexpected JSON %q", data)
	}
	sum, size, err := HashFile(path)
	want := sha256.Sum256(data)
	if err != nil || sum != hex.EncodeToString(want[:]) || size != int64(len(data)) {
		t.Fatalf("hash %s size %d err %v", sum, size, err)
	}
}

func TestWriteJSONRejectsUnencodableValue(t *testing.T) {
	if err := WriteJSON(filepath.Join(t.TempDir(), "x.json"), make(chan int)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestBuildManifestHashesEveryFile(t *testing.T) {
	dir := t.TempDir()
	doc := sampleDocument(t)
	for name, content := range map[string]string{"results.json": "{}", "summary.md": "# hi"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m, err := BuildManifest(dir, doc, []string{"results.json", "summary.md"})
	if err != nil {
		t.Fatal(err)
	}
	if m.ReportID != doc.ReportID || m.ImageDigest != doc.Image.Digest || len(m.Files) != 2 {
		t.Fatalf("unexpected manifest %+v", m)
	}
	want := sha256.Sum256([]byte("{}"))
	if m.Files[0].Name != "results.json" || m.Files[0].SHA256 != hex.EncodeToString(want[:]) || m.Files[0].Bytes != 2 {
		t.Errorf("unexpected entry %+v", m.Files[0])
	}
	encoded, _ := json.Marshal(m)
	if !bytes.Contains(encoded, []byte(`"schema":"scanproof-manifest/v1"`)) {
		t.Errorf("manifest schema missing: %s", encoded)
	}
	if _, err := BuildManifest(dir, doc, []string{"missing.pdf"}); err == nil {
		t.Error("expected an error for a missing file")
	}
}

func TestVerifyAgainstManifest(t *testing.T) {
	sum := sha256.Sum256([]byte("data"))
	manifest, _ := json.Marshal(Manifest{ImageDigest: "sha256:x", Files: []ManifestFile{{Name: "a.json", SHA256: hex.EncodeToString(sum[:])}}})
	if m, err := VerifyAgainstManifest(manifest, "a.json", []byte("data")); err != nil || m.ImageDigest != "sha256:x" {
		t.Fatalf("got %+v, %v", m, err)
	}
	if _, err := VerifyAgainstManifest(manifest, "a.json", []byte("changed")); err == nil {
		t.Error("a changed file must fail")
	}
	if _, err := VerifyAgainstManifest(manifest, "b.json", []byte("data")); err == nil {
		t.Error("a file the manifest does not list must fail")
	}
	if _, err := VerifyAgainstManifest([]byte("{"), "a.json", nil); err == nil {
		t.Error("a broken manifest must fail")
	}
}
