package store

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestOpenFileStore(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(context.Background(), "file://"+dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.(*FileStore); !ok {
		t.Fatalf("got %T", s)
	}
}

func TestOpenRejectsUnknownScheme(t *testing.T) {
	for _, raw := range []string{"", "ftp://x/y", "/plain/path", "s3://", "file://"} {
		if _, err := Open(context.Background(), raw); err == nil {
			t.Errorf("%q: expected an error", raw)
		}
	}
}

func TestFileStorePutGetList(t *testing.T) {
	ctx := context.Background()
	s := &FileStore{root: t.TempDir()}

	if err := s.Put(ctx, "scans/2026/11/24/SR-1/results.json", []byte(`{"a":1}`), "application/json"); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "scans/2026/11/24/SR-2/results.json", []byte(`{}`), "application/json"); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "scans/2026/11/25/SR-3/results.json", []byte(`{}`), "application/json"); err != nil {
		t.Fatal(err)
	}

	got, err := s.Get(ctx, "scans/2026/11/24/SR-1/results.json")
	if err != nil || string(got) != `{"a":1}` {
		t.Fatalf("got %q, %v", got, err)
	}

	keys, err := s.List(ctx, "scans/2026/11/24/")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(keys)
	want := []string{"scans/2026/11/24/SR-1/results.json", "scans/2026/11/24/SR-2/results.json"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", keys, want)
	}

	if keys, err := s.List(ctx, "scans/2030/"); err != nil || len(keys) != 0 {
		t.Fatalf("a missing prefix is empty, got %v, %v", keys, err)
	}
}

func TestFileStoreRejectsPathTraversal(t *testing.T) {
	s := &FileStore{root: t.TempDir()}
	for _, key := range []string{"../escape.json", "scans/../../escape.json", "/abs/key", ""} {
		if err := s.Put(context.Background(), key, []byte("x"), "text/plain"); err == nil {
			t.Errorf("%q: expected an error", key)
		}
	}
}

func TestFileStoreDoesNotOverwrite(t *testing.T) {
	ctx := context.Background()
	s := &FileStore{root: t.TempDir()}
	if err := s.Put(ctx, "a/b.json", []byte("1"), "application/json"); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "a/b.json", []byte("2"), "application/json"); err == nil {
		t.Fatal("evidence is write-once; a second write to the same key must fail")
	}
}

func TestFileStoreLocation(t *testing.T) {
	root := t.TempDir()
	s := &FileStore{root: root}
	if got := s.Location("scans/x"); got != "file://"+filepath.Join(root, "scans", "x") {
		t.Fatalf("got %q", got)
	}
}

func TestFileStoreGetMissing(t *testing.T) {
	s := &FileStore{root: t.TempDir()}
	if _, err := s.Get(context.Background(), "nope.json"); err == nil {
		t.Fatal("expected an error")
	}
}

func TestFileStoreCreatesRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "new", "dir")
	s, err := Open(context.Background(), "file://"+root)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(context.Background(), "k.json", []byte("{}"), "application/json"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "k.json")); err != nil {
		t.Fatal(err)
	}
}

func TestScanKey(t *testing.T) {
	if got := ScanPrefix("SR-20261124-7F3A9C", mustTime(t, "2026-11-24T08:16:48Z")); got != "scans/2026/11/24/SR-20261124-7F3A9C/" {
		t.Fatalf("got %q", got)
	}
	if got := DayPrefix(mustTime(t, "2026-07-01T23:00:00Z")); got != "scans/2026/07/01/" {
		t.Fatalf("got %q", got)
	}
}

func TestDigestIndexPrefix(t *testing.T) {
	got, err := DigestIndexPrefix("sha256:02bb6f428431fbc2809c5d1b41eab5a68350194fb508869a33cb1af4444c9b11")
	if err != nil || got != "index/digests/sha256/02bb6f428431fbc2809c5d1b41eab5a68350194fb508869a33cb1af4444c9b11/" {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, bad := range []string{"", "latest", "sha256:../../x", "sha256:XYZ", "md5:abc"} {
		if _, err := DigestIndexPrefix(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestSBOMEntriesNewestFirstAndValidated(t *testing.T) {
	ctx := context.Background()
	s := &FileStore{root: t.TempDir()}
	digest := "sha256:02bb6f428431fbc2809c5d1b41eab5a68350194fb508869a33cb1af4444c9b11"
	older := IndexEntry{ReportID: "SR-20261101-AAAAAA", ScanPrefix: "scans/2026/11/01/SR-20261101-AAAAAA/", HasSBOM: true}
	newer := IndexEntry{ReportID: "SR-20261124-BBBBBB", ScanPrefix: "scans/2026/11/24/SR-20261124-BBBBBB/", HasSBOM: true}
	forged := IndexEntry{ReportID: "SR-99999999-FFFFFF", ScanPrefix: "scans/evil/", HasSBOM: true}
	noSBOM := IndexEntry{ReportID: "SR-20261125-CCCCCC", ScanPrefix: "scans/2026/11/25/SR-20261125-CCCCCC/"}
	for _, e := range []IndexEntry{older, newer, forged, noSBOM} {
		if err := PutIndexEntry(ctx, s, digest, e); err != nil {
			t.Fatal(err)
		}
	}
	got, unusable, err := SBOMEntries(ctx, s, digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ReportID != newer.ReportID || got[1].ReportID != older.ReportID {
		t.Fatalf("got %+v", got)
	}
	if unusable != 2 {
		t.Errorf("the forged entry and the one without an SBOM cannot be used: %d", unusable)
	}
	if got, unusable, err := SBOMEntries(ctx, s, "sha256:"+strings.Repeat("a", 64)); err != nil || len(got) != 0 || unusable != 0 {
		t.Fatalf("an unknown digest has no entries: %v %d %v", got, unusable, err)
	}
}

func TestIndexErrors(t *testing.T) {
	ctx := context.Background()
	s := &FileStore{root: t.TempDir()}
	if err := PutIndexEntry(ctx, s, "not-a-digest", IndexEntry{ReportID: "SR-1"}); err == nil {
		t.Error("an invalid digest must be rejected")
	}
	if _, _, err := SBOMEntries(ctx, s, "latest"); err == nil {
		t.Error("an invalid digest must be rejected")
	}
	digest := "sha256:" + strings.Repeat("b", 64)
	prefix, _ := DigestIndexPrefix(digest)
	if err := s.Put(ctx, prefix+"SR-9.json", []byte("{broken"), "application/json"); err != nil {
		t.Fatal(err)
	}
	if got, unusable, err := SBOMEntries(ctx, s, digest); err != nil || len(got) != 0 || unusable != 1 {
		t.Errorf("a corrupt index entry is skipped and counted: %v %d %v", got, unusable, err)
	}
}

// folderStore lists an S3 "folder marker" key along with a real entry.
type folderStore struct{ *FileStore }

func (f folderStore) List(ctx context.Context, prefix string) ([]string, error) {
	keys, err := f.FileStore.List(ctx, prefix)
	return append([]string{prefix}, keys...), err
}

func TestSBOMEntriesIgnoresFolderMarkers(t *testing.T) {
	ctx := context.Background()
	s := folderStore{&FileStore{root: t.TempDir()}}
	digest := "sha256:" + strings.Repeat("c", 64)
	e := IndexEntry{ReportID: "SR-20261124-BBBBBB", ScanPrefix: "scans/2026/11/24/SR-20261124-BBBBBB/", HasSBOM: true}
	if err := PutIndexEntry(ctx, s, digest, e); err != nil {
		t.Fatal(err)
	}
	got, unusable, err := SBOMEntries(ctx, s, digest)
	if err != nil || len(got) != 1 || unusable != 0 {
		t.Fatalf("a folder marker is not an index entry: %v %d %v", got, unusable, err)
	}
}
