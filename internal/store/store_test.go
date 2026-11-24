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
