package tree

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDigestListsEntriesWithStamps(t *testing.T) {
	res := digest(t, makeTree(t))
	if len(res.Entries) != 8 || res.Entries[0].Path != "bin" || res.Entries[1].Path != "bin/worker" {
		t.Fatalf("entries = %+v", res.Entries)
	}
	if w := res.Entries[1]; w.Type != File || w.Size != 6 || w.Stamp.Size != 6 || w.Stamp.Mtime == 0 {
		t.Errorf("worker = %+v", w)
	}
}

func TestUnchanged(t *testing.T) {
	root := makeTree(t)
	first := digest(t, root)
	if err := Unchanged(first, digest(t, root)); err != nil {
		t.Fatalf("an untouched tree must be unchanged: %v", err)
	}

	// Write a file and put the same bytes back: same digest, new times.
	time.Sleep(10 * time.Millisecond)
	mustWrite(t, filepath.Join(root, "lib-a"), "something else", 0o644)
	mustWrite(t, filepath.Join(root, "lib-a"), "sorted before lib/ by bytes", 0o644)
	again := digest(t, root)
	if again.Digest != first.Digest {
		t.Fatal("the content was put back, so the digest must be the same")
	}
	err := Unchanged(first, again)
	if !errors.Is(err, ErrChanged) || !strings.Contains(err.Error(), "lib-a") {
		t.Fatalf("a change that was reverted must still be detected, got %v", err)
	}

	mustWrite(t, filepath.Join(root, "new"), "x", 0o644)
	if err := Unchanged(first, digest(t, root)); !errors.Is(err, ErrChanged) {
		t.Fatalf("a new file must be detected, got %v", err)
	}
}

func TestUnchangedIgnoresCopies(t *testing.T) {
	a, b := makeTree(t), makeTree(t)
	if err := Unchanged(digest(t, a), digest(t, b)); err == nil {
		t.Fatal("two different directories are different inodes and must not count as one")
	}
	if digest(t, a).Digest != digest(t, b).Digest {
		t.Fatal("but they have the same digest")
	}
}

func TestDigestStopsAReadWhenTheContextEnds(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "big"), strings.Repeat("x", 1<<20), 0o644)
	ctx, cancel := context.WithCancel(context.Background())
	_, err := Digest(ctx, root, func(e Entry, r io.Reader) error {
		cancel()
		_, err := io.Copy(io.Discard, r)
		return err
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestDigestMapsAShortReadToChanged(t *testing.T) {
	root := makeTree(t)
	_, err := Digest(context.Background(), root, func(e Entry, r io.Reader) error {
		return io.ErrUnexpectedEOF
	})
	if !errors.Is(err, ErrChanged) {
		t.Fatalf("a file that ended early changed while it was read, got %v", err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatal(err)
	}
}
