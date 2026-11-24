package tree

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// swapRoot moves the root away, puts a decoy in its place, and restores it.
func swapRoot(t *testing.T, root string) {
	t.Helper()
	parent := filepath.Dir(root)
	time.Sleep(10 * time.Millisecond)
	mustRun(t, os.Rename(root, filepath.Join(parent, "real")))
	mustWrite(t, filepath.Join(root, "decoy.txt"), "nothing here", 0o644)
	mustRun(t, os.RemoveAll(root))
	mustRun(t, os.Rename(filepath.Join(parent, "real"), root))
}

func TestUnchangedDetectsARootThatWasSwappedAndRestored(t *testing.T) {
	root := filepath.Join(t.TempDir(), "venv")
	mustWrite(t, filepath.Join(root, "lib", "pkg.py"), "real content", 0o644)
	before := digest(t, root)
	if before.Root.Ino == 0 && before.Root.Mtime == 0 {
		t.Fatal("the root must have a stamp")
	}
	swapRoot(t, root)
	if err := Unchanged(before, digest(t, root)); !errors.Is(err, ErrChanged) {
		t.Fatalf("a root swapped and restored between two reads must be detected, got %v", err)
	}
}

func TestCheckRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "venv")
	mustWrite(t, filepath.Join(root, "lib", "pkg.py"), "real content", 0o644)
	before := digest(t, root)
	if err := CheckRoot(root, before); err != nil {
		t.Fatalf("an untouched root: %v", err)
	}
	swapRoot(t, root)
	if err := CheckRoot(root, before); !errors.Is(err, ErrChanged) {
		t.Fatalf("got %v", err)
	}
	if err := CheckRoot(filepath.Join(root, "missing"), before); !errors.Is(err, ErrChanged) {
		t.Fatalf("a root that is gone must be changed, got %v", err)
	}
}
