//go:build unix

package tree

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// swapTree has files a and b, and a directory d with a file in it. Paths
// sort as a, b, d, d/x, so a content callback on "a" runs after everything
// was listed and before b and d/x are read.
func swapTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a"), "first file", 0o644)
	mustWrite(t, filepath.Join(root, "b"), "second file", 0o644)
	mustWrite(t, filepath.Join(root, "d", "x"), "in a directory", 0o644)
	return root
}

// digestWithSwap runs Digest and calls swap while "a" is being read.
func digestWithSwap(t *testing.T, root string, swap func()) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := Digest(context.Background(), root, func(e Entry, _ io.Reader) error {
			if e.Path == "a" {
				swap()
			}
			return nil
		})
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("Digest hung")
		return nil
	}
}

func mustRun(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDigestRefusesWhatWasSwappedInAfterListing(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside")
	mustWrite(t, outside, "second file", 0o644) // same content as b
	cases := map[string]func(t *testing.T, root string){
		"symlink to a file outside the root": func(t *testing.T, root string) {
			mustRun(t, os.Remove(filepath.Join(root, "b")))
			mustRun(t, os.Symlink(outside, filepath.Join(root, "b")))
		},
		"symlink to another file inside the root": func(t *testing.T, root string) {
			mustRun(t, os.Remove(filepath.Join(root, "b")))
			mustRun(t, os.Symlink("d/x", filepath.Join(root, "b")))
		},
		"directory replaced by a symlink to outside": func(t *testing.T, root string) {
			mustRun(t, os.RemoveAll(filepath.Join(root, "d")))
			mustRun(t, os.Symlink(filepath.Dir(outside), filepath.Join(root, "d")))
		},
		"named pipe": func(t *testing.T, root string) {
			mustRun(t, os.Remove(filepath.Join(root, "b")))
			mustRun(t, syscall.Mkfifo(filepath.Join(root, "b"), 0o644))
		},
		"file renamed over it": func(t *testing.T, root string) {
			mustWrite(t, filepath.Join(root, "c"), "second file", 0o644)
			mustRun(t, os.Rename(filepath.Join(root, "c"), filepath.Join(root, "b")))
		},
		"file deleted": func(t *testing.T, root string) {
			mustRun(t, os.Remove(filepath.Join(root, "b")))
		},
		"same content written again": func(t *testing.T, root string) {
			time.Sleep(10 * time.Millisecond)
			mustWrite(t, filepath.Join(root, "b"), "second file", 0o644)
		},
	}
	for name, swap := range cases {
		t.Run(name, func(t *testing.T) {
			root := swapTree(t)
			err := digestWithSwap(t, root, func() { swap(t, root) })
			if !errors.Is(err, ErrChanged) {
				t.Fatalf("got %v, want a changed error", err)
			}
		})
	}
}

func TestWalkRefusesADirectorySwappedBeforeItIsRead(t *testing.T) {
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, "secret"), "outside the root", 0o644)
	for name, target := range map[string]string{"outside": outside, "inside": "e"} {
		t.Run(name, func(t *testing.T) {
			root := swapTree(t)
			mustWrite(t, filepath.Join(root, "e", "y"), "another directory", 0o644)
			testHookBeforeReadDir = func(p string) {
				if p == "d" {
					mustRun(t, os.RemoveAll(filepath.Join(root, "d")))
					mustRun(t, os.Symlink(target, filepath.Join(root, "d")))
				}
			}
			t.Cleanup(func() { testHookBeforeReadDir = nil })
			_, err := Digest(context.Background(), root, nil)
			if !errors.Is(err, ErrChanged) {
				t.Fatalf("got %v, want a changed error", err)
			}
		})
	}
}

func TestDigestRefusesNamesThatAreNotUTF8(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "bad\xffname"), []byte("x"), 0o644); err != nil {
		t.Skipf("this file system does not allow such names: %v", err)
	}
	_, err := Digest(context.Background(), root, nil)
	if err == nil || !strings.Contains(err.Error(), `"bad\xffname"`) || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("got %v", err)
	}
}

func TestDigestDoesNotHangOnARootSwappedForANamedPipe(t *testing.T) {
	root := filepath.Join(t.TempDir(), "venv")
	mustWrite(t, filepath.Join(root, "a"), "x", 0o644)
	testHookBeforeOpenRoot = func(p string) {
		mustRun(t, os.RemoveAll(p))
		mustRun(t, syscall.Mkfifo(p, 0o644))
	}
	t.Cleanup(func() { testHookBeforeOpenRoot = nil })
	done := make(chan error, 1)
	go func() {
		_, err := Digest(context.Background(), root, nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a named pipe is not a directory")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Digest hung on a named pipe")
	}
}
