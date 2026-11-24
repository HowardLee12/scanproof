package tree

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// makeTree builds a small directory: files, a subdirectory, an empty
// directory and a symlink that points outside the tree.
func makeTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "lib", "site-packages"), 0o755)
	mustMkdir(t, filepath.Join(root, "empty"), 0o700)
	mustWrite(t, filepath.Join(root, "bin", "worker"), "binary", 0o755)
	mustWrite(t, filepath.Join(root, "lib", "site-packages", "METADATA"), "Name: requests\nVersion: 2.25.0\n", 0o644)
	mustWrite(t, filepath.Join(root, "lib-a"), "sorted before lib/ by bytes", 0o644)
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "outside")); err != nil {
		t.Fatal(err)
	}
	return root
}

func mustMkdir(t *testing.T, p string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func digest(t *testing.T, root string) Result {
	t.Helper()
	res, err := Digest(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func size(s string) string { return strconv.Itoa(len(s)) }

func hexSum(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestDigestMatchesTheDocumentedEncoding(t *testing.T) {
	root := makeTree(t)
	worker, libA, metadata := "binary", "sorted before lib/ by bytes", "Name: requests\nVersion: 2.25.0\n"
	// The records, sorted by the bytes of the relative path ("lib-a" sorts
	// before "lib/..." because '-' < '/'), exactly as docs/directories.md
	// describes them.
	records := strings.Join([]string{
		"dir\x00bin\x000755\x00",
		"file\x00bin/worker\x000755\x00" + size(worker) + "\x00" + hexSum(worker) + "\x00",
		"dir\x00empty\x000700\x00",
		"dir\x00lib\x000755\x00",
		"file\x00lib-a\x000644\x00" + size(libA) + "\x00" + hexSum(libA) + "\x00",
		"dir\x00lib/site-packages\x000755\x00",
		"file\x00lib/site-packages/METADATA\x000644\x00" + size(metadata) + "\x00" + hexSum(metadata) + "\x00",
		"symlink\x00outside\x00/etc/passwd\x00",
	}, "")
	want := "sha256:" + hexSum(Algorithm+"\x00"+records)

	got := digest(t, root)
	if got.Digest != want {
		t.Fatalf("digest = %s, want %s", got.Digest, want)
	}
	if got.Files != 3 || got.Dirs != 4 || got.Symlinks != 1 || got.Bytes != int64(len(worker+libA+metadata)) {
		t.Errorf("counts = %+v", got)
	}
}

func TestDigestIsDeterministic(t *testing.T) {
	a, b := makeTree(t), makeTree(t)
	if da, db := digest(t, a), digest(t, b); da.Digest != db.Digest {
		t.Fatalf("two identical trees have different digests: %s %s", da.Digest, db.Digest)
	}
	if d1, d2 := digest(t, a), digest(t, a); d1.Digest != d2.Digest {
		t.Fatal("the same tree gave two digests")
	}
}

func TestDigestChanges(t *testing.T) {
	cases := map[string]func(t *testing.T, root string){
		"content": func(t *testing.T, root string) {
			mustWrite(t, filepath.Join(root, "bin", "worker"), "binarY", 0o755)
		},
		"file mode": func(t *testing.T, root string) {
			mustChmod(t, filepath.Join(root, "lib-a"), 0o600)
		},
		"setuid bit": func(t *testing.T, root string) {
			mustChmod(t, filepath.Join(root, "bin", "worker"), 0o755|os.ModeSetuid)
		},
		"setgid and sticky bits": func(t *testing.T, root string) {
			mustChmod(t, filepath.Join(root, "empty"), 0o700|os.ModeSetgid|os.ModeSticky)
		},
		"directory mode": func(t *testing.T, root string) {
			mustChmod(t, filepath.Join(root, "empty"), 0o755)
		},
		"new empty file": func(t *testing.T, root string) {
			mustWrite(t, filepath.Join(root, "empty", "x"), "", 0o644)
		},
		"rename": func(t *testing.T, root string) {
			if err := os.Rename(filepath.Join(root, "lib-a"), filepath.Join(root, "lib-b")); err != nil {
				t.Fatal(err)
			}
		},
		"symlink target": func(t *testing.T, root string) {
			os.Remove(filepath.Join(root, "outside"))
			if err := os.Symlink("/etc/hosts", filepath.Join(root, "outside")); err != nil {
				t.Fatal(err)
			}
		},
		"file replaced by symlink": func(t *testing.T, root string) {
			os.Remove(filepath.Join(root, "lib-a"))
			if err := os.Symlink("lib", filepath.Join(root, "lib-a")); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			root := makeTree(t)
			before := digest(t, root).Digest
			change(t, root)
			if after := digest(t, root).Digest; after == before {
				t.Fatalf("a %s change must change the digest", name)
			}
		})
	}
}

func mustChmod(t *testing.T, p string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func TestDigestDoesNotFollowSymlinks(t *testing.T) {
	root := makeTree(t)
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, "payload"), "v1", 0o644)
	if err := os.Symlink(outside, filepath.Join(root, "linked-dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "payload"), filepath.Join(root, "linked-file")); err != nil {
		t.Fatal(err)
	}
	var seen []string
	before, err := Digest(context.Background(), root, func(e Entry, r io.Reader) error {
		seen = append(seen, e.Path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range seen {
		if strings.HasPrefix(p, "linked") {
			t.Fatalf("content behind a symlink was read: %v", seen)
		}
	}
	mustWrite(t, filepath.Join(outside, "payload"), "v2 changed", 0o644)
	if after := digest(t, root); after.Digest != before.Digest || after.Symlinks != 3 {
		t.Fatalf("a change outside the tree must not change the digest: %+v %+v", before, after)
	}
}

func TestDigestOfAnEmptyDirectory(t *testing.T) {
	want := "sha256:" + hexSum(Algorithm+"\x00")
	if got := digest(t, t.TempDir()); got.Digest != want || got.Files != 0 {
		t.Fatalf("got %+v, want %s", got, want)
	}
}

func TestDigestPassesEveryFileToContentInPathOrder(t *testing.T) {
	root := makeTree(t)
	var paths []string
	var data []string
	res, err := Digest(context.Background(), root, func(e Entry, r io.Reader) error {
		paths = append(paths, e.Path)
		if e.Path == "bin/worker" {
			b, err := io.ReadAll(r)
			data = append(data, string(b))
			return err
		}
		// Read only part of the file; the rest must still be hashed.
		buf := make([]byte, 2)
		_, err := io.ReadFull(r, buf)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(paths, ",") != "bin/worker,lib-a,lib/site-packages/METADATA" || data[0] != "binary" {
		t.Fatalf("paths %v data %v", paths, data)
	}
	if res.Digest != digest(t, root).Digest {
		t.Fatal("a partly read file must give the same digest")
	}
}

func TestDigestStopsOnContentError(t *testing.T) {
	boom := errors.New("disk full")
	_, err := Digest(context.Background(), makeTree(t), func(Entry, io.Reader) error { return boom })
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "bin/worker") {
		t.Fatalf("got %v", err)
	}
}

func TestDigestErrors(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	mustWrite(t, file, "x", 0o644)
	if _, err := Digest(context.Background(), file, nil); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("a file root must be refused, got %v", err)
	}
	if _, err := Digest(context.Background(), filepath.Join(t.TempDir(), "missing"), nil); err == nil {
		t.Error("a missing root must be an error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Digest(ctx, makeTree(t), nil); !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled context must stop the walk, got %v", err)
	}
}

func TestDigestReportsUnreadableFiles(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read every file")
	}
	root := makeTree(t)
	mustChmod(t, filepath.Join(root, "lib-a"), 0o000)
	if _, err := Digest(context.Background(), root, nil); err == nil || !strings.Contains(err.Error(), "lib-a") {
		t.Fatalf("an unreadable file must be an error naming it, got %v", err)
	}
}

func TestResolveRoot(t *testing.T) {
	root := makeTree(t)
	link := filepath.Join(t.TempDir(), "current")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveRoot(link)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(root)
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if _, err := ResolveRoot(filepath.Join(root, "lib-a")); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("a file must be refused, got %v", err)
	}
	if _, err := ResolveRoot(filepath.Join(root, "nope")); err == nil {
		t.Error("a missing path must be refused")
	}
}

func TestDigestDetectsAFileThatChangesWhileRead(t *testing.T) {
	root := makeTree(t)
	_, err := Digest(context.Background(), root, func(e Entry, r io.Reader) error {
		if e.Path == "bin/worker" {
			// Grow the file after it was listed.
			f, err := os.OpenFile(filepath.Join(root, "bin", "worker"), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = f.WriteString("more")
			return err
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "changed while") {
		t.Fatalf("a file that grows during the scan must be an error, got %v", err)
	}
}
