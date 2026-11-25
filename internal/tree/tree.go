// Package tree computes a deterministic digest of a directory tree, so a
// directory that is not a container image can be identified the way an image
// is identified by its digest: the same names, contents, permissions and
// symlinks always give the same digest, and any change gives a different one.
//
// docs/directories.md describes the algorithm so anyone can recompute it.
package tree

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/HowardLee12/scanproof/internal/stopped"
)

// Algorithm names the encoding. It is hashed first, so a future change to
// the encoding can never produce the same digest as this one.
const Algorithm = "scanproof-tree/v1"

// Type is the kind of an entry.
type Type string

// Entry types. Anything else (devices, sockets, named pipes) is refused.
const (
	File    Type = "file"
	Dir     Type = "dir"
	Symlink Type = "symlink"
)

// Entry is one file, directory or symlink below the root.
type Entry struct {
	// Path is relative to the root and uses "/" separators.
	Path string
	Type Type
	// Mode holds the 12 permission bits (st_mode & 07777): read, write and
	// execute for user, group and others, plus setuid, setgid and sticky.
	Mode uint32
	// Size is the file size in bytes (files only).
	Size int64
	// Target is the link target, exactly as stored (symlinks only).
	Target string
	// Stamp identifies the entry and when it last changed. It is not part
	// of the digest, so a copy has the same digest, but comparing stamps
	// shows a change that was reverted between two reads.
	Stamp Stamp
	info  fs.FileInfo
}

// Stamp is an entry's device, inode, size and modification and change
// times, where the platform has them.
type Stamp struct {
	Dev   uint64
	Ino   uint64
	Size  int64
	Mtime int64 // nanoseconds
	Ctime int64 // nanoseconds
}

// Result is the digest of a tree and what it contains.
type Result struct {
	Digest   string
	Files    int
	Dirs     int
	Symlinks int
	Bytes    int64
	// Root is the stamp of the root directory itself, so a root that was
	// swapped for another directory and put back is noticed.
	Root Stamp
	// Entries are every entry, sorted by path.
	Entries []Entry
}

// ErrChanged marks a tree that changed while it was being read.
var ErrChanged = errors.New("changed while it was being scanned")

func changed(path string) error {
	return fmt.Errorf("%s %w; scan the directory again when nothing is writing to it", path, ErrChanged)
}

func (r Result) add(e Entry) Result {
	switch e.Type {
	case File:
		r.Files++
		r.Bytes += e.Size
	case Dir:
		r.Dirs++
	case Symlink:
		r.Symlinks++
	}
	return r
}

// ContentFunc receives every regular file, in path order, while it is being
// hashed. It may read all, part or none of r; whatever it leaves is read and
// hashed after it returns. An error stops the walk.
type ContentFunc func(e Entry, r io.Reader) error

// ResolveRoot returns the absolute path of the directory at path, with
// symlinks in the path itself resolved. Symlinks inside the directory are
// never followed.
func ResolveRoot(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", path, err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", path, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", path)
	}
	return resolved, nil
}

// Options tune a walk; the zero value only hashes.
type Options struct {
	// Content, when set, receives each file's bytes as they are hashed, so
	// a caller can process exactly the bytes the digest covers.
	Content ContentFunc
	// Listed, when set, is told the number of regular files once the
	// directory is listed, before any file is read.
	Listed func(files int)
}

// Digest walks root without following symlinks and returns its tree digest.
// content, when not nil, receives each file's bytes as they are hashed.
// Every read goes through an os.Root, so nothing outside root is ever
// opened.
func Digest(ctx context.Context, root string, content ContentFunc) (Result, error) {
	return DigestWith(ctx, root, Options{Content: content})
}

// DigestWith is Digest with options. If the context ends, the error is a
// *stopped.Error that says how many files were read, not which file the
// walk was at.
func DigestWith(ctx context.Context, root string, opts Options) (Result, error) {
	r, rootStamp, err := openRoot(root)
	if err != nil {
		return Result{}, err
	}
	defer r.Close()
	entries, err := list(ctx, r)
	if stop := stopped.Check(ctx); err != nil && stop != nil {
		return Result{}, stopped.WithProgress(stop, "while listing the directory")
	}
	if err != nil {
		return Result{}, err
	}
	files := countFiles(entries)
	if opts.Listed != nil {
		opts.Listed(files)
	}
	h := sha256.New()
	io.WriteString(h, Algorithm+"\x00")
	res := Result{Root: rootStamp, Entries: entries}
	for _, e := range entries {
		sum := ""
		if e.Type == File {
			if sum, err = hashFile(ctx, r, e, opts.Content); err != nil {
				return Result{}, stopped.WithProgress(err, stopped.Count(res.Files)+" of "+stopped.Count(files)+" files read")
			}
		}
		h.Write(record(e, sum))
		res = res.add(e)
	}
	res.Digest = "sha256:" + hex.EncodeToString(h.Sum(nil))
	return res, nil
}

func countFiles(entries []Entry) int {
	n := 0
	for _, e := range entries {
		if e.Type == File {
			n++
		}
	}
	return n
}

// Unchanged reports whether two reads of a directory saw the same tree: the
// same digest, and the same entries with the same stamps. It returns an
// ErrChanged error naming the first difference.
func Unchanged(before, after Result) error {
	if before.Root != after.Root {
		return changed("the directory itself")
	}
	for i, a := range before.Entries {
		if i >= len(after.Entries) || after.Entries[i].Path != a.Path {
			return changed(a.Path)
		}
		b := after.Entries[i]
		if b.Type != a.Type || b.Mode != a.Mode || b.Stamp != a.Stamp || b.Target != a.Target {
			return changed(a.Path)
		}
	}
	if len(after.Entries) > len(before.Entries) {
		return changed(after.Entries[len(before.Entries)].Path)
	}
	if before.Digest != after.Digest {
		return changed("the directory")
	}
	return nil
}

// CheckRoot reports whether the directory at root is still the one a read
// found: the same device, inode and times.
func CheckRoot(root string, read Result) error {
	info, err := os.Lstat(root)
	if err != nil {
		return openError("the directory itself", err)
	}
	if !info.IsDir() || stampOf(info) != read.Root {
		return changed("the directory itself")
	}
	return nil
}

// testHookBeforeOpenRoot lets tests replace the root after it was checked.
var testHookBeforeOpenRoot func(root string)

// openRoot opens the directory at root and returns its stamp. The path is
// opened as root/. so that, if it was replaced by a named pipe after the
// check, the open fails at once instead of waiting for a writer.
func openRoot(root string) (*os.Root, Stamp, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, Stamp{}, fmt.Errorf("read %s: %w", root, err)
	}
	if !info.IsDir() {
		return nil, Stamp{}, fmt.Errorf("%s is not a directory", root)
	}
	if testHookBeforeOpenRoot != nil {
		testHookBeforeOpenRoot(root)
	}
	r, err := os.OpenRoot(root + string(os.PathSeparator) + ".")
	if err != nil {
		return nil, Stamp{}, fmt.Errorf("open %s: %w", root, err)
	}
	opened, err := r.Stat(".")
	if err != nil {
		r.Close()
		return nil, Stamp{}, fmt.Errorf("read %s: %w", root, err)
	}
	if !os.SameFile(info, opened) {
		r.Close()
		return nil, Stamp{}, changed("the directory itself")
	}
	return r, stampOf(opened), nil
}

// record encodes one entry. Every field ends with a NUL byte, which cannot
// occur in a path or link target, and the type decides how many fields
// follow, so the encoding is unambiguous.
func record(e Entry, sum string) []byte {
	fields := []string{string(e.Type), e.Path}
	switch e.Type {
	case File:
		fields = append(fields, modeText(e.Mode), strconv.FormatInt(e.Size, 10), sum)
	case Dir:
		fields = append(fields, modeText(e.Mode))
	case Symlink:
		fields = append(fields, e.Target)
	}
	return []byte(strings.Join(fields, "\x00") + "\x00")
}

func modeText(m uint32) string {
	return fmt.Sprintf("%04o", m)
}

// permBits converts Go's file mode to the Unix st_mode & 07777 bits.
func permBits(m fs.FileMode) uint32 {
	bits := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		bits |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		bits |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		bits |= 0o1000
	}
	return bits
}
