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
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	info   fs.FileInfo
}

// Result is the digest of a tree and what it contains.
type Result struct {
	Digest   string
	Files    int
	Dirs     int
	Symlinks int
	Bytes    int64
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

// Digest walks root without following symlinks and returns its tree digest.
// content, when not nil, receives each file's bytes as they are hashed, so a
// caller can process exactly the bytes the digest covers.
func Digest(ctx context.Context, root string, content ContentFunc) (Result, error) {
	entries, err := list(root)
	if err != nil {
		return Result{}, err
	}
	h := sha256.New()
	io.WriteString(h, Algorithm+"\x00")
	res := Result{}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		sum := ""
		if e.Type == File {
			if sum, err = hashFile(root, e, content); err != nil {
				return Result{}, err
			}
		}
		h.Write(record(e, sum))
		res = res.add(e)
	}
	res.Digest = "sha256:" + hex.EncodeToString(h.Sum(nil))
	return res, nil
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
