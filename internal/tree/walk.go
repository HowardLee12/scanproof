package tree

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// list returns every entry below root, sorted by the bytes of its path.
// filepath.WalkDir never follows symlinks; it reports them as entries.
func list(root string) ([]Entry, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}
	entries := make([]Entry, 0)
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("read %s: %w", p, err)
		}
		if p == root {
			return nil
		}
		e, err := newEntry(root, p, d)
		if err != nil {
			return err
		}
		entries = append(entries, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Sorting whole paths (rather than walking each directory in order)
	// makes "lib-a" come before "lib/x", as the documented algorithm says.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

func newEntry(root, p string, d fs.DirEntry) (Entry, error) {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return Entry{}, fmt.Errorf("relative path of %s: %w", p, err)
	}
	rel = filepath.ToSlash(rel)
	info, err := d.Info()
	if err != nil {
		return Entry{}, fmt.Errorf("read %s: %w", rel, err)
	}
	mode := info.Mode()
	e := Entry{Path: rel, Mode: permBits(mode), info: info}
	switch {
	case mode.IsRegular():
		e.Type, e.Size = File, info.Size()
	case mode.IsDir():
		e.Type = Dir
	case mode&fs.ModeSymlink != 0:
		target, err := os.Readlink(p)
		if err != nil {
			return Entry{}, fmt.Errorf("read symlink %s: %w", rel, err)
		}
		e.Type, e.Target = Symlink, target
	default:
		return Entry{}, fmt.Errorf("%s is a %s; only files, directories and symlinks can be scanned, "+
			"so scan a directory without devices, sockets or named pipes", rel, specialKind(mode))
	}
	return e, nil
}

func specialKind(m fs.FileMode) string {
	switch {
	case m&fs.ModeNamedPipe != 0:
		return "named pipe"
	case m&fs.ModeSocket != 0:
		return "socket"
	case m&fs.ModeDevice != 0:
		return "device"
	default:
		return "special file"
	}
}

// hashFile returns the hex SHA-256 of a file's content, passing the bytes to
// content as they are read. The file is opened without following a symlink
// and must be the same file that was listed, with the same size, so a file
// swapped or changed during the scan is an error rather than a wrong digest.
func hashFile(root string, e Entry, content ContentFunc) (string, error) {
	f, err := openNoFollow(filepath.Join(root, filepath.FromSlash(e.Path)))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", e.Path, err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("read %s: %w", e.Path, err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(opened, e.info) || opened.Size() != e.Size {
		return "", changed(e.Path)
	}

	h := sha256.New()
	n := &countingWriter{}
	r := io.TeeReader(f, io.MultiWriter(h, n))
	if content != nil {
		if err := content(e, r); err != nil {
			return "", fmt.Errorf("%s: %w", e.Path, err)
		}
	}
	if _, err := io.Copy(io.Discard, r); err != nil {
		return "", fmt.Errorf("read %s: %w", e.Path, err)
	}
	if n.n != e.Size {
		return "", changed(e.Path)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func changed(path string) error {
	return fmt.Errorf("%s changed while it was being scanned; scan the directory again when nothing is writing to it", path)
}

type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}
