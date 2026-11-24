package tree

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"unicode/utf8"
)

// testHookBeforeReadDir lets tests change the tree between listing a
// directory and reading its entries.
var testHookBeforeReadDir func(path string)

// list returns every entry below the root, sorted by the bytes of its path.
// Each directory is opened through the root (so nothing outside it can be
// read) and must be the directory that was listed, so a directory swapped
// for a symlink while the walk runs is an error rather than followed.
func list(ctx context.Context, r *os.Root) ([]Entry, error) {
	entries := make([]Entry, 0)
	if err := walkDir(ctx, r, ".", nil, &entries); err != nil {
		return nil, err
	}
	// Sorting whole paths (rather than walking each directory in order)
	// makes "lib-a" come before "lib/x", as the documented algorithm says.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

// walkDir adds the entries of the directory dir, which was listed as
// listed (nil for the root), and recurses into its subdirectories.
func walkDir(ctx context.Context, r *os.Root, dir string, listed *Entry, out *[]Entry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	names, err := readDirNames(r, dir, listed)
	if err != nil {
		return err
	}
	for _, name := range names {
		p := name
		if dir != "." {
			p = dir + "/" + name
		}
		e, err := newEntry(r, p)
		if err != nil {
			return err
		}
		*out = append(*out, e)
		if e.Type == Dir {
			if err := walkDir(ctx, r, p, &e, out); err != nil {
				return err
			}
		}
	}
	return nil
}

// readDirNames reads a directory's entry names from the directory that was
// listed: the opened directory must have the listed device and inode.
func readDirNames(r *os.Root, dir string, listed *Entry) ([]string, error) {
	if testHookBeforeReadDir != nil && listed != nil {
		testHookBeforeReadDir(dir)
	}
	f, err := r.OpenFile(dir, os.O_RDONLY|openFlags, 0)
	if err != nil {
		return nil, openError(dir, err)
	}
	defer f.Close()
	if listed != nil {
		info, err := f.Stat()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", dir, err)
		}
		if st := stampOf(info); !info.IsDir() || st.Dev != listed.Stamp.Dev || st.Ino != listed.Stamp.Ino {
			return nil, changed(dir)
		}
	}
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	return names, nil
}

func newEntry(r *os.Root, p string) (Entry, error) {
	if !utf8.ValidString(p) {
		return Entry{}, fmt.Errorf("%s is not valid UTF-8; such names cannot be shown exactly in the evidence, "+
			"so rename it or scan a directory without it", strconv.Quote(p))
	}
	info, err := r.Lstat(p)
	if err != nil {
		return Entry{}, openError(p, err)
	}
	mode := info.Mode()
	e := Entry{Path: p, Mode: permBits(mode), Stamp: stampOf(info), info: info}
	switch {
	case mode.IsRegular():
		e.Type, e.Size = File, info.Size()
	case mode.IsDir():
		e.Type = Dir
	case mode&fs.ModeSymlink != 0:
		target, err := r.Readlink(p)
		if err != nil {
			return Entry{}, openError(p, err)
		}
		e.Type, e.Target = Symlink, target
	default:
		return Entry{}, fmt.Errorf("%s is a %s; only files, directories and symlinks can be scanned, "+
			"so scan a directory without devices, sockets or named pipes", p, specialKind(mode))
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
