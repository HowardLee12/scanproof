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
	"strings"
	"syscall"
)

// hashFile returns the hex SHA-256 of a file's content, passing the bytes to
// content as they are read. The file is opened through the root and must be
// the file that was listed, unchanged: the same device, inode, size and
// times before and after it is read. A file that was swapped, replaced by a
// symlink or a named pipe, written to, or deleted is an ErrChanged error.
func hashFile(ctx context.Context, r *os.Root, e Entry, content ContentFunc) (string, error) {
	f, err := r.OpenFile(e.Path, os.O_RDONLY|openFlags, 0)
	if err != nil {
		return "", openError(e.Path, err)
	}
	defer f.Close()
	if err := sameAsListed(f, e); err != nil {
		return "", err
	}

	h := sha256.New()
	n := &countingWriter{}
	tee := io.TeeReader(ctxReader{ctx: ctx, r: f}, io.MultiWriter(h, n))
	if content != nil {
		if err := content(e, tee); err != nil {
			return "", readError(e.Path, err)
		}
	}
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return "", readError(e.Path, err)
	}
	if n.n != e.Size {
		return "", changed(e.Path)
	}
	if err := sameAsListed(f, e); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sameAsListed checks that an open file is the regular file that was listed
// and has not changed since.
func sameAsListed(f *os.File, e Entry) error {
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("read %s: %w", e.Path, err)
	}
	if !info.Mode().IsRegular() || !os.SameFile(info, e.info) || stampOf(info) != e.Stamp {
		return changed(e.Path)
	}
	return nil
}

// openError reports a path that disappeared, became a symlink, or now points
// outside the root as changed; anything else (for example a permission
// error) is passed on.
func openError(path string, err error) error {
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) ||
		strings.Contains(err.Error(), "path escapes from parent") {
		return changed(path)
	}
	return fmt.Errorf("read %s: %w", path, err)
}

// readError reports a file that ended early as changed.
func readError(path string, err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return changed(path)
	}
	return fmt.Errorf("%s: %w", path, err)
}

// ctxReader stops a long read when the context ends.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}
