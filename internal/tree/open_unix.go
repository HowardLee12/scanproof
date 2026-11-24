//go:build unix

package tree

import (
	"os"
	"syscall"
)

// openNoFollow opens a file for reading without following a symlink in the
// last path element. O_NONBLOCK keeps the open from hanging if the file was
// replaced by a named pipe; the caller then refuses it as not a regular file.
func openNoFollow(p string) (*os.File, error) {
	return os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
