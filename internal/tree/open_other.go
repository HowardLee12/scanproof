//go:build !unix

package tree

import "os"

// openNoFollow opens a file for reading. The caller checks that it is the
// regular file that was listed, so a symlink swapped in is still refused.
func openNoFollow(p string) (*os.File, error) {
	return os.Open(p)
}
