//go:build unix

package tree

import "syscall"

// openFlags keeps an open from hanging if a file was replaced by a named
// pipe; the file is then refused because it is not a regular file. (os.Root
// follows symlinks that stay inside the root, so O_NOFOLLOW would not help;
// the inode check after opening catches a swapped-in symlink instead.)
const openFlags = syscall.O_NONBLOCK
