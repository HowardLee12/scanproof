//go:build unix

package app

import (
	"io/fs"
	"os"
	"syscall"
)

// ownerOf returns the owner of a file.
func ownerOf(info fs.FileInfo) (uint32, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// currentUID is the user running the scan.
func currentUID() uint32 { return uint32(os.Geteuid()) }
