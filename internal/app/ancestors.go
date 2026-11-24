package app

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ancestor is a directory above the scanned one.
type ancestor struct {
	path  string
	mode  fs.FileMode
	uid   uint32
	owned bool // whether uid is known on this platform
}

// ancestorWarnings lists the directories above the scanned one that someone
// other than root or the user running the scan could change: writable by
// its group or by others without the sticky bit, or owned by another user.
// Whoever can change one could swap the scanned directory during the scan.
func ancestorWarnings(ancestors []ancestor, me uint32) []string {
	out := []string{}
	for _, a := range ancestors {
		switch {
		case a.mode.Perm()&0o022 != 0 && a.mode&fs.ModeSticky == 0:
			out = append(out, fmt.Sprintf("%s can be written by its group or others (mode %04o, no sticky bit), "+
				"so they could swap the scanned directory during the scan", a.path, a.mode.Perm()))
		case a.owned && a.uid != 0 && a.uid != me:
			out = append(out, fmt.Sprintf("%s is owned by uid %d, which is neither root nor the user running the scan, "+
				"so that user could swap the scanned directory during the scan", a.path, a.uid))
		}
	}
	return out
}

// ancestorsOf lists every directory above root, up to the file system root.
func ancestorsOf(root string) []ancestor {
	out := []ancestor{}
	for p := filepath.Dir(root); ; p = filepath.Dir(p) {
		if info, err := os.Lstat(p); err == nil {
			uid, owned := ownerOf(info)
			out = append(out, ancestor{path: p, mode: info.Mode(), uid: uid, owned: owned})
		}
		if filepath.Dir(p) == p {
			return out
		}
	}
}
