//go:build !linux && !darwin

package tree

import "io/fs"

// stampOf has only the size and modification time where the platform's
// stat data is not read; os.SameFile still checks the identity.
func stampOf(info fs.FileInfo) Stamp {
	return Stamp{Size: info.Size(), Mtime: info.ModTime().UnixNano()}
}
