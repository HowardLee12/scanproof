//go:build !unix

package app

import "io/fs"

// ownerOf is unknown where file owners are not Unix user IDs.
func ownerOf(fs.FileInfo) (uint32, bool) { return 0, false }

// currentUID is unknown on these platforms.
func currentUID() uint32 { return 0 }
