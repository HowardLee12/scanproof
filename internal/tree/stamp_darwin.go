package tree

import (
	"io/fs"
	"syscall"
)

func stampOf(info fs.FileInfo) Stamp {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return Stamp{Size: info.Size(), Mtime: info.ModTime().UnixNano()}
	}
	return Stamp{
		Dev: uint64(st.Dev), Ino: st.Ino, Size: st.Size,
		Mtime: st.Mtimespec.Nano(), Ctime: st.Ctimespec.Nano(),
	}
}
