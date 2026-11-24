//go:build unix

package tree

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestDigestRefusesSpecialFiles(t *testing.T) {
	root := makeTree(t)
	if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0o644); err != nil {
		t.Skipf("cannot make a named pipe here: %v", err)
	}
	_, err := Digest(context.Background(), root, nil)
	if err == nil || !strings.Contains(err.Error(), "pipe") || !strings.Contains(err.Error(), "named pipe") {
		t.Fatalf("a named pipe must be refused with a clear error, got %v", err)
	}
}

func TestDigestRefusesSockets(t *testing.T) {
	// Unix socket paths are limited to about 100 bytes; skip where TMPDIR is too long.
	root, err := os.MkdirTemp("", "sp")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	l, err := net.Listen("unix", filepath.Join(root, "s"))
	if err != nil {
		t.Skipf("cannot make a socket here: %v", err)
	}
	defer l.Close()
	if _, err := Digest(context.Background(), root, nil); err == nil || !strings.Contains(err.Error(), "socket") {
		t.Fatalf("a socket must be refused, got %v", err)
	}
}
