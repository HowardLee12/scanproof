package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	fileStoreDirMode  = 0o755
	fileStoreFileMode = 0o644
)

// FileStore keeps evidence in a local directory, for example a mounted
// network volume. It is mostly useful for testing and small setups.
type FileStore struct {
	root string
}

// Put writes data to key. It fails if key already exists. The data is
// written to a temporary file first and linked into place, so a failed write
// never leaves a truncated file behind.
func (s *FileStore) Put(_ context.Context, key string, data []byte, _ string) error {
	if err := validateKey(key); err != nil {
		return err
	}
	full := s.path(key)
	dir := filepath.Dir(full)
	if err := os.MkdirAll(dir, fileStoreDirMode); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		return fmt.Errorf("store %s: %w", key, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("store %s: %w", key, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("store %s: %w", key, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store %s: %w", key, err)
	}
	if err := os.Chmod(tmp.Name(), fileStoreFileMode); err != nil {
		return fmt.Errorf("store %s: %w", key, err)
	}
	// Link fails if the key already exists, which keeps the store write-once.
	if err := os.Link(tmp.Name(), full); err != nil {
		return fmt.Errorf("store %s: %w", key, err)
	}
	return nil
}

// Get reads key.
func (s *FileStore) Get(_ context.Context, key string) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(s.path(key))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", key, err)
	}
	return data, nil
}

// List returns the keys under prefix, sorted.
func (s *FileStore) List(_ context.Context, prefix string) ([]string, error) {
	keys := make([]string, 0)
	err := filepath.WalkDir(s.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() || strings.HasPrefix(d.Name(), ".upload-") {
			return nil
		}
		rel, err := filepath.Rel(s.root, p)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", prefix, err)
	}
	sortStrings(keys)
	return keys, nil
}

// Location returns a file:// URL for key. A key ending in "/" is a folder
// and keeps its trailing slash.
func (s *FileStore) Location(key string) string {
	loc := "file://" + s.path(key)
	if strings.HasSuffix(key, "/") {
		loc += "/"
	}
	return loc
}

func (s *FileStore) path(key string) string {
	return filepath.Join(s.root, filepath.FromSlash(key))
}
