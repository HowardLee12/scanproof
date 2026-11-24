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

// Put writes data to key. It fails if key already exists.
func (s *FileStore) Put(_ context.Context, key string, data []byte, _ string) error {
	if err := validateKey(key); err != nil {
		return err
	}
	full := s.path(key)
	if err := os.MkdirAll(filepath.Dir(full), fileStoreDirMode); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(full), err)
	}
	f, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileStoreFileMode)
	if err != nil {
		return fmt.Errorf("store %s: %w", key, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("store %s: %w", key, err)
	}
	return f.Close()
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
		if d.IsDir() {
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
