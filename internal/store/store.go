// Package store keeps evidence files in durable storage: a local directory or
// an S3-compatible bucket. Evidence is write-once: storing a key that already
// exists is an error, so an earlier result can never be replaced.
package store

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// Store saves and reads evidence files by key. Keys use "/" separators.
type Store interface {
	Put(ctx context.Context, key string, data []byte, contentType string) error
	Get(ctx context.Context, key string) ([]byte, error)
	// List returns every key that starts with prefix, sorted.
	List(ctx context.Context, prefix string) ([]string, error)
	// Location is a human-readable URL for a key.
	Location(key string) string
}

// Open returns the store for a URL such as file:///var/evidence or
// s3://bucket/prefix.
func Open(ctx context.Context, raw string) (Store, error) {
	switch {
	case strings.HasPrefix(raw, "file://"):
		root := strings.TrimPrefix(raw, "file://")
		if root == "" {
			return nil, fmt.Errorf("store URL %q has no directory", raw)
		}
		return &FileStore{root: root}, nil
	case strings.HasPrefix(raw, "s3://"):
		return openS3(ctx, raw)
	default:
		return nil, fmt.Errorf("unsupported store URL %q (use s3://bucket/prefix or file:///path)", raw)
	}
}

// ScanPrefix is where one scan's files are stored, grouped by UTC day.
func ScanPrefix(reportID string, scannedAt time.Time) string {
	return DayPrefix(scannedAt) + reportID + "/"
}

// DayPrefix holds every scan of one UTC day.
func DayPrefix(t time.Time) string {
	return "scans/" + t.UTC().Format("2006/01/02") + "/"
}

// SummaryPrefix is where a period summary's files are stored.
func SummaryPrefix(from, to time.Time, summaryID string) string {
	return fmt.Sprintf("summaries/%s_%s/%s/", from.Format("2006-01-02"), to.Format("2006-01-02"), summaryID)
}

func validateKey(key string) error {
	if key == "" || strings.HasPrefix(key, "/") || path.Clean(key) != key || strings.Contains(key, "..") {
		return fmt.Errorf("invalid store key %q", key)
	}
	return nil
}

func sortStrings(s []string) {
	sort.Strings(s)
}
