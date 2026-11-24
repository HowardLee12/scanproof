package store

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var digestPattern = regexp.MustCompile(`^(sha256|sha512):[a-f0-9]{32,128}$`)

// IndexEntry points from an image digest to one stored scan of that image,
// so a rescan can find the newest SBOM without listing every day.
type IndexEntry struct {
	ReportID   string `json:"report_id"`
	ScanPrefix string `json:"scan_prefix"`
	HasSBOM    bool   `json:"has_sbom"`
}

// DigestIndexPrefix is the folder that holds the index entries of a digest.
func DigestIndexPrefix(digest string) (string, error) {
	if !digestPattern.MatchString(digest) {
		return "", fmt.Errorf("invalid image digest %q", digest)
	}
	algo, hex, _ := strings.Cut(digest, ":")
	return "index/digests/" + algo + "/" + hex + "/", nil
}

// PutIndexEntry records that e is a scan of digest.
func PutIndexEntry(ctx context.Context, st Store, digest string, e IndexEntry) error {
	prefix, err := DigestIndexPrefix(digest)
	if err != nil {
		return err
	}
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode index entry: %w", err)
	}
	return st.Put(ctx, prefix+e.ReportID+".json", data, "application/json")
}

// LatestSBOM returns the newest indexed scan of digest that saved an SBOM.
// Report IDs start with the date, so key order is time order.
func LatestSBOM(ctx context.Context, st Store, digest string) (IndexEntry, bool, error) {
	prefix, err := DigestIndexPrefix(digest)
	if err != nil {
		return IndexEntry{}, false, err
	}
	keys, err := st.List(ctx, prefix)
	if err != nil {
		return IndexEntry{}, false, err
	}
	for i := len(keys) - 1; i >= 0; i-- {
		data, err := st.Get(ctx, keys[i])
		if err != nil {
			return IndexEntry{}, false, err
		}
		var e IndexEntry
		if err := json.Unmarshal(data, &e); err != nil {
			return IndexEntry{}, false, fmt.Errorf("decode %s: %w", st.Location(keys[i]), err)
		}
		if e.HasSBOM {
			return e, true, nil
		}
	}
	return IndexEntry{}, false, nil
}
