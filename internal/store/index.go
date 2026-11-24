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

var reportIDPattern = regexp.MustCompile(`^SR-(\d{8})-[0-9A-F]{6}$`)

// SBOMEntries returns the indexed scans of digest that saved an SBOM, newest
// first. Entries whose report ID or folder does not have the expected form
// are skipped, so a stray object in the index cannot redirect a rescan.
// Callers must still check the SBOM against the scan's manifest.
func SBOMEntries(ctx context.Context, st Store, digest string) ([]IndexEntry, error) {
	prefix, err := DigestIndexPrefix(digest)
	if err != nil {
		return nil, err
	}
	keys, err := st.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	out := make([]IndexEntry, 0, len(keys))
	for i := len(keys) - 1; i >= 0; i-- {
		data, err := st.Get(ctx, keys[i])
		if err != nil {
			return nil, err
		}
		var e IndexEntry
		if err := json.Unmarshal(data, &e); err != nil {
			continue
		}
		if e.HasSBOM && validEntry(e) && keys[i] == prefix+e.ReportID+".json" {
			out = append(out, e)
		}
	}
	return out, nil
}

func validEntry(e IndexEntry) bool {
	m := reportIDPattern.FindStringSubmatch(e.ReportID)
	if m == nil {
		return false
	}
	day := m[1]
	want := "scans/" + day[0:4] + "/" + day[4:6] + "/" + day[6:8] + "/" + e.ReportID + "/"
	return e.ScanPrefix == want
}
