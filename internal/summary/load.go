package summary

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/policy"
	"github.com/HowardLee12/scanproof/internal/report"
	"github.com/HowardLee12/scanproof/internal/store"
)

// maxParallelDownloads bounds concurrent reads from the store.
const maxParallelDownloads = 8

// Loaded is one stored scan and where it lives.
type Loaded struct {
	report.Document
	Location string
}

// LoadResult holds the complete scans and the folders that were skipped
// because their upload never finished (no manifest.json).
type LoadResult struct {
	Scans      []Loaded
	Incomplete []string
}

// errIncomplete marks a scan whose manifest was never written.
var errIncomplete = errors.New("incomplete upload")

// Load reads every scan stored between the start of the look-back window and
// the end of the period, oldest first.
//
// A scan counts only once its manifest.json exists, because the manifest is
// uploaded last; folders without one are reported as incomplete. A
// results.json whose SHA-256 differs from its manifest, or that cannot be
// decoded, is an error: it would leave a silent hole in the population.
func Load(ctx context.Context, st store.Store, p Period) (LoadResult, error) {
	keys, err := resultKeys(ctx, st, p)
	if err != nil {
		return LoadResult{}, err
	}

	results := make([]Loaded, len(keys))
	errs := make([]error, len(keys))
	sem := make(chan struct{}, maxParallelDownloads)
	var wg sync.WaitGroup
	for i, key := range keys {
		wg.Add(1)
		go func(i int, key string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i], errs[i] = loadOne(ctx, st, key)
		}(i, key)
	}
	wg.Wait()

	out := LoadResult{Scans: make([]Loaded, 0, len(keys)), Incomplete: []string{}}
	for i, err := range errs {
		switch {
		case errors.Is(err, errIncomplete):
			out.Incomplete = append(out.Incomplete, st.Location(strings.TrimSuffix(keys[i], "results.json")))
		case err != nil:
			return LoadResult{}, err
		default:
			out.Scans = append(out.Scans, results[i])
		}
	}
	sort.SliceStable(out.Scans, func(i, j int) bool {
		a, b := out.Scans[i], out.Scans[j]
		if !a.GeneratedAt.Equal(b.GeneratedAt) {
			return a.GeneratedAt.Before(b.GeneratedAt)
		}
		return a.ReportID < b.ReportID
	})
	return out, nil
}

func resultKeys(ctx context.Context, st store.Store, p Period) ([]string, error) {
	keys := make([]string, 0)
	for d := p.LoadFrom(); d.Before(p.End()); d = d.AddDate(0, 0, 1) {
		dayKeys, err := st.List(ctx, store.DayPrefix(d))
		if err != nil {
			return nil, err
		}
		for _, k := range dayKeys {
			if strings.HasSuffix(k, "/results.json") {
				keys = append(keys, k)
			}
		}
	}
	return keys, nil
}

func loadOne(ctx context.Context, st store.Store, key string) (Loaded, error) {
	prefix := strings.TrimSuffix(key, "results.json")
	manifestKeys, err := st.List(ctx, prefix+"manifest.json")
	if err != nil {
		return Loaded{}, err
	}
	if len(manifestKeys) == 0 {
		return Loaded{}, errIncomplete
	}
	manifestData, err := st.Get(ctx, prefix+"manifest.json")
	if err != nil {
		return Loaded{}, err
	}
	data, err := st.Get(ctx, key)
	if err != nil {
		return Loaded{}, err
	}
	if _, err := report.VerifyAgainstManifest(manifestData, "results.json", data); err != nil {
		return Loaded{}, fmt.Errorf("%s: %w", st.Location(key), err)
	}

	var doc report.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return Loaded{}, fmt.Errorf("decode %s: %w", st.Location(key), err)
	}
	if doc.Schema != report.SchemaVersion {
		return Loaded{}, fmt.Errorf("%s has schema %q, want %q", st.Location(key), doc.Schema, report.SchemaVersion)
	}
	return Loaded{Document: slim(doc), Location: st.Location(prefix)}, nil
}

// slim keeps only what the summary uses, so a long period fits in memory.
func slim(doc report.Document) report.Document {
	vulns := make([]policy.VulnerabilityFinding, 0, len(doc.Vulnerabilities))
	for _, f := range doc.Vulnerabilities {
		vulns = append(vulns, policy.VulnerabilityFinding{
			Vulnerability: model.Vulnerability{ID: f.ID, Package: f.Package, Severity: f.Severity, FixedVersion: f.FixedVersion},
			ExceptionID:   f.ExceptionID,
			Violation:     f.Violation,
		})
	}
	doc.Vulnerabilities = vulns
	if doc.Malware != nil {
		m := *doc.Malware
		m.Skipped = nil
		doc.Malware = &m
	}
	return doc
}
