package summary

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

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

// Load reads every results.json stored between the start of the look-back
// window and the end of the period, oldest first. A file that cannot be read
// or decoded is an error: dropping it would leave a hole in the population.
func Load(ctx context.Context, st store.Store, p Period) ([]Loaded, error) {
	keys, err := resultKeys(ctx, st, p)
	if err != nil {
		return nil, err
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
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}

	sort.SliceStable(results, func(i, j int) bool {
		if !results[i].GeneratedAt.Equal(results[j].GeneratedAt) {
			return results[i].GeneratedAt.Before(results[j].GeneratedAt)
		}
		return results[i].ReportID < results[j].ReportID
	})
	return results, nil
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
	data, err := st.Get(ctx, key)
	if err != nil {
		return Loaded{}, err
	}
	var doc report.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return Loaded{}, fmt.Errorf("decode %s: %w", st.Location(key), err)
	}
	if doc.Schema != report.SchemaVersion {
		return Loaded{}, fmt.Errorf("%s has schema %q, want %q", st.Location(key), doc.Schema, report.SchemaVersion)
	}
	return Loaded{Document: doc, Location: st.Location(strings.TrimSuffix(key, "results.json"))}, nil
}
