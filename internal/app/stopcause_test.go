package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/report"
	"github.com/HowardLee12/scanproof/internal/store"
)

// putFailingStore fails every Put with err.
type putFailingStore struct {
	store.Store
	err error
}

func (s putFailingStore) Put(context.Context, string, []byte, string) error { return s.err }

// A timeout inside a step, such as the AWS SDK giving up on the instance
// metadata service after its own 5 seconds, is that step's failure, not
// the scan reaching its --timeout.
func TestATimeoutInsideAStepIsNotTheScansTimeout(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, resultsFile), "{}")
	imds := fmt.Errorf("get credentials: operation error ec2imds: GetMetadata: %w", context.DeadlineExceeded)
	err := uploadFiles(context.Background(), putFailingStore{err: imds}, dir, "scans/x/", []string{resultsFile})
	msg := describeStop(err, 30*time.Minute, "the scan").Error()
	if !strings.Contains(msg, "ec2imds: GetMetadata") || strings.Contains(msg, "--timeout") {
		t.Fatalf("the real error must be shown: %q", msg)
	}
}

func TestAContextErrorAfterTheDeadlineIsTheStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, resultsFile), "{}")
	err := uploadFiles(ctx, putFailingStore{err: fmt.Errorf("put: %w", context.Canceled)}, dir, "scans/x/", []string{resultsFile})
	if msg := describeStop(err, time.Minute, "the scan").Error(); msg != "the scan was cancelled while storing the evidence" {
		t.Fatalf("got %q", msg)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

// indexFailingStore stores files but fails every index write with err.
type indexFailingStore struct {
	store.Store
	err error
}

func (s indexFailingStore) Put(_ context.Context, key string, _ []byte, _ string) error {
	if strings.HasPrefix(key, "index/") {
		return s.err
	}
	return nil
}

func (indexFailingStore) Location(key string) string { return "mem://" + key }

// A scan cancelled after its evidence was stored, while the digest index
// was written, must still say that the evidence is stored.
func TestACancelWhileIndexingSaysTheEvidenceIsStored(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir := t.TempDir()
	for _, name := range []string{resultsFile, sbomFile} {
		writeFile(t, filepath.Join(dir, name), "{}")
	}
	doc := report.Document{ReportID: "SR-20261125-ABCDEF", GeneratedAt: time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC),
		Image: model.Image{Digest: fixtureDigest}}
	_, err := uploadEvidence(ctx, indexFailingStore{err: fmt.Errorf("put: %w", context.Canceled)}, dir, doc, []string{resultsFile, sbomFile})
	msg := describeStop(err, time.Minute, "the scan").Error()
	want := "the scan was cancelled while indexing the stored evidence (report SR-20261125-ABCDEF is stored at " +
		"mem://scans/2026/11/25/SR-20261125-ABCDEF/ but not indexed, so rescans will not find it)"
	if msg != want {
		t.Fatalf("got %q, want %q", msg, want)
	}
}
