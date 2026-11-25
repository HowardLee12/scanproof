package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/HowardLee12/scanproof/internal/model"
)

const wantLimits = "Limits: files larger than 512 MiB are not scanned. ClamAV scans at most 50,000 files " +
	"and 2,048 MiB of data inside one file, such as an archive, and spends at most 10 minutes on it."

// withLimits returns doc with the limits a scan with
// --malware-max-archive-files 50000 runs with.
func withLimits(doc Document) Document {
	section := *doc.Malware
	section.Limits = &model.MalwareLimits{MaxFileBytes: 512 << 20, MaxScanBytes: 2048 << 20, MaxArchiveFiles: 50000, MaxScanTimeMS: 600000}
	doc.Malware = &section
	return doc
}

func TestBuildKeepsTheMalwareLimits(t *testing.T) {
	base := malwareDocument(t)
	scan := &model.MalwareScan{Limits: &model.MalwareLimits{MaxFileBytes: 1, MaxScanBytes: 2, MaxArchiveFiles: 3, MaxScanTimeMS: 4}}
	doc := Build(Input{ReportID: base.ReportID, GeneratedAt: base.GeneratedAt, Result: model.ScanResult{Malware: scan}})
	if doc.Malware == nil || doc.Malware.Limits == nil || *doc.Malware.Limits != *scan.Limits {
		t.Fatalf("malware = %+v", doc.Malware)
	}
}

func TestMalwareLimitsInResults(t *testing.T) {
	data, err := json.Marshal(withLimits(malwareDocument(t)))
	if err != nil {
		t.Fatal(err)
	}
	want := `"limits":{"max_file_bytes":536870912,"max_scan_bytes":2147483648,"max_archive_files":50000,"max_scan_time_ms":600000}`
	if !strings.Contains(string(data), want) {
		t.Errorf("results.json is missing %s: %s", want, data)
	}
}

func TestMalwareLimitsInMarkdown(t *testing.T) {
	for name, doc := range map[string]Document{
		"image":     withLimits(malwareDocument(t)),
		"directory": withLimits(sampleDirectoryDocument(t)),
	} {
		md := Markdown(doc)
		if !strings.Contains(md, wantLimits+"\n") {
			t.Errorf("%s: missing the limits in:\n%s", name, md)
		}
		if strings.Index(md, wantLimits) < strings.Index(md, "### Malware") {
			t.Errorf("%s: the limits belong in the malware section", name)
		}
	}
}

func TestMalwareLimitsInPDFView(t *testing.T) {
	if got := newPDFView(withLimits(malwareDocument(t)), "").MalwareLimits; got != wantLimits {
		t.Errorf("image: got %q", got)
	}
	if got := newPDFView(withLimits(sampleDirectoryDocument(t)), "").MalwareLimits; got != wantLimits {
		t.Errorf("directory: got %q", got)
	}
	if !strings.Contains(string(reportTemplate), "d.malware_limits") {
		t.Error("the PDF template should show the limits")
	}
}

// Results written before the limits were recorded have none; nothing is
// made up for them.
func TestOlderResultsWithoutLimits(t *testing.T) {
	doc := malwareDocument(t)
	if doc.Malware.Limits != nil {
		t.Fatal("the fixture should have no limits")
	}
	if md := Markdown(doc); strings.Contains(md, "Limits:") {
		t.Errorf("unexpected limits in:\n%s", md)
	}
	if got := newPDFView(doc, "").MalwareLimits; got != "" {
		t.Errorf("got %q", got)
	}
}

func TestLimitTime(t *testing.T) {
	cases := map[int64]string{120000: "2 minutes", 60000: "1 minute", 600000: "10 minutes", 148140: "2m28s", 0: "no time limit"}
	for in, want := range cases {
		if got := limitTime(in); got != want {
			t.Errorf("limitTime(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestLimitSize(t *testing.T) {
	cases := map[int64]string{512 << 20: "512 MiB", 4000 << 20: "4,000 MiB", 1 << 20: "1 MiB", 1024: "1.0 KB"}
	for in, want := range cases {
		if got := limitSize(in); got != want {
			t.Errorf("limitSize(%d) = %q, want %q", in, got, want)
		}
	}
}
