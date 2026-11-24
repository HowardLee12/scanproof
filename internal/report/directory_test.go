package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HowardLee12/scanproof/internal/cicontext"
	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/policy"
	"github.com/HowardLee12/scanproof/internal/trivy"
)

const treeDigest = "sha256:3f1c0a5e9d7b2c4e6f8a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e"

// sampleDirectoryDocument is a directory scan with one malware detection.
func sampleDirectoryDocument(t *testing.T) Document {
	t.Helper()
	data, err := os.ReadFile("../../testdata/trivy-alpine-3.18.0.json")
	if err != nil {
		t.Fatal(err)
	}
	res, err := trivy.ParseBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	dir := &model.Directory{Name: "acme-vllm", Version: "0.9.1", TreeDigest: treeDigest, Path: "/mnt/shared/venvs/vllm",
		Files: 1200, Dirs: 300, Symlinks: 4, Bytes: 5_400_000_000}
	res.ArtifactType = model.ArtifactDirectory
	res.Directory = dir
	res.Image = model.Image{Reference: model.DirectoryReference(dir.Name, dir.Version), Digest: treeDigest, OS: "alpine 3.18.0"}
	res.Malware = &model.MalwareScan{
		Engines:      []model.MalwareEngine{{Name: "ClamAV", Version: "1.4.7"}},
		TreeDigest:   treeDigest,
		FilesScanned: 1199, BytesScanned: 5_000_000_000,
		Skipped:    []model.SkippedFile{{Path: "models/big.bin", Bytes: 600 << 20, Reason: "larger than the file size limit"}},
		Detections: []model.MalwareDetection{{Path: "tests/eicar.com", Engine: "ClamAV", Signature: "Eicar-Test-Signature"}},
	}
	pol := policy.Default()
	return Build(Input{
		ReportID: "SR-20261124-ABCDEF", GeneratedAt: testNow, Tool: Tool{Name: "scanproof", Version: "0.2.0"},
		Trigger: TriggerManual, Result: res, Evaluation: policy.Evaluate(res, pol, nil, testNow),
		Policy: pol, PolicySource: policy.BuiltinSource(),
	})
}

func TestBuildMarksTheArtifactType(t *testing.T) {
	if doc := sampleDocument(t); doc.ArtifactType != model.ArtifactContainerImage || doc.IsDirectory() || doc.Directory != nil {
		t.Errorf("an image scan: type %q, directory %v", doc.ArtifactType, doc.Directory)
	}
	doc := sampleDirectoryDocument(t)
	if doc.ArtifactType != model.ArtifactDirectory || !doc.IsDirectory() || doc.Directory.Path != "/mnt/shared/venvs/vllm" {
		t.Fatalf("a directory scan: type %q, directory %+v", doc.ArtifactType, doc.Directory)
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"artifact_type":"directory"`, `"tree_digest":"` + treeDigest + `"`, `"reference":"dir:acme-vllm:0.9.1"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("results.json is missing %s", want)
		}
	}
	if strings.Contains(string(data), `"layer"`) || strings.Contains(string(data), `"config_digest"`) {
		t.Error("image-only malware fields must be left out for a directory")
	}
}

func TestArtifactLabel(t *testing.T) {
	if got := ArtifactLabel(sampleDocument(t)); got != "alpine:3.18.0" {
		t.Errorf("image label = %q", got)
	}
	if got := ArtifactLabel(sampleDirectoryDocument(t)); got != "directory acme-vllm:0.9.1" {
		t.Errorf("directory label = %q", got)
	}
	old := Document{ArtifactType: model.ArtifactDirectory, Image: model.Image{Reference: "dir:acme-vllm"}}
	if got := ArtifactLabel(old); got != "directory acme-vllm" {
		t.Errorf("a directory without details falls back to its reference, got %q", got)
	}
}

func TestMarkdownForADirectory(t *testing.T) {
	md := Markdown(sampleDirectoryDocument(t))
	for _, want := range []string{
		"Directory `acme-vllm:0.9.1`",
		"`/mnt/shared/venvs/vllm`",
		"tree digest `" + treeDigest + "`",
		"Scanned 1199 files (5.00 GB) of the directory",
		"| Engine | Signature | File | Status |",
		"| ClamAV | Eicar-Test-Signature | tests/eicar.com | Violation |",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("summary is missing %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "layer") || strings.Contains(md, "`dir:") {
		t.Errorf("a directory summary must not talk about layers or show the raw reference:\n%s", md)
	}
}

func TestMarkdownCodeSpansCannotBreakOut(t *testing.T) {
	doc := sampleDirectoryDocument(t)
	doc.Directory.Path = "/mnt/x`y|z\nw"
	if md := Markdown(doc); !strings.Contains(md, "`/mnt/x'y\\|z w`") {
		t.Errorf("path not escaped:\n%s", md)
	}
}

func TestPDFViewForADirectory(t *testing.T) {
	v := newPDFView(sampleDirectoryDocument(t), "abc")
	if v.Title != "Directory Scan Report" || v.ArtifactTitle != "Directory" || v.Subject != "directory" || v.LayerColumn {
		t.Errorf("labels = %q %q %q %v", v.Title, v.ArtifactTitle, v.Subject, v.LayerColumn)
	}
	for label, value := range map[string]string{
		"Name": "acme-vllm", "Version": "0.9.1", "Tree digest": treeDigest, "Scanned path": "/mnt/shared/venvs/vllm",
		"Contents": "1200 files · 300 directories · 4 symlinks · 5.40 GB", "Operating system": "alpine 3.18.0",
	} {
		if !hasRow(v.ArtifactRows, label, value) {
			t.Errorf("artifact rows are missing %s = %s: %+v", label, value, v.ArtifactRows)
		}
	}
	if len(v.MalwareFindings) != 1 || len(v.MalwareFindings[0]) != 4 || v.MalwareFindings[0][2] != "tests/eicar.com" {
		t.Errorf("malware rows = %v", v.MalwareFindings)
	}
	if len(v.MalwareSkipped) != 1 || len(v.MalwareSkipped[0]) != 3 {
		t.Errorf("skipped rows = %v", v.MalwareSkipped)
	}
	if !strings.Contains(v.MalwareStats, "of the directory") || strings.Contains(v.MalwareStats, "layer") {
		t.Errorf("stats = %q", v.MalwareStats)
	}
	if !strings.Contains(v.CC68Text, "directory") || strings.Contains(v.CC68Text, "layer") {
		t.Errorf("CC6.8 = %q", v.CC68Text)
	}
	if !strings.Contains(v.SecretsNone, "secret scanner reads") || strings.Contains(v.SecretsNone, "Coverage") {
		t.Errorf("secrets text = %q", v.SecretsNone)
	}
}

func TestPDFViewForAnImageKeepsImageLabels(t *testing.T) {
	v := newPDFView(sampleDocument(t), "")
	if v.Title != "Container Image Scan Report" || v.ArtifactTitle != "Image" || v.Subject != "image" || !v.LayerColumn {
		t.Errorf("labels = %q %q %q %v", v.Title, v.ArtifactTitle, v.Subject, v.LayerColumn)
	}
}

func TestPDFViewForADirectoryRescan(t *testing.T) {
	doc := sampleDirectoryDocument(t)
	doc.Context = cicontext.Context{}
	doc.Directory = &model.Directory{Name: "acme-vllm", Version: "0.9.1", TreeDigest: treeDigest}
	doc.Runtime = &Runtime{Locations: []string{"gpu/inference/vllm"}, Method: MethodSBOM, SBOMFrom: "SR-20261101-AAAAAA"}
	v := newPDFView(doc, "")
	if v.ContextTitle != "Deployed directory" || !hasRow(v.ContextRows, "Trigger", "Rescan of a deployed directory") {
		t.Errorf("context = %q %+v", v.ContextTitle, v.ContextRows)
	}
	if !strings.Contains(v.SecretsNote, "when the directory was first scanned") {
		t.Errorf("secrets note = %q", v.SecretsNote)
	}
	if hasLabel(v.ArtifactRows, "Scanned path") || hasLabel(v.ArtifactRows, "Contents") {
		t.Errorf("a rescan has no path or contents of its own: %+v", v.ArtifactRows)
	}
}

func hasLabel(rows []pdfRow, label string) bool {
	for _, r := range rows {
		if r.Label == label {
			return true
		}
	}
	return false
}

func TestManifestRecordsTheArtifactType(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "results.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := BuildManifest(dir, sampleDirectoryDocument(t), []string{"results.json"})
	if err != nil {
		t.Fatal(err)
	}
	if m.ArtifactType != model.ArtifactDirectory || m.ImageDigest != treeDigest {
		t.Errorf("manifest = %+v", m)
	}
	if m, _ := BuildManifest(dir, sampleDocument(t), []string{"results.json"}); m.ArtifactType != model.ArtifactContainerImage {
		t.Errorf("image manifest type = %q", m.ArtifactType)
	}
}

func TestSkippedRowsKeepTheirColumnCount(t *testing.T) {
	for _, directory := range []bool{true, false} {
		m := &MalwareSection{}
		for i := 0; i < maxSkippedRows+5; i++ {
			m.Skipped = append(m.Skipped, model.SkippedFile{Path: "f", Layer: 1, Bytes: 1, Reason: "r"})
		}
		rows := malwareSkipped(m, directory)
		want := 4
		if directory {
			want = 3
		}
		for _, r := range rows {
			if len(r) != want {
				t.Fatalf("directory=%v: a row has %d cells, the table has %d columns: %v", directory, len(r), want, r)
			}
		}
		if last := rows[len(rows)-1][0]; last != "5 more in results.json" {
			t.Errorf("last row = %q", last)
		}
	}
}

func withCoverage(doc Document) Document {
	doc.Directory.Coverage = &model.Coverage{
		NotScanned: model.UncheckedPaths{Files: 3, Paths: []model.UncheckedPath{
			{Path: "src/pkg/.git", Files: 2, Reason: "Trivy skips .git"},
			{Path: "dev", Files: 1, Reason: "Trivy skips dev, proc and sys at the top of the directory"},
		}},
		SecretsNotChecked: model.UncheckedPaths{Files: 120, ByReason: map[string]int{"binary file": 100, "file type .bin": 20},
			Paths: []model.UncheckedPath{{Path: "lib/libx.so", Files: 1, Reason: "binary file"}}, Omitted: 119},
	}
	return doc
}

func TestMarkdownListsWhatWasNotChecked(t *testing.T) {
	md := Markdown(withCoverage(sampleDirectoryDocument(t)))
	for _, want := range []string{
		"### Not checked",
		"3 files were not checked for vulnerabilities or secrets",
		"`src/pkg/.git` (2 files, Trivy skips .git)",
		"120 files were not checked for secrets: binary file 100, file type .bin 20",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("summary is missing %q:\n%s", want, md)
		}
	}
	if strings.Contains(Markdown(sampleDirectoryDocument(t)), "### Not checked") {
		t.Error("nothing to say when every file was checked")
	}
}

func TestPDFViewListsWhatWasNotChecked(t *testing.T) {
	v := newPDFView(withCoverage(sampleDirectoryDocument(t)), "")
	if !hasRow(v.ArtifactRows, "Not checked", "3 files not checked for vulnerabilities or secrets · 120 files not checked for secrets (see Coverage)") {
		t.Errorf("artifact rows = %+v", v.ArtifactRows)
	}
	if len(v.NotScanned) != 2 || v.NotScanned[0][0] != "src/pkg/.git" || v.NotScanned[0][1] != "2" {
		t.Errorf("not scanned rows = %v", v.NotScanned)
	}
	if !strings.Contains(v.SecretsSkippedNote, "120 files") || !strings.Contains(v.SecretsSkippedNote, "binary file 100") {
		t.Errorf("secrets note = %q", v.SecretsSkippedNote)
	}
	if len(v.SecretsSkipped) != 2 || v.SecretsSkipped[1][0] != "119 more in results.json" {
		t.Errorf("secrets skipped rows = %v", v.SecretsSkipped)
	}
	if !strings.Contains(v.SecretsNone, "files Trivy's secret scanner reads") {
		t.Errorf("the none-found note must not claim every file was read: %q", v.SecretsNone)
	}
	if image := newPDFView(sampleDocument(t), ""); !strings.Contains(image.SecretsNone, "binary files") {
		t.Errorf("image note = %q", image.SecretsNone)
	}
}

func TestImageSecretNotesNameTrivysAllowRules(t *testing.T) {
	doc := sampleDocument(t)
	for name, text := range map[string]string{"pdf": newPDFView(doc, "").SecretsNone, "markdown": Markdown(doc)} {
		for _, want := range []string{"test", "example", "Markdown", "locale", "vendor", "usr/share", "usr/local/go",
			"opt/yarn-v", ".git", "node_modules", "lock files", "binary"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s: the image secret note must say Trivy skips %q:\n%s", name, want, text)
			}
		}
	}
	if md := Markdown(sampleDirectoryDocument(t)); strings.Contains(md, "allow rules apply") {
		t.Error("directory scans switch the allow rules off")
	}
}
