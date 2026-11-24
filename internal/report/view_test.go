package report

import (
	"strings"
	"testing"

	"github.com/HowardLee12/scanproof/internal/cicontext"
	"github.com/HowardLee12/scanproof/internal/policy"
)

func TestPDFViewHeadlineAndRows(t *testing.T) {
	v := newPDFView(sampleDocument(t), "abc123")

	if v.Verdict != "WARN" || !strings.HasPrefix(v.Headline, "2 policy violations") {
		t.Errorf("headline = %q (%s)", v.Headline, v.Verdict)
	}
	if !strings.Contains(v.Detail, "1 approved exception applied") || !strings.Contains(v.Detail, "Trivy 0.76.2") {
		t.Errorf("detail = %q", v.Detail)
	}
	if v.DigestShort != "sha256:02bb6f428431…" {
		t.Errorf("short digest = %q", v.DigestShort)
	}
	if !hasRow(v.ArtifactRows, "Digest", "sha256:02bb6f428431fbc2809c5d1b41eab5a68350194fb508869a33cb1af4444c9b11") {
		t.Errorf("image rows = %+v", v.ArtifactRows)
	}
	if !hasRow(v.ContextRows, "Repository", "example-org/example-api") {
		t.Errorf("context rows = %+v", v.ContextRows)
	}
	if !hasRow(v.IntegrityRows, "results.json SHA-256", "abc123") {
		t.Errorf("integrity rows = %+v", v.IntegrityRows)
	}
	if len(v.Tiles) != 6 || v.Tiles[0].Label != "Critical" || v.Tiles[0].Value != "3" {
		t.Errorf("tiles = %+v", v.Tiles)
	}
}

func TestPDFViewListsCriticalAndHighOnly(t *testing.T) {
	v := newPDFView(sampleDocument(t), "")
	if len(v.Vulns) != 9 {
		t.Fatalf("got %d rows, want 3 Critical + 6 High", len(v.Vulns))
	}
	kinds := map[string]int{}
	for _, row := range v.Vulns {
		kinds[row.StatusKind]++
	}
	if kinds["violation"] != 2 || kinds["accepted"] != 1 {
		t.Errorf("status kinds = %v", kinds)
	}
	if len(v.LowerByPackage) == 0 || v.LowerByPackage[0][0] == "" {
		t.Errorf("medium/low summary missing: %+v", v.LowerByPackage)
	}
}

func TestPDFViewOutsideCI(t *testing.T) {
	doc := sampleDocument(t)
	doc.Context = cicontext.Context{}
	doc.Verdict = policy.VerdictPass
	doc.Summary.Violations = 0
	v := newPDFView(doc, "")
	if !hasRow(v.ContextRows, "Run", "Not run in a recognised CI system") {
		t.Errorf("context rows = %+v", v.ContextRows)
	}
	if !strings.HasPrefix(v.Headline, "All 2 policy rules passed") {
		t.Errorf("headline = %q", v.Headline)
	}
}

func TestPDFViewFailHeadline(t *testing.T) {
	doc := sampleDocument(t)
	doc.Verdict = policy.VerdictFail
	if v := newPDFView(doc, ""); !strings.Contains(v.Headline, "stops the pipeline") {
		t.Errorf("headline = %q", v.Headline)
	}
}

func hasRow(rows []pdfRow, label, value string) bool {
	for _, r := range rows {
		if r.Label == label && r.Value == value {
			return true
		}
	}
	return false
}

func TestPDFViewForRescan(t *testing.T) {
	doc := sampleDocument(t)
	doc.Context = cicontext.Context{}
	doc.Runtime = &Runtime{Locations: []string{"k8s gpu/a", "k8s gpu/b", "k8s gpu/c", "k8s gpu/d", "k8s gpu/e", "k8s gpu/f"},
		Method: MethodSBOM, SBOMFrom: "SR-20261101-AAAAAA"}
	doc.Image.SizeBytes = 0
	v := newPDFView(doc, "")
	if v.ContextTitle != "Running image" || !hasRow(v.ArtifactRows, "Size", "1 layer") {
		t.Errorf("title %q, image rows %+v", v.ContextTitle, v.ArtifactRows)
	}
	if !hasRow(v.ContextRows, "Running in", "k8s gpu/a, k8s gpu/b, k8s gpu/c, k8s gpu/d, k8s gpu/e and 1 more") {
		t.Errorf("context rows = %+v", v.ContextRows)
	}
	if !strings.Contains(v.SecretsNote, "stored SBOM") {
		t.Errorf("secrets note = %q", v.SecretsNote)
	}
	if !strings.Contains(Markdown(doc), "rescan of the stored SBOM SR-20261101-AAAAAA") {
		t.Error("the job summary should say the SBOM was rescanned")
	}
	doc.Runtime.Method = MethodImage
	if v := newPDFView(doc, ""); !hasRow(v.ContextRows, "Method", "Pulled and scanned the running image") || v.SecretsNote != "" {
		t.Errorf("image rescan rows = %+v, note %q", v.ContextRows, v.SecretsNote)
	}
}
