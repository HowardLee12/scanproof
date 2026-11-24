package summary

import (
	"strings"
	"testing"

	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/policy"
	"github.com/HowardLee12/scanproof/internal/report"
)

func dirDoc(id, ref, digest string, n int, trigger string, vulns ...policy.VulnerabilityFinding) report.Document {
	d := scanDoc(id, ref, digest, day(n), trigger, policy.VerdictWarn, vulns...)
	d.ArtifactType = model.ArtifactDirectory
	return d
}

func TestDirectoriesAreTrackedByNameApartFromImages(t *testing.T) {
	crit := finding("CVE-V", "urllib3", model.SeverityCritical, "1.26.5")
	scans := loaded(
		dirDoc("SR-D1", "dir:acme-vllm:0.9.1", "sha256:t1", 1, report.TriggerCI, crit),
		// An image with the same name must not close the directory's finding.
		scanDoc("SR-I1", "acme-vllm:2", "sha256:i1", day(2), report.TriggerCI, policy.VerdictPass),
		dirDoc("SR-D2", "dir:acme-vllm:0.9.1", "sha256:t1", 3, report.TriggerRescan, crit),
		// The next version, scanned without a version, fixes it.
		dirDoc("SR-D3", "dir:acme-vllm", "sha256:t2", 6, report.TriggerRescan),
	)
	tracked := track(scans, policy.Default())
	if len(tracked) != 1 || tracked[0].Image != "dir:acme-vllm" || !tracked[0].Fixed() || !tracked[0].ClosedAt.Equal(day(6)) {
		t.Fatalf("tracked = %+v", tracked)
	}
}

func TestCoverageCountsDirectoriesSeparately(t *testing.T) {
	scans := loaded(
		dirDoc("SR-D1", "dir:acme-vllm:0.9.1", "sha256:t1", 1, report.TriggerCI),
		dirDoc("SR-D2", "dir:acme-vllm:0.9.1", "sha256:t1", 2, report.TriggerRescan),
		dirDoc("SR-D3", "dir:example-worker:1", "sha256:t3", 2, report.TriggerRescan),
		scanDoc("SR-I1", "repo/api:1", "sha256:a1", day(2), report.TriggerCI, policy.VerdictPass),
	)
	s := Build(Input{GeneratedAt: periodTo.AddDate(0, 0, 2), Period: testPeriod(), Policy: policy.Default(), Scans: scans})
	if c := s.Coverage; c.Images != 1 || c.Repositories != 1 || c.Directories != 2 || c.Scans != 4 {
		t.Fatalf("coverage = %+v", c)
	}
	if md := Markdown(s); !strings.Contains(md, "of 1 images in 1 repositories and 2 directories") {
		t.Errorf("markdown = %s", md)
	}
	v := newPDFView(s, nil)
	if !strings.Contains(v.Tiles[1].Hint, "2 directories") {
		t.Errorf("tile = %+v", v.Tiles[1])
	}
	csv, err := PopulationCSV(s.Population)
	if err != nil {
		t.Fatal(err)
	}
	text := string(csv)
	if !strings.Contains(text, ",rescan,directory,dir:example-worker:1,sha256:t3,") || !strings.Contains(text, ",ci,container_image,repo/api:1,") {
		t.Errorf("population.csv must name the artifact type:\n%s", text)
	}
}

func TestOldScansWithoutATypeAreImages(t *testing.T) {
	s := Build(Input{GeneratedAt: periodTo, Period: testPeriod(), Policy: policy.Default(),
		Scans: loaded(scanDoc("SR-1", "dir:5000/app:1", "sha256:x", day(1), report.TriggerCI, policy.VerdictPass))})
	if s.Population[0].ArtifactType != model.ArtifactContainerImage || s.Coverage.Directories != 0 {
		t.Fatalf("a scan without artifact_type is an image (registry dir:5000): %+v %+v", s.Population[0], s.Coverage)
	}
}
