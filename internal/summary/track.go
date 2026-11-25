package summary

import (
	"sort"
	"time"

	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/policy"
	"github.com/HowardLee12/scanproof/internal/report"
)

// How a tracked finding stopped being open.
const (
	ResolutionFixed    = "fixed"
	ResolutionAccepted = "accepted"
	ResolutionNoFix    = "no_longer_fixable"
)

// TrackedFinding follows one vulnerability in one image name over time.
type TrackedFinding struct {
	Image      string         `json:"image"`
	ID         string         `json:"id"`
	Package    string         `json:"package"`
	Severity   model.Severity `json:"severity"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	Due        time.Time      `json:"due"`
	ClosedAt   *time.Time     `json:"closed_at,omitempty"`
	Resolution string         `json:"resolution,omitempty"`

	// The fields below go to findings.csv, not summary.json.

	// ArtifactType is container_image or directory.
	ArtifactType string `json:"-"`
	// FirstSeenReport is the scan that first reported the finding.
	FirstSeenReport string `json:"-"`
	// LastSeenReport is the latest scan that reported it as open. LastSeen
	// is the first such scan on that day, so with several scans that day
	// the two point at different scans.
	LastSeenReport string `json:"-"`
	// ClosedBy lists every scan of the day it was closed. None of them
	// reported it as open: they no longer reported it, or reported it as
	// accepted or without a fix. It is empty while the finding is open.
	ClosedBy []string `json:"-"`
	// Reopened counts how often it came back after being closed.
	Reopened int `json:"-"`
}

// Fixed reports whether the finding was closed because it went away.
func (f TrackedFinding) Fixed() bool { return f.Resolution == ResolutionFixed }

// DaysOpen is the time from first seen to closing, or to asOf if still open.
func (f TrackedFinding) DaysOpen(asOf time.Time) float64 {
	stop := asOf
	if f.ClosedAt != nil {
		stop = *f.ClosedAt
	}
	return stop.Sub(f.FirstSeen).Hours() / 24
}

// imageName drops the tag and digest, so builds of the same image are
// compared with each other.
func imageName(ref string) string {
	return model.ImageName(ref)
}

// artifactName is what findings are tracked by: the image name, or
// dir:NAME for a directory, so every version of a directory is compared
// with the others and never with an image of the same name.
func artifactName(doc report.Document) string {
	return model.ArtifactName(doc.ArtifactType, doc.Image.Reference, doc.Directory)
}

// status of one finding in one day's scans of an image name.
type status int

const (
	statusAbsent status = iota
	statusNoFix
	statusAccepted
	statusOpen
)

// track follows every finding that has a deadline (a fix exists, no
// exception accepts it, and its severity has an SLA).
//
// Scans of one image name are combined per UTC day: a finding stays open
// while any scan that day still reports it, so an image that runs in two
// places (say prod with the finding and staging without it) does not look
// fixed. A finding that comes back after being closed is reopened with its
// original first-seen date and deadline, so it cannot reset its SLA clock.
// Findings later accepted by an exception, or whose fix disappears from the
// vulnerability data, are closed with that reason and never count as fixed.
func track(scans []Loaded, pol policy.Policy) []TrackedFinding {
	byImage := map[string][]Loaded{}
	names := []string{}
	for _, s := range scans {
		name := artifactName(s.Document)
		if _, ok := byImage[name]; !ok {
			names = append(names, name)
		}
		byImage[name] = append(byImage[name], s)
	}
	sort.Strings(names)

	out := make([]TrackedFinding, 0)
	for _, name := range names {
		out = append(out, trackImage(name, byImage[name], pol)...)
	}
	return out
}

type dayScan struct {
	at       time.Time // first scan of the day
	reports  []string  // report IDs of every scan of the day, oldest first
	statuses map[string]status
	seen     map[string]trackedInfo
}

// trackedInfo describes a finding that the day's scans report as open.
type trackedInfo struct {
	id, pkg     string
	severity    model.Severity
	at          time.Time // first scan of the day that reported it
	firstReport string    // that scan's report ID
	lastReport  string    // the last scan of the day that reported it
}

// groupByDay merges one image name's scans (oldest first) into days.
func groupByDay(scans []Loaded, pol policy.Policy) []dayScan {
	days := []dayScan{}
	for _, s := range scans {
		day := s.GeneratedAt.UTC().Format("2006-01-02")
		if len(days) == 0 || days[len(days)-1].at.UTC().Format("2006-01-02") != day {
			days = append(days, dayScan{at: s.GeneratedAt, statuses: map[string]status{}, seen: map[string]trackedInfo{}})
		}
		d := &days[len(days)-1]
		d.reports = append(d.reports, s.ReportID)
		for _, f := range s.Vulnerabilities {
			d.add(s.ReportID, s.GeneratedAt, f, pol)
		}
	}
	return days
}

// add records one finding of one scan. The day keeps the strongest status
// any of its scans gave the finding, so it stays open while one still has it.
func (d *dayScan) add(reportID string, at time.Time, f policy.VulnerabilityFinding, pol policy.Policy) {
	if pol.SLA(f.Severity) == 0 {
		return
	}
	key := f.ID + "|" + f.Package
	st := scanStatus(f)
	if st > d.statuses[key] {
		d.statuses[key] = st
	}
	if st != statusOpen {
		return
	}
	info, ok := d.seen[key]
	if !ok {
		info = trackedInfo{id: f.ID, pkg: f.Package, severity: f.Severity, at: at, firstReport: reportID}
	}
	info.lastReport = reportID
	d.seen[key] = info
}

// resolution says why a finding closed, from its status on the closing day.
func resolution(st status) string {
	switch st {
	case statusAccepted:
		return ResolutionAccepted
	case statusNoFix:
		return ResolutionNoFix
	default:
		return ResolutionFixed
	}
}

func scanStatus(f policy.VulnerabilityFinding) status {
	switch {
	case f.Accepted():
		return statusAccepted
	case f.Fixable():
		return statusOpen
	default:
		return statusNoFix
	}
}

// tracker follows the findings of one image name from day to day.
type tracker struct {
	name, artifactType string
	pol                policy.Policy
	all                []*TrackedFinding
	open               map[string]*TrackedFinding
	lastClosed         map[string]*TrackedFinding
}

func trackImage(name string, scans []Loaded, pol policy.Policy) []TrackedFinding {
	t := &tracker{
		name: name, artifactType: artifactTypeOf(scans[0].Document), pol: pol,
		open: map[string]*TrackedFinding{}, lastClosed: map[string]*TrackedFinding{},
	}
	for _, d := range groupByDay(scans, pol) {
		t.recordSightings(d)
		t.closeMissing(d)
	}
	return t.findings()
}

// recordSightings opens, reopens or extends every finding the day's scans
// report as open.
func (t *tracker) recordSightings(d dayScan) {
	for key, st := range d.statuses {
		if st != statusOpen {
			continue
		}
		info := d.seen[key]
		f := t.open[key]
		if f == nil {
			f = t.openFinding(key, info)
		}
		f.LastSeen, f.LastSeenReport = info.at, info.lastReport
	}
}

// openFinding reopens a closed finding, keeping its first-seen date and
// deadline, or starts tracking a new one.
func (t *tracker) openFinding(key string, info trackedInfo) *TrackedFinding {
	f := t.lastClosed[key]
	if f != nil {
		f.ClosedAt, f.Resolution, f.ClosedBy = nil, "", nil
		f.Reopened++
		delete(t.lastClosed, key)
	} else {
		f = &TrackedFinding{
			Image: t.name, ID: info.id, Package: info.pkg, Severity: info.severity,
			FirstSeen: info.at, Due: info.at.AddDate(0, 0, t.pol.SLA(info.severity)),
			ArtifactType: t.artifactType, FirstSeenReport: info.firstReport,
		}
		t.all = append(t.all, f)
	}
	t.open[key] = f
	return f
}

// closeMissing closes every open finding that no scan of the day reports as
// open, citing all of the day's scans.
func (t *tracker) closeMissing(d dayScan) {
	for key, f := range t.open {
		st := d.statuses[key]
		if st == statusOpen {
			continue
		}
		closed := d.at
		f.ClosedAt, f.Resolution = &closed, resolution(st)
		f.ClosedBy = append([]string{}, d.reports...)
		t.lastClosed[key] = f
		delete(t.open, key)
	}
}

// findings returns copies of the tracked findings, oldest first.
func (t *tracker) findings() []TrackedFinding {
	out := make([]TrackedFinding, 0, len(t.all))
	for _, f := range t.all {
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].FirstSeen.Equal(out[j].FirstSeen) {
			return out[i].FirstSeen.Before(out[j].FirstSeen)
		}
		return out[i].ID+out[i].Package < out[j].ID+out[j].Package
	})
	return out
}
