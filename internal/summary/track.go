package summary

import (
	"sort"
	"time"

	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/policy"
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
		name := imageName(s.Image.Reference)
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
	statuses map[string]status
	seen     map[string]trackedInfo
}

type trackedInfo struct {
	id, pkg  string
	severity model.Severity
	at       time.Time
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
		for _, f := range s.Vulnerabilities {
			if pol.SLA(f.Severity) == 0 {
				continue
			}
			key := f.ID + "|" + f.Package
			st := statusNoFix
			switch {
			case f.Accepted():
				st = statusAccepted
			case f.Fixable():
				st = statusOpen
			}
			if st > d.statuses[key] {
				d.statuses[key] = st
			}
			if _, ok := d.seen[key]; !ok && st == statusOpen {
				d.seen[key] = trackedInfo{id: f.ID, pkg: f.Package, severity: f.Severity, at: s.GeneratedAt}
			}
		}
	}
	return days
}

func trackImage(name string, scans []Loaded, pol policy.Policy) []TrackedFinding {
	all := []*TrackedFinding{}
	open := map[string]*TrackedFinding{}
	lastClosed := map[string]*TrackedFinding{}

	for _, d := range groupByDay(scans, pol) {
		for key, st := range d.statuses {
			if st != statusOpen {
				continue
			}
			info := d.seen[key]
			switch {
			case open[key] != nil:
				open[key].LastSeen = info.at
			case lastClosed[key] != nil:
				f := lastClosed[key]
				f.ClosedAt, f.Resolution, f.LastSeen = nil, "", info.at
				open[key] = f
				delete(lastClosed, key)
			default:
				f := &TrackedFinding{
					Image: name, ID: info.id, Package: info.pkg, Severity: info.severity,
					FirstSeen: info.at, LastSeen: info.at, Due: info.at.AddDate(0, 0, pol.SLA(info.severity)),
				}
				open[key] = f
				all = append(all, f)
			}
		}
		for key, f := range open {
			st := d.statuses[key]
			if st == statusOpen {
				continue
			}
			closed := d.at
			f.ClosedAt = &closed
			f.Resolution = map[status]string{
				statusAbsent: ResolutionFixed, statusAccepted: ResolutionAccepted, statusNoFix: ResolutionNoFix,
			}[st]
			lastClosed[key] = f
			delete(open, key)
		}
	}

	out := make([]TrackedFinding, 0, len(all))
	for _, f := range all {
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
