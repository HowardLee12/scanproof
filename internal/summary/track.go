package summary

import (
	"sort"
	"strings"
	"time"

	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/policy"
)

// TrackedFinding follows one vulnerability in one image from the first scan
// that reported it to the first later scan of that image without it.
type TrackedFinding struct {
	Image     string         `json:"image"`
	ID        string         `json:"id"`
	Package   string         `json:"package"`
	Severity  model.Severity `json:"severity"`
	FirstSeen time.Time      `json:"first_seen"`
	FixedAt   *time.Time     `json:"fixed_at,omitempty"`
	Due       time.Time      `json:"due"`
}

// DaysOpen is the time from first seen to the fix, or to end if not fixed.
func (f TrackedFinding) DaysOpen(end time.Time) float64 {
	stop := end
	if f.FixedAt != nil {
		stop = *f.FixedAt
	}
	return stop.Sub(f.FirstSeen).Hours() / 24
}

// imageName drops the tag and digest, so builds of the same image are
// compared with each other.
func imageName(ref string) string {
	name, _, _ := strings.Cut(ref, "@")
	slash := strings.LastIndex(name, "/")
	if colon := strings.LastIndex(name, ":"); colon > slash {
		name = name[:colon]
	}
	return name
}

// track follows every finding that has a deadline: it has a fix available,
// no exception accepts it, and its severity has an SLA. Scans must be sorted
// oldest first. Scans of the same image name are compared in time order, so
// if two versions of one image run at the same time a finding can appear to
// close and reopen.
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

func trackImage(name string, scans []Loaded, pol policy.Policy) []TrackedFinding {
	done := make([]TrackedFinding, 0)
	open := map[string]TrackedFinding{}
	for _, s := range scans {
		at := s.GeneratedAt
		present := map[string]bool{}
		for _, f := range s.Vulnerabilities {
			sla := pol.SLA(f.Severity)
			if !f.Fixable() || f.Accepted() || sla == 0 {
				continue
			}
			key := f.ID + "|" + f.Package
			present[key] = true
			if _, ok := open[key]; !ok {
				open[key] = TrackedFinding{
					Image: name, ID: f.ID, Package: f.Package, Severity: f.Severity,
					FirstSeen: at, Due: at.AddDate(0, 0, sla),
				}
			}
		}
		for key, f := range open {
			if !present[key] {
				fixed := at
				f.FixedAt = &fixed
				done = append(done, f)
				delete(open, key)
			}
		}
	}
	for _, f := range open {
		done = append(done, f)
	}
	sort.Slice(done, func(i, j int) bool {
		if !done[i].FirstSeen.Equal(done[j].FirstSeen) {
			return done[i].FirstSeen.Before(done[j].FirstSeen)
		}
		return done[i].ID+done[i].Package < done[j].ID+done[j].Package
	})
	return done
}
