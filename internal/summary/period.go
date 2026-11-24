// Package summary builds the period report an auditor asks for: every scan in
// the period (the population), how much was covered, and whether findings
// were fixed within their deadlines.
package summary

import "time"

// Period is a range of whole UTC days, plus a look-back window used only to
// find out when findings that were already open at the start first appeared.
type Period struct {
	From         time.Time
	To           time.Time
	LookbackDays int
}

// NewPeriod covers from and to inclusive, as UTC calendar days.
func NewPeriod(from, to time.Time, lookbackDays int) Period {
	return Period{From: midnight(from), To: midnight(to), LookbackDays: lookbackDays}
}

func midnight(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// End is the first instant after the period.
func (p Period) End() time.Time { return p.To.AddDate(0, 0, 1) }

// Contains reports whether t falls in the period.
func (p Period) Contains(t time.Time) bool {
	return !t.Before(p.From) && t.Before(p.End())
}

// Days is the number of calendar days in the period.
func (p Period) Days() int {
	return int(p.End().Sub(p.From).Hours() / 24)
}

// LoadFrom is the first day whose scans must be read.
func (p Period) LoadFrom() time.Time {
	return p.From.AddDate(0, 0, -p.LookbackDays)
}

// AsOf is when open findings are judged: the end of the period, or now if
// the summary is made before the period is over.
func (p Period) AsOf(now time.Time) time.Time {
	if now.Before(p.End()) {
		return now
	}
	return p.End()
}

// DaysUntil counts the period's days that have started by t.
func (p Period) DaysUntil(t time.Time) int {
	if !t.After(p.From) {
		return 0
	}
	days := int(t.Sub(p.From).Hours() / 24)
	if p.From.AddDate(0, 0, days).Before(t) {
		days++
	}
	return min(days, p.Days())
}
