// Package stopped reports a step that ended because the scan's context
// ended, its deadline (--timeout) passed or it was cancelled, rather than
// because the step itself failed. A child process killed by the deadline
// otherwise looks like a crash ("exited with -1"), and the file a scan was
// at when time ran out looks like the cause.
package stopped

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Error is a step that stopped because its context ended. It wraps
// context.DeadlineExceeded or context.Canceled.
type Error struct {
	// Phase names the step, such as "the malware scan".
	Phase string
	// Progress says how far it got, such as "41,233 of 95,150 files scanned".
	Progress string
	Err      error
}

func (e *Error) Error() string {
	msg := "stopped"
	if e.Phase != "" {
		msg += " during " + e.Phase
	}
	if e.Progress != "" {
		msg += " (" + e.Progress + ")"
	}
	return msg + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

// Check returns an *Error when ctx has ended, nil otherwise. Call it after a
// step failed: if the context ended, that is why the step failed, so report
// it instead of the step's own error. A step that failed while the context
// was still live is reported as itself.
func Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return &Error{Err: err}
	}
	return nil
}

// InPhase names the step of a stopped error that has no step yet, and turns
// a bare context error into one. Other errors pass unchanged.
func InPhase(err error, phase string) error {
	var s *Error
	switch {
	case errors.As(err, &s) && s.Phase == "":
		return &Error{Phase: phase, Progress: s.Progress, Err: s.Err}
	case s == nil && isContextError(err):
		return &Error{Phase: phase, Err: contextError(err)}
	}
	return err
}

// WithProgress records how far a stopped step got, replacing what an inner
// step said: the caller that runs a step knows best how to count it (a
// malware scan counts files scanned, not files read). Other errors pass
// unchanged.
func WithProgress(err error, progress string) error {
	var s *Error
	if errors.As(err, &s) {
		return &Error{Phase: s.Phase, Progress: progress, Err: s.Err}
	}
	return err
}

// Describe says, for people, that what (such as "the scan") stopped at its
// --timeout or was cancelled, where it was and how far it got. ok is false
// when err is not about the context ending.
func Describe(err error, timeout time.Duration, what string) (msg string, ok bool) {
	var s *Error
	if !errors.As(err, &s) {
		if !isContextError(err) {
			return "", false
		}
		s = &Error{Err: contextError(err)}
	}
	where := ""
	if s.Phase != "" {
		where = " during " + s.Phase
	}
	if s.Progress != "" {
		where += " (" + s.Progress + ")"
	}
	if errors.Is(s.Err, context.Canceled) {
		return what + " was cancelled" + where, true
	}
	return fmt.Sprintf("%s stopped at its --timeout of %s%s; raise --timeout", what, timeout, where), true
}

func isContextError(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

func contextError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	return context.DeadlineExceeded
}

// Count writes n with thousands separators: 95150 is "95,150".
func Count(n int) string {
	s := strconv.Itoa(n)
	if n < 0 {
		return "-" + Count(-n)
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
