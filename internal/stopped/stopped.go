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
	"os/exec"
	"strconv"
	"time"
)

// Error is a step that stopped because its context ended. It wraps
// context.DeadlineExceeded or context.Canceled.
type Error struct {
	// Phase names the step with its preposition, such as "during the
	// malware scan" or "while making the PDF".
	Phase string
	// Progress says how far it got, such as "41,233 of 95,150 files scanned".
	Progress string
	Err      error
}

func (e *Error) Error() string {
	msg := "stopped"
	if e.Phase != "" {
		msg += " " + e.Phase
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

// Cause returns the stop when ctx has ended and err is a context error that
// is not one yet, for example a store listing cut off by the scan's
// deadline. Anything else passes unchanged: while ctx is live, a timeout
// inside a step (an SDK's credential lookup, an HTTP client's Timeout) is
// that step's own failure, and an error that is not about a context is
// kept even after the deadline.
func Cause(ctx context.Context, err error) error {
	var s *Error
	if err == nil || errors.As(err, &s) || !isContextError(err) {
		return err
	}
	if stop := Check(ctx); stop != nil {
		return stop
	}
	return err
}

// InPhase names the step of a stopped error that has no step yet. Other
// errors pass unchanged: only Check makes a stop.
func InPhase(err error, phase string) error {
	var s *Error
	if errors.As(err, &s) && s.Phase == "" {
		return &Error{Phase: phase, Progress: s.Progress, Err: s.Err}
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

// Killed returns the stop when ctx has ended and err is how a command ends
// when it is stopped: killed by a signal, or not run to completion. A
// command that exited with a status of its own failed by itself, even if
// the deadline passed a moment later.
func Killed(ctx context.Context, err error) error {
	stop := Check(ctx)
	if stop == nil || err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() != -1 {
		return nil
	}
	return stop
}

// Describe says, for people, that what (such as "the scan") stopped at its
// --timeout or was cancelled, where it was and how far it got. ok is false
// when err is not about the context ending.
func Describe(err error, timeout time.Duration, what string) (msg string, ok bool) {
	var s *Error
	if !errors.As(err, &s) {
		return "", false
	}
	where := ""
	if s.Phase != "" {
		where = " " + s.Phase
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

// Plural writes n with thousands separators and the right form of the
// noun: "1 file", "95,150 files".
func Plural(n int, one, many string) string {
	if n == 1 {
		return Count(n) + " " + one
	}
	return Count(n) + " " + many
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
