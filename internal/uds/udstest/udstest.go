// Package udstest provides helpers to test UDS services.
package udstest

import (
	"bytes"
	"testing"
	"time"

	"github.com/adpego/godoip/internal/uds"
)

// Clock is a manually advanced time source.
type Clock struct{ T time.Time }

// NewClock returns a clock set to a fixed arbitrary instant.
func NewClock() *Clock { return &Clock{T: time.Unix(1_700_000_000, 0)} }

func (c *Clock) Now() time.Time          { return c.T }
func (c *Clock) Advance(d time.Duration) { c.T = c.T.Add(d) }
func (c *Clock) Option() uds.Option      { return uds.WithClock(c.Now) }

// Send issues a physically addressed request and checks the exact response
// (nil means no response).
func Send(t testing.TB, e *uds.ECU, req []byte, want []byte) {
	t.Helper()
	got := e.Handle(req, false)
	if !bytes.Equal(got, want) {
		t.Fatalf("request % X: got % X, want % X", req, got, want)
	}
}

// NRC builds a negative response.
func NRC(sid, code byte) []byte { return uds.NegativeResponse(sid, code) }

// SetSession forces the active session, bypassing DiagnosticSessionControl.
func SetSession(e *uds.ECU, id uint8) {
	e.Do(func(c *uds.Context) { c.SetSession(id) })
}

// Unlock forces a security level, bypassing SecurityAccess.
func Unlock(e *uds.ECU, level uint8) {
	e.Do(func(c *uds.Context) { c.SetSecurityLevel(level) })
}

// New returns an empty ECU driven by a manual clock.
func New(t testing.TB, opts ...uds.Option) (*uds.ECU, *Clock) {
	t.Helper()
	clock := NewClock()
	return uds.New(append([]uds.Option{clock.Option()}, opts...)...), clock
}

// Must fails the test on error.
func Must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
