package uds

import (
	"bytes"
	"testing"
	"time"

	"github.com/adpego/godoip/internal/config"
)

// --- test helpers ---

// fakeClock is a manually advanced time source.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestECU(t *testing.T, cfg config.ECU) (*ECU, *fakeClock) {
	t.Helper()
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	e, err := NewECU(cfg, WithClock(clock.now))
	if err != nil {
		t.Fatalf("NewECU: %v", err)
	}
	return e, clock
}

// send issues a physically addressed request and checks the exact response.
func send(t *testing.T, e *ECU, req []byte, want []byte) {
	t.Helper()
	got := e.Handle(req, false)
	if !bytes.Equal(got, want) {
		t.Fatalf("request % X: got % X, want % X", req, got, want)
	}
}

func nrc(sid, code byte) []byte { return negativeResponse(sid, code) }

func sessionServices() config.Services {
	return config.Services{
		DiagnosticSessionControl: &config.SessionControlService{},
		TesterPresent:            &config.Service{},
	}
}

// --- generic dispatch ---

func TestHandleEmptyRequest(t *testing.T) {
	e, _ := newTestECU(t, config.ECU{})
	if resp := e.Handle(nil, false); resp != nil {
		t.Errorf("got % X, want no response", resp)
	}
}

func TestServiceNotSupported(t *testing.T) {
	e, _ := newTestECU(t, config.ECU{})
	send(t, e, []byte{0x10, 0x01}, nrc(0x10, NRCServiceNotSupported))
	send(t, e, []byte{0xBA}, nrc(0xBA, NRCServiceNotSupported))
}

func TestServiceNotSupportedInActiveSession(t *testing.T) {
	svcs := sessionServices()
	svcs.TesterPresent.Access.Sessions = []uint8{SessionExtended}
	e, _ := newTestECU(t, config.ECU{Services: svcs})

	send(t, e, []byte{0x3E, 0x00}, nrc(0x3E, NRCServiceNotSupportedInActiveSession))
	send(t, e, []byte{0x10, 0x03}, []byte{0x50, 0x03, 0x00, 0x32, 0x01, 0xF4})
	send(t, e, []byte{0x3E, 0x00}, []byte{0x7E, 0x00})
}

func TestServiceSecurityDenied(t *testing.T) {
	svcs := sessionServices()
	svcs.TesterPresent.Access.SecurityLevels = []uint8{0x01}
	e, _ := newTestECU(t, config.ECU{Services: svcs})
	send(t, e, []byte{0x3E, 0x00}, nrc(0x3E, NRCSecurityAccessDenied))

	e.security.unlocked = 0x01
	send(t, e, []byte{0x3E, 0x00}, []byte{0x7E, 0x00})
}

func TestServiceForcedNRC(t *testing.T) {
	svcs := sessionServices()
	svcs.TesterPresent.Access.NRC = NRCConditionsNotCorrect
	e, _ := newTestECU(t, config.ECU{Services: svcs})
	send(t, e, []byte{0x3E, 0x00}, nrc(0x3E, NRCConditionsNotCorrect))
}

func TestServiceMinimumLength(t *testing.T) {
	e, _ := newTestECU(t, config.ECU{Services: sessionServices()})
	send(t, e, []byte{0x10}, nrc(0x10, NRCInvalidMessageLengthOrFormat))
}

func TestSuppressPositiveResponse(t *testing.T) {
	e, _ := newTestECU(t, config.ECU{Services: sessionServices()})
	if resp := e.Handle([]byte{0x3E, 0x80}, false); resp != nil {
		t.Errorf("got % X, want no response", resp)
	}
	// Negative responses are still sent with the suppress bit set.
	send(t, e, []byte{0x3E, 0x81}, nrc(0x3E, NRCSubFunctionNotSupported))
}

func TestFunctionalSuppressesSomeNRCs(t *testing.T) {
	svcs := sessionServices()
	svcs.TesterPresent.Access.NRC = NRCConditionsNotCorrect
	e, _ := newTestECU(t, config.ECU{Services: svcs})

	if resp := e.Handle([]byte{0x22, 0xF1, 0x90}, true); resp != nil {
		t.Errorf("functional 0x11: got % X, want no response", resp)
	}
	if resp := e.Handle([]byte{0x10, 0x7A}, true); resp != nil {
		t.Errorf("functional 0x12: got % X, want no response", resp)
	}
	// Other NRCs are sent on functional requests.
	got := e.Handle([]byte{0x3E, 0x00}, true)
	if !bytes.Equal(got, nrc(0x3E, NRCConditionsNotCorrect)) {
		t.Errorf("functional 0x22: got % X", got)
	}
	// Positive responses too.
	got = e.Handle([]byte{0x10, 0x01}, true)
	if len(got) == 0 || got[0] != 0x50 {
		t.Errorf("functional positive: got % X", got)
	}
}
