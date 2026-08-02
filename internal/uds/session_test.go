package uds

import (
	"testing"
	"time"

	"github.com/adpego/godoip/internal/config"
)

func TestSessionControlDefaultSessions(t *testing.T) {
	e, _ := newTestECU(t, config.ECU{Services: sessionServices()})

	for _, id := range []uint8{SessionDefault, SessionProgramming, SessionExtended} {
		send(t, e, []byte{0x10, id}, []byte{0x50, id, 0x00, 0x32, 0x01, 0xF4})
		if e.Session() != id {
			t.Errorf("active session: got 0x%02X, want 0x%02X", e.Session(), id)
		}
	}
	send(t, e, []byte{0x10, SessionSafetySystem}, nrc(0x10, NRCSubFunctionNotSupported))
}

func TestSessionControlCustomTimings(t *testing.T) {
	svcs := sessionServices()
	svcs.DiagnosticSessionControl.Sessions = []config.Session{
		{ID: SessionExtended, P2Ms: 25, P2StarMs: 2000},
	}
	e, _ := newTestECU(t, config.ECU{Services: svcs})

	send(t, e, []byte{0x10, 0x03}, []byte{0x50, 0x03, 0x00, 0x19, 0x00, 0xC8})
	// Default session is always available even if not listed.
	send(t, e, []byte{0x10, 0x01}, []byte{0x50, 0x01, 0x00, 0x32, 0x01, 0xF4})
	// Programming is not configured.
	send(t, e, []byte{0x10, 0x02}, nrc(0x10, NRCSubFunctionNotSupported))
}

func TestSessionControlTransitionNotAllowed(t *testing.T) {
	svcs := sessionServices()
	svcs.DiagnosticSessionControl.Sessions = []config.Session{
		{ID: SessionProgramming, Access: config.Access{Sessions: []uint8{SessionExtended}}},
		{ID: SessionExtended},
	}
	e, _ := newTestECU(t, config.ECU{Services: svcs})

	send(t, e, []byte{0x10, 0x02}, nrc(0x10, NRCSubFunctionNotSupportedInActiveSession))
	send(t, e, []byte{0x10, 0x03}, []byte{0x50, 0x03, 0x00, 0x32, 0x01, 0xF4})
	send(t, e, []byte{0x10, 0x02}, []byte{0x50, 0x02, 0x00, 0x32, 0x01, 0xF4})
}

func TestSessionControlSecurityRequired(t *testing.T) {
	svcs := sessionServices()
	svcs.DiagnosticSessionControl.Sessions = []config.Session{
		{ID: SessionProgramming, Access: config.Access{SecurityLevels: []uint8{0x01}}},
	}
	e, _ := newTestECU(t, config.ECU{Services: svcs})

	send(t, e, []byte{0x10, 0x02}, nrc(0x10, NRCSecurityAccessDenied))
	e.security.unlocked = 0x01
	send(t, e, []byte{0x10, 0x02}, []byte{0x50, 0x02, 0x00, 0x32, 0x01, 0xF4})
}

func TestSessionControlSessionForcedNRC(t *testing.T) {
	svcs := sessionServices()
	svcs.DiagnosticSessionControl.Sessions = []config.Session{
		{ID: SessionProgramming, Access: config.Access{NRC: NRCConditionsNotCorrect}},
	}
	e, _ := newTestECU(t, config.ECU{Services: svcs})
	send(t, e, []byte{0x10, 0x02}, nrc(0x10, NRCConditionsNotCorrect))
}

func TestSessionControlInvalidLength(t *testing.T) {
	e, _ := newTestECU(t, config.ECU{Services: sessionServices()})
	send(t, e, []byte{0x10, 0x03, 0x00}, nrc(0x10, NRCInvalidMessageLengthOrFormat))
}

func TestSessionChangeLocksSecurity(t *testing.T) {
	e, _ := newTestECU(t, config.ECU{Services: sessionServices()})
	send(t, e, []byte{0x10, 0x03}, []byte{0x50, 0x03, 0x00, 0x32, 0x01, 0xF4})
	e.security.unlocked = 0x01
	send(t, e, []byte{0x10, 0x03}, []byte{0x50, 0x03, 0x00, 0x32, 0x01, 0xF4})
	if e.security.unlocked != 0 {
		t.Errorf("security should be locked after a session change")
	}
}

func TestSessionControlSuppressPositive(t *testing.T) {
	e, _ := newTestECU(t, config.ECU{Services: sessionServices()})
	if resp := e.Handle([]byte{0x10, 0x83}, false); resp != nil {
		t.Errorf("got % X, want no response", resp)
	}
	if e.Session() != SessionExtended {
		t.Errorf("session should change even when the response is suppressed")
	}
}

func TestS3TimeoutReturnsToDefault(t *testing.T) {
	e, clock := newTestECU(t, config.ECU{S3TimeoutMs: 2000, Services: sessionServices()})
	send(t, e, []byte{0x10, 0x03}, []byte{0x50, 0x03, 0x00, 0x32, 0x01, 0xF4})

	clock.advance(1500 * time.Millisecond)
	send(t, e, []byte{0x3E, 0x00}, []byte{0x7E, 0x00}) // keeps the session alive
	clock.advance(1500 * time.Millisecond)
	if e.Session() != SessionExtended {
		t.Fatalf("session should still be extended")
	}

	clock.advance(time.Second)
	if e.Session() != SessionDefault {
		t.Errorf("session should have timed out to default, got 0x%02X", e.Session())
	}
}

func TestDuplicateSessionIsRejected(t *testing.T) {
	svcs := sessionServices()
	svcs.DiagnosticSessionControl.Sessions = []config.Session{{ID: 0x03}, {ID: 0x03}}
	if _, err := NewECU(config.ECU{Services: svcs}); err == nil {
		t.Error("expected error for duplicate session")
	}
}

func TestTesterPresent(t *testing.T) {
	e, _ := newTestECU(t, config.ECU{Services: sessionServices()})
	send(t, e, []byte{0x3E, 0x00}, []byte{0x7E, 0x00})
	send(t, e, []byte{0x3E, 0x01}, nrc(0x3E, NRCSubFunctionNotSupported))
	send(t, e, []byte{0x3E, 0x00, 0x00}, nrc(0x3E, NRCInvalidMessageLengthOrFormat))
	send(t, e, []byte{0x3E}, nrc(0x3E, NRCInvalidMessageLengthOrFormat))
}
