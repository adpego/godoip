package uds

import (
	"encoding/binary"
	"fmt"

	"github.com/adpego/godoip/internal/config"
)

const (
	defaultP2Ms     = 50
	defaultP2StarMs = 5000
)

type sessionInfo struct {
	id     uint8
	p2     uint16 // ms
	p2Star uint16 // ms
	access config.Access
}

func defaultSessions() map[uint8]sessionInfo {
	return map[uint8]sessionInfo{
		SessionDefault: {id: SessionDefault, p2: defaultP2Ms, p2Star: defaultP2StarMs},
	}
}

func newSessionInfo(s config.Session) (sessionInfo, error) {
	if s.ID == 0 || s.ID&suppressPosRspBit != 0 {
		return sessionInfo{}, fmt.Errorf("invalid session id 0x%02X", s.ID)
	}
	info := sessionInfo{id: s.ID, p2: defaultP2Ms, p2Star: defaultP2StarMs, access: s.Access}
	if s.P2Ms > 0 {
		info.p2 = uint16(s.P2Ms)
	}
	if s.P2StarMs > 0 {
		info.p2Star = uint16(s.P2StarMs)
	}
	return info, nil
}

func buildSessionControl(e *ECU, cfg config.ECU) (*service, error) {
	c := cfg.Services.DiagnosticSessionControl
	if c == nil {
		return nil, nil
	}

	sessions := c.Sessions
	if len(sessions) == 0 {
		sessions = []config.Session{{ID: SessionDefault}, {ID: SessionProgramming}, {ID: SessionExtended}}
	}
	for _, s := range sessions {
		if _, dup := e.sessions[s.ID]; dup && s.ID != SessionDefault {
			return nil, fmt.Errorf("duplicate session 0x%02X", s.ID)
		}
		info, err := newSessionInfo(s)
		if err != nil {
			return nil, err
		}
		e.sessions[s.ID] = info
	}

	return &service{
		access:         c.Access,
		minLen:         2,
		hasSubFunction: true,
		handle:         handleSessionControl,
	}, nil
}

// handleSessionControl implements DiagnosticSessionControl (0x10).
func handleSessionControl(e *ECU, req request) []byte {
	s, ok := e.sessions[req.subFunction]
	if !ok {
		return negativeResponse(req.sid, NRCSubFunctionNotSupported)
	}
	if nrc := e.checkAccess(s.access, NRCSubFunctionNotSupportedInActiveSession); nrc != 0 {
		return negativeResponse(req.sid, nrc)
	}
	if len(req.data) != 2 {
		return negativeResponse(req.sid, NRCInvalidMessageLengthOrFormat)
	}

	e.changeSession(s.id)

	resp := positiveResponse(req.sid, s.id, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(resp[2:4], s.p2)
	binary.BigEndian.PutUint16(resp[4:6], s.p2Star/10) // P2* is encoded in 10 ms units
	return resp
}

// changeSession switches the active session and resets session-bound state.
func (e *ECU) changeSession(id uint8) {
	e.session = id
	e.security.lock()
}

// checkS3 returns to the default session when the S3 timer has expired.
func (e *ECU) checkS3() {
	if e.session != SessionDefault && e.now().Sub(e.lastActivity) > e.s3Timeout {
		e.changeSession(SessionDefault)
	}
}
