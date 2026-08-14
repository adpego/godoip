package uds

import (
	"fmt"

	"github.com/adpego/godoip/internal/config"
)

// ECUReset sub-functions (ISO 14229-1).
const (
	ResetHard                      uint8 = 0x01
	ResetKeyOffOn                  uint8 = 0x02
	ResetSoft                      uint8 = 0x03
	ResetEnableRapidPowerShutDown  uint8 = 0x04
	ResetDisableRapidPowerShutDown uint8 = 0x05
)

func buildECUReset(e *ECU, cfg config.ECU) (*service, error) {
	c := cfg.Services.ECUReset
	if c == nil {
		return nil, nil
	}

	types := c.ResetTypes
	if len(types) == 0 {
		types = []config.ResetType{{ID: ResetHard}, {ID: ResetKeyOffOn}, {ID: ResetSoft}}
	}
	e.resetTypes = make(map[uint8]config.ResetType, len(types))
	for _, rt := range types {
		if rt.ID == 0 || rt.ID&suppressPosRspBit != 0 {
			return nil, fmt.Errorf("invalid reset type 0x%02X", rt.ID)
		}
		if _, dup := e.resetTypes[rt.ID]; dup {
			return nil, fmt.Errorf("duplicate reset type 0x%02X", rt.ID)
		}
		e.resetTypes[rt.ID] = rt
	}

	return &service{
		access:         c.Access,
		minLen:         2,
		hasSubFunction: true,
		handle:         handleECUReset,
	}, nil
}

// handleECUReset implements ECUReset (0x11).
func handleECUReset(e *ECU, req request) []byte {
	rt, ok := e.resetTypes[req.subFunction]
	if !ok {
		return negativeResponse(req.sid, NRCSubFunctionNotSupported)
	}
	if nrc := e.checkAccess(rt.Access, NRCSubFunctionNotSupportedInActiveSession); nrc != 0 {
		return negativeResponse(req.sid, nrc)
	}
	if len(req.data) != 2 {
		return negativeResponse(req.sid, NRCInvalidMessageLengthOrFormat)
	}

	resp := positiveResponse(req.sid, rt.ID)
	switch rt.ID {
	case ResetEnableRapidPowerShutDown:
		resp = append(resp, rt.PowerDownTime)
	case ResetDisableRapidPowerShutDown:
		// Only changes the power-down behaviour, no actual reset.
	default:
		e.reset()
	}
	return resp
}

// reset simulates an ECU restart: the ECU goes back to the default session,
// security is relocked and volatile data is restored. Security attempt
// counters and lockout delays survive the reset.
func (e *ECU) reset() {
	e.changeSession(SessionDefault)
	e.restoreVolatileDIDs()
}
