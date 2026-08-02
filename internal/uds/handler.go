package uds

import (
	"encoding/binary"

	"github.com/adpego/godoip/internal/config"
)

// SID constants
const (
	SIDDiagnosticSessionControl = 0x10
	SIDReadDataByIdentifier     = 0x22
)

func HandleRequest(ecus []config.ECU, targetAddr uint16, data []byte) []byte {
	if len(data) == 0 {
		return negativeResponse(0x00, NRCServiceNotSupported)
	}

	sid := data[0]
	params := data[1:]

	ecu := findECU(ecus, targetAddr)
	if ecu == nil {
		return negativeResponse(sid, NRCServiceNotSupported)
	}

	switch sid {
	case SIDReadDataByIdentifier:
		return handleReadDID(ecu, params)
	case SIDDiagnosticSessionControl:
		return handleSessionControl(ecu, params)
	default:
		return negativeResponse(sid, NRCServiceNotSupported)
	}
}

func findECU(ecus []config.ECU, addr uint16) *config.ECU {
	for i := range ecus {
		if uint16(ecus[i].LogicalAddress) == addr {
			return &ecus[i]
		}
	}
	return nil
}

func handleReadDID(ecu *config.ECU, params []byte) []byte {
	if len(params) < 2 {
		return negativeResponse(SIDReadDataByIdentifier, NRCInvalidMessageLengthOrFormat)
	}

	didID := int(binary.BigEndian.Uint16(params[0:2]))

	for _, svc := range ecu.Services {
		if svc.SID != SIDReadDataByIdentifier {
			continue
		}
		if svc.NRC != 0 {
			return negativeResponse(SIDReadDataByIdentifier, svc.NRC)
		}
		for _, did := range svc.DIDs {
			if did.ID == didID {
				if did.NRC != 0 {
					return negativeResponse(SIDReadDataByIdentifier, did.NRC)
				}
				resp := []byte{0x62, params[0], params[1]}
				return append(resp, []byte(did.Value)...)
			}
		}
	}

	return negativeResponse(SIDReadDataByIdentifier, NRCRequestOutOfRange)
}

func handleSessionControl(ecu *config.ECU, params []byte) []byte {
	if len(params) < 1 {
		return negativeResponse(SIDDiagnosticSessionControl, NRCInvalidMessageLengthOrFormat)
	}

	sessionType := params[0]

	for _, svc := range ecu.Services {
		if svc.SID != SIDDiagnosticSessionControl {
			continue
		}
		if svc.NRC != 0 {
			return negativeResponse(SIDDiagnosticSessionControl, svc.NRC)
		}
		for _, s := range svc.Sessions {
			if byte(s) == sessionType {
				// 0x50 = positive response, P2=25ms, P2*=5000ms (ISO defaults)
				return []byte{0x50, sessionType, 0x00, 0x19, 0x01, 0xF4}
			}
		}
	}

	return negativeResponse(SIDDiagnosticSessionControl, NRCSubFunctionNotSupported)
}

func negativeResponse(sid, nrc byte) []byte {
	return []byte{0x7F, sid, nrc}
}
