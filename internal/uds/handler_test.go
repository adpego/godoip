package uds

import (
	"testing"

	"github.com/adpego/godoip/internal/config"
)

// helpers

func makeECU(logicalAddr int, services []config.Service) config.ECU {
	return config.ECU{LogicalAddress: logicalAddr, Services: services}
}

func makeReadDIDService(dids []config.DID) config.Service {
	return config.Service{SID: SIDReadDataByIdentifier, DIDs: dids}
}

func makeSessionService(sessions []int) config.Service {
	return config.Service{SID: SIDDiagnosticSessionControl, Sessions: sessions}
}

// --- HandleRequest general ---

func TestHandleRequestEmptyData(t *testing.T) {
	resp := HandleRequest(nil, 0x0E80, []byte{})
	if resp[0] != 0x7F || resp[2] != NRCServiceNotSupported {
		t.Errorf("got % X, want 7F 00 11", resp)
	}
}

func TestHandleRequestUnknownECU(t *testing.T) {
	resp := HandleRequest(nil, 0x0E80, []byte{0x22, 0xF1, 0x90})
	if resp[0] != 0x7F || resp[2] != NRCServiceNotSupported {
		t.Errorf("got % X, want 7F 22 11", resp)
	}
}

func TestHandleRequestUnknownSID(t *testing.T) {
	ecu := makeECU(0x0E80, nil)
	resp := HandleRequest([]config.ECU{ecu}, 0x0E80, []byte{0x27}) // SecurityAccess
	if resp[0] != 0x7F || resp[1] != 0x27 || resp[2] != NRCServiceNotSupported {
		t.Errorf("got % X, want 7F 27 11", resp)
	}
}

// --- ReadDataByIdentifier (0x22) ---

func TestReadDIDSuccess(t *testing.T) {
	ecu := makeECU(0x0E80, []config.Service{
		makeReadDIDService([]config.DID{
			{ID: 0xF190, Value: "WBA12345678901234"},
		}),
	})

	resp := HandleRequest([]config.ECU{ecu}, 0x0E80, []byte{0x22, 0xF1, 0x90})

	if resp[0] != 0x62 {
		t.Fatalf("expected positive response 0x62, got 0x%02X", resp[0])
	}
	if resp[1] != 0xF1 || resp[2] != 0x90 {
		t.Errorf("DID echoed incorrectly: got %02X %02X", resp[1], resp[2])
	}
	if string(resp[3:]) != "WBA12345678901234" {
		t.Errorf("value: got %q, want %q", string(resp[3:]), "WBA12345678901234")
	}
}

func TestReadDIDNotFound(t *testing.T) {
	ecu := makeECU(0x0E80, []config.Service{
		makeReadDIDService([]config.DID{
			{ID: 0xF190, Value: "WBA12345678901234"},
		}),
	})

	resp := HandleRequest([]config.ECU{ecu}, 0x0E80, []byte{0x22, 0xF1, 0x8C})
	if resp[0] != 0x7F || resp[2] != NRCRequestOutOfRange {
		t.Errorf("got % X, want 7F 22 31", resp)
	}
}

func TestReadDIDTooShortParams(t *testing.T) {
	ecu := makeECU(0x0E80, []config.Service{makeReadDIDService(nil)})
	resp := HandleRequest([]config.ECU{ecu}, 0x0E80, []byte{0x22, 0xF1}) // only 1 byte param
	if resp[0] != 0x7F || resp[2] != NRCInvalidMessageLengthOrFormat {
		t.Errorf("got % X, want 7F 22 13", resp)
	}
}

func TestReadDIDServiceNRC(t *testing.T) {
	ecu := makeECU(0x0E80, []config.Service{
		{SID: SIDReadDataByIdentifier, NRC: NRCSecurityAccessDenied,
			DIDs: []config.DID{{ID: 0xF190, Value: "WBA12345678901234"}}},
	})

	resp := HandleRequest([]config.ECU{ecu}, 0x0E80, []byte{0x22, 0xF1, 0x90})
	if resp[0] != 0x7F || resp[2] != NRCSecurityAccessDenied {
		t.Errorf("got % X, want 7F 22 33", resp)
	}
}

func TestReadDIDDIDNRC(t *testing.T) {
	ecu := makeECU(0x0E80, []config.Service{
		makeReadDIDService([]config.DID{
			{ID: 0xF190, Value: "WBA12345678901234", NRC: NRCConditionsNotCorrect},
		}),
	})

	resp := HandleRequest([]config.ECU{ecu}, 0x0E80, []byte{0x22, 0xF1, 0x90})
	if resp[0] != 0x7F || resp[2] != NRCConditionsNotCorrect {
		t.Errorf("got % X, want 7F 22 22", resp)
	}
}

// --- DiagnosticSessionControl (0x10) ---

func TestSessionControlSuccess(t *testing.T) {
	ecu := makeECU(0x0E80, []config.Service{
		makeSessionService([]int{0x01, 0x02, 0x03}),
	})

	resp := HandleRequest([]config.ECU{ecu}, 0x0E80, []byte{0x10, 0x02})
	if resp[0] != 0x50 {
		t.Fatalf("expected positive response 0x50, got 0x%02X", resp[0])
	}
	if resp[1] != 0x02 {
		t.Errorf("session type echoed incorrectly: got 0x%02X, want 0x02", resp[1])
	}
}

func TestSessionControlUnknownSession(t *testing.T) {
	ecu := makeECU(0x0E80, []config.Service{
		makeSessionService([]int{0x01}),
	})

	resp := HandleRequest([]config.ECU{ecu}, 0x0E80, []byte{0x10, 0x04})
	if resp[0] != 0x7F || resp[2] != NRCSubFunctionNotSupported {
		t.Errorf("got % X, want 7F 10 12", resp)
	}
}

func TestSessionControlTooShortParams(t *testing.T) {
	ecu := makeECU(0x0E80, []config.Service{makeSessionService([]int{0x01})})
	resp := HandleRequest([]config.ECU{ecu}, 0x0E80, []byte{0x10})
	if resp[0] != 0x7F || resp[2] != NRCInvalidMessageLengthOrFormat {
		t.Errorf("got % X, want 7F 10 13", resp)
	}
}

func TestSessionControlServiceNRC(t *testing.T) {
	ecu := makeECU(0x0E80, []config.Service{
		{SID: SIDDiagnosticSessionControl, NRC: NRCConditionsNotCorrect, Sessions: []int{0x01}},
	})

	resp := HandleRequest([]config.ECU{ecu}, 0x0E80, []byte{0x10, 0x01})
	if resp[0] != 0x7F || resp[2] != NRCConditionsNotCorrect {
		t.Errorf("got % X, want 7F 10 22", resp)
	}
}
