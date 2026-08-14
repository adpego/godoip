package uds

import (
	"bytes"
	"testing"

	"github.com/adpego/godoip/internal/config"
)

var extendedOnly = &config.Access{Sessions: []uint8{SessionExtended}}

func didConfig(dids ...config.DID) config.ECU {
	svcs := sessionServices()
	svcs.SecurityAccess = &config.SecurityAccessService{Levels: []config.SecurityLevel{level1}}
	svcs.ReadDataByIdentifier = &config.ReadDIDService{}
	svcs.WriteDataByIdentifier = &config.Service{}
	return config.ECU{Services: svcs, DIDs: dids}
}

func enterExtended(t *testing.T, e *ECU) {
	t.Helper()
	send(t, e, []byte{0x10, 0x03}, []byte{0x50, 0x03, 0x00, 0x32, 0x01, 0xF4})
}

var (
	vinDID     = config.DID{ID: 0xF190, Data: config.Data{ASCII: "WBA12345678901234"}}
	swDID      = config.DID{ID: 0xF189, Data: config.Data{Hex: "01 02"}}
	writeDID   = config.DID{ID: 0x0100, Data: config.Data{Hex: "00 00"}, Write: extendedOnly}
	vinRequest = []byte{0x22, 0xF1, 0x90}
)

// --- ReadDataByIdentifier (0x22) ---

func TestReadDID(t *testing.T) {
	e, _ := newTestECU(t, didConfig(vinDID))
	send(t, e, vinRequest, append([]byte{0x62, 0xF1, 0x90}, "WBA12345678901234"...))
}

func TestReadMultipleDIDs(t *testing.T) {
	e, _ := newTestECU(t, didConfig(vinDID, swDID))
	want := append([]byte{0x62, 0xF1, 0x89, 0x01, 0x02, 0xF1, 0x90}, "WBA12345678901234"...)
	send(t, e, []byte{0x22, 0xF1, 0x89, 0xF1, 0x90}, want)
}

func TestReadDIDSkipsUnsupported(t *testing.T) {
	e, _ := newTestECU(t, didConfig(swDID))
	send(t, e, []byte{0x22, 0xAA, 0xAA, 0xF1, 0x89}, []byte{0x62, 0xF1, 0x89, 0x01, 0x02})
}

func TestReadDIDNotFound(t *testing.T) {
	e, _ := newTestECU(t, didConfig(vinDID))
	send(t, e, []byte{0x22, 0xF1, 0x8C}, nrc(0x22, NRCRequestOutOfRange))
}

func TestReadDIDInvalidLength(t *testing.T) {
	e, _ := newTestECU(t, didConfig(vinDID))
	send(t, e, []byte{0x22, 0xF1}, nrc(0x22, NRCInvalidMessageLengthOrFormat))
	send(t, e, []byte{0x22, 0xF1, 0x90, 0xF1}, nrc(0x22, NRCInvalidMessageLengthOrFormat))
}

func TestReadDIDMaxPerRequest(t *testing.T) {
	cfg := didConfig(vinDID, swDID)
	cfg.Services.ReadDataByIdentifier.MaxDIDsPerRequest = 1
	e, _ := newTestECU(t, cfg)
	send(t, e, []byte{0x22, 0xF1, 0x89, 0xF1, 0x90}, nrc(0x22, NRCInvalidMessageLengthOrFormat))
	send(t, e, []byte{0x22, 0xF1, 0x89}, []byte{0x62, 0xF1, 0x89, 0x01, 0x02})
}

func TestReadDIDSessionRestricted(t *testing.T) {
	d := swDID
	d.Read = extendedOnly
	e, _ := newTestECU(t, didConfig(d))

	send(t, e, []byte{0x22, 0xF1, 0x89}, nrc(0x22, NRCRequestOutOfRange))
	enterExtended(t, e)
	send(t, e, []byte{0x22, 0xF1, 0x89}, []byte{0x62, 0xF1, 0x89, 0x01, 0x02})
}

func TestReadDIDSecurityRestricted(t *testing.T) {
	d := swDID
	d.Read = &config.Access{SecurityLevels: []uint8{0x01}}
	e, _ := newTestECU(t, didConfig(d))

	send(t, e, []byte{0x22, 0xF1, 0x89}, nrc(0x22, NRCSecurityAccessDenied))
	unlock(t, e)
	send(t, e, []byte{0x22, 0xF1, 0x89}, []byte{0x62, 0xF1, 0x89, 0x01, 0x02})
}

func TestReadDIDForcedNRC(t *testing.T) {
	d := swDID
	d.Read = &config.Access{NRC: NRCConditionsNotCorrect}
	e, _ := newTestECU(t, didConfig(d))
	send(t, e, []byte{0x22, 0xF1, 0x89}, nrc(0x22, NRCConditionsNotCorrect))
}

func TestReadDIDLengthWithoutValueIsZeros(t *testing.T) {
	e, _ := newTestECU(t, didConfig(config.DID{ID: 0x0200, Length: 3}))
	send(t, e, []byte{0x22, 0x02, 0x00}, []byte{0x62, 0x02, 0x00, 0x00, 0x00, 0x00})
}

func TestReadDIDServiceSessionRestricted(t *testing.T) {
	cfg := didConfig(vinDID)
	cfg.Services.ReadDataByIdentifier.Access.Sessions = []uint8{SessionExtended}
	e, _ := newTestECU(t, cfg)
	send(t, e, vinRequest, nrc(0x22, NRCServiceNotSupportedInActiveSession))
}

// --- WriteDataByIdentifier (0x2E) ---

func TestWriteDIDThenRead(t *testing.T) {
	e, _ := newTestECU(t, didConfig(writeDID))
	send(t, e, []byte{0x22, 0x01, 0x00}, []byte{0x62, 0x01, 0x00, 0x00, 0x00})

	enterExtended(t, e)
	send(t, e, []byte{0x2E, 0x01, 0x00, 0xAB, 0xCD}, []byte{0x6E, 0x01, 0x00})
	send(t, e, []byte{0x22, 0x01, 0x00}, []byte{0x62, 0x01, 0x00, 0xAB, 0xCD})

	// The value survives session changes.
	send(t, e, []byte{0x10, 0x01}, []byte{0x50, 0x01, 0x00, 0x32, 0x01, 0xF4})
	send(t, e, []byte{0x22, 0x01, 0x00}, []byte{0x62, 0x01, 0x00, 0xAB, 0xCD})

	if v, ok := e.DID(0x0100); !ok || !bytes.Equal(v, []byte{0xAB, 0xCD}) {
		t.Errorf("DID(): got % X, %v", v, ok)
	}
}

func TestWriteDIDWrongSession(t *testing.T) {
	e, _ := newTestECU(t, didConfig(writeDID))
	send(t, e, []byte{0x2E, 0x01, 0x00, 0xAB, 0xCD}, nrc(0x2E, NRCRequestOutOfRange))
	send(t, e, []byte{0x22, 0x01, 0x00}, []byte{0x62, 0x01, 0x00, 0x00, 0x00})
}

func TestWriteDIDNotWritable(t *testing.T) {
	e, _ := newTestECU(t, didConfig(vinDID))
	send(t, e, []byte{0x2E, 0xF1, 0x90, 0x41}, nrc(0x2E, NRCRequestOutOfRange))
}

func TestWriteDIDUnknown(t *testing.T) {
	e, _ := newTestECU(t, didConfig())
	send(t, e, []byte{0x2E, 0x12, 0x34, 0x41}, nrc(0x2E, NRCRequestOutOfRange))
}

func TestWriteDIDSecurity(t *testing.T) {
	d := writeDID
	d.Write = &config.Access{Sessions: []uint8{SessionExtended}, SecurityLevels: []uint8{0x01}}
	e, _ := newTestECU(t, didConfig(d))

	enterExtended(t, e)
	send(t, e, []byte{0x2E, 0x01, 0x00, 0xAB, 0xCD}, nrc(0x2E, NRCSecurityAccessDenied))
	unlock(t, e)
	send(t, e, []byte{0x2E, 0x01, 0x00, 0xAB, 0xCD}, []byte{0x6E, 0x01, 0x00})
}

func TestWriteDIDForcedNRC(t *testing.T) {
	d := writeDID
	d.Write = &config.Access{NRC: NRCConditionsNotCorrect}
	e, _ := newTestECU(t, didConfig(d))
	send(t, e, []byte{0x2E, 0x01, 0x00, 0xAB, 0xCD}, nrc(0x2E, NRCConditionsNotCorrect))
}

func TestWriteDIDLengthMismatch(t *testing.T) {
	e, _ := newTestECU(t, didConfig(writeDID))
	enterExtended(t, e)
	send(t, e, []byte{0x2E, 0x01, 0x00, 0xAB}, nrc(0x2E, NRCInvalidMessageLengthOrFormat))
	send(t, e, []byte{0x2E, 0x01, 0x00, 0xAB, 0xCD, 0xEF}, nrc(0x2E, NRCInvalidMessageLengthOrFormat))
	send(t, e, []byte{0x2E, 0x01, 0x00}, nrc(0x2E, NRCInvalidMessageLengthOrFormat))
}

func TestWriteDIDVariableLength(t *testing.T) {
	d := config.DID{ID: 0x0101, Data: config.Data{ASCII: "abc"}, VariableLength: true, Write: &config.Access{}}
	e, _ := newTestECU(t, didConfig(d))
	send(t, e, []byte{0x2E, 0x01, 0x01, 'h', 'e', 'l', 'l', 'o'}, []byte{0x6E, 0x01, 0x01})
	send(t, e, []byte{0x22, 0x01, 0x01}, []byte{0x62, 0x01, 0x01, 'h', 'e', 'l', 'l', 'o'})
}

func TestWriteDIDDoesNotAliasRequest(t *testing.T) {
	d := config.DID{ID: 0x0101, Data: config.Data{Hex: "00"}, Write: &config.Access{}}
	e, _ := newTestECU(t, didConfig(d))
	req := []byte{0x2E, 0x01, 0x01, 0x11}
	send(t, e, req, []byte{0x6E, 0x01, 0x01})
	req[3] = 0xFF
	send(t, e, []byte{0x22, 0x01, 0x01}, []byte{0x62, 0x01, 0x01, 0x11})
}

// --- configuration ---

func TestDIDInvalidConfig(t *testing.T) {
	cases := map[string][]config.DID{
		"duplicate":       {vinDID, vinDID},
		"bad hex":         {{ID: 1, Data: config.Data{Hex: "XY"}}},
		"ascii and hex":   {{ID: 1, Data: config.Data{Hex: "01", ASCII: "a"}}},
		"length mismatch": {{ID: 1, Data: config.Data{Hex: "01"}, Length: 2}},
	}
	for name, dids := range cases {
		if _, err := NewECU(didConfig(dids...)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
