package uds

import (
	"testing"

	"github.com/adpego/godoip/internal/config"
)

func resetConfig(types ...config.ResetType) config.ECU {
	cfg := didConfig(
		config.DID{ID: 0x0101, Data: config.Data{Hex: "00"}, Volatile: true, Write: &config.Access{}},
		config.DID{ID: 0x0102, Data: config.Data{Hex: "00"}, Write: &config.Access{}},
	)
	cfg.Services.ECUReset = &config.ECUResetService{ResetTypes: types}
	return cfg
}

func TestECUResetDefaultTypes(t *testing.T) {
	e, _ := newTestECU(t, resetConfig())
	for _, id := range []uint8{ResetHard, ResetKeyOffOn, ResetSoft} {
		send(t, e, []byte{0x11, id}, []byte{0x51, id})
	}
	send(t, e, []byte{0x11, ResetEnableRapidPowerShutDown}, nrc(0x11, NRCSubFunctionNotSupported))
}

func TestECUResetReturnsToDefaultAndLocks(t *testing.T) {
	e, _ := newTestECU(t, resetConfig())
	enterExtended(t, e)
	unlock(t, e)

	send(t, e, []byte{0x11, 0x01}, []byte{0x51, 0x01})
	if e.Session() != SessionDefault {
		t.Errorf("session: got 0x%02X, want default", e.Session())
	}
	if e.security.unlocked != 0 {
		t.Error("security should be locked after reset")
	}
}

func TestECUResetRestoresVolatileDIDs(t *testing.T) {
	e, _ := newTestECU(t, resetConfig())
	send(t, e, []byte{0x2E, 0x01, 0x01, 0xAA}, []byte{0x6E, 0x01, 0x01})
	send(t, e, []byte{0x2E, 0x01, 0x02, 0xBB}, []byte{0x6E, 0x01, 0x02})

	send(t, e, []byte{0x11, 0x03}, []byte{0x51, 0x03})

	send(t, e, []byte{0x22, 0x01, 0x01}, []byte{0x62, 0x01, 0x01, 0x00}) // volatile: restored
	send(t, e, []byte{0x22, 0x01, 0x02}, []byte{0x62, 0x01, 0x02, 0xBB}) // persistent: kept
}

func TestECUResetRapidPowerShutDown(t *testing.T) {
	e, _ := newTestECU(t, resetConfig(
		config.ResetType{ID: ResetEnableRapidPowerShutDown, PowerDownTime: 0x0A},
		config.ResetType{ID: ResetDisableRapidPowerShutDown},
	))
	enterExtended(t, e)
	send(t, e, []byte{0x11, 0x04}, []byte{0x51, 0x04, 0x0A})
	send(t, e, []byte{0x11, 0x05}, []byte{0x51, 0x05})
	if e.Session() != SessionExtended {
		t.Error("rapid power shutdown control must not reset the ECU")
	}
}

func TestECUResetTypeAccess(t *testing.T) {
	e, _ := newTestECU(t, resetConfig(
		config.ResetType{ID: ResetHard, Access: config.Access{Sessions: []uint8{SessionExtended}}},
		config.ResetType{ID: ResetSoft, Access: config.Access{SecurityLevels: []uint8{0x01}}},
		config.ResetType{ID: ResetKeyOffOn, Access: config.Access{NRC: NRCConditionsNotCorrect}},
	))
	send(t, e, []byte{0x11, 0x01}, nrc(0x11, NRCSubFunctionNotSupportedInActiveSession))
	send(t, e, []byte{0x11, 0x03}, nrc(0x11, NRCSecurityAccessDenied))
	send(t, e, []byte{0x11, 0x02}, nrc(0x11, NRCConditionsNotCorrect))

	enterExtended(t, e)
	send(t, e, []byte{0x11, 0x01}, []byte{0x51, 0x01})
}

func TestECUResetInvalidLength(t *testing.T) {
	e, _ := newTestECU(t, resetConfig())
	send(t, e, []byte{0x11}, nrc(0x11, NRCInvalidMessageLengthOrFormat))
	send(t, e, []byte{0x11, 0x01, 0x00}, nrc(0x11, NRCInvalidMessageLengthOrFormat))
}

func TestECUResetSuppressPositive(t *testing.T) {
	e, _ := newTestECU(t, resetConfig())
	enterExtended(t, e)
	if resp := e.Handle([]byte{0x11, 0x81}, false); resp != nil {
		t.Errorf("got % X, want no response", resp)
	}
	if e.Session() != SessionDefault {
		t.Error("reset must happen even when the response is suppressed")
	}
}

func TestECUResetInvalidConfig(t *testing.T) {
	for name, types := range map[string][]config.ResetType{
		"zero":      {{ID: 0x00}},
		"spr bit":   {{ID: 0x81}},
		"duplicate": {{ID: 0x01}, {ID: 0x01}},
	} {
		if _, err := NewECU(resetConfig(types...)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
