package uds

import (
	"bytes"
	"testing"
	"time"

	"github.com/adpego/godoip/internal/config"
)

func securityConfig(levels ...config.SecurityLevel) config.ECU {
	svcs := sessionServices()
	svcs.SecurityAccess = &config.SecurityAccessService{Levels: levels}
	return config.ECU{Services: svcs}
}

// level1 uses a fixed seed 11 22 33 44 and key = seed XOR AA BB CC DD = BB 99 FF 99.
var level1 = config.SecurityLevel{
	Level:       0x01,
	Seed:        "11 22 33 44",
	Algorithm:   "xor",
	Secret:      "AA BB CC DD",
	MaxAttempts: 3,
	LockoutMs:   10000,
}

var (
	level1Seed = []byte{0x67, 0x01, 0x11, 0x22, 0x33, 0x44}
	level1Key  = []byte{0x27, 0x02, 0xBB, 0x99, 0xFF, 0x99}
	badKey     = []byte{0x27, 0x02, 0x00, 0x00, 0x00, 0x00}
)

func unlock(t *testing.T, e *ECU) {
	t.Helper()
	send(t, e, []byte{0x27, 0x01}, level1Seed)
	send(t, e, level1Key, []byte{0x67, 0x02})
}

func TestSecurityAccessUnlock(t *testing.T) {
	e, _ := newTestECU(t, securityConfig(level1))
	unlock(t, e)
	if e.security.unlocked != 0x01 {
		t.Errorf("unlocked level: got 0x%02X, want 0x01", e.security.unlocked)
	}
	// Requesting the seed of an unlocked level returns a zero seed.
	send(t, e, []byte{0x27, 0x01}, []byte{0x67, 0x01, 0x00, 0x00, 0x00, 0x00})
}

func TestSecurityAccessUnknownLevel(t *testing.T) {
	e, _ := newTestECU(t, securityConfig(level1))
	send(t, e, []byte{0x27, 0x03}, nrc(0x27, NRCSubFunctionNotSupported))
	send(t, e, []byte{0x27, 0x04, 0x00}, nrc(0x27, NRCSubFunctionNotSupported))
	send(t, e, []byte{0x27, 0x00}, nrc(0x27, NRCSubFunctionNotSupported))
}

func TestSecurityAccessKeyWithoutSeed(t *testing.T) {
	e, _ := newTestECU(t, securityConfig(level1))
	send(t, e, level1Key, nrc(0x27, NRCRequestSequenceError))
}

func TestSecurityAccessSeedIsSingleUse(t *testing.T) {
	e, _ := newTestECU(t, securityConfig(level1))
	send(t, e, []byte{0x27, 0x01}, level1Seed)
	send(t, e, badKey, nrc(0x27, NRCInvalidKey))
	send(t, e, level1Key, nrc(0x27, NRCRequestSequenceError))
}

func TestSecurityAccessInvalidKeyLength(t *testing.T) {
	e, _ := newTestECU(t, securityConfig(level1))
	send(t, e, []byte{0x27, 0x01}, level1Seed)
	send(t, e, []byte{0x27, 0x02, 0xBB}, nrc(0x27, NRCInvalidMessageLengthOrFormat))
	// The seed is still valid after a malformed request.
	send(t, e, level1Key, []byte{0x67, 0x02})
}

func TestSecurityAccessLockout(t *testing.T) {
	e, clock := newTestECU(t, securityConfig(level1))

	for i := 0; i < 2; i++ {
		send(t, e, []byte{0x27, 0x01}, level1Seed)
		send(t, e, badKey, nrc(0x27, NRCInvalidKey))
	}
	send(t, e, []byte{0x27, 0x01}, level1Seed)
	send(t, e, badKey, nrc(0x27, NRCExceededNumberOfAttempts))

	send(t, e, []byte{0x27, 0x01}, nrc(0x27, NRCRequiredTimeDelayNotExpired))
	clock.advance(9 * time.Second)
	send(t, e, []byte{0x27, 0x01}, nrc(0x27, NRCRequiredTimeDelayNotExpired))
	clock.advance(time.Second)
	unlock(t, e)
}

func TestSecurityAccessSuccessResetsAttempts(t *testing.T) {
	e, _ := newTestECU(t, securityConfig(level1))
	send(t, e, []byte{0x27, 0x01}, level1Seed)
	send(t, e, badKey, nrc(0x27, NRCInvalidKey))
	send(t, e, []byte{0x27, 0x01}, level1Seed)
	send(t, e, badKey, nrc(0x27, NRCInvalidKey))
	unlock(t, e)

	send(t, e, []byte{0x10, 0x01}, []byte{0x50, 0x01, 0x00, 0x32, 0x01, 0xF4}) // relock
	send(t, e, []byte{0x27, 0x01}, level1Seed)
	send(t, e, badKey, nrc(0x27, NRCInvalidKey)) // counter restarted: not 0x36
}

func TestSecurityAccessLevelSessionRestriction(t *testing.T) {
	l := level1
	l.Access = config.Access{Sessions: []uint8{SessionExtended}}
	e, _ := newTestECU(t, securityConfig(l))

	send(t, e, []byte{0x27, 0x01}, nrc(0x27, NRCSubFunctionNotSupportedInActiveSession))
	send(t, e, []byte{0x10, 0x03}, []byte{0x50, 0x03, 0x00, 0x32, 0x01, 0xF4})
	unlock(t, e)
}

func TestSecurityAccessRelockOnSessionChange(t *testing.T) {
	e, _ := newTestECU(t, securityConfig(level1))
	unlock(t, e)
	send(t, e, []byte{0x10, 0x03}, []byte{0x50, 0x03, 0x00, 0x32, 0x01, 0xF4})
	send(t, e, []byte{0x27, 0x01}, level1Seed) // non-zero seed: locked again
}

func TestSecurityAccessMultipleLevels(t *testing.T) {
	level3 := config.SecurityLevel{Level: 0x03, Seed: "01 02", Algorithm: "not"}
	e, _ := newTestECU(t, securityConfig(level1, level3))

	unlock(t, e)
	send(t, e, []byte{0x27, 0x03}, []byte{0x67, 0x03, 0x01, 0x02})
	send(t, e, []byte{0x27, 0x04, 0xFE, 0xFD}, []byte{0x67, 0x04})
	if e.security.unlocked != 0x03 {
		t.Errorf("unlocked level: got 0x%02X, want 0x03", e.security.unlocked)
	}
}

func TestSecurityAccessRandomSeed(t *testing.T) {
	l := config.SecurityLevel{Level: 0x01, SeedLength: 2, Algorithm: "seed"}
	cfg := securityConfig(l)
	// The all-zero seed is skipped.
	rnd := bytes.NewReader([]byte{0x00, 0x00, 0xCA, 0xFE})
	e, err := NewECU(cfg, WithRandom(rnd))
	if err != nil {
		t.Fatal(err)
	}
	send(t, e, []byte{0x27, 0x01}, []byte{0x67, 0x01, 0xCA, 0xFE})
	send(t, e, []byte{0x27, 0x02, 0xCA, 0xFE}, []byte{0x67, 0x02})
}

func TestSecurityAccessSuppressPositive(t *testing.T) {
	e, _ := newTestECU(t, securityConfig(level1))
	send(t, e, []byte{0x27, 0x01}, level1Seed)
	if resp := e.Handle([]byte{0x27, 0x82, 0xBB, 0x99, 0xFF, 0x99}, false); resp != nil {
		t.Errorf("got % X, want no response", resp)
	}
	if e.security.unlocked != 0x01 {
		t.Error("level should be unlocked")
	}
}

func TestSecurityAccessInvalidConfig(t *testing.T) {
	cases := map[string]config.SecurityLevel{
		"even level":        {Level: 0x02, Secret: "01"},
		"unknown algorithm": {Level: 0x01, Algorithm: "rot13"},
		"missing secret":    {Level: 0x01, Algorithm: "xor"},
		"zero seed":         {Level: 0x01, Seed: "00 00", Algorithm: "not"},
		"bad seed":          {Level: 0x01, Seed: "XYZ", Algorithm: "not"},
	}
	for name, l := range cases {
		if _, err := NewECU(securityConfig(l)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := NewECU(securityConfig(level1, level1)); err == nil {
		t.Error("duplicate level: expected error")
	}
}

// --- key algorithms ---

func TestKeyAlgorithms(t *testing.T) {
	cases := []struct {
		name         string
		seed, secret []byte
		want         []byte
	}{
		{"xor", []byte{0x11, 0x22, 0x33}, []byte{0xFF}, []byte{0xEE, 0xDD, 0xCC}},
		{"add", []byte{0x00, 0xFF, 0xFF}, []byte{0x01}, []byte{0x01, 0x00, 0x00}},
		{"add", []byte{0xFF, 0xFF}, []byte{0x00, 0x02}, []byte{0x00, 0x01}},
		{"add", []byte{0x10}, []byte{0x01, 0x02}, []byte{0x12}},
		{"not", []byte{0x0F, 0xF0}, nil, []byte{0xF0, 0x0F}},
		{"fixed", []byte{0x01}, []byte{0xDE, 0xAD}, []byte{0xDE, 0xAD}},
		{"seed", []byte{0x01, 0x02}, nil, []byte{0x01, 0x02}},
	}
	for _, c := range cases {
		got := keyAlgorithms[c.name](c.seed, c.secret)
		if !bytes.Equal(got, c.want) {
			t.Errorf("%s(% X, % X): got % X, want % X", c.name, c.seed, c.secret, got, c.want)
		}
	}
}

func TestRegisterKeyAlgorithm(t *testing.T) {
	RegisterKeyAlgorithm("swap", func(seed, _ []byte) []byte {
		return []byte{seed[1], seed[0]}
	})
	defer delete(keyAlgorithms, "swap")

	e, _ := newTestECU(t, securityConfig(config.SecurityLevel{Level: 0x01, Seed: "12 34", Algorithm: "swap"}))
	send(t, e, []byte{0x27, 0x01}, []byte{0x67, 0x01, 0x12, 0x34})
	send(t, e, []byte{0x27, 0x02, 0x34, 0x12}, []byte{0x67, 0x02})
}
