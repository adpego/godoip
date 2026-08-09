package uds

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/adpego/godoip/internal/config"
)

const (
	defaultSeedLength  = 4
	defaultMaxAttempts = 3
	defaultLockout     = 10 * time.Second
)

type securityLevel struct {
	level       uint8
	access      config.Access
	fixedSeed   []byte
	seedLength  int
	algorithm   KeyAlgorithm
	secret      []byte
	maxAttempts int
	lockout     time.Duration
}

func newSecurityLevel(c config.SecurityLevel) (*securityLevel, error) {
	if c.Level%2 == 0 || c.Level >= 0x7F {
		return nil, fmt.Errorf("level 0x%02X must be an odd requestSeed sub-function", c.Level)
	}
	l := &securityLevel{
		level:       c.Level,
		access:      c.Access,
		seedLength:  defaultSeedLength,
		maxAttempts: defaultMaxAttempts,
		lockout:     defaultLockout,
	}

	var err error
	if l.fixedSeed, err = config.ParseHex(c.Seed); err != nil {
		return nil, fmt.Errorf("level 0x%02X seed: %w", c.Level, err)
	}
	if c.Seed != "" && allZero(l.fixedSeed) {
		return nil, fmt.Errorf("level 0x%02X seed must not be all zeros", c.Level)
	}
	if len(l.fixedSeed) == 0 {
		l.fixedSeed = nil
	}
	if l.secret, err = config.ParseHex(c.Secret); err != nil {
		return nil, fmt.Errorf("level 0x%02X secret: %w", c.Level, err)
	}
	if l.algorithm, err = lookupKeyAlgorithm(c.Algorithm, l.secret); err != nil {
		return nil, fmt.Errorf("level 0x%02X: %w", c.Level, err)
	}
	if c.SeedLength > 0 {
		l.seedLength = c.SeedLength
	}
	if c.MaxAttempts > 0 {
		l.maxAttempts = c.MaxAttempts
	}
	if c.LockoutMs > 0 {
		l.lockout = time.Duration(c.LockoutMs) * time.Millisecond
	}
	return l, nil
}

// newSeed returns the fixed seed or a random non-zero one.
func (l *securityLevel) newSeed(r io.Reader) ([]byte, error) {
	if l.fixedSeed != nil {
		return append([]byte(nil), l.fixedSeed...), nil
	}
	seed := make([]byte, l.seedLength)
	for {
		if _, err := io.ReadFull(r, seed); err != nil {
			return nil, err
		}
		if !allZero(seed) {
			return seed, nil
		}
	}
}

func buildSecurityAccess(e *ECU, cfg config.ECU) (*service, error) {
	c := cfg.Services.SecurityAccess
	if c == nil {
		return nil, nil
	}
	e.securityLevels = make(map[uint8]*securityLevel)
	for _, lc := range c.Levels {
		if _, dup := e.securityLevels[lc.Level]; dup {
			return nil, fmt.Errorf("duplicate security level 0x%02X", lc.Level)
		}
		l, err := newSecurityLevel(lc)
		if err != nil {
			return nil, err
		}
		e.securityLevels[l.level] = l
	}
	return &service{
		access:         c.Access,
		minLen:         2,
		hasSubFunction: true,
		handle:         handleSecurityAccess,
	}, nil
}

// handleSecurityAccess implements SecurityAccess (0x27).
func handleSecurityAccess(e *ECU, req request) []byte {
	sendKey := req.subFunction%2 == 0
	level := req.subFunction
	if sendKey {
		level--
	}
	l, ok := e.securityLevels[level]
	if req.subFunction == 0 || !ok {
		return negativeResponse(req.sid, NRCSubFunctionNotSupported)
	}
	if nrc := e.checkAccess(l.access, NRCSubFunctionNotSupportedInActiveSession); nrc != 0 {
		return negativeResponse(req.sid, nrc)
	}
	if sendKey {
		return e.securitySendKey(req, l)
	}
	return e.securityRequestSeed(req, l)
}

func (e *ECU) securityRequestSeed(req request, l *securityLevel) []byte {
	s := &e.security
	if e.now().Before(s.lockedUntil[l.level]) {
		return negativeResponse(req.sid, NRCRequiredTimeDelayNotExpired)
	}

	seed, err := l.newSeed(e.rand)
	if err != nil {
		return negativeResponse(req.sid, NRCConditionsNotCorrect)
	}
	// An already unlocked level answers with an all-zero seed.
	if s.unlocked == l.level {
		s.clearSeed()
		return positiveResponse(req.sid, append([]byte{req.subFunction}, make([]byte, len(seed))...)...)
	}

	s.seedLevel = l.level
	s.seed = seed
	return positiveResponse(req.sid, append([]byte{req.subFunction}, seed...)...)
}

func (e *ECU) securitySendKey(req request, l *securityLevel) []byte {
	s := &e.security
	if s.seedLevel != l.level {
		return negativeResponse(req.sid, NRCRequestSequenceError)
	}

	key := req.data[2:]
	expected := l.algorithm(s.seed, l.secret)
	if len(key) != len(expected) {
		return negativeResponse(req.sid, NRCInvalidMessageLengthOrFormat)
	}

	// A seed can only be used once.
	s.clearSeed()

	if !bytes.Equal(key, expected) {
		s.attempts[l.level]++
		if s.attempts[l.level] >= l.maxAttempts {
			s.attempts[l.level] = 0
			s.lockedUntil[l.level] = e.now().Add(l.lockout)
			return negativeResponse(req.sid, NRCExceededNumberOfAttempts)
		}
		return negativeResponse(req.sid, NRCInvalidKey)
	}

	s.attempts[l.level] = 0
	s.unlocked = l.level
	return positiveResponse(req.sid, req.subFunction)
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
