package uds

import "time"

// securityState tracks the SecurityAccess (0x27) state of the ECU.
type securityState struct {
	unlocked    uint8  // unlocked level (requestSeed sub-function), 0 = locked
	seedLevel   uint8  // level whose seed is waiting for a key, 0 = none
	seed        []byte // seed sent for seedLevel
	attempts    map[uint8]int
	lockedUntil map[uint8]time.Time
}

func newSecurityState() securityState {
	return securityState{
		attempts:    make(map[uint8]int),
		lockedUntil: make(map[uint8]time.Time),
	}
}

// lock relocks the ECU, as required on every session transition.
// Attempt counters and lockout delays are kept.
func (s *securityState) lock() {
	s.unlocked = 0
	s.clearSeed()
}

func (s *securityState) clearSeed() {
	s.seedLevel = 0
	s.seed = nil
}
