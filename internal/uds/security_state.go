package uds

// securityState tracks the SecurityAccess (0x27) state of the ECU.
type securityState struct {
	unlocked uint8 // unlocked level (requestSeed sub-function), 0 = locked
}

func newSecurityState() securityState {
	return securityState{}
}

// lock relocks the ECU, as required on every session transition.
func (s *securityState) lock() {
	s.unlocked = 0
}
