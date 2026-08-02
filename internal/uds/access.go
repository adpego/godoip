package uds

import (
	"slices"

	"github.com/adpego/godoip/internal/config"
)

// sessionAllowed reports whether the active session satisfies a.
func (e *ECU) sessionAllowed(a config.Access) bool {
	return len(a.Sessions) == 0 || slices.Contains(a.Sessions, e.session)
}

// securityGranted reports whether the unlocked security level satisfies a.
func (e *ECU) securityGranted(a config.Access) bool {
	return len(a.SecurityLevels) == 0 || slices.Contains(a.SecurityLevels, e.security.unlocked)
}

// checkAccess validates a in ISO order (session, security, forced NRC) and
// returns the NRC to send, or 0 if access is granted. sessionNRC is the code
// used when the active session is not allowed, which depends on the context.
func (e *ECU) checkAccess(a config.Access, sessionNRC byte) byte {
	switch {
	case !e.sessionAllowed(a):
		return sessionNRC
	case !e.securityGranted(a):
		return NRCSecurityAccessDenied
	default:
		return a.NRC
	}
}
