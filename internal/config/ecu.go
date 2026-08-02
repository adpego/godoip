package config

// ECU describes the single ECU simulated behind the DoIP entity.
type ECU struct {
	Name        string   `yaml:"name"`
	S3TimeoutMs int      `yaml:"s3_timeout_ms"` // non-default session timeout; defaults to 5000
	Services    Services `yaml:"services"`
}

// Access describes the conditions under which an element (service, session,
// DID, routine...) can be used.
type Access struct {
	Sessions       []uint8 `yaml:"sessions"`        // allowed active sessions; empty = any session
	SecurityLevels []uint8 `yaml:"security_levels"` // one of these levels must be unlocked; empty = no security
	NRC            uint8   `yaml:"nrc"`             // if non-zero, always answer with this NRC
}

// Service holds the settings shared by every UDS service.
type Service struct {
	Access Access `yaml:"access"`
}

// Services lists the UDS services supported by the ECU. A nil entry means the
// service is not supported (NRC 0x11). Use `{}` in YAML to enable a service
// with its default settings.
type Services struct {
	DiagnosticSessionControl *SessionControlService `yaml:"diagnostic_session_control"`
	TesterPresent            *Service               `yaml:"tester_present"`
}

// SessionControlService configures DiagnosticSessionControl (0x10).
type SessionControlService struct {
	Service  `yaml:",inline"`
	Sessions []Session `yaml:"sessions"` // empty = default, programming and extended
}

// Session describes a diagnostic session. Access.Sessions lists the sessions
// from which this one can be entered.
type Session struct {
	ID       uint8  `yaml:"id"`
	Name     string `yaml:"name"`
	P2Ms     int    `yaml:"p2_ms"`      // defaults to 50
	P2StarMs int    `yaml:"p2_star_ms"` // defaults to 5000
	Access   Access `yaml:"access"`
}
