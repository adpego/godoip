package config

// ECU describes the single ECU simulated behind the DoIP entity.
type ECU struct {
	Name        string    `yaml:"name"`
	S3TimeoutMs int       `yaml:"s3_timeout_ms"` // non-default session timeout; defaults to 5000
	Services    Services  `yaml:"services"`
	DIDs        []DID     `yaml:"dids"`
	Memory      *Memory   `yaml:"memory"`
	Routines    []Routine `yaml:"routines"`
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
	ECUReset                 *ECUResetService       `yaml:"ecu_reset"`
	SecurityAccess           *SecurityAccessService `yaml:"security_access"`
	TesterPresent            *Service               `yaml:"tester_present"`
	ReadDataByIdentifier     *ReadDIDService        `yaml:"read_data_by_identifier"`
	WriteDataByIdentifier    *Service               `yaml:"write_data_by_identifier"`
	ReadMemoryByAddress      *ReadMemoryService     `yaml:"read_memory_by_address"`
	WriteMemoryByAddress     *Service               `yaml:"write_memory_by_address"`
	RoutineControl           *Service               `yaml:"routine_control"`
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

// ECUResetService configures ECUReset (0x11).
type ECUResetService struct {
	Service    `yaml:",inline"`
	ResetTypes []ResetType `yaml:"reset_types"` // empty = hard (0x01), keyOffOn (0x02) and soft (0x03)
}

// ResetType describes a supported ECUReset sub-function.
type ResetType struct {
	ID            uint8  `yaml:"id"`
	Name          string `yaml:"name"`
	Access        Access `yaml:"access"`
	PowerDownTime uint8  `yaml:"power_down_time"` // seconds, only for enableRapidPowerShutDown (0x04)
}

// SecurityAccessService configures SecurityAccess (0x27).
type SecurityAccessService struct {
	Service `yaml:",inline"`
	Levels  []SecurityLevel `yaml:"levels"`
}

// SecurityLevel describes a seed/key level. Level is the requestSeed
// sub-function (odd value); the matching sendKey sub-function is Level+1.
type SecurityLevel struct {
	Level       uint8  `yaml:"level"`
	Name        string `yaml:"name"`
	Access      Access `yaml:"access"`       // e.g. sessions in which the level can be unlocked
	Seed        string `yaml:"seed"`         // fixed seed (hex); empty = random seed
	SeedLength  int    `yaml:"seed_length"`  // random seed length; defaults to 4
	Algorithm   string `yaml:"algorithm"`    // xor | add | not | fixed | seed; defaults to xor
	Secret      string `yaml:"secret"`       // hex parameter of the key algorithm
	MaxAttempts int    `yaml:"max_attempts"` // invalid keys before lockout; defaults to 3
	LockoutMs   int    `yaml:"lockout_ms"`   // delay after exceeding attempts; defaults to 10000
}

// ReadDIDService configures ReadDataByIdentifier (0x22).
type ReadDIDService struct {
	Service           `yaml:",inline"`
	MaxDIDsPerRequest int `yaml:"max_dids_per_request"` // 0 = unlimited
}

// DID is a data identifier shared by ReadDataByIdentifier and
// WriteDataByIdentifier: a successful write changes the value later read.
type DID struct {
	ID             uint16           `yaml:"id"`
	Name           string           `yaml:"name"`
	Data           `yaml:",inline"` // initial value
	Length         int              `yaml:"length"`          // fixed size; 0 = size of the initial value. Empty value = zeros
	VariableLength bool             `yaml:"variable_length"` // accept writes of any length
	Volatile       bool             `yaml:"volatile"`        // restore the initial value on ECU reset
	Read           *Access          `yaml:"read"`            // nil = readable in any session without security
	Write          *Access          `yaml:"write"`           // nil = not writable
}
