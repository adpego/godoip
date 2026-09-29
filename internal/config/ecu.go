package config

// ECU describes the single ECU simulated behind the DoIP entity.
type ECU struct {
	Name        string    `yaml:"name"`
	S3TimeoutMs int       `yaml:"s3_timeout_ms"` // non-default session timeout; defaults to 5000
	Services    Services  `yaml:"services"`
	DIDs        []DID     `yaml:"dids"`
	Memory      *Memory   `yaml:"memory"`
	Routines    []Routine `yaml:"routines"`
	DTCs        []DTC     `yaml:"dtcs"`
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
	Access          Access           `yaml:"access"`
	ResponsePending *ResponsePending `yaml:"response_pending"` // simulate NRC 0x78 before the final response
}

// ResponsePending simulates a slow service: Count NRC 0x78 responses are sent,
// IntervalMs apart, before the final response.
type ResponsePending struct {
	Count      int `yaml:"count"`       // defaults to 1
	IntervalMs int `yaml:"interval_ms"` // defaults to 1000 (must stay below P2*)
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
	ReadDTCInformation       *ReadDTCService        `yaml:"read_dtc_information"`
	ClearDiagnosticInfo      *ClearDTCService       `yaml:"clear_diagnostic_information"`
	ControlDTCSetting        *Service               `yaml:"control_dtc_setting"`
	IOControl                *Service               `yaml:"input_output_control_by_identifier"`
	CommunicationControl     *CommControlService    `yaml:"communication_control"`
	LinkControl              *LinkControlService    `yaml:"link_control"`
	RequestDownload          *TransferService       `yaml:"request_download"`
	RequestUpload            *TransferService       `yaml:"request_upload"`
	TransferData             *Service               `yaml:"transfer_data"`
	RequestTransferExit      *Service               `yaml:"request_transfer_exit"`
	ReadScalingData          *Service               `yaml:"read_scaling_data_by_identifier"`
	DynamicallyDefineDID     *DDDIService           `yaml:"dynamically_define_data_identifier"`
	ReadDataByPeriodicID     *PeriodicService       `yaml:"read_data_by_periodic_identifier"`
}

// PeriodicService configures ReadDataByPeriodicIdentifier (0x2A). Periodic
// identifier 0xNN reads DID 0xF2NN (static or dynamically defined).
type PeriodicService struct {
	Service         `yaml:",inline"`
	SlowMs          int `yaml:"slow_ms"`           // transmissionMode 0x01; defaults to 1000
	MediumMs        int `yaml:"medium_ms"`         // transmissionMode 0x02; defaults to 300
	FastMs          int `yaml:"fast_ms"`           // transmissionMode 0x03; defaults to 100
	MaxPeriodicDIDs int `yaml:"max_periodic_dids"` // scheduled at the same time; defaults to 8
	MessageType     int `yaml:"message_type"`      // 1: 0x6A + pDID + data (default), 2: pDID + data
}

// DDDIService configures DynamicallyDefineDataIdentifier (0x2C).
type DDDIService struct {
	Service      `yaml:",inline"`
	SubFunctions []SubFunction `yaml:"sub_functions"` // empty = 0x01-0x03
	Identifiers  []uint16      `yaml:"identifiers"`   // definable DIDs; empty = 0xF200-0xF3FF
	MaxSources   int           `yaml:"max_sources"`   // per dynamic DID; defaults to 16
	Read         *Access       `yaml:"read"`          // access to read dynamic DIDs; nil = any
}

// TransferService configures RequestDownload (0x34) / RequestUpload (0x35).
type TransferService struct {
	Service        `yaml:",inline"`
	MaxBlockLength uint32  `yaml:"max_block_length"` // maxNumberOfBlockLength (SID and counter included); defaults to 1026
	DataFormats    []uint8 `yaml:"data_formats"`     // accepted dataFormatIdentifiers; defaults to 0x00 (plain data)
}

// CommControlService configures CommunicationControl (0x28).
type CommControlService struct {
	Service            `yaml:",inline"`
	ControlTypes       []SubFunction `yaml:"control_types"`       // empty = 0x00-0x03
	CommunicationTypes []uint8       `yaml:"communication_types"` // accepted communicationType bytes; empty = any valid
}

// LinkControlService configures LinkControl (0x87).
type LinkControlService struct {
	Service      `yaml:",inline"`
	SubFunctions []SubFunction `yaml:"sub_functions"` // empty = 0x01-0x03
	Modes        []uint8       `yaml:"modes"`         // supported linkControlModeIdentifiers; empty = ISO CAN/PC baudrates
	MaxBaudrate  uint32        `yaml:"max_baudrate"`  // max specific baudrate for 0x02; 0 = any
}

// SubFunction restricts access to one sub-function of a service.
type SubFunction struct {
	ID     uint8  `yaml:"id"`
	Access Access `yaml:"access"`
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
	IOControl      *IOControl       `yaml:"io_control"`      // nil = not controllable by 0x2F
	Scaling        *Data            `yaml:"scaling"`         // scalingByte + extensions for 0x24; nil = none
}

// IOControl makes a DID controllable by InputOutputControlByIdentifier (0x2F).
type IOControl struct {
	Access     Access  `yaml:"access"`
	Parameters []uint8 `yaml:"parameters"`  // supported inputOutputControlParameters; empty = 0x00-0x03
	Default    *Data   `yaml:"default"`     // value for resetToDefault; defaults to the DID initial value
	EnableMask bool    `yaml:"enable_mask"` // shortTermAdjustment carries a controlEnableMask of the DID size
}
