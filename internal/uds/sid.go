package uds

// Service identifiers (ISO 14229-1).
const (
	SIDDiagnosticSessionControl   byte = 0x10
	SIDECUReset                   byte = 0x11
	SIDClearDiagnosticInformation byte = 0x14
	SIDReadDTCInformation         byte = 0x19
	SIDReadDataByIdentifier       byte = 0x22
	SIDSecurityAccess             byte = 0x27
	SIDCommunicationControl       byte = 0x28
	SIDWriteDataByIdentifier      byte = 0x2E
	SIDRoutineControl             byte = 0x31
	SIDTesterPresent              byte = 0x3E
	SIDControlDTCSetting          byte = 0x85

	negativeResponseSID byte = 0x7F
	positiveResponseBit byte = 0x40
	suppressPosRspBit   byte = 0x80
)

// Diagnostic sessions (ISO 14229-1).
const (
	SessionDefault      uint8 = 0x01
	SessionProgramming  uint8 = 0x02
	SessionExtended     uint8 = 0x03
	SessionSafetySystem uint8 = 0x04
)
