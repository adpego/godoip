package doip

const (
	// Payload types
	GenericNack           uint16 = 0x0000
	VehicleIdentRequest   uint16 = 0x0001
	VehicleIdentResponse  uint16 = 0x0004
	RoutingActivationReq  uint16 = 0x0005
	RoutingActivationResp uint16 = 0x0006
	DiagnosticMessage     uint16 = 0x8001
	DiagnosticPositiveAck uint16 = 0x8002
	DiagnosticNegativeAck uint16 = 0x8003

	HeaderLength = 8
)
