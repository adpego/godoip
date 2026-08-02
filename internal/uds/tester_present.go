package uds

import "github.com/adpego/godoip/internal/config"

func buildTesterPresent(_ *ECU, cfg config.ECU) (*service, error) {
	c := cfg.Services.TesterPresent
	if c == nil {
		return nil, nil
	}
	return &service{
		access:         c.Access,
		minLen:         2,
		hasSubFunction: true,
		handle:         handleTesterPresent,
	}, nil
}

// handleTesterPresent implements TesterPresent (0x3E). Keeping the session
// alive is handled generically: every request restarts the S3 timer.
func handleTesterPresent(_ *ECU, req request) []byte {
	if req.subFunction != 0x00 {
		return negativeResponse(req.sid, NRCSubFunctionNotSupported)
	}
	if len(req.data) != 2 {
		return negativeResponse(req.sid, NRCInvalidMessageLengthOrFormat)
	}
	return positiveResponse(req.sid, 0x00)
}
