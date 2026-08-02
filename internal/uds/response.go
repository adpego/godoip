package uds

func negativeResponse(sid, nrc byte) []byte {
	return []byte{negativeResponseSID, sid, nrc}
}

func positiveResponse(sid byte, data ...byte) []byte {
	return append([]byte{sid + positiveResponseBit}, data...)
}

func isNegative(resp []byte) bool {
	return len(resp) >= 3 && resp[0] == negativeResponseSID
}

// suppressedOnFunctional lists the NRCs that must not be sent for functionally
// addressed requests (ISO 14229-1, 7.5).
func suppressedOnFunctional(nrc byte) bool {
	switch nrc {
	case NRCServiceNotSupported, NRCSubFunctionNotSupported, NRCRequestOutOfRange,
		NRCSubFunctionNotSupportedInActiveSession, NRCServiceNotSupportedInActiveSession:
		return true
	}
	return false
}
