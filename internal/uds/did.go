package uds

import (
	"encoding/binary"
	"fmt"

	"github.com/adpego/godoip/internal/config"
)

// did is a data identifier with its current (possibly written) value.
type did struct {
	id             uint16
	initial        []byte
	value          []byte
	variableLength bool
	volatile       bool
	read           config.Access
	write          *config.Access
}

func newDID(c config.DID) (*did, error) {
	value, err := c.Bytes()
	if err != nil {
		return nil, fmt.Errorf("DID 0x%04X: %w", c.ID, err)
	}
	switch {
	case c.Length > 0 && len(value) == 0:
		value = make([]byte, c.Length)
	case c.Length > 0 && len(value) != c.Length:
		return nil, fmt.Errorf("DID 0x%04X: value has %d bytes, length is %d", c.ID, len(value), c.Length)
	}
	d := &did{
		id:             c.ID,
		initial:        value,
		value:          append([]byte(nil), value...),
		variableLength: c.VariableLength,
		volatile:       c.Volatile,
		write:          c.Write,
	}
	if c.Read != nil {
		d.read = *c.Read
	}
	return d, nil
}

func newDIDStore(cfgs []config.DID) (map[uint16]*did, error) {
	dids := make(map[uint16]*did, len(cfgs))
	for _, c := range cfgs {
		if _, dup := dids[c.ID]; dup {
			return nil, fmt.Errorf("duplicate DID 0x%04X", c.ID)
		}
		d, err := newDID(c)
		if err != nil {
			return nil, err
		}
		dids[c.ID] = d
	}
	return dids, nil
}

// DID returns a copy of the current value of a data identifier.
func (e *ECU) DID(id uint16) ([]byte, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	d, ok := e.dids[id]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), d.value...), true
}

// restoreVolatileDIDs resets volatile DIDs to their initial value.
func (e *ECU) restoreVolatileDIDs() {
	for _, d := range e.dids {
		if d.volatile {
			d.value = append([]byte(nil), d.initial...)
		}
	}
}

// --- ReadDataByIdentifier (0x22) ---

func buildReadDID(e *ECU, cfg config.ECU) (*service, error) {
	c := cfg.Services.ReadDataByIdentifier
	if c == nil {
		return nil, nil
	}
	e.maxDIDsPerRead = c.MaxDIDsPerRequest
	return &service{access: c.Access, minLen: 3, handle: handleReadDID}, nil
}

// handleReadDID implements ReadDataByIdentifier (0x22). DIDs that are unknown
// or not readable in the active session are skipped; NRC 0x31 is returned
// only if none of the requested DIDs can be read.
func handleReadDID(e *ECU, req request) []byte {
	ids := req.data[1:]
	if len(ids)%2 != 0 || (e.maxDIDsPerRead > 0 && len(ids)/2 > e.maxDIDsPerRead) {
		return negativeResponse(req.sid, NRCInvalidMessageLengthOrFormat)
	}

	resp := positiveResponse(req.sid)
	for i := 0; i < len(ids); i += 2 {
		d, ok := e.dids[binary.BigEndian.Uint16(ids[i:])]
		if !ok || !e.sessionAllowed(d.read) {
			continue
		}
		if !e.securityGranted(d.read) {
			return negativeResponse(req.sid, NRCSecurityAccessDenied)
		}
		if d.read.NRC != 0 {
			return negativeResponse(req.sid, d.read.NRC)
		}
		resp = append(resp, ids[i], ids[i+1])
		resp = append(resp, d.value...)
	}

	if len(resp) == 1 {
		return negativeResponse(req.sid, NRCRequestOutOfRange)
	}
	return resp
}

// --- WriteDataByIdentifier (0x2E) ---

func buildWriteDID(_ *ECU, cfg config.ECU) (*service, error) {
	c := cfg.Services.WriteDataByIdentifier
	if c == nil {
		return nil, nil
	}
	return &service{access: c.Access, minLen: 4, handle: handleWriteDID}, nil
}

// handleWriteDID implements WriteDataByIdentifier (0x2E). The written value
// is returned by subsequent ReadDataByIdentifier requests.
func handleWriteDID(e *ECU, req request) []byte {
	id := binary.BigEndian.Uint16(req.data[1:3])
	d, ok := e.dids[id]
	if !ok || d.write == nil {
		return negativeResponse(req.sid, NRCRequestOutOfRange)
	}
	if nrc := e.checkAccess(*d.write, NRCRequestOutOfRange); nrc != 0 {
		return negativeResponse(req.sid, nrc)
	}

	value := req.data[3:]
	if !d.variableLength && len(value) != len(d.initial) {
		return negativeResponse(req.sid, NRCInvalidMessageLengthOrFormat)
	}
	d.value = append([]byte(nil), value...)

	return positiveResponse(req.sid, req.data[1], req.data[2])
}
