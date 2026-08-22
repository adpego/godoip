// Package did implements the data identifier store and the services that use
// it: ReadDataByIdentifier (0x22) and WriteDataByIdentifier (0x2E).
package did

import (
	"fmt"

	"github.com/adpego/godoip/internal/config"
	"github.com/adpego/godoip/internal/uds"
)

// DID is a data identifier with its current (possibly written) value.
type DID struct {
	ID             uint16
	Initial        []byte
	Value          []byte
	VariableLength bool
	Volatile       bool
	Read           config.Access
	Write          *config.Access // nil = not writable
}

func newDID(c config.DID) (*DID, error) {
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
	d := &DID{
		ID:             c.ID,
		Initial:        value,
		Value:          append([]byte(nil), value...),
		VariableLength: c.VariableLength,
		Volatile:       c.Volatile,
		Write:          c.Write,
	}
	if c.Read != nil {
		d.Read = *c.Read
	}
	return d, nil
}

// Store holds the data identifiers of the ECU. It is shared by every service
// that reads or writes DIDs, and must only be used with the ECU locked (from
// handlers or uds.ECU.Do).
type Store struct {
	dids map[uint16]*DID
}

// NewStore builds a store from configuration. Volatile DIDs are restored to
// their initial value whenever e is reset.
func NewStore(e *uds.ECU, cfgs []config.DID) (*Store, error) {
	s := &Store{dids: make(map[uint16]*DID, len(cfgs))}
	for _, c := range cfgs {
		if _, dup := s.dids[c.ID]; dup {
			return nil, fmt.Errorf("duplicate DID 0x%04X", c.ID)
		}
		d, err := newDID(c)
		if err != nil {
			return nil, err
		}
		s.dids[c.ID] = d
	}
	e.OnReset(s.restoreVolatile)
	return s, nil
}

// Get returns a DID, or nil if unknown.
func (s *Store) Get(id uint16) *DID {
	return s.dids[id]
}

// Set changes the current value of a DID.
func (s *Store) Set(id uint16, value []byte) {
	if d := s.dids[id]; d != nil {
		d.Value = append([]byte(nil), value...)
	}
}

func (s *Store) restoreVolatile() {
	for _, d := range s.dids {
		if d.Volatile {
			d.Value = append([]byte(nil), d.Initial...)
		}
	}
}
