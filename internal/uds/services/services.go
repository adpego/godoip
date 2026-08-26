// Package services builds a fully configured UDS ECU by registering every
// service sub-package according to the configuration.
//
// Adding a service: create a sub-package with a Register function taking the
// ECU and its configuration (plus any shared store), then add one step below.
package services

import (
	"fmt"
	"time"

	"github.com/adpego/godoip/internal/config"
	"github.com/adpego/godoip/internal/uds"
	"github.com/adpego/godoip/internal/uds/services/did"
	"github.com/adpego/godoip/internal/uds/services/ecureset"
	"github.com/adpego/godoip/internal/uds/services/memory"
	"github.com/adpego/godoip/internal/uds/services/security"
	"github.com/adpego/godoip/internal/uds/services/session"
	"github.com/adpego/godoip/internal/uds/services/testerpresent"
)

type step struct {
	name string
	run  func() error
}

// New builds an ECU with every service enabled in cfg.
func New(cfg config.ECU, opts ...uds.Option) (*uds.ECU, error) {
	opts = append([]uds.Option{uds.WithS3Timeout(time.Duration(cfg.S3TimeoutMs) * time.Millisecond)}, opts...)
	e := uds.New(opts...)
	svc := cfg.Services

	// Shared stores, used by several services.
	dids, err := did.NewStore(e, cfg.DIDs)
	if err != nil {
		return nil, fmt.Errorf("dids: %w", err)
	}
	mem, err := memory.New(cfg.Memory)
	if err != nil {
		return nil, fmt.Errorf("memory: %w", err)
	}

	steps := []step{
		{"diagnostic_session_control", func() error { return session.Register(e, svc.DiagnosticSessionControl) }},
		{"ecu_reset", func() error { return ecureset.Register(e, svc.ECUReset) }},
		{"security_access", func() error { return security.Register(e, svc.SecurityAccess) }},
		{"tester_present", func() error { return testerpresent.Register(e, svc.TesterPresent) }},
		{"read_data_by_identifier", func() error { return did.RegisterRead(e, svc.ReadDataByIdentifier, dids) }},
		{"write_data_by_identifier", func() error { return did.RegisterWrite(e, svc.WriteDataByIdentifier, dids) }},
		{"read_memory_by_address", func() error { return memory.RegisterRead(e, svc.ReadMemoryByAddress, mem) }},
		{"write_memory_by_address", func() error { return memory.RegisterWrite(e, svc.WriteMemoryByAddress, mem) }},
	}
	for _, s := range steps {
		if err := s.run(); err != nil {
			return nil, fmt.Errorf("%s: %w", s.name, err)
		}
	}
	return e, nil
}
