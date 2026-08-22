// Package uds implements the core of a configurable UDS (ISO 14229-1) server:
// request dispatching, generic validation, session and security state.
// Individual services live in the services sub-packages and are registered
// on an ECU with Register.
package uds

import (
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"time"
)

const defaultS3Timeout = 5000 * time.Millisecond

// ECU is a stateful UDS server. It is safe for concurrent use; every request
// is processed atomically.
type ECU struct {
	mu       sync.Mutex
	ctx      Context
	services map[byte]Service
}

// Option customizes an ECU.
type Option func(*ECU)

// WithClock replaces the time source (used by timers such as S3).
func WithClock(now func() time.Time) Option {
	return func(e *ECU) { e.ctx.now = now }
}

// WithRandom replaces the random source (used for security seeds).
func WithRandom(r io.Reader) Option {
	return func(e *ECU) { e.ctx.rand = r }
}

// WithS3Timeout sets the timeout after which a non-default session falls back
// to the default session. Non-positive values keep the default (5 s).
func WithS3Timeout(d time.Duration) Option {
	return func(e *ECU) {
		if d > 0 {
			e.ctx.s3Timeout = d
		}
	}
}

// New creates an ECU without services, in the default session.
func New(opts ...Option) *ECU {
	e := &ECU{
		ctx: Context{
			now:       time.Now,
			rand:      rand.Reader,
			s3Timeout: defaultS3Timeout,
			session:   SessionDefault,
		},
		services: make(map[byte]Service),
	}
	for _, opt := range opts {
		opt(e)
	}
	e.ctx.lastActivity = e.ctx.now()
	return e
}

// Register adds a service. It fails if the SID is already registered.
func (e *ECU) Register(svc Service) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, dup := e.services[svc.SID]; dup {
		return fmt.Errorf("service 0x%02X already registered", svc.SID)
	}
	if svc.Handle == nil {
		return fmt.Errorf("service 0x%02X has no handler", svc.SID)
	}
	e.services[svc.SID] = svc
	return nil
}

// OnSessionChange registers a listener called on every session transition.
func (e *ECU) OnSessionChange(fn func(from, to uint8)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ctx.sessionListeners = append(e.ctx.sessionListeners, fn)
}

// OnReset registers a listener called when the ECU is reset.
func (e *ECU) OnReset(fn func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ctx.resetListeners = append(e.ctx.resetListeners, fn)
}

// Do runs fn with the ECU locked, after applying pending timeouts.
func (e *ECU) Do(fn func(c *Context)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ctx.checkS3()
	fn(&e.ctx)
}

// Session returns the active diagnostic session.
func (e *ECU) Session() uint8 {
	var s uint8
	e.Do(func(c *Context) { s = c.Session() })
	return s
}

// SecurityLevel returns the unlocked security level, 0 if locked.
func (e *ECU) SecurityLevel() uint8 {
	var l uint8
	e.Do(func(c *Context) { l = c.SecurityLevel() })
	return l
}

// Handle processes a UDS request and returns the response. It returns nil when
// no response must be sent (suppressPosRspMsgIndicationBit or suppressed NRC
// on a functional request).
func (e *ECU) Handle(data []byte, functional bool) []byte {
	if len(data) == 0 {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.ctx.checkS3()
	resp, suppressPositive := e.dispatch(data)
	e.ctx.lastActivity = e.ctx.now()

	if isNegative(resp) {
		if functional && suppressedOnFunctional(resp[2]) {
			return nil
		}
		return resp
	}
	if suppressPositive {
		return nil
	}
	return resp
}

// dispatch applies the generic checks of ISO 14229-1 (figure 5) and hands the
// request to the service handler.
func (e *ECU) dispatch(data []byte) ([]byte, bool) {
	sid := data[0]
	svc, ok := e.services[sid]
	if !ok {
		return NegativeResponse(sid, NRCServiceNotSupported), false
	}
	if nrc := e.ctx.CheckAccess(svc.Access, NRCServiceNotSupportedInActiveSession); nrc != 0 {
		return NegativeResponse(sid, nrc), false
	}
	if len(data) < max(svc.MinLength, 1) || (svc.HasSubFunction && len(data) < 2) {
		return NegativeResponse(sid, NRCInvalidMessageLengthOrFormat), false
	}

	req := Request{SID: sid, Data: data}
	suppress := false
	if svc.HasSubFunction {
		req.SubFunction = data[1] &^ SuppressPosRspBit
		suppress = data[1]&SuppressPosRspBit != 0
	}
	return svc.Handle(&e.ctx, req), suppress
}
