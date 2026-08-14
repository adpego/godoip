package uds

import (
	"crypto/rand"
	"fmt"
	"io"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/adpego/godoip/internal/config"
)

const defaultS3Timeout = 5000 * time.Millisecond

// ECU is a stateful UDS server built from configuration. It is safe for
// concurrent use; every request is processed atomically.
type ECU struct {
	mu   sync.Mutex
	now  func() time.Time
	rand io.Reader

	name         string
	s3Timeout    time.Duration
	services     map[byte]*service
	lastActivity time.Time

	// Session state.
	session  uint8
	sessions map[uint8]sessionInfo

	// Security state.
	security       securityState
	securityLevels map[uint8]*securityLevel

	// Data identifiers.
	dids           map[uint16]*did
	maxDIDsPerRead int
}

// Option customizes an ECU.
type Option func(*ECU)

// WithClock replaces the time source (used by timers such as S3).
func WithClock(now func() time.Time) Option {
	return func(e *ECU) { e.now = now }
}

// WithRandom replaces the random source (used for security seeds).
func WithRandom(r io.Reader) Option {
	return func(e *ECU) { e.rand = r }
}

// request is a decoded UDS request handed to service handlers.
type request struct {
	sid         byte
	subFunction byte // without the suppressPosRsp bit; only for services with sub-functions
	data        []byte
}

type handlerFunc func(e *ECU, req request) []byte

// service is a registered UDS service with its generic validation settings.
type service struct {
	access         config.Access
	minLen         int // minimum request length, SID included
	hasSubFunction bool
	handle         handlerFunc
}

// serviceBuilder sets up one UDS service from configuration. It returns
// (nil, nil) when the service is not enabled.
type serviceBuilder func(e *ECU, cfg config.ECU) (*service, error)

var serviceBuilders = map[byte]serviceBuilder{
	SIDDiagnosticSessionControl: buildSessionControl,
	SIDSecurityAccess:           buildSecurityAccess,
	SIDReadDataByIdentifier:     buildReadDID,
	SIDWriteDataByIdentifier:    buildWriteDID,
	SIDTesterPresent:            buildTesterPresent,
}

// NewECU builds an ECU from its configuration.
func NewECU(cfg config.ECU, opts ...Option) (*ECU, error) {
	e := &ECU{
		now:       time.Now,
		rand:      rand.Reader,
		name:      cfg.Name,
		s3Timeout: defaultS3Timeout,
		services:  make(map[byte]*service),
		session:   SessionDefault,
		sessions:  defaultSessions(),
		security:  newSecurityState(),
	}
	for _, opt := range opts {
		opt(e)
	}
	if cfg.S3TimeoutMs > 0 {
		e.s3Timeout = time.Duration(cfg.S3TimeoutMs) * time.Millisecond
	}

	var err error
	if e.dids, err = newDIDStore(cfg.DIDs); err != nil {
		return nil, err
	}

	for _, sid := range slices.Sorted(maps.Keys(serviceBuilders)) {
		svc, err := serviceBuilders[sid](e, cfg)
		if err != nil {
			return nil, fmt.Errorf("service 0x%02X: %w", sid, err)
		}
		if svc != nil {
			e.services[sid] = svc
		}
	}
	e.lastActivity = e.now()
	return e, nil
}

// Name returns the configured ECU name.
func (e *ECU) Name() string { return e.name }

// Session returns the active diagnostic session.
func (e *ECU) Session() uint8 {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.checkS3()
	return e.session
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

	e.checkS3()
	resp, suppressPositive := e.dispatch(data)
	e.lastActivity = e.now()

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
		return negativeResponse(sid, NRCServiceNotSupported), false
	}
	if nrc := e.checkAccess(svc.access, NRCServiceNotSupportedInActiveSession); nrc != 0 {
		return negativeResponse(sid, nrc), false
	}
	if len(data) < svc.minLen {
		return negativeResponse(sid, NRCInvalidMessageLengthOrFormat), false
	}

	req := request{sid: sid, data: data}
	suppress := false
	if svc.hasSubFunction {
		req.subFunction = data[1] &^ suppressPosRspBit
		suppress = data[1]&suppressPosRspBit != 0
	}
	return svc.handle(e, req), suppress
}
