# godoip

A DoIP (ISO 13400-2) server in Go that simulates a single, fully configurable
UDS (ISO 14229-1) ECU for automotive diagnostics testing.

Everything the ECU does is driven by [`config.yaml`](config.yaml): which
services exist, which sessions and security levels they need, DIDs, DTCs,
routines and a memory image loaded from an S-Record / Intel HEX / binary file.

## Quick start

```sh
make run                          # go run ./cmd/server (uses ./config.yaml)
go run ./cmd/server -config path/to/config.yaml
make test                         # Go unit tests
make e2e                          # end-to-end tests with doipclient + udsoncan
```

## Implementation status

Legend: ✅ done · ⚠️ partial · ❌ not implemented

**Unit** = Go tests in the service package. **E2E** = verified over a real
DoIP connection with [`doipclient`](https://github.com/jacobschaer/python-doipclient)
and [`udsoncan`](https://github.com/pylessard/python-udsoncan) (`tests/e2e`).

### UDS services (ISO 14229-1)

| SID  | Service                          | Implemented | Unit | E2E | Notes |
|------|----------------------------------|:-----------:|:----:|:---:|-------|
| 0x10 | DiagnosticSessionControl         | ✅ | ✅ | ✅ | Custom sessions, P2/P2* timings, allowed transitions, S3 timeout |
| 0x11 | ECUReset                         | ✅ | ✅ | ✅ | Configurable reset types, rapid power shutdown (0x04/0x05) |
| 0x14 | ClearDiagnosticInformation       | ✅ | ✅ | ✅ | All, single DTC, user-defined groups |
| 0x19 | ReadDTCInformation               | ⚠️ | ✅ | ✅ | Report types 0x01–0x04, 0x06, 0x0A–0x0E, 0x14, 0x15 |
| 0x22 | ReadDataByIdentifier             | ✅ | ✅ | ✅ | Multiple DIDs per request, per-DID access |
| 0x23 | ReadMemoryByAddress              | ✅ | ✅ | ✅ | Backed by S-Record / Intel HEX / binary file, per-region access |
| 0x24 | ReadScalingDataByIdentifier      | ✅ | ✅ | ✅ | Per-DID scaling record, DID read access applies |
| 0x27 | SecurityAccess                   | ✅ | ✅ | ✅ | Fixed/random seeds, xor/add/not/fixed/seed algorithms, lockout |
| 0x28 | CommunicationControl             | ✅ | ✅ | ✅ | Control types 0x00–0x05, communication type filter, reset on default session |
| 0x29 | Authentication                   | ❌ |    |    | |
| 0x2A | ReadDataByPeriodicIdentifier     | ✅ | ✅ | ✅ | Slow/medium/fast rates, stop, message type 1/2, works with dynamic DIDs |
| 0x2C | DynamicallyDefineDataIdentifier  | ✅ | ✅ | ✅ | By identifier, by memory address, clear; computed at read time |
| 0x2E | WriteDataByIdentifier            | ✅ | ✅ | ✅ | Writes are visible to later reads; fixed/variable length, volatile DIDs |
| 0x2F | InputOutputControlByIdentifier   | ✅ | ✅ | ✅ | Per-DID control, all 4 parameters, enable mask, auto return on default session |
| 0x31 | RoutineControl                   | ✅ | ✅ | ✅ | Start/stop/results, timed routines, option-based cases, effects |
| 0x34 | RequestDownload                  | ✅ | ✅ | ✅ | Buffered, applied and persisted on RequestTransferExit |
| 0x35 | RequestUpload                    | ✅ | ✅ | ✅ | Reads from the memory image |
| 0x36 | TransferData                     | ✅ | ✅ | ✅ | Block sequence counter (wraps), repeated blocks, max block length |
| 0x37 | RequestTransferExit              | ✅ | ✅ | ✅ | Rejects incomplete transfers |
| 0x38 | RequestFileTransfer              | ❌ |    |    | |
| 0x3D | WriteMemoryByAddress             | ✅ | ✅ | ✅ | Persisted to a separate output file, the input file is never modified |
| 0x3E | TesterPresent                    | ✅ | ✅ | ✅ | |
| 0x83 | AccessTimingParameter            | ❌ |    |    | Withdrawn in ISO 14229-1:2020 |
| 0x84 | SecuredDataTransmission          | ❌ |    |    | |
| 0x85 | ControlDTCSetting                | ✅ | ✅ | ✅ | Blocks DTC status updates, re-enabled in default session |
| 0x86 | ResponseOnEvent                  | ❌ |    |    | |
| 0x87 | LinkControl                      | ✅ | ✅ | ✅ | Fixed/specific baudrate verification and transition |

### Generic UDS behaviour

| Feature                                                        | Implemented | Unit | E2E |
|----------------------------------------------------------------|:-----------:|:----:|:---:|
| ISO NRC order (0x11 → 0x7F → 0x33 → 0x13 → service checks)      | ✅ | ✅ | ✅ |
| Per-element access: sessions, security levels, forced NRC      | ✅ | ✅ | ✅ |
| suppressPosRspMsgIndicationBit                                 | ✅ | ✅ | ✅ |
| Functional addressing (NRC 0x11/0x12/0x31/0x7E/0x7F suppressed) | ✅ | ✅ | ✅ |
| S3 session timeout                                             | ✅ | ✅ | ✅ |
| Security relock on session change / reset                      | ✅ | ✅ | ✅ |
| Response pending (NRC 0x78) simulation, per service           | ✅ | ✅ | ✅ |

### DoIP (ISO 13400-2)

| Feature                                                      | Implemented | Unit | E2E | Notes |
|--------------------------------------------------------------|:-----------:|:----:|:---:|-------|
| Vehicle announcement on start-up (UDP)                       | ✅ | ✅ | ✅ | Enable/disable, count, interval, initial delay, destination |
| Vehicle identification request (0x0001)                      | ✅ | ✅ | ✅ | Also accepts default protocol version 0xFF |
| Vehicle identification request with EID / VIN (0x0002/0x0003) | ✅ | ✅ | ✅ | Answers only when EID/VIN match |
| DoIP entity status (0x4001/0x4002)                           | ✅ | ✅ | ✅ | Node type, max/open sockets, max data size |
| Diagnostic power mode (0x4003/0x4004)                        | ✅ | ✅ | ✅ | Configurable mode |
| Routing activation (0x0005/0x0006)                           | ✅ | ✅ | ✅ | Client address range, activation types, SA checks, max sockets |
| Alive check (0x0007/0x0008)                                  | ⚠️ | ✅ | ✅ | Answers client requests; the server never initiates alive checks |
| Diagnostic message + positive/negative ACK (0x8001-0x8003)   | ✅ | ✅ | ✅ | Physical and functional addressing |
| Generic header NACK (0x0000)                                 | ✅ | ✅ | ✅ | Pattern, unknown type, too large, invalid length (TCP and UDP) |
| Initial / general inactivity timers                          | ✅ | ✅ |    | |
| TLS (DoIP over port 3496)                                    | ❌ |    |    | |
| IPv6 / multicast announcements                               | ❌ |    |    | |

## Configuration overview

See [`config.yaml`](config.yaml) for a complete, commented example.

- `server`: DoIP settings. `logical_address` is both the DoIP entity and the
  ECU physical address; `functional_address` defaults to `0xE400`.
  `server.announcement` controls the start-up vehicle announcements
  (`enabled: false` to disable them); node type, power mode, socket limits,
  activation types and inactivity timers are configurable too.
- `ecu.services`: a service missing from this map is not supported (NRC 0x11);
  use `{}` to enable it with defaults. Every service accepts an `access` block
  and a `response_pending: {count, interval_ms}` block to simulate a slow ECU
  (NRC 0x78 before the final response).
- `access` (services, sessions, reset types, security levels, DIDs, memory
  regions, routines, DTC report types...):
  ```yaml
  access:
    sessions: [0x03]          # allowed active sessions (empty = any)
    security_levels: [0x01]   # one of these levels must be unlocked
    nrc: 0x22                 # always answer with this NRC
  ```
- `ecu.dids`: shared by 0x22 / 0x24 / 0x2C / 0x2E / 0x2F (and routine effects).
- `ecu.dtcs`: shared by 0x19 / 0x14 / 0x85 (and routine effects).
- `ecu.routines`: RoutineControl definitions.
- `ecu.memory`: firmware file used by 0x23 / 0x3D. Writes go to
  `output_file`, never to `file`.

## Project layout

```
cmd/server/                 entry point (config loading, wiring)
internal/config/            YAML configuration types
internal/doip/              DoIP message encoding/decoding
internal/transport/         UDP (announcements) and TCP (routing, diagnostics) servers
internal/memimage/          S-Record / Intel HEX / binary memory images
internal/uds/               UDS core: ECU, dispatcher, session/security state, access checks
internal/uds/udstest/       test helpers for services
internal/uds/services/      one package per service + services.New wiring them all
  session/ ecureset/ security/ testerpresent/ did/ dtc/ memory/ routine/
  iocontrol/ commcontrol/ linkcontrol/ transfer/ dddi/ periodic/
tests/e2e/                  pytest suite using doipclient + udsoncan
firmware/                   sample firmware for config.yaml
```

### Adding a service

1. Add its configuration type to `internal/config` and a field in `Services`.
2. Create `internal/uds/services/<name>/` with a `Register(e *uds.ECU, cfg ...)`
   function returning `nil` when `cfg` is nil, plus its tests.
3. Add one step to `internal/uds/services/services.go`.
4. Add an example to `config.yaml`, e2e tests and update the table above.
