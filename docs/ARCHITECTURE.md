# Architecture Documentation

## Overview

HuaweiFirmwareTool is a comprehensive toolset for working with Huawei ONT (Optical Network Terminal) firmware. The project consists of two main components:

1. **C++ Core Tools**: Low-level firmware manipulation utilities
2. **Python GUI Application**: User-friendly interface for firmware flashing via OBSC protocol

## Architecture Layers

```
┌─────────────────────────────────────────────────┐
│           GUI Layer (Python/Tkinter)            │
│  - Main Application (obsc_tool/main.py)         │
│  - Tab Mixins (obsc_tool/gui/*.py)              │
└─────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────┐
│         Business Logic Layer (Python)           │
│  - Protocol Implementation (protocol.py)        │
│  - Firmware Parser (firmware.py)                │
│  - Network Transport (network.py)               │
│  - Terminal Clients (terminal.py)               │
└─────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────┐
│      System Interfaces & External Tools         │
│  - UDP/Serial Communications                    │
│  - C++ Firmware Tools (hw_fmw, hw_sign, etc.)   │
│  - Cryptographic Libraries (OpenSSL)            │
└─────────────────────────────────────────────────┘
```

## Component Details

### 1. C++ Firmware Tools

Located in `cpp/` directory, these provide low-level firmware operations:

#### hw_fmw - Firmware Pack/Unpack
- **Purpose**: Extract and repack HWNP firmware files
- **Operations**:
  - Unpack: Extract firmware items from .bin file
  - Pack: Create HWNP package from individual items
- **Key Classes**: `Firmware` (util_hw.cpp)

#### hw_sign - Firmware Signing
- **Purpose**: Sign firmware with RSA private key
- **Algorithm**: RSA-2048 with SHA-256
- **Key Classes**: `RSAKey` (util_rsa.cpp)

#### hw_verify - Signature Verification
- **Purpose**: Verify firmware signatures
- **Validation**: RSA public key verification

### 2. Python GUI Application

#### Main Application (obsc_tool/main.py)
- **Pattern**: Mixin-based architecture
- **Base Class**: `OBSCToolApp(tk.Tk, ...Mixins)`
- **Mixins**: 11 tab mixins for different functionality
- **State Management**: Instance attributes (needs improvement)

#### Core Modules

**firmware.py** - HWNP Parser
```python
HWNPFirmware
├── load(file_path) → Parse firmware file
├── validate_crc32() → Verify checksums
├── get_info() → Extract metadata
└── items: List[HWNPItem] → Firmware components
```

**protocol.py** - OBSC Protocol
```python
OBSCProtocol
├── Packet Types:
│   ├── OBSCFlashRequest
│   ├── OBSCFlashResponse
│   ├── OBSCDataPacket
│   └── OBSCChecksumRequest
├── State Machine:
│   ├── INIT → AUTHENTICATE → TRANSFER → VERIFY → COMPLETE
└── Frame Format: [Header][Type][Length][Data][CRC32]
```

**network.py** - Network Layer
```python
NetworkAdapter
├── discover_adapters() → Find network interfaces
├── UDPTransport → Send/receive packets
└── Platform-specific implementations (Windows/Linux)
```

**terminal.py** - Device Access
```python
TelnetClient → Telnet-based device access
SerialClient → Serial port communication
```

### 3. GUI Layer Architecture

#### Current Architecture (Mixin Pattern)
```python
OBSCToolApp(
    tk.Tk,
    UpgradeTabMixin,      # Firmware upload
    PresetsTabMixin,      # Configuration presets
    SettingsTabMixin,     # Application settings
    VerificationTabMixin, # Firmware verification
    CryptoTabMixin,       # Cryptographic operations
    TerminalTabMixin,     # Terminal access
    DumpTabMixin,         # Memory dumping
    InfoTabMixin,         # Device information
    LogTabMixin,          # Audit logging
    ThemeMixin,           # Theme management
    AdaptersMixin         # Network adapter selection
)
```

**Issues with Current Design**:
- Heavy coupling (11 mixins)
- State scattered across mixins
- Hard to test
- Complex inheritance chain

**Recommended Refactoring**:
```python
# Controller pattern
AppController
├── UIManager → Manage UI components
├── StateManager → Centralized state
├── ProtocolHandler → OBSC operations
└── DeviceManager → Device communication
```

## Data Flow

### Firmware Upload Flow

```
User Selects Firmware
        ↓
HWNPFirmware.load(path) → Parse .bin file
        ↓
Validate CRC32 checksums
        ↓
User Selects Network Adapter
        ↓
UDPTransport.connect(adapter, device_ip)
        ↓
OBSCProtocol.authenticate(device)
        ↓
For each HWNPItem:
    OBSCProtocol.send_data_packet(item.data)
    Wait for acknowledgment
        ↓
OBSCProtocol.send_checksum_request()
        ↓
Device validates and flashes firmware
        ↓
Complete
```

### Protocol State Machine

```
┌──────┐  authenticate  ┌────────────┐
│ INIT │───────────────→│ AUTH_SENT  │
└──────┘                └────────────┘
                              ↓ response OK
                        ┌────────────┐
                        │   READY    │
                        └────────────┘
                              ↓ flash_request
                        ┌────────────┐
                        │ FLASHING   │←──┐
                        └────────────┘   │
                              ↓ data_packet
                        ┌────────────┐   │
                        │ TRANSFERRING│───┘
                        └────────────┘
                              ↓ all sent
                        ┌────────────┐
                        │ VERIFYING  │
                        └────────────┘
                              ↓ checksum OK
                        ┌────────────┐
                        │  COMPLETE  │
                        └────────────┘
```

## Security Considerations

### Cryptographic Operations

1. **Firmware Signing**:
   - RSA-2048 keys
   - SHA-256 hashing
   - PKCS#1 v1.5 padding
   - OpenSSL library

2. **Configuration Encryption**:
   - AES-256-ECB (config_crypto.py)
   - Base64 encoding
   - Device-specific keys

3. **CRC32 Validation**:
   - zlib.crc32 for data integrity
   - Header and data checksums

### Network Security

**Current State**:
- UDP protocol (no encryption)
- No authentication beyond initial handshake
- Broadcast-based device discovery

**Recommendations**:
- Add TLS/DTLS for UDP
- Implement device certificates
- Add replay attack prevention

## Build System

### Python Build
```bash
# Development
pip install -e .[dev]

# Production
pip install .

# Executable
pip install .[build]
pyinstaller run_obsc_tool.py
```

### C++ Build
```bash
mkdir build && cd build
cmake ..
make
# Outputs: hw_fmw, hw_sign, hw_verify
```

## Testing Strategy

### Unit Tests
- `tests/unit/test_firmware.py` - HWNP parsing
- `tests/unit/test_protocol.py` - OBSC protocol (TODO)
- `tests/unit/test_crypto.py` - Cryptographic operations (TODO)

### Integration Tests
- End-to-end firmware upload
- Device communication
- Protocol state transitions

### Test Coverage Goals
- Core modules: >80%
- GUI modules: >50%
- Overall: >70%

## Performance Considerations

### Bottlenecks
1. **Firmware Parsing**: Linear scan of large files
2. **UDP Transfer**: No pipelining, ACK per packet
3. **GUI Updates**: Blocking operations on main thread

### Optimizations
1. Use memory-mapped files for large firmware
2. Implement sliding window protocol
3. Move network I/O to worker threads

## Extension Points

### Adding New Device Types
1. Create device profile in `presets.py`
2. Add device-specific packet handlers in `protocol.py`
3. Update GUI device selection

### Adding New Protocols
1. Implement protocol class inheriting from base
2. Register in `protocol.py`
3. Add GUI tab if needed

### Plugin Architecture (Future)
```python
class ProtocolPlugin:
    def __init__(self, transport):
        self.transport = transport

    def authenticate(self, credentials):
        raise NotImplementedError

    def transfer_firmware(self, firmware):
        raise NotImplementedError
```

## Dependencies

### Critical Dependencies
- **ttkbootstrap**: GUI framework
- **pyserial**: Serial communication
- **pycryptodome**: Cryptographic operations
- **netifaces**: Network interface enumeration

### Optional Dependencies
- **matplotlib**: Visualization (minimal use)
- **qrcode**: QR code generation (optional feature)
- Theme libraries: Can be reduced

## Known Issues

1. **No Linux/macOS CI**: Only Windows builds tested
2. **No Unit Tests**: Critical gap in quality assurance
3. **State Management**: Scattered across GUI
4. **Error Recovery**: Failed transfers not recoverable
5. **Thread Safety**: GUI updates from worker threads

## Future Improvements

### Phase 1: Code Quality
- [ ] Add comprehensive unit tests
- [ ] Implement type hints
- [ ] Add linting to CI/CD
- [ ] Create API documentation

### Phase 2: Architecture
- [ ] Refactor GUI to Controller pattern
- [ ] Implement State Manager
- [ ] Create plugin system
- [ ] Add event bus for component communication

### Phase 3: Features
- [ ] Add TLS/DTLS support
- [ ] Implement firmware validation
- [ ] Add rollback mechanism
- [ ] Create REST API for automation

### Phase 4: Performance
- [ ] Memory-mapped file I/O
- [ ] Implement packet pipelining
- [ ] Optimize CRC32 calculation
- [ ] Add progress streaming

## References

- HWNP Format: See `ANALISIS_EXE.md`
- OBSC Protocol: See `obsc_tool/README.md`
- Build Instructions: See `README.md`
