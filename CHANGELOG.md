# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **CRITICAL**: Updated Pillow from 10.2.0 to 10.3.0 to fix buffer overflow vulnerability (CVE-2024-28219)
  - Affected versions: < 10.3.0
  - Impact: Buffer overflow in image processing
  - Severity: High
  - Action: All users should update immediately

### Added
- Modern Python packaging with `pyproject.toml`
- Comprehensive linting configuration (`.pylintrc`, `.flake8`)
- Pinned dependency versions for reproducible builds
- Split requirements files (`requirements.txt`, `requirements-dev.txt`, `requirements-build.txt`)
- Complete testing infrastructure with pytest
- 16 comprehensive unit tests for firmware parsing module
- Type hints for `firmware.py` module (Python 3.8+ compatible)
- Extensive documentation:
  - API documentation (`docs/API.md`) - Complete API reference
  - Architecture documentation (`docs/ARCHITECTURE.md`) - System design overview
  - Development guide (`docs/DEVELOPMENT.md`) - Contributing guidelines
- Enhanced CI/CD workflow (`.github/workflows/test.yml`):
  - Python linting (flake8, pylint, black, isort)
  - Multi-platform testing (Ubuntu, Windows, macOS)
  - Multi-Python version testing (3.8-3.12)
  - Type checking with mypy
  - C++ builds for Linux and macOS
  - Security scanning (safety, bandit)
- Comprehensive README with badges, feature list, and usage examples
- CHANGELOG to track project changes

### Changed
- Reorganized project structure for better maintainability
- Updated `.gitignore` with comprehensive patterns
- Improved firmware.py code quality with type annotations
- Enhanced README with modern documentation and examples

### Improved
- Development workflow with clear guidelines
- Code quality standards and enforcement
- Testing coverage and test infrastructure
- Documentation completeness and accessibility
- CI/CD pipeline with automated quality checks

## [1.0.0] - Previous Release

### Features
- C++ firmware manipulation tools:
  - `hw_fmw` - Pack and unpack HWNP firmware files
  - `hw_sign` - Sign firmware with RSA-2048 keys
  - `hw_verify` - Verify firmware signatures
- Python GUI application (OBSC Tool):
  - Firmware flashing via OBSC protocol
  - Network adapter selection
  - Terminal access (Telnet/Serial)
  - Configuration encryption/decryption
  - Device information display
  - Memory dumping utilities
  - Modern UI with theme support
- HWNP firmware format parser
- OBSC protocol implementation
- Network transport layer (UDP)
- Cross-platform support (Windows, Linux, macOS)
- RSA-2048 firmware signing
- CRC32 validation
- GitHub Actions CI/CD for Windows builds

### C++ Tools
- CMake build system
- OpenSSL integration for cryptography
- zlib integration for compression
- Cross-platform compatibility layer (getopt)

### Python GUI
- Mixin-based architecture for modular tabs
- ttkbootstrap modern UI framework
- Multiple GUI tabs:
  - Firmware upload
  - Configuration presets
  - Settings management
  - Verification
  - Cryptographic operations
  - Terminal access
  - Memory dumping
  - Device information
  - Audit logging
- Dark/light theme support
- System tray integration
- Configuration preset management

## Versioning Strategy

This project uses [Semantic Versioning](https://semver.org/):

- **MAJOR** version: Incompatible API changes
- **MINOR** version: Backward-compatible functionality additions
- **PATCH** version: Backward-compatible bug fixes

## Types of Changes

- `Added` - New features
- `Changed` - Changes in existing functionality
- `Deprecated` - Soon-to-be removed features
- `Removed` - Removed features
- `Fixed` - Bug fixes
- `Security` - Vulnerability fixes

---

[Unreleased]: https://github.com/Uaemextop/HuaweiFirmwareTool/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Uaemextop/HuaweiFirmwareTool/releases/tag/v1.0.0
