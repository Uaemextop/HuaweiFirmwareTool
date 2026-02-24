# Development Guide

## Getting Started

### Prerequisites

**For Python Development:**
- Python 3.8 or later
- pip (Python package manager)
- Virtual environment tool (venv, virtualenv, or conda)

**For C++ Development:**
- CMake 3.12 or later
- C++17 compatible compiler (GCC 7+, Clang 5+, MSVC 2017+)
- OpenSSL development libraries
- zlib development libraries

### Setting Up Development Environment

#### 1. Clone the Repository

```bash
git clone https://github.com/Uaemextop/HuaweiFirmwareTool.git
cd HuaweiFirmwareTool
```

#### 2. Python Setup

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Install package in editable mode
pip install -e .
```

#### 3. C++ Setup

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get update
sudo apt-get install cmake g++ libssl-dev zlib1g-dev
cd cpp
mkdir build && cd build
cmake ..
make
```

**macOS:**
```bash
brew install cmake openssl@3 zlib
cd cpp
mkdir build && cd build
cmake .. -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
make
```

**Windows:**
```powershell
# Install vcpkg
vcpkg install openssl:x64-windows-static zlib:x64-windows-static

cd cpp
mkdir build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE="[vcpkg root]/scripts/buildsystems/vcpkg.cmake"
cmake --build . --config Release
```

## Project Structure

```
HuaweiFirmwareTool/
├── obsc_tool/              # Python package
│   ├── __init__.py
│   ├── main.py             # Main GUI application
│   ├── firmware.py         # HWNP firmware parser
│   ├── protocol.py         # OBSC protocol implementation
│   ├── network.py          # Network transport layer
│   ├── terminal.py         # Terminal clients
│   ├── config_crypto.py    # Cryptographic utilities
│   ├── presets.py          # Configuration presets
│   ├── splash.py           # Splash screen
│   └── gui/                # GUI modules
│       ├── upgrade_tab.py
│       ├── presets_tab.py
│       ├── settings_tab.py
│       └── ... (other tabs)
├── cpp/                    # C++ tools
│   ├── CMakeLists.txt
│   ├── hw_fmw.cpp          # Firmware pack/unpack
│   ├── hw_sign.cpp         # Firmware signing
│   ├── hw_verify.cpp       # Signature verification
│   └── util_*.cpp/hpp      # Utility libraries
├── tests/                  # Test suite
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── docs/                   # Documentation
│   ├── API.md
│   ├── ARCHITECTURE.md
│   └── DEVELOPMENT.md (this file)
├── tools/                  # Analysis utilities
├── pyproject.toml          # Python project configuration
├── requirements.txt        # Python dependencies
├── requirements-dev.txt    # Development dependencies
└── README.md
```

## Development Workflow

### 1. Creating a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Making Changes

Follow these guidelines:
- Write clean, readable code
- Add docstrings to functions and classes
- Follow PEP 8 style guide for Python
- Add unit tests for new functionality
- Update documentation as needed

### 3. Running Tests

```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/unit/test_firmware.py

# Run with coverage
pytest tests/ --cov=obsc_tool --cov-report=html

# View coverage report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
start htmlcov/index.html  # Windows
```

### 4. Code Quality Checks

```bash
# Format code with black
black obsc_tool/

# Sort imports with isort
isort obsc_tool/

# Lint with flake8
flake8 obsc_tool/

# Lint with pylint
pylint obsc_tool/

# Type check with mypy
mypy obsc_tool/

# Run all checks at once
black obsc_tool/ && isort obsc_tool/ && flake8 obsc_tool/ && pylint obsc_tool/
```

### 5. Committing Changes

```bash
git add .
git commit -m "feat: Add feature description"
```

**Commit Message Format:**
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Formatting changes
- `refactor:` Code refactoring
- `test:` Adding tests
- `chore:` Maintenance tasks

### 6. Pushing Changes

```bash
git push origin feature/your-feature-name
```

### 7. Creating Pull Request

1. Go to GitHub repository
2. Click "New Pull Request"
3. Select your feature branch
4. Add description of changes
5. Submit for review

## Testing Guidelines

### Writing Unit Tests

Place unit tests in `tests/unit/` directory:

```python
# tests/unit/test_mymodule.py
import pytest
from obsc_tool.mymodule import MyClass

class TestMyClass:
    def test_initialization(self):
        obj = MyClass()
        assert obj is not None

    def test_method(self):
        obj = MyClass()
        result = obj.some_method(42)
        assert result == 84
```

### Writing Integration Tests

Place integration tests in `tests/integration/` directory:

```python
# tests/integration/test_firmware_workflow.py
from obsc_tool.firmware import HWNPFirmware
from obsc_tool.protocol import OBSCProtocol

def test_complete_workflow(tmp_path):
    # Create test firmware
    fw_path = tmp_path / "test.bin"
    create_test_firmware(fw_path)

    # Load and parse
    fw = HWNPFirmware()
    fw.load(str(fw_path))

    # Validate
    assert fw.item_count > 0
```

### Test Fixtures

Store test data in `tests/fixtures/`:

```python
import pytest

@pytest.fixture
def sample_firmware_path():
    return "tests/fixtures/sample_firmware.bin"

def test_with_fixture(sample_firmware_path):
    # Use fixture
    pass
```

## Code Style Guide

### Python Style

Follow PEP 8 with these specifics:
- Line length: 100 characters
- Indentation: 4 spaces
- Quotes: Use double quotes for strings
- Imports: Sort with isort (black profile)

**Example:**

```python
"""Module docstring."""

import os
from typing import List, Optional

from obsc_tool.firmware import HWNPFirmware


class MyClass:
    """Class docstring.

    Attributes:
        value: Description of value attribute.
    """

    def __init__(self, value: int):
        """Initialize MyClass.

        Args:
            value: Initial value.
        """
        self.value = value

    def process(self, data: bytes) -> Optional[List[int]]:
        """Process data and return results.

        Args:
            data: Input data to process.

        Returns:
            List of processed integers, or None if processing fails.

        Raises:
            ValueError: If data is invalid.
        """
        if not data:
            raise ValueError("Data cannot be empty")
        return [ord(c) for c in data.decode('ascii')]
```

### C++ Style

- Use C++17 features where appropriate
- Line length: 100 characters
- Indentation: 4 spaces
- Naming: snake_case for functions/variables, PascalCase for classes
- Use `const` and `constexpr` where possible
- Prefer smart pointers over raw pointers

**Example:**

```cpp
#include <string>
#include <vector>
#include <memory>

class FirmwareParser {
public:
    FirmwareParser(const std::string& path);
    ~FirmwareParser() = default;

    bool parse();
    std::vector<uint8_t> get_data() const;

private:
    std::string file_path_;
    std::unique_ptr<std::vector<uint8_t>> data_;
};
```

## Debugging

### Python Debugging

**Using pdb:**
```python
import pdb

def problematic_function():
    x = 42
    pdb.set_trace()  # Breakpoint
    y = x * 2
    return y
```

**Using IDE:**
- VS Code: Set breakpoints and use F5
- PyCharm: Set breakpoints and use Debug

### C++ Debugging

**GDB (Linux/macOS):**
```bash
cd cpp/build
gdb ./hw_fmw
(gdb) break main
(gdb) run -u firmware.bin output/
(gdb) next
```

**LLDB (macOS):**
```bash
lldb ./hw_fmw
(lldb) breakpoint set --name main
(lldb) run -u firmware.bin output/
```

**Visual Studio (Windows):**
Open solution, set breakpoints, press F5

## Performance Profiling

### Python Profiling

**cProfile:**
```python
import cProfile
import pstats

profiler = cProfile.Profile()
profiler.enable()

# Code to profile
fw = HWNPFirmware()
fw.load("firmware.bin")

profiler.disable()
stats = pstats.Stats(profiler)
stats.sort_stats('cumulative')
stats.print_stats(20)
```

**line_profiler:**
```bash
pip install line_profiler
kernprof -l -v script.py
```

### C++ Profiling

**Valgrind (Linux):**
```bash
valgrind --tool=callgrind ./hw_fmw -u firmware.bin out/
kcachegrind callgrind.out.*
```

**perf (Linux):**
```bash
perf record ./hw_fmw -u firmware.bin out/
perf report
```

## Building Executables

### Python Executable

```bash
# Install build dependencies
pip install -r requirements-build.txt

# Build with PyInstaller
pyinstaller run_obsc_tool.py \
    --onefile \
    --windowed \
    --name "OBSCFirmwareTool" \
    --add-data "obsc_tool:obsc_tool"

# Output in dist/
```

### C++ Executables

```bash
cd cpp/build
cmake --build . --config Release

# Executables:
# - hw_fmw (firmware pack/unpack)
# - hw_sign (firmware signing)
# - hw_verify (signature verification)
```

## Continuous Integration

CI/CD workflows run on GitHub Actions:

### Test Workflow (`.github/workflows/test.yml`)
- Runs on: push, pull_request
- Jobs:
  - Python linting (flake8, pylint, black, isort)
  - Python tests (pytest) on multiple OS/Python versions
  - Type checking (mypy)
  - C++ builds (Linux, macOS, Windows)
  - Security scanning (safety, bandit)

### Build Workflow (`.github/workflows/build.yml`)
- Runs on: push, pull_request, tags
- Jobs:
  - Build Windows executable with PyInstaller
  - Build C++ tools for Windows
  - Upload artifacts
  - Create releases on tags

## Common Tasks

### Adding a New Python Module

1. Create module in `obsc_tool/`:
```python
# obsc_tool/newmodule.py
"""New module description."""

class NewClass:
    """New class description."""
    pass
```

2. Add tests:
```python
# tests/unit/test_newmodule.py
from obsc_tool.newmodule import NewClass

def test_new_class():
    obj = NewClass()
    assert obj is not None
```

3. Update documentation in `docs/API.md`

### Adding a New GUI Tab

1. Create tab mixin in `obsc_tool/gui/`:
```python
# obsc_tool/gui/newtab.py
import tkinter as tk
from tkinter import ttk

class NewTabMixin:
    def create_new_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="New Tab")
        # Add widgets
```

2. Add mixin to main app:
```python
# obsc_tool/main.py
from obsc_tool.gui.newtab import NewTabMixin

class OBSCToolApp(tk.Tk, ..., NewTabMixin):
    def __init__(self):
        super().__init__()
        self.create_new_tab()
```

### Adding a New C++ Tool

1. Create source file:
```cpp
// cpp/hw_newtool.cpp
#include <iostream>
#include "util.hpp"

int main(int argc, char** argv) {
    // Implementation
    return 0;
}
```

2. Update CMakeLists.txt:
```cmake
add_executable(hw_newtool hw_newtool.cpp util.cpp)
target_link_libraries(hw_newtool OpenSSL::Crypto ZLIB::ZLIB)
```

## Troubleshooting

### Common Issues

**Issue: Import errors when running tests**
```bash
# Solution: Install package in editable mode
pip install -e .
```

**Issue: CMake can't find OpenSSL**
```bash
# Linux: Install dev package
sudo apt-get install libssl-dev

# macOS: Specify path
cmake .. -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)

# Windows: Use vcpkg
```

**Issue: PyInstaller executable fails**
```bash
# Solution: Add hidden imports
pyinstaller --hidden-import module_name ...
```

## Getting Help

- GitHub Issues: https://github.com/Uaemextop/HuaweiFirmwareTool/issues
- Documentation: See `docs/` directory
- Code Examples: See `tests/` directory

## Contributing

See [Contributing Guidelines](CONTRIBUTING.md) for more details on:
- Code of conduct
- Pull request process
- Coding standards
- Review process
