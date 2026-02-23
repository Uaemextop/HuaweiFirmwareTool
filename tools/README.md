# Analysis Tools

This directory contains tools for analyzing firmware and related executables.

## analyze_exe.py

A Python script for performing static analysis on Windows PE executables.

### Features

- PE header parsing (DOS, COFF, Optional headers)
- Section analysis with detailed characteristics
- String extraction and filtering
- Packer detection
- Entropy calculation
- Import/export analysis

### Usage

```bash
python3 tools/analyze_exe.py <exe_file> [exe_file2 ...]
```

### Example

```bash
python3 tools/analyze_exe.py firmware_tool.exe
```

### Requirements

- Python 3.x
- No external dependencies (uses only standard library)

### Output

The tool provides:
- File size and basic information
- PE header details (machine type, timestamp, characteristics)
- Section breakdown with flags
- Interesting strings (filtered by keywords)
- Packer detection
- Entropy analysis (indicates compression/encryption)

### Entropy Scale

- 0-6.5: Normal executable code
- 6.5-7.5: Possibly packed
- 7.5-8.0: Likely compressed or encrypted

## Related Documentation

See [EXE_ANALYSIS_REPORT.md](../EXE_ANALYSIS_REPORT.md) for a complete analysis of Huawei ONT firmware tools.
