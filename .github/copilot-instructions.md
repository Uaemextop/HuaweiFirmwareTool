# Copilot Instructions — HuaweiFirmwareTool

## Repository Summary

This repository contains tools for analyzing, extracting, and flashing Huawei ONT (Optical Network Terminal) firmware images. It targets HiSilicon ARM Cortex-A9 based routers (HG8145V5, EG8145V5, HN8145XR, HG8245C family).

## Languages & Frameworks

- **Python 3.12+** — all tools and the GUI application (`hwflash/`)
- **C** — decompiled `aescrypt2` (uses mbedTLS / `libmbedtls-dev`)
- **GitHub Actions** — CI/CD workflows

## Project Layout

```
hwflash/            GUI application (ttkbootstrap + customtkinter)
tools/              CLI analysis tools
  fw_extract.py       Extract SquashFS rootfs from HWNP firmware
  fw_ctree_extract.py Extract /etc/wap/ configs from firmware
  extract_web_ui.py   Extract web UI + configs for all firmwares
  download_firmwares.py  Download firmware images from releases
  config_analyzer.py  Compare configs across firmwares
  arm_disasm.py       ARM ELF disassembler (Capstone)
  nand_dump_analyze.py  Analyze HG8145V5 NAND dumps
decompiled/aescrypt2/  Re-implemented aescrypt2 (CMake + mbedTLS)
configs/            Extracted configuration XML files
tests/              pytest test suite
.github/workflows/  CI workflows
.github/agents/     Custom Copilot agents
```

## Build & Test

```bash
# Install Python dependencies
pip install -r hwflash/requirements.txt
pip install pytest capstone r2pipe

# Run tests (skip tkinter-dependent test)
python -m pytest tests/ -q --ignore=tests/testsync_engine.py

# Build decompiled aescrypt2
cd decompiled/aescrypt2 && cmake -B build && cmake --build build

# Build Windows EXE (CI only)
pyinstaller --onefile --windowed --name HuaweiFlash launcher.py
```

## Analysis Tools

The development environment (see `copilot-setup-steps.yml`, runs on `aapt` runner) provides:

| Tool | Usage |
|------|-------|
| **Capstone** (`pip install capstone`) | ARM disassembly — `tools/arm_disasm.py` uses it for PLT/GOT resolution and function analysis |
| **radare2** (`r2`) | Interactive binary analysis — use `r2 -A binary` for full analysis, `afl` to list functions, `pdf @func` to disassemble |
| **r2pipe** (`pip install r2pipe`) | Python scripting for radare2 — `import r2pipe; r2 = r2pipe.open('binary')` |
| **qemu-arm-static** | Execute ARM binaries — required for `aescrypt2` chroot decryption |
| **qemu-system-arm** | Full system ARM emulation |
| **unsquashfs** | Extract SquashFS rootfs from firmware images |
| **binutils-arm** | ARM cross-tools: `arm-linux-gnueabi-objdump`, `arm-linux-gnueabi-readelf` |
| **xxd** | Hex dump for binary inspection |

### Using Capstone for Binary Analysis

```python
import capstone
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
md.detail = True
for insn in md.disasm(code_bytes, base_address):
    print(f"0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
```

### Using radare2 for Binary Analysis

```bash
# Quick function list
r2 -qc 'aaa; afl' bin/aescrypt2

# Disassemble a function
r2 -qc 'aaa; pdf @sym.main' bin/aescrypt2

# Cross-references to a function
r2 -qc 'aaa; axt @sym.HW_XML_CFGFileSecurity' lib/libhw_ssp_basic.so

# Strings search
r2 -qc 'izz~password' bin/cfgtool
```

```python
# radare2 via Python
import r2pipe
r2 = r2pipe.open('bin/aescrypt2')
r2.cmd('aaa')
functions = r2.cmdj('aflj')
for f in functions:
    print(f"{f['name']} at 0x{f['offset']:08x} ({f['size']} bytes)")
```

## Firmware Architecture

- **Format**: HWNP (Huawei Network Package) with `whwh`-wrapped partitions (U-Boot, kernel, rootfs)
- **Kernel**: uImage + LZMA compressed Linux (ARM)
- **Rootfs**: SquashFS with LZMA/XZ compression, musl libc (V500) or uClibc (V300)
- **Web UI**: ASP-based pages in `/html/` directory
- **Config**: AES-256-CBC encrypted XML in `/etc/wap/hw_ctree.xml`

## hw_ctree.xml Decryption

The main configuration `hw_ctree.xml` uses mbedTLS `aescrypt2` format:

- **Header**: `AEST` magic (4B) + original size (4B) + IV (16B) + AES-256-CBC ciphertext + HMAC-SHA-256 (32B)
- **Key source**: Hardware e-fuse → work key (flash) → AES-256-CBC via PBKDF2
- **V500 firmwares**: Key material from `kmc_store_A`/`kmc_store_B` in `/etc/wap/`
- **V300 firmwares**: Key from `prvt.key` + `EquipKey`
- **HN8145XR**: No `kmc_store` (e-fuse derived at first boot). Create empty files in `/mnt/jffs2/` to trigger fallback decryption

```bash
# Decrypt with firmware's own aescrypt2 via qemu chroot
sudo chroot rootfs qemu-arm-static /bin/aescrypt2 1 /etc/wap/hw_ctree.xml /tmp/out.xml
# Output is gzip-compressed: gunzip out.xml.gz

# HN8145XR fallback trick
mkdir -p rootfs/mnt/jffs2/
touch rootfs/mnt/jffs2/kmc_store_A rootfs/mnt/jffs2/kmc_store_B
```

## SquashFS Extraction

```bash
# V300 firmwares need extra flags for device nodes
unsquashfs -f -d rootfs -no-xattrs -ignore-errors firmware.sqfs
```

## Private Keys

All V500 firmwares share identical `prvt.key` (MD5: `0de20c81fc6cf1d0d3607a1bd600f935`, AES-256-CBC PEM). Passphrase is derived via `KMC_GetAppointKey` → `PBKDF2`, not a simple string.

## Configuration Files in `/etc/wap/`

| File | Description |
|------|-------------|
| `hw_ctree.xml` | Main config tree (AES-encrypted) |
| `hw_default_ctree.xml` | Factory defaults (same encryption) |
| `hw_aes_tree.xml` | Schema for encrypted field paths |
| `hw_flashcfg.xml` | Flash/NAND partition layout |
| `hw_boardinfo` | Device identity (board ID, MACs) |
| `prvt.key` | Encrypted RSA private key |
| `kmc_store_A`/`kmc_store_B` | Key management material (V500) |
| `passwd` | System users and password hashes |

## Firmware Signing

Certificate chain: e-fuse root → `app_cert.crt` (4096-bit RSA) → Code Signing CA 2 → Code Signing Cert 3. No private signing key in any binary. Verification via `SWM_Sig_VerifySignature`.

## Conventions

- Use `defusedxml` for XML parsing (security)
- All file reads should handle `PermissionError` gracefully
- Config analysis uses unified XML path comparison (1,021 elements, 3,208 attributes, only 17 differ across firmwares)
- Use **Capstone** (`tools/arm_disasm.py`) for programmatic ARM disassembly with PLT resolution
- Use **radare2** for interactive binary exploration, cross-reference analysis, and string search
- Use **r2pipe** to script radare2 analysis from Python
