# Copilot Instructions — Huawei ONT Firmware

## Context

Huawei ONT (Optical Network Terminal) firmware for HiSilicon ARM Cortex-A9 routers (HG8145V5, EG8145V5, HN8145XR, HG8245C family). Firmware uses HWNP format with `whwh`-wrapped partitions (U-Boot, Linux kernel, SquashFS rootfs). V500 firmwares use musl libc; V300 use uClibc.

## Analysis Tools

| Tool | Usage |
|------|-------|
| **Capstone** | ARM disassembly from Python — `import capstone; md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)` |
| **radare2** | Interactive binary analysis — `r2 -A binary`, then `afl`, `pdf @func`, `axt @sym.func` |
| **r2pipe** | Script radare2 from Python — `import r2pipe; r2 = r2pipe.open('binary')` |
| **qemu-arm-static** | Execute ARM binaries on x86 — required for `aescrypt2` chroot decryption |
| **qemu-system-arm** | Full system ARM emulation |
| **unsquashfs** | Extract SquashFS — `unsquashfs -f -d rootfs -no-xattrs -ignore-errors fw.sqfs` |
| **arm-linux-gnueabi-objdump** | ARM disassembly — `arm-linux-gnueabi-objdump -d binary` |
| **arm-linux-gnueabi-readelf** | ARM ELF inspection — `arm-linux-gnueabi-readelf -a binary` |
| **xxd** | Hex dump — `xxd -s 0x100 -l 64 binary` |

### Capstone Example

```python
import capstone
with open('bin/aescrypt2', 'rb') as f:
    code = f.read()
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
md.detail = True
for insn in md.disasm(code[offset:offset+256], base_address + offset):
    print(f"0x{insn.address:08x}: {insn.mnemonic}\t{insn.op_str}")
```

### radare2 Example

```bash
r2 -qc 'aaa; afl' bin/aescrypt2           # list functions
r2 -qc 'aaa; pdf @sym.main' bin/aescrypt2 # disassemble main
r2 -qc 'aaa; axt @sym.HW_XML_CFGFileSecurity' lib/libhw_ssp_basic.so  # xrefs
r2 -qc 'izz~kmc_store' bin/aescrypt2      # search strings
```

```python
import r2pipe
r2 = r2pipe.open('bin/aescrypt2')
r2.cmd('aaa')
for f in r2.cmdj('aflj'):
    print(f"{f['name']} at 0x{f['offset']:08x} ({f['size']} bytes)")
r2.quit()
```

## hw_ctree.xml Decryption

Encrypted with AES-256-CBC using mbedTLS `aescrypt2` format:
- **Header**: `AEST` magic (4B) + original size (4B) + IV (16B) + ciphertext + HMAC-SHA-256 (32B)
- **Key**: Hardware e-fuse → work key (flash) → PBKDF2 → AES-256-CBC
- **V500**: Key from `kmc_store_A`/`kmc_store_B` in `/etc/wap/`
- **V300**: Key from `prvt.key` + `EquipKey`
- **HN8145XR**: No `kmc_store` — create empty files in `/mnt/jffs2/` for fallback decryption

```bash
# Decrypt via qemu chroot
sudo cp /usr/bin/qemu-arm-static rootfs/usr/bin/
sudo chroot rootfs qemu-arm-static /bin/aescrypt2 1 /etc/wap/hw_ctree.xml /tmp/out.xml
gunzip /tmp/out.xml.gz

# HN8145XR fallback
mkdir -p rootfs/mnt/jffs2/
touch rootfs/mnt/jffs2/kmc_store_A rootfs/mnt/jffs2/kmc_store_B
sudo chroot rootfs qemu-arm-static /bin/aescrypt2 1 /etc/wap/hw_ctree.xml /tmp/out.xml
```

## SquashFS Extraction

```bash
unsquashfs -f -d rootfs -no-xattrs -ignore-errors firmware.sqfs
```

Flags `-no-xattrs -ignore-errors` required for V300 firmwares with device nodes.

## Private Keys

All V500 firmwares share identical `prvt.key` (MD5: `0de20c81fc6cf1d0d3607a1bd600f935`, AES-256-CBC PEM). Passphrase derived via `KMC_GetAppointKey` → `PBKDF2`, not a simple string.

## Configuration Files (`/etc/wap/`)

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

## Key ARM Binaries

| Binary | Description | Analyze with |
|--------|-------------|--------------|
| `/bin/aescrypt2` | Config encryption/decryption | `r2 -A bin/aescrypt2` |
| `/bin/cfgtool` | Config management API | `r2 -qc 'aaa; afl' bin/cfgtool` |
| `/lib/libhw_ssp_basic.so` | Core security functions | `arm-linux-gnueabi-readelf -s lib/libhw_ssp_basic.so` |
| `/lib/libhw_swm_dll.so` | Firmware signature verification | `r2 -qc 'aaa; ii' lib/libhw_swm_dll.so` |

## Firmware Signing

Certificate chain: e-fuse root → `app_cert.crt` (4096-bit RSA) → Code Signing CA 2 → Code Signing Cert 3. No private signing key in any binary. Verify with: `r2 -qc 'aaa; axt @sym.SWM_Sig_VerifySignature' lib/libhw_swm_dll.so`

## Configuration Flow

1,021+ XML elements, 3,208+ attributes, only 17 differ across firmwares.
- **Build**: gzip + AES-256-CBC
- **Boot**: decrypt → parse → DBInit
- **Save**: SetPara → DBSave → gzip + AES → flash
- **Key functions** (find with `r2`): `HW_CFGTOOL_Get/Set/Add/Del/CloneXMLValByPath`
