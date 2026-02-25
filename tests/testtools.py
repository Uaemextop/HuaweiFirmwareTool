"""Tests for firmware extraction and ARM disassembly tools."""

import os
import struct
import tempfile
import pytest

# ── fw_extract tests ─────────────────────────────────────────────────────────

from tools.fw_extract import find_squashfs

# Minimal SquashFS superblock (little-endian):
#   bytes  0-3:  magic  "hsqs"
#   bytes 40-47: bytes_used (u64 LE)
_SQFS_HEADER = bytearray(48)
_SQFS_HEADER[0:4] = b"hsqs"
struct.pack_into("<Q", _SQFS_HEADER, 40, 48)  # bytes_used = 48 (self-referential)


class TestFindSquashfs:
    """Tests for find_squashfs()."""

    def test_no_squashfs_in_empty_data(self):
        assert find_squashfs(b"\x00" * 128) == []

    def test_single_squashfs(self):
        data = b"\x00" * 100 + bytes(_SQFS_HEADER) + b"\x00" * 100
        result = find_squashfs(data)
        assert len(result) == 1
        offset, size = result[0]
        assert offset == 100
        assert size == 48

    def test_multiple_squashfs_sorted_by_size(self):
        # First image: 48 bytes
        hdr1 = bytearray(48)
        hdr1[0:4] = b"hsqs"
        struct.pack_into("<Q", hdr1, 40, 48)

        # Second image: 96 bytes (larger)
        hdr2 = bytearray(96)
        hdr2[0:4] = b"hsqs"
        struct.pack_into("<Q", hdr2, 40, 96)

        data = bytes(hdr1) + b"\x00" * 100 + bytes(hdr2)
        result = find_squashfs(data)
        # Sorted by size descending, so largest first
        assert len(result) == 2
        assert result[0][1] >= result[1][1]


# ── arm_disasm tests ─────────────────────────────────────────────────────────

from tools.arm_disasm import parse_elf32, _read_str, ElfInfo


def _make_minimal_elf32() -> bytes:
    """Build a minimal 32-bit ARM ELF with a .text section."""
    # ELF header (52 bytes)
    ehdr = bytearray(52)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 1    # EI_CLASS = 32-bit
    ehdr[5] = 1    # EI_DATA = little-endian
    ehdr[6] = 1    # EI_VERSION
    struct.pack_into("<H", ehdr, 16, 2)     # e_type = ET_EXEC
    struct.pack_into("<H", ehdr, 18, 0x28)  # e_machine = ARM
    struct.pack_into("<I", ehdr, 24, 0x100) # e_entry
    struct.pack_into("<H", ehdr, 46, 40)    # e_shentsize

    # Section header string table
    shstrtab = b"\x00.text\x00.shstrtab\x00.dynsym\x00.dynstr\x00"

    # .text: 4 bytes of NOP (ARM: 0xe1a00000)
    text_data = b"\x00\x00\xa0\xe1"

    # Layout: ehdr(52) + text(4@52) + shstrtab(@56)
    text_off = 52
    shstrtab_off = text_off + len(text_data)
    shdr_off = shstrtab_off + len(shstrtab)

    # 3 section headers: null + .text + .shstrtab
    # Null section header
    null_sh = bytearray(40)

    # .text section header
    text_name_idx = shstrtab.index(b".text")
    text_sh = bytearray(40)
    struct.pack_into("<I", text_sh, 0, text_name_idx)  # sh_name
    struct.pack_into("<I", text_sh, 4, 1)              # sh_type = SHT_PROGBITS
    struct.pack_into("<I", text_sh, 12, 0x100)         # sh_addr
    struct.pack_into("<I", text_sh, 16, text_off)      # sh_offset
    struct.pack_into("<I", text_sh, 20, len(text_data)) # sh_size

    # .shstrtab section header
    shstr_name_idx = shstrtab.index(b".shstrtab")
    shstr_sh = bytearray(40)
    struct.pack_into("<I", shstr_sh, 0, shstr_name_idx) # sh_name
    struct.pack_into("<I", shstr_sh, 4, 3)              # sh_type = SHT_STRTAB
    struct.pack_into("<I", shstr_sh, 16, shstrtab_off)  # sh_offset
    struct.pack_into("<I", shstr_sh, 20, len(shstrtab)) # sh_size

    struct.pack_into("<I", ehdr, 32, shdr_off)  # e_shoff
    struct.pack_into("<H", ehdr, 48, 3)         # e_shnum
    struct.pack_into("<H", ehdr, 50, 2)         # e_shstrndx

    return bytes(ehdr) + text_data + shstrtab + bytes(null_sh) + bytes(text_sh) + bytes(shstr_sh)


class TestReadStr:
    """Tests for _read_str() helper."""

    def test_reads_null_terminated(self):
        data = b"hello\x00world\x00"
        assert _read_str(data, 0) == "hello"
        assert _read_str(data, 6) == "world"

    def test_empty_string(self):
        data = b"\x00stuff"
        assert _read_str(data, 0) == ""


class TestParseElf32:
    """Tests for parse_elf32()."""

    def test_minimal_elf(self):
        data = _make_minimal_elf32()
        info = parse_elf32(data)
        assert info.entry == 0x100
        assert ".text" in info.sections
        assert info.sections[".text"].addr == 0x100

    def test_rejects_non_elf(self):
        with pytest.raises(AssertionError):
            parse_elf32(b"\x00" * 52)


# ── aescrypt2 decompiled binary integration test ─────────────────────────────

class TestAescrypt2Build:
    """Verify the decompiled aescrypt2 binary compiles and round-trips."""

    BUILD_DIR = os.path.join(
        os.path.dirname(__file__), "..", "decompiled", "aescrypt2", "build"
    )
    BINARY = os.path.join(BUILD_DIR, "aescrypt2")

    @pytest.fixture(autouse=True)
    def _check_binary(self):
        if not os.path.isfile(self.BINARY):
            pytest.skip("aescrypt2 binary not built (run cmake in decompiled/aescrypt2)")

    def test_usage_output(self):
        import subprocess
        result = subprocess.run([self.BINARY], capture_output=True, text=True)
        assert "aescrypt2 <mode>" in result.stdout or "aescrypt2 <mode>" in result.stderr

    def test_encrypt_decrypt_roundtrip(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            plain = os.path.join(tmp, "plain.txt")
            enc = os.path.join(tmp, "enc.aes")
            dec = os.path.join(tmp, "dec.txt")

            with open(plain, "w") as f:
                f.write("Test data for round-trip verification\n")

            # Encrypt
            ret = subprocess.run(
                [self.BINARY, "0", plain, enc, "testkey"],
                capture_output=True,
            )
            assert ret.returncode == 0, ret.stderr.decode()
            assert os.path.isfile(enc)

            # Check AEST magic
            with open(enc, "rb") as f:
                magic = f.read(4)
            assert magic == b"AEST"

            # Decrypt
            ret = subprocess.run(
                [self.BINARY, "1", enc, dec, "testkey"],
                capture_output=True,
            )
            assert ret.returncode == 0, ret.stderr.decode()

            # Verify content
            with open(plain) as f:
                original = f.read()
            with open(dec) as f:
                decrypted = f.read()
            assert original == decrypted
