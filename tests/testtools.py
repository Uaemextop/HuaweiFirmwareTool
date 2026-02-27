"""Tests for firmware extraction, ARM disassembly, and firmware analysis tools."""

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


# ── firmware_analyzer tests ──────────────────────────────────────────────────

from tools.firmware_analyzer import (
    classify_file,
    extract_shell_access_info,
    extract_wan_info,
    analyze_elf_imports,
    analyze_config_file,
    find_squashfs as fa_find_squashfs,
    is_arm_elf,
    ISP_ALIASES,
)


# Sample decrypted hw_ctree.xml fragment for testing
_SAMPLE_CTREE_XML = """\
<InternetGatewayDevice>
<X_HW_Security>
<AclServices TELNETLanEnable="1" TELNETWanEnable="0"
    SSHLanEnable="1" SSHWanEnable="0"
    HTTPPORT="80" TELNETPORT="23" SSHPORT="22"
    TELNETWifiEnable="1" HTTPWifiEnable="1"/>
</X_HW_Security>
<NetInfo HostName="WAP" DomainName="HOME"/>
<UserInterface>
<X_HW_CLITelnetAccess Access="1"/>
<X_HW_CLIUserInfo NumberOfInstances="1">
<X_HW_CLIUserInfoInstance InstanceID="1" Username="root"
    Userpassword="admin" UserGroup="" EncryptMode="3"/>
</X_HW_CLIUserInfo>
<X_HW_WebUserInfo NumberOfInstances="2">
<X_HW_WebUserInfoInstance InstanceID="1" UserName="root"
    Password="hash1" UserLevel="1" Enable="1" PassMode="2"/>
<X_HW_WebUserInfoInstance InstanceID="2" UserName="telecomadmin"
    Password="hash2" UserLevel="0" Enable="1" PassMode="2"/>
</X_HW_WebUserInfo>
</UserInterface>
<WANDevice>
<WANConnectionDevice>
<WANPPPConnectionInstance Name="ppp0" Username="user@isp"
    Enable="1" ConnectionType="IP_Routed"/>
<WANIPConnectionInstance Name="ipoe0" Enable="0"
    ConnectionType="IP_Routed" AddressingType="DHCP"/>
</WANConnectionDevice>
</WANDevice>
</InternetGatewayDevice>
"""


class TestClassifyFile:
    """Tests for classify_file()."""

    def test_xml_file(self):
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False,
                                          mode="w") as f:
            f.write("<?xml version='1.0'?><root/>")
            path = f.name
        try:
            assert classify_file(path) == "XML"
        finally:
            os.unlink(path)

    def test_encrypted_file(self):
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False,
                                          mode="wb") as f:
            f.write(b"\x01\x00\x00\x00" + b"\xff" * 100)
            path = f.name
        try:
            assert classify_file(path) == "encrypted"
        finally:
            os.unlink(path)

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            assert classify_file(path) == "empty"
        finally:
            os.unlink(path)

    def test_gzip_file(self):
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            f.write(b"\x1f\x8b\x08" + b"\x00" * 50)
            path = f.name
        try:
            assert classify_file(path) == "gzip"
        finally:
            os.unlink(path)

    def test_elf_file(self):
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            f.write(b"\x7fELF" + b"\x00" * 50)
            path = f.name
        try:
            assert classify_file(path) == "ELF"
        finally:
            os.unlink(path)

    def test_nonexistent_file(self):
        assert classify_file("/nonexistent/path/file.bin") == "unreadable"


class TestExtractShellAccessInfo:
    """Tests for extract_shell_access_info()."""

    def test_extracts_hostname(self):
        info = extract_shell_access_info(_SAMPLE_CTREE_XML)
        assert info["hostname"] == "WAP"

    def test_extracts_telnet_settings(self):
        info = extract_shell_access_info(_SAMPLE_CTREE_XML)
        assert info["telnet_lan_enable"] == "1"
        assert info["telnet_wan_enable"] == "0"
        assert info["telnet_wifi_enable"] == "1"
        assert info["telnet_port"] == "23"

    def test_extracts_ssh_settings(self):
        info = extract_shell_access_info(_SAMPLE_CTREE_XML)
        assert info["ssh_lan_enable"] == "1"
        assert info["ssh_wan_enable"] == "0"
        assert info["ssh_port"] == "22"

    def test_extracts_cli_telnet_access(self):
        info = extract_shell_access_info(_SAMPLE_CTREE_XML)
        assert info["cli_telnet_access"] == "1"

    def test_extracts_cli_users(self):
        info = extract_shell_access_info(_SAMPLE_CTREE_XML)
        assert len(info["cli_users"]) == 1
        assert info["cli_users"][0]["username"] == "root"
        assert info["cli_users"][0]["password"] == "admin"
        assert info["cli_users"][0]["encrypt_mode"] == "3"

    def test_extracts_web_users(self):
        info = extract_shell_access_info(_SAMPLE_CTREE_XML)
        assert len(info["web_users"]) == 2
        assert info["web_users"][0]["username"] == "root"
        assert info["web_users"][0]["user_level"] == "1"
        assert info["web_users"][1]["username"] == "telecomadmin"
        assert info["web_users"][1]["user_level"] == "0"

    def test_handles_invalid_xml(self):
        info = extract_shell_access_info("not valid xml <<<")
        assert info["hostname"] == ""
        assert info["cli_users"] == []

    def test_handles_empty_xml(self):
        info = extract_shell_access_info("")
        assert info["hostname"] == ""


class TestExtractWanInfo:
    """Tests for extract_wan_info()."""

    def test_extracts_pppoe(self):
        connections = extract_wan_info(_SAMPLE_CTREE_XML)
        pppoe = [c for c in connections if c["type"] == "PPPoE"]
        assert len(pppoe) == 1
        assert pppoe[0]["name"] == "ppp0"
        assert pppoe[0]["username"] == "user@isp"

    def test_extracts_ipoe(self):
        connections = extract_wan_info(_SAMPLE_CTREE_XML)
        ipoe = [c for c in connections if c["type"] == "IPoE"]
        assert len(ipoe) == 1
        assert ipoe[0]["name"] == "ipoe0"
        assert ipoe[0]["addressing_type"] == "DHCP"

    def test_handles_no_wan(self):
        connections = extract_wan_info("<Root/>")
        assert connections == []


class TestIsArmElf:
    """Tests for is_arm_elf()."""

    def test_arm_elf(self):
        data = _make_minimal_elf32()
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            f.write(data)
            path = f.name
        try:
            assert is_arm_elf(path) is True
        finally:
            os.unlink(path)

    def test_non_elf(self):
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            f.write(b"not an elf file")
            path = f.name
        try:
            assert is_arm_elf(path) is False
        finally:
            os.unlink(path)

    def test_nonexistent(self):
        assert is_arm_elf("/nonexistent/path") is False


class TestAnalyzeElfImports:
    """Tests for analyze_elf_imports()."""

    def test_minimal_elf(self):
        data = _make_minimal_elf32()
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            f.write(data)
            path = f.name
        try:
            result = analyze_elf_imports(path)
            assert result["is_elf"] is True
            assert result["arch"] == "ARM"
            assert result["type"] == "executable"
            assert result["size"] == len(data)
        finally:
            os.unlink(path)

    def test_non_elf_file(self):
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            f.write(b"not an ELF")
            path = f.name
        try:
            result = analyze_elf_imports(path)
            assert result["is_elf"] is False
        finally:
            os.unlink(path)

    def test_nonexistent_file(self):
        result = analyze_elf_imports("/nonexistent/path")
        assert result["is_elf"] is False
        assert result["size"] == 0


class TestAnalyzeConfigFile:
    """Tests for analyze_config_file()."""

    def test_xml_config(self):
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False,
                                          mode="w") as f:
            f.write('<?xml version="1.0"?>\n<Config><Item key="val"/></Config>')
            path = f.name
        try:
            result = analyze_config_file(path)
            assert result["format"] == "XML"
            assert result["elements"] == 2  # Config + Item
            assert result["attributes"] == 1  # key="val"
        finally:
            os.unlink(path)

    def test_encrypted_config(self):
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False,
                                          mode="wb") as f:
            f.write(b"\x01\x00\x00\x00" + b"\xaa" * 100)
            path = f.name
        try:
            result = analyze_config_file(path)
            assert result["format"] == "encrypted"
            assert result["elements"] == 0
        finally:
            os.unlink(path)


class TestFirmwareAnalyzerFindSquashfs:
    """Tests for firmware_analyzer.find_squashfs()."""

    def test_no_squashfs(self):
        assert fa_find_squashfs(b"\x00" * 128) == []

    def test_single_squashfs(self):
        hdr = bytearray(48)
        hdr[0:4] = b"hsqs"
        struct.pack_into("<Q", hdr, 40, 48)
        data = b"\x00" * 100 + bytes(hdr)
        result = fa_find_squashfs(data)
        assert len(result) == 1
        assert result[0][0] == 100


class TestISPAliases:
    """Tests for ISP alias mapping."""

    def test_megacable_aliases(self):
        assert "megacable" in ISP_ALIASES
        aliases = ISP_ALIASES["megacable"]
        assert "megacable" in aliases
        assert "mega" in aliases
        assert "megacable2" in aliases
