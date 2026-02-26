# How to Obtain the eFuse Key (HG8145V5 / HiSilicon SD511x)

The AES-256 key protecting hw_ctree.xml is derived from the device eFuse OTP.
It **cannot** be extracted from the NAND flash dump alone.

## Option A: U-Boot Serial Console
Connect via UART (115200 8N1) and interrupt boot:
    md.b 0x12010100 40        ; read 64 bytes of eFuse SRAM shadow
    md.b 0x12010140 40        ; second 64 bytes
Save the 128-byte hex dump and pass it to this tool:
    python3 tools/decrypt_ctree.py --dump NAND.BIN --efuse <64-bytes-hex> --out keys/

## Option B: Root Shell on Running Device
    cat /proc/soc_info              ; may contain eFuse readout
    cat /dev/efuse 2>/dev/null | xxd -l 64
    strings /proc/kcore | grep -i efuse

## Option C: JTAG/SWD (HiSilicon ARM Cortex-A9 DAP)
Use OpenOCD with CoreSight DAP access to read eFuse SRAM shadow registers
at 0x12010100 on the SD511x SoC.

## Once You Have the eFuse Key
    python3 tools/decrypt_ctree.py \
        --dump Dump_LOCK_HG8145v5-20_r020.s212_DS35Q1GA.x4.@WSON8_nonECC.BIN \
        --efuse <64-bytes-hex-from-eFuse-registers> \
        --out keys/

The tool will:
1. AES-ECB decrypt the 96-byte KeyFile header using the eFuse key
2. PBKDF2-HMAC-SHA256 derive the hw_ctree.xml AES-256-CBC key
3. Decrypt hw_ctree.xml and extract certprvtPassword
4. Decrypt all PEM private keys using certprvtPassword
5. Save PEM + DER to keys/
