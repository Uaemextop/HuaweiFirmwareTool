# Huawei Firmware Deep Analysis Results

Generated from: realfirmware-net repository

========================================================================
FIRMWARE DEEP ANALYSIS - COMPLETE FINDINGS
========================================================================

=== HARDCODED KEYS (CONFIRMED) ===
  AES-128 Fallback Key: 'Df7!ui%s9(lmV1L8' (16 bytes)
    Found in: libhw_ssp_basic.so @ 0xa0fbf
    Found in: libhw_swm_dll.so @ 0x37f68
    Found in: aescrypt2 @ 0x3117 (/bin/aescrypt2)
    Purpose: CTOOL_GetKeyChipStr fallback when KMC unavailable
    Used for: hw_ctree.xml encryption via OS_AescryptEncrypt/Decrypt

  PolarSSL Test Passphrase: 'PolarSSLTest'
    Found hardcoded in: libpolarssl.so @ 0x6db4c, 0x6efd4
    Decrypts: RSA PRIVATE KEY @ 0x6db60 (DES-EDE3-CBC,A8A95B05D5B7206B)
    Decrypts: EC PRIVATE KEY  @ 0x6efe8 (DES-EDE3-CBC,307EAB469933D64E)
    These are PolarSSL/mbedTLS built-in test keys, NOT production keys

=== FIRMWARE ENCRYPTION ARCHITECTURE ===

  V500R019 (HG8145V5) ctree format:
    Header: 01000000 + CRC(4) + IV(16) + AES-CBC ciphertext + HMAC-SHA256(32)
    Key chain: eFuse(device) → KMC domain-0 → work key → AES-256-CBC
    kmc_store_A/B: In firmware at /etc/wap/ (1056 bytes each)
    kmc_store MD5: same A=B (redundant copies)
    CANNOT decrypt statically: requires device eFuse chip ID

  V500R022 (X6-10, MEGACABLE) HWNP format:
    Magic: HWNP + 'hzs%' sub-magic (offset 0x10)
    Payload: AES-256-CBC @ 0x460, IV @ 0x450, SHA1 @ 0x40c
    Version: V500R022C00SPC266B012
    Product: MA5600/OLT (H801EPBA board)
    CANNOT decrypt statically: KMC domain-0 + eFuse chip ID required
    Same file content: MEGACABLE=TIGO=TOTAL (byte-for-byte identical)

=== FIRMWARE ROOTFS EXTRACTED ===

  Huawei-HG8145V5_R019C10SPC310B002/ (20 files)
    ✓ etc/wap/prvt.key
  Huawei-HG8145V5_R019C10SPC386B020/ (20 files)
    ✓ etc/wap/prvt.key
  Huawei-HG8145V5_R020C00SPC240B470/ (26 files)
    ✓ etc/wap/prvt.key
  Huawei-HG8145V5_R020C10SPC212B465/ (22 files)
    ✓ etc/wap/prvt.key
  Huawei-HG8145V5_Telmex_R019C10SPC310B002/ (19 files)
    ✓ etc/wap/prvt.key
    ✓ etc/wap/kmc_store_A
    ✓ etc/wap/hw_ctree.xml
    ✓ bin/aescrypt2
  Huawei-HG8245Q_R017C10SPC115B136/ (13 files)
    ✓ etc/wap/prvt.key
  Huawei-HG8246M_R019C00SPC050B051/ (13 files)
    ✓ etc/wap/prvt.key
  Huawei-HG8247H_R017C10SPC102B075/ (13 files)
    ✓ etc/wap/prvt.key

=== NEW ROOTFS EXTRACTIONS ===
  Telmex R019 (V500R019C10SPC310B002): 5661 inodes, LZMA SquashFS
    → 19 important files copied to keys/extracted/Huawei-HG8145V5_Telmex_R019C10SPC310B002/
    → passwd file: root has empty password
    → kmc_store_A = kmc_store_B (1056 bytes, redundant)

=== ARM LIBRARY KEY FINDINGS ===

  libpolarssl.so (510,940 bytes):
    - 30+ PEM blocks (14 certs, 8 RSA keys, 4 EC keys, DH params)
    - 2 ENCRYPTED: RSA @ 0x6db60 + EC @ 0x6efe8 (PolarSSLTest passphrase)
    - 12 PLAINTEXT private keys (test keys only)
    - Decrypted DER files saved to keys/extracted/

  libhw_ssp_basic.so (751,728 bytes):
    - KMC API: HW_KMC_GetActiveKey, HW_KMC_GetAppointKey
    - PBKDF2: HW_OS_GetSaltStrForPbkdf2, HW_OS_PBKDF2_SHA256
    - Hardcoded key: Df7!ui%s9(lmV1L8 @ 0xa0fbf

  libhw_swm_dll.so (279,508 bytes):
    - HW_SWM_LoadEfuse, HW_DM_GetEncryptedKey
    - HW_XML_CFGFileEncryptWithKey, HW_XML_CFGFileSecurityWithKey
    - Hardcoded key: Df7!ui%s9(lmV1L8 @ 0x37f68
    - aescrypt2 call: 'aescrypt2 1 %s %s' for ctree decrypt

=== SMALL HWNP UNLOCK SCRIPTS (41 found) ===
  These are UNENCRYPTED configuration/unlock packages
  3 contain embedded shell scripts:
  • megav5.bin + unlock.bin: hw_boardinfo ObjID 0x00000001 = '4' (COMMON mode)
  • HG8245 common ok.bin: Telnet enable + wifi name change + reset key logic
  • shell.bin: equipment.tar.gz extraction + module loading
  • HG8245H XPON.bin: hw_boardinfo mode conversion (GPON→XPON)

=== DECRYPTION FEASIBILITY SUMMARY ===

  DECRYPTABLE NOW:
    ✓ PolarSSL test keys in libpolarssl.so (passphrase: PolarSSLTest)
    ✓ hw_ctree.xml in HN8145XR rootfs (empty kmc_store trick)

  REQUIRES DEVICE eFUSE (not possible statically):
    ✗ hw_ctree.xml in HG8145V5 V500R019 firmware
    ✗ hw_ctree.xml in HG8145X6-10 V500R022 firmware
    ✗ HWNP encrypted payload (hzs% magic) in X6-10 MEGACABLE
    ✗ prvt.key / plugprvt.key passphrase (KMC/PBKDF2 derived)

  WORKAROUND (chroot method - works only if same device eFuse):
    $ mkdir -p rootfs/mnt/jffs2
    $ touch rootfs/mnt/jffs2/kmc_store_A rootfs/mnt/jffs2/kmc_store_B
    $ sudo chroot rootfs qemu-arm-static /bin/aescrypt2 1 ctree.xml out.xml
    $ gunzip out.xml → plaintext XML config (132KB)