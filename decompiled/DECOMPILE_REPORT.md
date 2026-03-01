# fw_full_decompile.py – Decompilation Report
rootfs: /tmp/telmex_rootfs

## aescrypt2
- Path: `/tmp/telmex_rootfs/bin/aescrypt2`
- Size: 17,920 bytes
- Purpose: AES encrypt/decrypt; key derived from KMC chain
- Instructions: 1,719
- Exports: 13  Imports: 44
- **Key strings**:
  - `0x0000080f: 'HW_SSL_AesSetKeyEnc'`
  - `0x0000085f: 'HW_OS_AESCBCEncrypt'`
  - `0x000008cb: 'HW_OS_AESCBCDecrypt'`
  - `0x0000094d: 'HW_SSL_AesCryptEcb'`
  - `0x00000960: 'HW_SSL_AesSetKeyDec'`
  - `0x000009ba: 'HW_KMC_CfgGetKey'`
  - `0x000009d7: 'HW_OS_AESCBCCalPSWLen'`
  - `0x00002fbb: '<%s:%d>file (%s) read head key len err, len (%d)'`
  - `0x00002fee: '<%s:%d>file (%s) read head key failed, errno (%d)'`
  - `0x00003117: 'Df7!ui%s9(lmV1L8'`

## cfgtool
- Path: `/tmp/telmex_rootfs/bin/cfgtool`
- Size: 14,104 bytes
- Purpose: Config manipulation; HW_CFGTOOL_Get/Set/Add/Del
- Instructions: 347
- Exports: 28  Imports: 33

## libhw_ssp_basic
- Path: `/tmp/telmex_rootfs/lib/libhw_ssp_basic.so`
- Size: 751,728 bytes
- Purpose: KMC API, PBKDF2, AES wrappers, hardcoded fallback key Df7!ui%s9(lmV1L8
- Instructions: 390
- Exports: 2134  Imports: 1592
- **Key strings**:
  - `0x0000f11c: 'HW_OS_CheckPass'`
  - `0x0000f12c: 'HW_OS_CheckCertPwdComplex'`
  - `0x00010129: 'HW_OS_GetSaltStrForPbkdf2'`
  - `0x00010192: 'HW_OS_PBKDF2_SHA256'`
  - `0x000101a6: 'HW_AES_ECB'`
  - `0x000101b1: 'HW_SSL_AesSetKeyDec'`
  - `0x000101c5: 'HW_SSL_AesSetKeyEnc'`
  - `0x000101d9: 'HW_SSL_AesCryptEcb'`
  - `0x000101ec: 'HW_AES_CMAC'`
  - `0x000101f8: 'HW_SSL_AesCmac'`

## libhw_ssp_ssl
- Path: `/tmp/telmex_rootfs/lib/libhw_ssp_ssl.so`
- Size: 13,188 bytes
- Purpose: SSL wrapper; HW_SSL_LoadCertFile; polarssl_set_pub_prv_to_conf
- Instructions: 35
- Exports: 34  Imports: 42
- **Key strings**:
  - `0x0000083b: 'libpolarssl.so'`
  - `0x0000089f: 'polarssl_enable_ca_update'`
  - `0x000008d0: 'HW_SSL_GetCipher'`
  - `0x000008e1: 'polarssl_ssl_get_ciphersuite'`
  - `0x00000910: 'polarssl_ssl_get_version'`
  - `0x00000929: 'HW_SSL_LoadCertFile'`
  - `0x0000093d: 'polarssl_set_pub_prv_to_conf'`
  - `0x0000097a: 'polarssl_conf_setCaList'`
  - `0x000009c7: 'polarssl_ssl_set_hostname'`
  - `0x000009ee: 'polarssl_ssl_set_bio'`

## libhw_swm_dll
- Path: `/tmp/telmex_rootfs/lib/libhw_swm_dll.so`
- Size: 279,508 bytes
- Purpose: ctree encrypt/decrypt, eFuse load, /mnt/jffs2/prvt.key loading
- Instructions: 180
- Exports: 541  Imports: 718
- **Key strings**:
  - `0x00004fbc: 'HW_DM_GetEncryptedKey'`
  - `0x00004fde: 'HW_XML_CFGFileSecurityWithKey'`
  - `0x00005428: 'HW_SWM_LoadCertFileInit'`
  - `0x00005453: 'g_stLoadCertFileCtrl'`
  - `0x00005468: 'HW_SWM_LoadCertFileExit'`
  - `0x000054b7: 'HW_SWM_LoadCertDown'`
  - `0x000054db: 'HW_SWM_LoadCertFinishDown'`
  - `0x000054f5: 'HW_SWM_LoadCertEncrypt'`
  - `0x0000550c: 'HW_SWM_LoadCertFinishEncrypt'`
  - `0x00005529: 'HW_SWM_LoadCertFileFsm'`

## libpolarssl
- Path: `/tmp/telmex_rootfs/lib/libpolarssl.so`
- Size: 510,940 bytes
- Purpose: PolarSSL/mbedTLS; PolarSSLTest passphrase; mbedtls_pk_parse_keyfile
- Instructions: 12,575
- Exports: 908  Imports: 618
- **Key strings**:
  - `0x00005660: 'mbedtls_aes_init'`
  - `0x00005678: 'mbedtls_aes_free'`
  - `0x000056a2: 'mbedtls_aes_xts_init'`
  - `0x000056b7: 'mbedtls_aes_xts_free'`
  - `0x000056cc: 'mbedtls_aes_setkey_enc'`
  - `0x000056e3: 'mbedtls_aes_setkey_dec'`
  - `0x000056fa: 'mbedtls_aes_xts_setkey_enc'`
  - `0x00005715: 'mbedtls_aes_xts_setkey_dec'`
  - `0x00005730: 'mbedtls_internal_aes_encrypt'`
  - `0x0000574d: 'mbedtls_aes_encrypt'`

## libwlan_aes_crypto
- Path: `/tmp/telmex_rootfs/lib/libwlan_aes_crypto.so`
- Size: 4,964 bytes
- Purpose: WLAN AES-128-CBC encrypt/decrypt wrapper
- Instructions: 155
- Exports: 9  Imports: 8
- **Key strings**:
  - `0x000002e5: 'WLAN_AES_Cbc_128_Encrypt'`
  - `0x00000320: 'polarssl_aes_init'`
  - `0x00000332: 'polarssl_aes_setkey_enc'`
  - `0x0000034a: 'polarssl_aes_crypt_cbc'`
  - `0x0000039c: 'WLAN_AES_Cbc_128_Decrypt'`
  - `0x000003b5: 'polarssl_aes_setkey_dec'`
  - `0x0000040b: 'libwlan_aes_crypto.so'`
  - `0x000007ac: 'wlan_aes_crypto.c'`

