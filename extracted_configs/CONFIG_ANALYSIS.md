# Unified Firmware Configuration Analysis

Generated from decrypted `hw_ctree.xml` across all firmware images.

## Firmware Summary

| Firmware | Elements | Attributes | Size |
|----------|----------|------------|------|
| EG8145V5-V500R022C00SPC340B019 | 1,011 | 3,163 | 132,215 B |
| HG8145C-V5R019C00S105 | 987 | 2,960 | 125,365 B |
| HG8145C_17120_ENG | 931 | 2,729 | 117,359 B |
| HG8145V5-V500R020C10SPC212 | 1,007 | 3,141 | 131,509 B |
| HG8245C-8145C-BLUE-R019-xpon | 987 | 2,960 | 125,365 B |
| HN8145XR-V500R022C10SPC160 | 1,012 | 3,165 | 132,367 B |

**Unified config**: 1,021 elements, 3,208 attributes

## Path Analysis

- Common paths (all firmwares): **1,106**
- Total unique paths (union): **1,363**
- Parameters with different values: **17**

## Configuration Differences

Parameters that have different values across firmwares:

### `InternetGatewayDevice.LANDevice.LANDeviceInstance.LANEthernetInterfaceConfig@NumberOfInstances`

| Firmware | Value |
|----------|-------|
| EG8145V5-V500R022C00SPC340B019 | `8` |
| HG8145C-V5R019C00S105 | `5` |
| HG8145C_17120_ENG | `5` |
| HG8145V5-V500R020C10SPC212 | `8` |
| HG8245C-8145C-BLUE-R019-xpon | `5` |
| HN8145XR-V500R022C10SPC160 | `8` |

### `InternetGatewayDevice.LANDevice.LANDeviceInstance.WLANConfiguration.WLANConfigurationInstance.Accounting@SecondaryServerIPAddr`

| Firmware | Value |
|----------|-------|
| EG8145V5-V500R022C00SPC340B019 | `` |
| HG8145C-V5R019C00S105 | `192.168.0.100` |
| HG8145V5-V500R020C10SPC212 | `192.168.0.100` |
| HG8245C-8145C-BLUE-R019-xpon | `192.168.0.100` |
| HN8145XR-V500R022C10SPC160 | `` |

### `InternetGatewayDevice.LANDevice.LANDeviceInstance.WLANConfiguration.WLANConfigurationInstance.PreSharedKey.PreSharedKeyInstance@PreSharedKey`

| Firmware | Value |
|----------|-------|
| EG8145V5-V500R022C00SPC340B019 | `apDTrdz%` |
| HG8145C-V5R019C00S105 | `eeeeeeee` |
| HG8145V5-V500R020C10SPC212 | `eeeeeeee` |
| HG8245C-8145C-BLUE-R019-xpon | `eeeeeeee` |
| HN8145XR-V500R022C10SPC160 | `apDTrdz%` |

### `InternetGatewayDevice.LANDevice.LANDeviceInstance.WLANConfiguration.WLANConfigurationInstance.WEPKey.WEPKeyInstance@WEPKey`

| Firmware | Value |
|----------|-------|
| EG8145V5-V500R022C00SPC340B019 | `V37Gal8xf69mY` |
| HG8145C-V5R019C00S105 | `aaaaaaaaaaaaa` |
| HG8145V5-V500R020C10SPC212 | `aaaaaaaaaaaaa` |
| HG8245C-8145C-BLUE-R019-xpon | `aaaaaaaaaaaaa` |
| HN8145XR-V500R022C10SPC160 | `V37Gal8xf69mY` |

### `InternetGatewayDevice.LANDevice.LANDeviceInstance.WLANConfiguration.WLANConfigurationInstance.WPS@Enable`

| Firmware | Value |
|----------|-------|
| EG8145V5-V500R022C00SPC340B019 | `1` |
| HG8145C-V5R019C00S105 | `0` |
| HG8145V5-V500R020C10SPC212 | `1` |
| HG8245C-8145C-BLUE-R019-xpon | `0` |
| HN8145XR-V500R022C10SPC160 | `1` |

### `InternetGatewayDevice.LANDevice.LANDeviceInstance.WLANConfiguration.WLANConfigurationInstance@BeaconType`

| Firmware | Value |
|----------|-------|
| EG8145V5-V500R022C00SPC340B019 | `11i` |
| HG8145C-V5R019C00S105 | `WPAand11i` |
| HG8145V5-V500R020C10SPC212 | `WPAand11i` |
| HG8245C-8145C-BLUE-R019-xpon | `WPAand11i` |
| HN8145XR-V500R022C10SPC160 | `11i` |

### `InternetGatewayDevice.LANDevice.LANDeviceInstance.WLANConfiguration.WLANConfigurationInstance@X_HW_HT20`

| Firmware | Value |
|----------|-------|
| EG8145V5-V500R022C00SPC340B019 | `1` |
| HG8145C-V5R019C00S105 | `0` |
| HG8145V5-V500R020C10SPC212 | `1` |
| HG8245C-8145C-BLUE-R019-xpon | `0` |
| HN8145XR-V500R022C10SPC160 | `1` |

### `InternetGatewayDevice.LANDevice.LANDeviceInstance.WLANConfiguration.WLANConfigurationInstance@X_HW_RadiuServer`

| Firmware | Value |
|----------|-------|
| EG8145V5-V500R022C00SPC340B019 | `` |
| HG8145C-V5R019C00S105 | `192.168.0.100` |
| HG8145V5-V500R020C10SPC212 | `192.168.0.100` |
| HG8245C-8145C-BLUE-R019-xpon | `192.168.0.100` |
| HN8145XR-V500R022C10SPC160 | `` |

### `InternetGatewayDevice.LANDevice.LANDeviceInstance.WiFi.Radio.RadioInstance@GuardInterval`

| Firmware | Value |
|----------|-------|
| EG8145V5-V500R022C00SPC340B019 | `Auto` |
| HG8145C-V5R019C00S105 | `400nsec` |
| HG8145V5-V500R020C10SPC212 | `Auto` |
| HG8245C-8145C-BLUE-R019-xpon | `400nsec` |
| HN8145XR-V500R022C10SPC160 | `Auto` |

### `InternetGatewayDevice.Service.VoiceService.VoiceServiceInstance.VoiceProfile.VoiceProfileInstance.SIP.X_HW_SIPProfile@ProfileBody`

| Firmware | Value |
|----------|-------|
| EG8145V5-V500R022C00SPC340B019 | `1=2;2=1;3=1;4=0;5=0;6=0;7=1;8=600;9=1;10=0;11=0;12=0;13=1;14=1;15=0;16=0;17=0;18...` |
| HG8145C-V5R019C00S105 | `1=2;2=1;3=1;4=0;5=0;6=0;7=1;8=600;9=1;10=0;11=0;12=0;13=1;14=1;15=0;16=0;17=0;18...` |
| HG8145C_17120_ENG | `1=2;2=1;3=1;4=0;5=0;6=0;7=1;8=600;9=1;10=0;11=0;12=0;13=1;14=1;15=0;16=0;17=0;18...` |
| HG8145V5-V500R020C10SPC212 | `1=2;2=1;3=1;4=0;5=0;6=0;7=1;8=600;9=1;10=0;11=0;12=0;13=1;14=1;15=0;16=0;17=0;18...` |
| HG8245C-8145C-BLUE-R019-xpon | `1=2;2=1;3=1;4=0;5=0;6=0;7=1;8=600;9=1;10=0;11=0;12=0;13=1;14=1;15=0;16=0;17=0;18...` |
| HN8145XR-V500R022C10SPC160 | `1=2;2=1;3=1;4=0;5=0;6=0;7=1;8=600;9=1;10=0;11=0;12=0;13=1;14=1;15=0;16=0;17=0;18...` |

### `InternetGatewayDevice.Service.VoiceService.VoiceServiceInstance.VoiceProfile.VoiceProfileInstance.SIP.X_HW_SIPSrvLogic@NumberOfInstances`

| Firmware | Value |
|----------|-------|
| EG8145V5-V500R022C00SPC340B019 | `588` |
| HG8145C-V5R019C00S105 | `588` |
| HG8145C_17120_ENG | `567` |
| HG8145V5-V500R020C10SPC212 | `588` |
| HG8245C-8145C-BLUE-R019-xpon | `588` |
| HN8145XR-V500R022C10SPC160 | `589` |

### `InternetGatewayDevice.Service.VoiceService.VoiceServiceInstance.X_HW_InnerParameters@NoneOMCISIPAlarmEnable`

| Firmware | Value |
|----------|-------|
| EG8145V5-V500R022C00SPC340B019 | `1` |
| HG8145C-V5R019C00S105 | `0` |
| HG8145C_17120_ENG | `0` |
| HG8145V5-V500R020C10SPC212 | `1` |
| HG8245C-8145C-BLUE-R019-xpon | `0` |
| HN8145XR-V500R022C10SPC160 | `1` |

### `InternetGatewayDevice.UserInterface.X_HW_CLIUserInfo.X_HW_CLIUserInfoInstance@ModifyPWDFlag`

| Firmware | Value |
|----------|-------|
| EG8145V5-V500R022C00SPC340B019 | `1` |
| HG8145C-V5R019C00S105 | `0` |
| HG8145C_17120_ENG | `0` |
| HG8145V5-V500R020C10SPC212 | `0` |
| HG8245C-8145C-BLUE-R019-xpon | `0` |
| HN8145XR-V500R022C10SPC160 | `1` |

### `InternetGatewayDevice.X_HW_ProductInfo@currentVersion`

| Firmware | Value |
|----------|-------|
| EG8145V5-V500R022C00SPC340B019 | `V500R022` |
| HG8145C-V5R019C00S105 | `` |
| HG8145C_17120_ENG | `V300R017` |
| HG8145V5-V500R020C10SPC212 | `V300R020` |
| HG8245C-8145C-BLUE-R019-xpon | `` |
| HN8145XR-V500R022C10SPC160 | `V500R022` |

### `InternetGatewayDevice.X_HW_ProductInfo@originalVersion`

| Firmware | Value |
|----------|-------|
| EG8145V5-V500R022C00SPC340B019 | `V500R022C00SPC340A2402080348` |
| HG8145C-V5R019C00S105 | `` |
| HG8145C_17120_ENG | `V300R017C10SPC120A1709050021` |
| HG8145V5-V500R020C10SPC212 | `V300R020C10SPC212A2206210275` |
| HG8245C-8145C-BLUE-R019-xpon | `` |
| HN8145XR-V500R022C10SPC160 | `V500R022C10SPC160A2304260943` |

### `InternetGatewayDevice.X_HW_SSMPPDT.Deviceinfo.X_HW_MobileInterface@LTEBandSet`

| Firmware | Value |
|----------|-------|
| EG8145V5-V500R022C00SPC340B019 | `` |
| HG8145V5-V500R020C10SPC212 | `B1B3B7B20B28` |
| HN8145XR-V500R022C10SPC160 | `` |

### `InternetGatewayDevice.X_HW_Security.AclServices@SSHLanEnable`

| Firmware | Value |
|----------|-------|
| EG8145V5-V500R022C00SPC340B019 | `1` |
| HG8145C-V5R019C00S105 | `0` |
| HG8145C_17120_ENG | `0` |
| HG8145V5-V500R020C10SPC212 | `0` |
| HG8245C-8145C-BLUE-R019-xpon | `0` |
| HN8145XR-V500R022C10SPC160 | `1` |

## Configuration Tree Structure

Top-level sections in `<InternetGatewayDevice>`:

| Section | Children | Description |
|---------|----------|-------------|
| `LANDevice` | 1 | LAN interface settings (Ethernet, WiFi, DHCP) |
| `X_HW_LswPortInfo` | 3 | Ethernet switch port configuration |
| `X_HW_LswChipInfo` | 1 |  |
| `X_HW_OmciInfo` | 5 | OMCI (GPON management) settings |
| `X_HW_GponLed` | 1 |  |
| `Optical` | 1 |  |
| `X_HW_VendorInfo` | 0 |  |
| `X_HW_AMPConfig` | 1 |  |
| `X_HW_OAMFREQUENCY` | 0 |  |
| `X_HW_AmpInfo` | 1 |  |
| `X_HW_DEBUG` | 1 |  |
| `X_HW_PonQualityMonitor` | 0 |  |
| `Service` | 6 | Voice/VoIP service configuration |
| `X_HW_Dot1agCfm` | 0 |  |
| `WANDevice` | 1 | WAN connection settings (PPPoE, DHCP, routing) |
| `X_HW_DNS` | 1 |  |
| `Layer3Forwarding` | 0 | IP routing and forwarding rules |
| `X_HW_APService` | 0 |  |
| `QueueManagement` | 2 |  |
| `X_HW_DHCPSLVSERVER` | 0 |  |
| `X_HW_Security` | 10 | Security settings (firewall, ACL, SSH) |
| `X_HW_ALG` | 0 |  |
| `X_HW_MainUPnP` | 0 |  |
| `X_HW_SlvUPnP` | 0 |  |
| `X_HW_IPv6Layer3Forwarding` | 1 |  |
| `X_HW_FeatureList` | 1 |  |
| `X_HW_PDT_FeatureList` | 5 |  |
| `X_HW_Mobile_Backup` | 0 |  |
| `Time` | 0 |  |
| `X_HW_LogCfg` | 2 |  |
| `X_HW_SystemTimerConfig` | 1 |  |
| `UserInterface` | 3 | Web and CLI user accounts |
| `ManagementServer` | 0 |  |
| `X_HW_APMPolicy` | 1 |  |
| `X_HW_PSIXmlReset` | 0 |  |
| `X_HW_UserInfo` | 0 |  |
| `X_HW_ServiceManage` | 0 |  |
| `X_HW_SSMPPDT` | 1 | SSMP product-specific settings |
| `X_HW_DataModel` | 2 |  |
| `ExtDeviceInfo` | 1 |  |
| `X_HW_ProductInfo` | 0 | Product identity and version info |
| `DeviceInfo` | 5 | Device information and diagnostics |
| `X_HW_AppRemoteManage` | 0 |  |

## Config Generation Flow

How `hw_ctree.xml` is generated, stored, and used:

```
┌─────────────────────────────────────────────────────────┐
│                    FIRMWARE BUILD                       │
│                                                         │
│  hw_default_ctree.xml (factory defaults)                │
│       │                                                 │
│       ▼                                                 │
│  gzip compress → AES-256-CBC encrypt                    │
│       │         (PBKDF2 key from kmc_store)             │
│       ▼                                                 │
│  hw_ctree.xml (encrypted, in /etc/wap/)                 │
│  hw_default_ctree.xml (encrypted, identical at factory) │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                   DEVICE BOOT                           │
│                                                         │
│  1. /bin/aescrypt2 1 hw_ctree.xml → decrypt             │
│  2. gunzip → plaintext XML                              │
│  3. HW_XML_DBInit() → parse into in-memory DOM tree     │
│  4. HW_XML_DBTreeInit() → build TTree (template tree)   │
│  5. HW_XML_DataMapInit() → attach data map overlays     │
│  6. Services read config via HW_XML_DBGetSiglePara()    │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                  CONFIG SAVE                            │
│                                                         │
│  1. Service calls HW_XML_DBSetSiglePara() to update     │
│  2. HW_XML_DBSave() → serialize DOM to XML             │
│  3. gzip compress → AES-256-CBC encrypt                 │
│  4. Write to /mnt/jffs2/hw_ctree.xml (flash)            │
│  5. Backup: XML_BakCtree() → /var/backKey/              │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                CONFIG IMPORT/EXPORT                     │
│                                                         │
│  Import (Web/TR-069):                                   │
│    1. Upload encrypted .xml file                        │
│    2. HW_XML_CFGFileSecurity() → validate + decrypt     │
│    3. HW_XML_ParseFile() → parse XML                    │
│    4. Merge into current config tree                    │
│    5. HW_XML_DBSave() → re-encrypt + save              │
│                                                         │
│  Export (Web/TR-069):                                   │
│    1. HW_XML_DomCtreeToXml() → serialize current tree   │
│    2. HW_XML_CFGFileEncryptWithKey() → encrypt          │
│    3. Download encrypted .xml file                      │
│                                                         │
│  cfgtool CLI:                                           │
│    cfgtool get deftree <path> → read parameter          │
│    cfgtool set deftree <path> <attr> <value> → write    │
│    cfgtool add/del deftree <path> → add/remove instance │
│    cfgtool clone deftree <path> <file> → export subset  │
│    cfgtool batch deftree <file> → batch import          │
└─────────────────────────────────────────────────────────┘
```

## Key Library Functions

From `libhw_ssp_basic.so` analysis:

| Function | Purpose |
|----------|---------|
| `OS_AescryptEncrypt` | Encrypt file (AEST format: AES-256-CBC + HMAC-SHA-256) |
| `OS_AescryptDecrypt` | Decrypt AEST file |
| `HW_XML_GetEncryptedKey` | Get AES key from KMC keystore |
| `HW_XML_DBInit` | Initialize config database from XML |
| `HW_XML_DBSave` | Save config database to encrypted XML |
| `HW_XML_DBSaveCTreeXmlToFlash` | Write encrypted ctree to flash |
| `HW_XML_DBSaveToFlash` | Save all config trees to flash |
| `HW_XML_CFGFileSecurity` | Validate and decrypt config file |
| `HW_XML_CFGFileEncryptWithKey` | Encrypt config file for export |
| `HW_XML_DomCtreeToXml` | Serialize DOM tree to XML string |
| `HW_XML_ParseFile` | Parse XML file into DOM tree |
| `HW_XML_DBUnCompressFile` | Decompress gzipped config |
| `HW_XML_DBZipFile` | Compress config with gzip |
| `XML_BakCtree` | Backup ctree to /var/backKey/ |
| `HW_KMC_GetAppointKey` | Get encryption key from KMC store |
| `HW_CFGTOOL_GetXMLValByPath` | cfgtool: read parameter by path |
| `HW_CFGTOOL_SetXMLValByPath` | cfgtool: write parameter by path |
| `HW_CFGTOOL_AddXMLValByPath` | cfgtool: add instance by path |
| `HW_CFGTOOL_DelXMLValByPath` | cfgtool: delete instance by path |
| `HW_CFGTOOL_CloneXMLValByPath` | cfgtool: export subtree to file |
