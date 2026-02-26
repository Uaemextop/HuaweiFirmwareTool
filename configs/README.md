# Firmware Configuration Analysis

Original configuration files extracted from Huawei ONT firmware images
(V2 releases). These are the factory-default configs embedded in the
SquashFS rootfs at `/etc/wap/`.

## Firmware Sources

| Directory | Firmware | Version | Device |
|-----------|----------|---------|--------|
| `HG8145V5_SPC212` | 5611_HG8145V5V500R020C10SPC212.bin | V500R020C10SPC212 | HG8145V5 |
| `EG8145V5_SPC340` | EG8145V5-V500R022C00SPC340B019.bin | V500R022C00SPC340 | EG8145V5 |
| `HN8145XR_SPC160` | HN8145XRV500R022C10SPC160.1.bin | V500R022C10SPC160 | HN8145XR |
| `HG8245C_V5R019` | HG8245C.rar → 8145C-V5R019C00S105-EN-BLUE.bin | V5R019C00S105 | HG8145C/HG8245C |

## Configuration Files

### Encrypted Files (device-specific AES key)

- **`hw_ctree.xml`** – Main configuration tree. AES-256-CBC encrypted with a
  key derived from the hardware e-fuse via the work-key partition. Cannot be
  decrypted without physical device access. Format: `01 00 00 00` header +
  encrypted payload.
- **`hw_default_ctree.xml`** – Factory default config tree. Same encrypted
  format. Identical to `hw_ctree.xml` in factory firmware images.

### Plaintext XML Configuration

- **`hw_aes_tree.xml`** – Defines which XML paths in `hw_ctree.xml` contain
  AES-encrypted fields (passwords, keys, secrets). This is the schema that
  tells the device which values need encryption/decryption.
- **`hw_flashcfg.xml`** – Flash partition layout including UBI volume
  configuration, NAND geometry, and A/B system rotation.
- **`hw_boardinfo`** – Device identity template with board ID, MAC address
  placeholders, product type, and hardware version fields.
- **`hw_firewall_v5.xml`** – Default firewall rules (stateful, drop incoming,
  accept outgoing from LAN).
- **`keyconfig.xml`** – Hardware reset button configuration and product
  board ID mappings.
- **`cfgpartreset.xml`** – Partial reset configuration defining which
  settings to preserve during factory reset.
- **`hw_bootcfg.xml`** – Boot configuration (available in HG8145V5 and
  HG8245C).
- **`UpgradeCheck.xml`** – Firmware upgrade compatibility checks including
  board IDs, chip types (LSW, WiFi, Voice, USB, Optical), product IDs,
  and program variants.
- **`tde_zone0.xml`** / **`tde_zone1.xml`** – Default timezone settings
  (GMT / GMT+1).

## Key Findings

### hw_ctree.xml Encryption

The configuration tree uses a multi-layer encryption scheme:

1. **e-fuse root key** (burned into SoC, unique per device)
2. **Work key** (stored in flash `keyfile` partition, encrypted by e-fuse key)
3. **AES-256-CBC** encryption of the XML content using the work key

The binary format of `hw_ctree.xml`:
```
Offset  Size  Description
0x00    4     Magic: 01 00 00 00 (version/type flag)
0x04    N     AES-256-CBC encrypted XML data
```

Since the key is hardware-bound, the encrypted `hw_ctree.xml` files included
here serve only as reference for format analysis. They cannot be decrypted
without access to the specific device's e-fuse.

### Fields Protected by AES Encryption (from hw_aes_tree.xml)

The `hw_aes_tree.xml` file defines all config paths that contain sensitive
data encrypted within `hw_ctree.xml`:

- **User credentials**: Web UI passwords, CLI passwords, factory passwords
- **WAN**: PPPoE passwords, DDNS passwords, IPoE passwords
- **WiFi**: WPA/WEP keys, WPS PINs, RADIUS secrets
- **VoIP**: SIP auth passwords, H.248 keys
- **Management**: TR-069/CWMP passwords, STUN passwords, SFTP keys
- **Certificates**: SSL/TLS certificate passwords
- **XGPON**: Registration ID, pre-shared keys
- **VPN**: L2TP/PPTP passwords

### Flash Partition Layout (from hw_flashcfg.xml)

**EG8145V5 / HG8145V5** (128 MB NAND):
```
Partition         Offset       Size        UBI  Rotation
L1boot            0x00000000   0x00020000  No   No
L2boot (A/B)      0x00020000   0x00040000  No   Yes
eFuse             0x000A0000   0x00020000  No   No
allsystem (A/B)   -            0x02C00000  No   Yes
  ├── signinfo
  ├── uboot
  ├── kernel
  └── rootfs
UBI layer v5      0x00000000   0x02400000  Yes  No
  ├── flash_config (A/B)  0x1F000 each
  ├── slave_param (A/B)   0x1F000 each
  ├── wifi_param (A/B)    0x1F000 each
  ├── keyfile             0x100000
  └── file_system         0x1D80000
```

### Default Firewall Rules

All firmwares use the same default stateful firewall:
- **Outgoing (LAN→WAN)**: Accept all
- **Incoming (WAN→LAN)**: Drop all
- Port mapping enabled by default
- Single chain: "StandardChain"

## Extraction Tool

Use `tools/fw_ctree_extract.py` to extract configs from any HWNP firmware:

```bash
# Single firmware
python tools/fw_ctree_extract.py firmware.bin -o output_dir

# Download and extract from URL
python tools/fw_ctree_extract.py --url https://...bin -o output_dir

# Process all V2 release firmwares
python tools/fw_ctree_extract.py --all -o configs_output
```

Requires `unsquashfs` (part of `squashfs-tools` package) and optionally
`7z` (for RAR extraction).
