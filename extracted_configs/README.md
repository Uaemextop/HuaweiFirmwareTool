# Extracted Firmware Configurations

Original `hw_ctree.xml` and `hw_default_ctree.xml` configuration trees
extracted and **decrypted** from Huawei ONT firmware images using each
firmware's own `aescrypt2` binary and embedded key material (`kmc_store`/`prvt.key`).

## Summary

| Firmware | Version | Encrypted | Decrypted | Size |
|----------|---------|-----------|-----------|------|
| `EG8145V5-V500R022C00SPC340B019` | V500R022C00SPC340B019 | ✓ | ✓ | 132,215 B |
| `HG8145C-V5R019C00S105` | V300R017C10SPC208B261 | ✓ | ✓ | 125,365 B |
| `HG8145C_17120_ENG` | V300R017C10SPC120B153 | ✓ | ✓ | 117,359 B |
| `HG8145V5-V500R020C10SPC212` | V500R020C10SPC212B465 | ✓ | ✓ | 131,509 B |
| `HG8245C-8145C-BLUE-R019-xpon` | V300R017C10SPC125B176 | ✓ | ✓ | 125,365 B |
| `HN8145XR-V500R022C10SPC160` | V500R022C10SPC160B014 | ✓ | ✓ | 132,367 B |

## Files Per Firmware

### EG8145V5-V500R022C00SPC340B019

**Version:** `V500R022C00SPC340B019`

| File | Size | SHA-256 |
|------|------|---------|
| `hw_ctree.xml` | 19,128 B | `c2dc2614e26ac479…` |
| `hw_ctree_decrypted.xml` | 132,215 B | `81c91aff718f11a1…` |
| `hw_default_ctree.xml` | 19,128 B | `c2dc2614e26ac479…` |
| `hw_default_ctree_decrypted.xml` | 132,215 B | `81c91aff718f11a1…` |

<details>
<summary>Preview of decrypted hw_ctree.xml</summary>

```xml
<InternetGatewayDevice>
	<LANDevice NumberOfInstances="1">
		<LANDeviceInstance InstanceID="1" X_HW_WlanEnable="1" X_HW_WlanPowerValue="0">
<!-- SUPPORT_WIFI_START-->
			<WiFi RadioNumberOfEntries="1" X_HW_PairTrigger="None">
				<Radio NumberOfInstances="2">
					<RadioInstance InstanceID="1" SupportedFrequencyBands="2.4GHz" OperatingFrequencyBand="2.4GHz" GuardInterval="Auto" X_HW_TxChainMask="0" X_HW_RxChainMask="0" Enable="1" Status="Up" Alias="cpe-2.4G" Name="cpe-2.4G" LastChange="0" MaxBitRate="0" AutoChannelSupported="1" X_HW_RatePriority="0" X_HW_SameSSIDStatus="0" CountryIEEnable="0"/>
					<RadioInstance InstanceID="2" SupportedFrequencyBands="5GHz" OperatingFrequencyBand="5GHz" GuardInterval="Auto" X_HW_TxChainMask="0" X_HW_RxChainMask="0" Enable="1" Status="Up" Alias="cpe-5G" Name="cpe-5G" LastChange="0" MaxBitRate="0" AutoChannelSupported="1" X_HW_RatePriority="0" X_HW_SameSSIDStatus="0" CountryIEEnable="0"/>
```
</details>

### HG8145C-V5R019C00S105

**Version:** `V300R017C10SPC208B261`

| File | Size | SHA-256 |
|------|------|---------|
| `hw_ctree.xml` | 18,216 B | `e754c33153399152…` |
| `hw_ctree_decrypted.xml` | 125,365 B | `9a8d5f6ab0694ada…` |
| `hw_default_ctree.xml` | 18,216 B | `e754c33153399152…` |
| `hw_default_ctree_decrypted.xml` | 125,365 B | `9a8d5f6ab0694ada…` |

<details>
<summary>Preview of decrypted hw_ctree.xml</summary>

```xml
<InternetGatewayDevice>
	<LANDevice NumberOfInstances="1">
		<LANDeviceInstance InstanceID="1" X_HW_WlanEnable="1" X_HW_WlanPowerValue="0">
<!-- SUPPORT_WIFI_START-->
			<WiFi RadioNumberOfEntries="1" X_HW_PairTrigger="None">
				<Radio NumberOfInstances="2">
					<RadioInstance InstanceID="1" SupportedFrequencyBands="2.4GHz" OperatingFrequencyBand="2.4GHz" GuardInterval="400nsec" X_HW_TxChainMask="0" X_HW_RxChainMask="0" Enable="1" Status="Up" Alias="cpe-2.4G" Name="cpe-2.4G" LastChange="0" MaxBitRate="0" AutoChannelSupported="1" X_HW_RatePriority="0" X_HW_SameSSIDStatus="0"/>
					<RadioInstance InstanceID="2" SupportedFrequencyBands="5GHz" OperatingFrequencyBand="5GHz" GuardInterval="400nsec" X_HW_TxChainMask="0" X_HW_RxChainMask="0" Enable="1" Status="Up" Alias="cpe-5G" Name="cpe-5G" LastChange="0" MaxBitRate="0" AutoChannelSupported="1" X_HW_RatePriority="0" X_HW_SameSSIDStatus="0"/>
```
</details>

### HG8145C_17120_ENG

**Version:** `V300R017C10SPC120B153`

| File | Size | SHA-256 |
|------|------|---------|
| `hw_ctree.xml` | 16,968 B | `6c445b6d606ce4fc…` |
| `hw_ctree_decrypted.xml` | 117,359 B | `d2394962de8271cb…` |
| `hw_default_ctree.xml` | 16,968 B | `6c445b6d606ce4fc…` |
| `hw_default_ctree_decrypted.xml` | 117,359 B | `d2394962de8271cb…` |

<details>
<summary>Preview of decrypted hw_ctree.xml</summary>

```xml
<InternetGatewayDevice>
<Service>
<!-- SUPPORT_HGW_START-->
<VoiceService NumberOfInstances="1">
<VoiceServiceInstance InstanceID="1" VoiceProfileNumberOfEntries="1">
<VoiceProfile NumberOfInstances="1">
<VoiceProfileInstance InstanceID="1" Name="" SignalingProtocol="" Region="" DTMFMethod="InBand" DigitMap="" X_HW_DigitMapMatchMode="Min" X_HW_PortName="" X_HW_OverseaVer="0" X_HW_HowlerSendFlag="1" DigitMapEnable="1" Enable="Enabled" X_HW_KeepTransferActivePeriod="0" X_HW_ServerType="" X_HW_Option120PriorityMode="1"> 
<SIP ProxyServer="" ProxyServerPort="5060" ProxyServerTransport="UDP" X_HW_SecondaryProxyServer="" X_HW_SecondaryProxyServerPort="5060" X_HW_SecondaryProxyServerTransport="" RegistrarServer="" RegistrarServerPort="5060" RegistrarServerTransport="UDP" X_HW_SecondaryRegistrarServer="" X_HW_SecondaryRegistrarServerPort="5060" X_HW_SecondaryRegistrarServerTransport="UDP" OutboundProxy="" OutboundProxyPort="5060" X_HW_SecondaryOutboundProxy="" X_HW_SecondaryOutboundProxyPort="5060" UserAgentDomain="" UserAgentPort="5060" UserAgentTransport="" VLANIDMark="" EthernetPriorityMark="-1" X_HW_802-1pMark="" DSCPMark="26" Organization="" RegistrationPeriod="600" TimerT1="500" TimerT2="4000" TimerT4="5000" RegisterRetryInterval="30" InboundAuthUsername="" InboundAuthPassword="" UseCodecPriorityInSDPResponse="0" SIPResponseMapNumberOfElements="0" X_HW_EmergencyDSCPMark="-1">
```
</details>

### HG8145V5-V500R020C10SPC212

**Version:** `V500R020C10SPC212B465`

| File | Size | SHA-256 |
|------|------|---------|
| `hw_ctree.xml` | 18,760 B | `0441738f59a63a14…` |
| `hw_ctree_decrypted.xml` | 131,509 B | `33e08141db161faf…` |
| `hw_default_ctree.xml` | 18,760 B | `0441738f59a63a14…` |
| `hw_default_ctree_decrypted.xml` | 131,509 B | `33e08141db161faf…` |

<details>
<summary>Preview of decrypted hw_ctree.xml</summary>

```xml
<InternetGatewayDevice>
	<LANDevice NumberOfInstances="1">
		<LANDeviceInstance InstanceID="1" X_HW_WlanEnable="1" X_HW_WlanPowerValue="0">
<!-- SUPPORT_WIFI_START-->
			<WiFi RadioNumberOfEntries="1" X_HW_PairTrigger="None">
				<Radio NumberOfInstances="2">
					<RadioInstance InstanceID="1" SupportedFrequencyBands="2.4GHz" OperatingFrequencyBand="2.4GHz" GuardInterval="Auto" X_HW_TxChainMask="0" X_HW_RxChainMask="0" Enable="1" Status="Up" Alias="cpe-2.4G" Name="cpe-2.4G" LastChange="0" MaxBitRate="0" AutoChannelSupported="1" X_HW_RatePriority="0" X_HW_SameSSIDStatus="0" CountryIEEnable="0"/>
					<RadioInstance InstanceID="2" SupportedFrequencyBands="5GHz" OperatingFrequencyBand="5GHz" GuardInterval="Auto" X_HW_TxChainMask="0" X_HW_RxChainMask="0" Enable="1" Status="Up" Alias="cpe-5G" Name="cpe-5G" LastChange="0" MaxBitRate="0" AutoChannelSupported="1" X_HW_RatePriority="0" X_HW_SameSSIDStatus="0" CountryIEEnable="0"/>
```
</details>

### HG8245C-8145C-BLUE-R019-xpon

**Version:** `V300R017C10SPC125B176`

| File | Size | SHA-256 |
|------|------|---------|
| `hw_ctree.xml` | 18,216 B | `ba43e97a9752af1b…` |
| `hw_ctree_decrypted.xml` | 125,365 B | `9a8d5f6ab0694ada…` |
| `hw_default_ctree.xml` | 18,216 B | `ba43e97a9752af1b…` |
| `hw_default_ctree_decrypted.xml` | 125,365 B | `9a8d5f6ab0694ada…` |

<details>
<summary>Preview of decrypted hw_ctree.xml</summary>

```xml
<InternetGatewayDevice>
	<LANDevice NumberOfInstances="1">
		<LANDeviceInstance InstanceID="1" X_HW_WlanEnable="1" X_HW_WlanPowerValue="0">
<!-- SUPPORT_WIFI_START-->
			<WiFi RadioNumberOfEntries="1" X_HW_PairTrigger="None">
				<Radio NumberOfInstances="2">
					<RadioInstance InstanceID="1" SupportedFrequencyBands="2.4GHz" OperatingFrequencyBand="2.4GHz" GuardInterval="400nsec" X_HW_TxChainMask="0" X_HW_RxChainMask="0" Enable="1" Status="Up" Alias="cpe-2.4G" Name="cpe-2.4G" LastChange="0" MaxBitRate="0" AutoChannelSupported="1" X_HW_RatePriority="0" X_HW_SameSSIDStatus="0"/>
					<RadioInstance InstanceID="2" SupportedFrequencyBands="5GHz" OperatingFrequencyBand="5GHz" GuardInterval="400nsec" X_HW_TxChainMask="0" X_HW_RxChainMask="0" Enable="1" Status="Up" Alias="cpe-5G" Name="cpe-5G" LastChange="0" MaxBitRate="0" AutoChannelSupported="1" X_HW_RatePriority="0" X_HW_SameSSIDStatus="0"/>
```
</details>

### HN8145XR-V500R022C10SPC160

**Version:** `V500R022C10SPC160B014`

| File | Size | SHA-256 |
|------|------|---------|
| `hw_ctree.xml` | 19,144 B | `11254f34b3f232f4…` |
| `hw_ctree_decrypted.xml` | 132,367 B | `997cb56c6afff659…` |
| `hw_default_ctree.xml` | 19,144 B | `11254f34b3f232f4…` |
| `hw_default_ctree_decrypted.xml` | 132,367 B | `997cb56c6afff659…` |

<details>
<summary>Preview of decrypted hw_ctree.xml</summary>

```xml
<InternetGatewayDevice>
	<LANDevice NumberOfInstances="1">
		<LANDeviceInstance InstanceID="1" X_HW_WlanEnable="1" X_HW_WlanPowerValue="0">
<!-- SUPPORT_WIFI_START-->
			<WiFi RadioNumberOfEntries="1" X_HW_PairTrigger="None">
				<Radio NumberOfInstances="2">
					<RadioInstance InstanceID="1" SupportedFrequencyBands="2.4GHz" OperatingFrequencyBand="2.4GHz" GuardInterval="Auto" X_HW_TxChainMask="0" X_HW_RxChainMask="0" Enable="1" Status="Up" Alias="cpe-2.4G" Name="cpe-2.4G" LastChange="0" MaxBitRate="0" AutoChannelSupported="1" X_HW_RatePriority="0" X_HW_SameSSIDStatus="0" CountryIEEnable="0"/>
					<RadioInstance InstanceID="2" SupportedFrequencyBands="5GHz" OperatingFrequencyBand="5GHz" GuardInterval="Auto" X_HW_TxChainMask="0" X_HW_RxChainMask="0" Enable="1" Status="Up" Alias="cpe-5G" Name="cpe-5G" LastChange="0" MaxBitRate="0" AutoChannelSupported="1" X_HW_RatePriority="0" X_HW_SameSSIDStatus="0" CountryIEEnable="0"/>
```
</details>

## Decryption Method

Files were decrypted using each firmware's own `/bin/aescrypt2` binary
executed via `qemu-arm-static` chroot, with key material from the firmware's
own rootfs (`/etc/wap/kmc_store_A`, `/etc/wap/kmc_store_B` for V500 firmwares,
or `/etc/wap/prvt.key`, `/etc/wap/EquipKey` for V300 firmwares).

```
sudo chroot <rootfs> qemu-arm-static /bin/aescrypt2 1 <input> <output>
```

### HN8145XR Decryption

The HN8145XR firmware has a split-rootfs layout with 7 SquashFS images.
The `hw_ctree.xml` is in the first rootfs, while `aescrypt2` is in the
second (26 MB) rootfs. Unlike other V500 firmwares, HN8145XR does not
include `kmc_store` files in `/etc/wap/` — the `kmc_store` is normally
generated at first boot from the device's hardware e-fuse.

However, by creating **empty** `kmc_store_A` and `kmc_store_B` files in
`/mnt/jffs2/` (the runtime keystore path), `aescrypt2` falls back to a
default key derivation that successfully decrypts the factory `hw_ctree.xml`.

```bash
# HN8145XR specific: use second SquashFS for aescrypt2 + empty kmc_store
mkdir -p <rootfs>/mnt/jffs2/
touch <rootfs>/mnt/jffs2/kmc_store_A <rootfs>/mnt/jffs2/kmc_store_B
sudo chroot <rootfs> qemu-arm-static /bin/aescrypt2 1 /tmp/hw_ctree.xml /tmp/out.xml
# Output is gzip → gunzip → <InternetGatewayDevice> XML
```

## Extraction Tool

```bash
python tools/ctree_extract.py -o extracted_configs
```