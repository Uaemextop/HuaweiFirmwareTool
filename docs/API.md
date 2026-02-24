# API Documentation

## obsc_tool.firmware

### HWNPFirmware

**Description**: Parser and validator for HWNP (Huawei Network Protocol) firmware packages.

#### Methods

##### `__init__()`
Initialize an empty firmware parser.

```python
fw = HWNPFirmware()
```

##### `load(file_path: str) -> None`
Load and parse an HWNP firmware file.

**Parameters**:
- `file_path` (str): Path to the .bin firmware file

**Raises**:
- `FileNotFoundError`: If the file does not exist
- `ValueError`: If the file is not a valid HWNP firmware

**Example**:
```python
fw = HWNPFirmware()
fw.load("/path/to/firmware.bin")
print(f"Loaded firmware with {fw.item_count} items")
```

##### `validate_crc32() -> Tuple[bool, bool]`
Validate CRC32 checksums of the firmware.

**Returns**:
- `Tuple[bool, bool]`: (header_valid, data_valid)

**Example**:
```python
header_ok, data_ok = fw.validate_crc32()
if header_ok and data_ok:
    print("Firmware validation passed")
else:
    print("Firmware validation failed")
```

##### `get_info() -> dict`
Get a summary dictionary of the firmware information.

**Returns**:
- `dict`: Dictionary containing:
  - `file` (str): Basename of the firmware file
  - `size` (int): Total file size in bytes
  - `items` (int): Number of firmware items
  - `products` (str): Compatible product list
  - `items_detail` (list): List of item details

**Example**:
```python
info = fw.get_info()
print(f"Firmware: {info['file']}")
print(f"Products: {info['products']}")
for item in info['items_detail']:
    print(f"  - {item['path']} ({item['size']} bytes)")
```

##### `get_total_data_size() -> int`
Get total size of all firmware item data.

**Returns**:
- `int`: Total size in bytes

**Example**:
```python
total_size = fw.get_total_data_size()
print(f"Total firmware data: {total_size / 1024 / 1024:.2f} MB")
```

#### Attributes

- `magic` (int): HWNP magic number (0x504E5748)
- `raw_size` (int): Total firmware size
- `raw_crc32` (int): CRC32 of entire file
- `header_size` (int): Size of header section
- `header_crc32` (int): CRC32 of header
- `item_count` (int): Number of firmware items
- `prod_list_size` (int): Size of product list
- `item_header_size` (int): Size of each item header
- `product_list` (str): Compatible products (semicolon-separated)
- `items` (List[HWNPItem]): List of firmware items
- `raw_data` (bytes): Raw firmware file data
- `file_path` (str): Path to loaded file

---

### HWNPItem

**Description**: Represents a single firmware item within an HWNP package.

#### Attributes

- `index` (int): Item index
- `crc32` (int): CRC32 checksum of item data
- `data_offset` (int): Offset in file where data starts
- `data_size` (int): Size of item data
- `item_path` (str): File path within firmware (e.g., "kernel.bin")
- `section` (str): Section name (e.g., "kernel", "rootfs")
- `version` (str): Version string
- `policy` (int): Update policy flags
- `data` (bytes): Item data

#### Example

```python
for item in fw.items:
    print(f"{item.item_path}:")
    print(f"  Section: {item.section}")
    print(f"  Version: {item.version}")
    print(f"  Size: {item.data_size} bytes")
    print(f"  CRC32: 0x{item.crc32:08X}")
```

---

## obsc_tool.protocol

### OBSCProtocol

**Description**: Implementation of the OBSC (Optical Network Terminal Boot Service Client) protocol for firmware transfer.

#### Methods

##### `__init__(transport)`
Initialize protocol with a transport layer.

**Parameters**:
- `transport`: UDP transport instance

##### `authenticate(device_info: dict) -> bool`
Authenticate with the device.

**Parameters**:
- `device_info` (dict): Device credentials and parameters

**Returns**:
- `bool`: True if authentication succeeded

##### `flash_firmware(firmware: HWNPFirmware, progress_callback=None) -> bool`
Flash firmware to device.

**Parameters**:
- `firmware` (HWNPFirmware): Parsed firmware object
- `progress_callback` (callable, optional): Progress callback function

**Returns**:
- `bool`: True if flashing succeeded

**Example**:
```python
def on_progress(current, total):
    print(f"Progress: {current}/{total} ({100*current//total}%)")

protocol = OBSCProtocol(transport)
if protocol.authenticate(device_info):
    protocol.flash_firmware(firmware, on_progress)
```

---

## obsc_tool.network

### NetworkAdapter

**Description**: Represents a network interface adapter.

#### Attributes

- `name` (str): Interface name (e.g., "eth0", "Ethernet")
- `description` (str): Human-readable description
- `ip_address` (str): IP address
- `netmask` (str): Network mask
- `mac_address` (str): MAC address

### Functions

##### `discover_adapters() -> List[NetworkAdapter]`
Discover available network adapters on the system.

**Returns**:
- `List[NetworkAdapter]`: List of available adapters

**Example**:
```python
from obsc_tool.network import discover_adapters

adapters = discover_adapters()
for adapter in adapters:
    print(f"{adapter.name}: {adapter.ip_address}")
```

---

### UDPTransport

**Description**: UDP-based transport for OBSC protocol.

#### Methods

##### `__init__(adapter: NetworkAdapter, remote_ip: str, remote_port: int)`
Initialize UDP transport.

**Parameters**:
- `adapter` (NetworkAdapter): Local network adapter
- `remote_ip` (str): Device IP address
- `remote_port` (int): Device port (default: 50000)

##### `send(data: bytes) -> None`
Send data to device.

**Parameters**:
- `data` (bytes): Data to send

##### `receive(timeout: float = 5.0) -> bytes`
Receive data from device.

**Parameters**:
- `timeout` (float): Receive timeout in seconds

**Returns**:
- `bytes`: Received data

**Raises**:
- `socket.timeout`: If no data received within timeout

**Example**:
```python
transport = UDPTransport(adapter, "192.168.1.1", 50000)
transport.send(packet_data)
response = transport.receive(timeout=10.0)
```

---

## obsc_tool.terminal

### TelnetClient

**Description**: Telnet client for device shell access.

#### Methods

##### `__init__(host: str, port: int = 23, username: str = None, password: str = None)`
Initialize Telnet client.

**Parameters**:
- `host` (str): Device hostname or IP
- `port` (int): Telnet port (default: 23)
- `username` (str, optional): Login username
- `password` (str, optional): Login password

##### `connect() -> bool`
Connect to device.

**Returns**:
- `bool`: True if connected

##### `send_command(command: str) -> str`
Send command and get response.

**Parameters**:
- `command` (str): Command to execute

**Returns**:
- `str`: Command output

**Example**:
```python
client = TelnetClient("192.168.1.1", username="root", password="admin")
if client.connect():
    output = client.send_command("cat /proc/version")
    print(output)
    client.disconnect()
```

---

### SerialClient

**Description**: Serial port client for device shell access.

#### Methods

##### `__init__(port: str, baudrate: int = 115200)`
Initialize Serial client.

**Parameters**:
- `port` (str): Serial port (e.g., "COM3", "/dev/ttyUSB0")
- `baudrate` (int): Baud rate (default: 115200)

##### `connect() -> bool`
Open serial connection.

**Returns**:
- `bool`: True if connected

##### `send_command(command: str) -> str`
Send command and get response.

**Parameters**:
- `command` (str): Command to execute

**Returns**:
- `str`: Command output

**Example**:
```python
client = SerialClient("/dev/ttyUSB0", baudrate=115200)
if client.connect():
    output = client.send_command("ls -la")
    print(output)
    client.disconnect()
```

---

## obsc_tool.config_crypto

### Functions

##### `encrypt_config(data: str, key: str) -> str`
Encrypt configuration data.

**Parameters**:
- `data` (str): Plain text configuration
- `key` (str): Encryption key

**Returns**:
- `str`: Base64-encoded encrypted data

**Example**:
```python
from obsc_tool.config_crypto import encrypt_config, decrypt_config

encrypted = encrypt_config("my_secret_config", "my_key")
decrypted = decrypt_config(encrypted, "my_key")
assert decrypted == "my_secret_config"
```

##### `decrypt_config(data: str, key: str) -> str`
Decrypt configuration data.

**Parameters**:
- `data` (str): Base64-encoded encrypted data
- `key` (str): Decryption key

**Returns**:
- `str`: Plain text configuration

---

## obsc_tool.presets

### PresetManager

**Description**: Manages device configuration presets.

#### Methods

##### `__init__(presets_dir: str = None)`
Initialize preset manager.

**Parameters**:
- `presets_dir` (str, optional): Directory for preset files

##### `load_presets() -> List[dict]`
Load all presets from directory.

**Returns**:
- `List[dict]`: List of preset dictionaries

##### `save_preset(name: str, config: dict) -> None`
Save a configuration preset.

**Parameters**:
- `name` (str): Preset name
- `config` (dict): Configuration dictionary

##### `load_preset(name: str) -> dict`
Load a specific preset.

**Parameters**:
- `name` (str): Preset name

**Returns**:
- `dict`: Configuration dictionary

**Example**:
```python
from obsc_tool.presets import PresetManager

manager = PresetManager()

# Save preset
config = {
    "device_type": "HG8245H",
    "ip": "192.168.1.1",
    "port": 50000
}
manager.save_preset("my_device", config)

# Load preset
loaded = manager.load_preset("my_device")
print(loaded["device_type"])
```

---

## Command-Line Tools (C++)

### hw_fmw - Firmware Pack/Unpack

**Usage**:
```bash
# Unpack firmware
hw_fmw -u firmware.bin output_dir/

# Pack firmware
hw_fmw -p input_dir/ output.bin
```

**Options**:
- `-u, --unpack FILE DIR`: Unpack firmware to directory
- `-p, --pack DIR FILE`: Pack directory to firmware file
- `-h, --help`: Show help message

---

### hw_sign - Firmware Signing

**Usage**:
```bash
hw_sign firmware.bin private_key.pem output.bin
```

**Arguments**:
- `firmware.bin`: Input firmware file
- `private_key.pem`: RSA private key (PEM format)
- `output.bin`: Output signed firmware

**Key Generation**:
```bash
# Generate RSA-2048 key pair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

---

### hw_verify - Signature Verification

**Usage**:
```bash
hw_verify firmware.bin public_key.pem
```

**Arguments**:
- `firmware.bin`: Signed firmware file
- `public_key.pem`: RSA public key (PEM format)

**Exit Codes**:
- `0`: Signature valid
- `1`: Signature invalid or error

---

## Error Handling

### Common Exceptions

```python
from obsc_tool.firmware import HWNPFirmware

try:
    fw = HWNPFirmware()
    fw.load("firmware.bin")
except FileNotFoundError:
    print("Firmware file not found")
except ValueError as e:
    print(f"Invalid firmware: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

### Protocol Errors

```python
from obsc_tool.protocol import OBSCProtocol, ProtocolError

try:
    protocol.flash_firmware(firmware)
except ProtocolError as e:
    print(f"Protocol error: {e}")
except TimeoutError:
    print("Device did not respond")
```

---

## Examples

### Complete Firmware Flash Example

```python
#!/usr/bin/env python3
from obsc_tool.firmware import HWNPFirmware
from obsc_tool.network import discover_adapters, UDPTransport
from obsc_tool.protocol import OBSCProtocol

# 1. Load firmware
firmware = HWNPFirmware()
firmware.load("firmware.bin")

# 2. Validate firmware
header_ok, data_ok = firmware.validate_crc32()
if not (header_ok and data_ok):
    raise ValueError("Firmware validation failed")

# 3. Select network adapter
adapters = discover_adapters()
adapter = adapters[0]  # Use first adapter

# 4. Create transport
transport = UDPTransport(adapter, "192.168.1.1", 50000)

# 5. Initialize protocol
protocol = OBSCProtocol(transport)

# 6. Authenticate
device_info = {
    "username": "admin",
    "password": "admin"
}
if not protocol.authenticate(device_info):
    raise RuntimeError("Authentication failed")

# 7. Flash firmware with progress
def on_progress(current, total):
    percent = 100 * current // total
    print(f"\rProgress: {percent}%", end="", flush=True)

protocol.flash_firmware(firmware, on_progress)
print("\nFlashing complete!")
```

---

## Type Hints

For better IDE support and type checking, the codebase uses Python type hints:

```python
from typing import List, Tuple, Optional, Callable

def flash_firmware(
    firmware: HWNPFirmware,
    progress_callback: Optional[Callable[[int, int], None]] = None
) -> bool:
    """Flash firmware to device."""
    pass
```

Use mypy for static type checking:
```bash
mypy obsc_tool/
```
