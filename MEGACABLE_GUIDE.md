# Guía Megacable — Análisis de Firmware Huawei ONT

Guía específica para usuarios de **Megacable** (alias: mega, megacable2)
con dispositivos Huawei ONT (HG8145V5, EG8145V5, HN8145XR, HG8245C).

## Índice

1. [Descargar Firmware](#1-descargar-firmware)
2. [Extraer y Analizar Firmware](#2-extraer-y-analizar-firmware)
3. [Desencriptar Configuración](#3-desencriptar-configuración)
4. [Activar la Shell WAP (Telnet/SSH)](#4-activar-la-shell-wap-telnetssh)
5. [Análisis de Binarios](#5-análisis-de-binarios)
6. [Análisis de Configuraciones XML](#6-análisis-de-configuraciones-xml)
7. [Credenciales de Fábrica](#7-credenciales-de-fábrica)
8. [Comandos cfgtool](#8-comandos-cfgtool)

---

## 1. Descargar Firmware

Usar el script de descarga incluido en el repositorio:

```bash
# Descargar todos los firmwares disponibles
python tools/download_firmwares.py --output-dir firmwares

# Los firmwares se descargan de GitHub Releases (V2):
#   - HG8145V5 (V500R020C10SPC212)
#   - EG8145V5 (V500R022C00SPC340B019)
#   - HN8145XR (V500R022C10SPC160)
#   - HG8245C  (V5R019C00S105)
```

## 2. Extraer y Analizar Firmware

### Extracción del rootfs (SquashFS)

```bash
# Extraer rootfs y binarios clave de un firmware específico
python tools/fw_extract.py firmwares/EG8145V5-V500R022C00SPC340B019.bin -o extracted

# Extraer todos los archivos de configuración
python tools/fw_ctree_extract.py firmwares/EG8145V5-V500R022C00SPC340B019.bin -o configs

# Análisis completo con detección de ISP
python tools/firmware_analyzer.py --isp megacable -o analysis_output

# Analizar un firmware específico
python tools/firmware_analyzer.py firmwares/EG8145V5-V500R022C00SPC340B019.bin \
    --isp megacable -o analysis_output
```

### Análisis completo con extracción y desencriptación

```bash
# Descargar, extraer y analizar todos los firmwares
python tools/ctree_extract.py -o extracted_configs
```

## 3. Desencriptar Configuración

### Método 1: Usando aescrypt2 del propio firmware (qemu chroot)

Para firmwares V500 (HG8145V5, EG8145V5):

```bash
# 1. Extraer el rootfs
python tools/fw_extract.py firmware.bin -o extracted

# 2. Configurar qemu-arm-static
sudo cp /usr/bin/qemu-arm-static rootfs/usr/bin/

# 3. Desencriptar hw_ctree.xml
sudo chroot rootfs qemu-arm-static /bin/aescrypt2 1 \
    /etc/wap/hw_ctree.xml /tmp/out.xml

# 4. Descomprimir (el output es gzip)
gunzip /tmp/out.xml.gz
```

Para HN8145XR (sin kmc_store):

```bash
# Crear archivos kmc_store vacíos para forzar clave por defecto
mkdir -p rootfs/mnt/jffs2/
touch rootfs/mnt/jffs2/kmc_store_A rootfs/mnt/jffs2/kmc_store_B

sudo chroot rootfs qemu-arm-static /bin/aescrypt2 1 \
    /etc/wap/hw_ctree.xml /tmp/out.xml
gunzip /tmp/out.xml.gz
```

### Método 2: Usando el módulo crypto de Python

Para archivos de respaldo exportados desde la interfaz web:

```python
from hwflash.core.crypto import try_decrypt_all_keys

with open("config_backup.xml", "rb") as f:
    data = f.read()

# Probar todas las claves conocidas (chip IDs)
results = try_decrypt_all_keys(data)
if results:
    chip_id, xml_content = results[0]
    print(f"Desencriptado con chip ID: {chip_id}")
    with open("config_decrypted.xml", "wb") as f:
        f.write(xml_content)
```

### Método 3: Usando el analizador integrado

```bash
python tools/firmware_analyzer.py firmware.bin --isp megacable -o output
# Si la desencriptación es exitosa, se genera hw_ctree_decrypted.xml
```

## 4. Activar la Shell WAP (Telnet/SSH)

La **Shell WAP** es la interfaz de línea de comandos (CLI) de Huawei
accesible por Telnet en el puerto 23. El hostname del dispositivo
es `WAP` (configurado como `<NetInfo HostName="WAP"/>`).

### Configuración actual de fábrica

Según el análisis de los firmwares desencriptados:

| Parámetro | Valor | Descripción |
|-----------|-------|-------------|
| `TELNETLanEnable` | `1` | Telnet habilitado desde LAN |
| `TELNETWanEnable` | `0` | Telnet deshabilitado desde WAN |
| `TELNETWifiEnable` | `1` | Telnet habilitado desde WiFi |
| `TELNETPORT` | `23` | Puerto Telnet |
| `SSHLanEnable` | `0` o `1` | SSH desde LAN (varía por firmware) |
| `SSHWanEnable` | `0` | SSH deshabilitado desde WAN |
| `SSHPORT` | `22` | Puerto SSH |
| `X_HW_CLITelnetAccess` | `Access=1` | Acceso CLI por Telnet activo |

### Método 1: Usando la herramienta ONT Tool (OBSC)

La forma más directa es usar la herramienta ONT Tool incluida en
el repositorio, que utiliza el protocolo OBSC UDP para habilitar
el acceso remoto:

1. Ejecutar `ONT-tool.exe` (Windows) o `1211.exe`
2. Seleccionar **Enable Package**:
   - **Package 1** (V3): Habilita Telnet + SSH
   - **Package 2** (V5): Factory reset y re-habilita Telnet + SSH
   - **Package 3** (dispositivos nuevos): Upgrade completo, Telnet + SSH
3. Conectar al dispositivo por Telnet: `telnet 192.168.1.1 23`

### Método 2: Usando cfgtool (desde la shell del dispositivo)

Si ya tienes acceso a la shell del dispositivo:

```bash
# Habilitar Telnet desde LAN
cfgtool set deftree \
    "InternetGatewayDevice.X_HW_Security.AclServices" \
    "TELNETLanEnable" "1"

# Habilitar SSH desde LAN
cfgtool set deftree \
    "InternetGatewayDevice.X_HW_Security.AclServices" \
    "SSHLanEnable" "1"

# Habilitar acceso CLI por Telnet
cfgtool set deftree \
    "InternetGatewayDevice.UserInterface.X_HW_CLITelnetAccess" \
    "Access" "1"

# Configurar usuario CLI
cfgtool set deftree \
    "InternetGatewayDevice.UserInterface.X_HW_CLIUserInfo.1" \
    "Username" "root"
cfgtool set deftree \
    "InternetGatewayDevice.UserInterface.X_HW_CLIUserInfo.1" \
    "Userpassword" "admin"

# Guardar cambios
cfgtool save
```

### Método 3: Modificando el archivo de configuración

1. **Exportar** la configuración desde la interfaz web del dispositivo
2. **Desencriptar** usando el módulo crypto (ver sección 3)
3. **Modificar** los atributos XML relevantes:

```xml
<!-- Habilitar servicios de acceso -->
<AclServices
    TELNETLanEnable="1"
    TELNETWanEnable="0"
    SSHLanEnable="1"
    SSHWanEnable="0"
    TELNETPORT="23"
    SSHPORT="22"
    TELNETWifiEnable="1"/>

<!-- Habilitar CLI Telnet -->
<X_HW_CLITelnetAccess Access="1"/>

<!-- Configurar usuario CLI -->
<X_HW_CLIUserInfoInstance
    InstanceID="1"
    Username="root"
    Userpassword="admin"
    UserGroup=""
    EncryptMode="3"/>
```

4. **Re-encriptar** y **importar** la configuración modificada

### Conexión a la Shell WAP

```bash
# Conectar por Telnet
telnet 192.168.1.1 23

# Login con credenciales CLI
# Usuario: root
# Contraseña: admin

# Comandos útiles en la shell WAP:
WAP> display version          # Versión del firmware
WAP> display current-config   # Configuración actual
WAP> display interface        # Interfaces de red
WAP> display ont info         # Información ONT/GPON
WAP> display sysinfo          # Información del sistema
```

## 5. Análisis de Binarios

### Descompilar binarios ARM con Capstone

```bash
# Desensamblar aescrypt2
python tools/arm_disasm.py rootfs/bin/aescrypt2 -o disasm_output

# Desensamblar libhw_ssp_basic.so
python tools/arm_disasm.py rootfs/lib/libhw_ssp_basic.so -o disasm_output
```

### Binarios clave

| Binario | Descripción | Funciones clave |
|---------|-------------|-----------------|
| `/bin/aescrypt2` | Encriptación/desencriptación de configuración | `OS_AescryptEncrypt`, `OS_AescryptDecrypt` |
| `/bin/cfgtool` | API de gestión de configuración | `HW_CFGTOOL_GetXMLValByPath`, `HW_CFGTOOL_SetXMLValByPath` |
| `/lib/libhw_ssp_basic.so` | Funciones de seguridad centrales | `HW_XML_CFGFileSecurity`, `HW_KMC_GetAppointKey` |
| `/lib/libpolarssl.so` | Librería crypto mbedTLS | `mbedtls_aes_crypt_cbc`, `mbedtls_sha256` |
| `/lib/libhw_swm_dll.so` | Verificación de firma de firmware | `SWM_Sig_VerifySignature` |

### Usar radare2 para análisis profundo

```bash
# Listar funciones
r2 -qc 'aaa; afl' bin/aescrypt2

# Desensamblar función main
r2 -qc 'aaa; pdf @sym.main' bin/aescrypt2

# Buscar strings relacionados con shell/telnet
r2 -qc 'izz~telnet' bin/cfgtool
r2 -qc 'izz~shell' bin/cfgtool
r2 -qc 'izz~kmc_store' bin/aescrypt2

# Referencias cruzadas
r2 -qc 'aaa; axt @sym.HW_XML_CFGFileSecurity' lib/libhw_ssp_basic.so
```

## 6. Análisis de Configuraciones XML

### Archivos de configuración en `/etc/wap/`

| Archivo | Formato | Descripción |
|---------|---------|-------------|
| `hw_ctree.xml` | Encriptado (AES-256-CBC) | Árbol de configuración principal |
| `hw_default_ctree.xml` | Encriptado | Configuración de fábrica |
| `hw_aes_tree.xml` | XML plano | Esquema de campos encriptados |
| `hw_flashcfg.xml` | XML plano | Diseño de particiones flash |
| `hw_boardinfo` | Texto plano | Identidad del dispositivo |
| `hw_firewall_v5.xml` | XML plano | Reglas de firewall |
| `keyconfig.xml` | XML plano | Configuración de botón reset |
| `passwd` | Texto plano | Cuentas del sistema |
| `hw_cli.xml` | XML plano | Configuración CLI |

### Analizar con el script integrado

```bash
# Analizar todas las configuraciones extraídas
python tools/config_analyzer.py --configs-dir extracted_configs

# Ver diferencias entre firmwares
# Output: extracted_configs/CONFIG_ANALYSIS.md
```

### Configuraciones pre-extraídas

El repositorio incluye configuraciones ya extraídas y desencriptadas en:

- `configs/` — Archivos de configuración crudos por firmware
- `extracted_configs/` — Configuraciones desencriptadas con análisis completo

## 7. Credenciales de Fábrica

Extraídas del `hw_ctree.xml` desencriptado:

### Usuarios Web

| Usuario | Nivel | Contraseña de fábrica |
|---------|-------|-----------------------|
| `root` | 1 (Usuario) | `admin` |
| `telecomadmin` | 0 (Administrador) | *(hash SHA-256, ISP-específica)* |

### Usuarios CLI (Telnet/SSH)

| Usuario | Contraseña | Grupo |
|---------|------------|-------|
| `root` | `admin` | *(vacío)* |

### Usuarios del sistema (passwd)

| Usuario | UID | Descripción |
|---------|-----|-------------|
| `root` | 0 | Root (sin shell de login) |
| `mgt_ssmp` | 3008 | Gestión del dispositivo |
| `srv_web` | 3004 | Servidor web |
| `cfg_cwmp` | 3007 | TR-069 CWMP |
| `kmc` | 3020 | Key Management Center |
| `cfg_pon` | 3009 | OMCI/OAM |

### Nota sobre Megacable

Los dispositivos Megacable (mega/megacable2) típicamente usan:
- **telecomadmin** como cuenta de administrador del ISP
- La contraseña de `telecomadmin` es configurada por el ISP y difiere
  de la contraseña de fábrica
- El hash SHA-256 de la contraseña está almacenado con `PassMode=2`
  (SHA-256) en el `hw_ctree.xml`
- Para acceso completo, usar las credenciales CLI (`root`/`admin`)
  via Telnet después de habilitarlo

## 8. Comandos cfgtool

El binario `cfgtool` permite leer y modificar la configuración del
dispositivo directamente desde la shell:

```bash
# Leer un parámetro
cfgtool get deftree "InternetGatewayDevice.X_HW_Security.AclServices"

# Modificar un parámetro
cfgtool set deftree "<path>" "<atributo>" "<valor>"

# Agregar una instancia
cfgtool add deftree "<path>"

# Eliminar una instancia
cfgtool del deftree "<path>"

# Exportar un subárbol
cfgtool clone deftree "<path>" "<archivo>"

# Importar configuración por lotes
cfgtool batch deftree "<archivo>"

# Ejemplos específicos para Megacable:

# Ver estado de Telnet
cfgtool get deftree \
    "InternetGatewayDevice.X_HW_Security.AclServices"

# Ver usuarios web
cfgtool get deftree \
    "InternetGatewayDevice.UserInterface.X_HW_WebUserInfo"

# Ver usuarios CLI
cfgtool get deftree \
    "InternetGatewayDevice.UserInterface.X_HW_CLIUserInfo"

# Ver información del producto
cfgtool get deftree "InternetGatewayDevice.X_HW_ProductInfo"

# Ver información WAN
cfgtool get deftree "InternetGatewayDevice.WANDevice"
```

---

## Herramientas del Repositorio

| Script | Descripción |
|--------|-------------|
| `tools/download_firmwares.py` | Descargar firmwares desde GitHub Releases |
| `tools/fw_extract.py` | Extraer rootfs y binarios de firmware HWNP |
| `tools/fw_ctree_extract.py` | Extraer archivos de configuración |
| `tools/ctree_extract.py` | Extraer y desencriptar hw_ctree.xml |
| `tools/firmware_analyzer.py` | Análisis completo del firmware |
| `tools/arm_disasm.py` | Desensamblador ARM con Capstone |
| `tools/config_analyzer.py` | Análisis comparativo de configuraciones |
| `launcher.py` | Interfaz gráfica HuaweiFlash |
