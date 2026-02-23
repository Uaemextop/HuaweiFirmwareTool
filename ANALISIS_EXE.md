# Análisis de Ejecutables - Herramientas de Firmware Huawei ONT

## Resumen

Este documento presenta el análisis estático detallado de dos ejecutables utilizados para
la gestión y modificación de firmware en dispositivos Huawei ONT (Optical Network Terminal),
específicamente el modelo HG8145V5.

Los ejecutables analizados son:
1. **ONT_V100R002C00SPC253.exe** — Herramienta oficial de Huawei para actualización de firmware ONT
2. **1211.exe** (v1.12) — Versión anterior de la misma herramienta, incluida en el paquete de desbloqueo

---

## 1. ONT_V100R002C00SPC253.exe — Herramienta Oficial OBSC

### Información del Archivo

| Campo | Valor |
|-------|-------|
| Tamaño | 9,101,312 bytes (8.68 MB) |
| MD5 | `dcf146eae9125b175c0fc448e2e246a7` |
| SHA-256 | `c882032e2dcd1a3ea2fc5e359e7c22a94d024fb0ae7e7be2f1cefd341796f8ec` |
| Tipo | PE32 ejecutable (GUI) Intel 80386 |
| Compilador | MSVC 14.0 (Visual Studio 2015) |
| Fecha compilación | 2021-03-03 09:13:12 UTC |
| Frameworks | MFC (Microsoft Foundation Classes), POCO C++ Libraries, OpenSSL |

### Estructura PE

```
Sección       DirVirtual  TamVirtual  TamReal     Entropía  Notas
.text         0x00001000  0x0030C5CA  0x0030C600  6.64      Código ejecutable principal
.rdata        0x0030E000  0x000F2486  0x000F2600  5.84      Datos de solo lectura
.data         0x00401000  0x00018AB4  0x0000C000  4.74      Datos globales
.gfids        0x0041A000  0x0001ACDC  0x0001AE00  4.23      Guard CF (seguridad)
.giats        0x00435000  0x00000010  0x00000200  0.16      Guard IAT
.tls          0x00436000  0x00000009  0x00000200  0.02      Thread Local Storage
.rsrc         0x00437000  0x004521E0  0x00452200  7.81      Recursos (iconos, diálogos, firmware)
.reloc        0x0088A000  0x00035B48  0x00035C00  6.55      Tabla de reubicación
```

**Nota:** La sección `.rsrc` tiene entropía alta (7.81) porque contiene firmware embebido con
7 cabeceras HWNP detectadas, además de un binario ELF embebido.

### Bibliotecas Importadas (21 DLLs)

| DLL | Funciones | Propósito |
|-----|-----------|-----------|
| WS2_32.dll | 19 | Comunicación red (sockets, UDP/TCP) |
| IPHLPAPI.DLL | 1 | Obtener adaptadores de red |
| ADVAPI32.dll | 29 | Criptografía, registro de Windows |
| KERNEL32.dll | 187 | API base del sistema |
| USER32.dll | 226 | Interfaz gráfica (ventanas, controles) |
| GDI32.dll | 98 | Dibujo y gráficos |
| SHELL32.dll | 11 | Exploración de archivos |
| CRYPT32.dll | 7 | Certificados digitales |
| bcrypt.dll | 1 | Generación de números aleatorios |
| ole32.dll | 34 | COM/OLE |
| gdiplus.dll | 22 | Gráficos avanzados (GDI+) |
| OpenSSL (estático) | — | Criptografía RSA, verificación de firmas |

### Cómo Funciona el Programa

#### Arquitectura Interna

El programa está construido sobre el framework **ONTFrameWork**, una arquitectura C++ propietaria
de Huawei que implementa el protocolo **OBSC** (ONT Bootloader Service Client). Las clases
principales identificadas son:

```
ONTFrameWork::
├── COBSCWorker        — Motor principal de actualización (hilo de trabajo)
├── CUDPSender         — Envío de paquetes UDP al ONT
├── CUdp               — Capa de comunicación UDP
├── CCtrlPktSender     — Envío de paquetes de control
├── CDataPktSender     — Envío de paquetes de datos (firmware)
├── CMachineManage     — Gestión de múltiples dispositivos ONT
├── CMachineCtrlPkg    — Paquete de control de máquina
├── CMachineCtrlEquipsWPkg  — Paquete de control para equipos
├── CDialogChannel     — Canal de comunicación con la interfaz
├── CDefaultPolicy     — Política de verificación por defecto
├── CIMachineCheckPolicy — Política de verificación de máquina
├── CAuditInfoMgr      — Gestión de logs de auditoría
├── CDefaultAuditLog   — Log de auditoría por defecto
├── CEquipsAuditLog    — Log de auditoría de equipos
└── MailSlotServer     — Comunicación inter-procesos
```

#### Protocolo OBSC

El protocolo OBSC es un protocolo propietario de Huawei basado en UDP para la actualización
de firmware de dispositivos ONT a través de la red local. El formato de sesión es:

```
UpgradeType[tipo] PKGVERSION[versión]
Service Started! ID[0xXXXX] VERSION[ver]
  SIP[ip_origen] DIP[ip_destino]
  FRSIZE[tamaño_frame] FRINTERV[intervalo_ms]
  PKSIZE[tamaño_paquete] PKCRC[crc32]
  FlashMode[modo] DeleteCfg[sí/no]
  MachineFilter[filtro] CheckPolicy[política]
  AuditPolicy[auditoría] BomCode[código]
  LogLevel[nivel]
```

**Parámetros clave del protocolo:**
- **FRSIZE** / **FRINTERV**: Tamaño de frame y intervalo entre envíos (en ms)
- **SIP** / **DIP**: Dirección IP fuente y destino
- **FlashMode**: Modo de escritura en flash (normal/forzado)
- **DeleteCfg**: Si se borran configuraciones previas
- **MachineFilter**: Filtro por número de serie del equipo
- **CheckPolicy**: Política de verificación de hardware compatible

#### Flujo de Actualización

```
1. INICIO
   ├── Usuario selecciona adaptador de red
   ├── Usuario selecciona archivo de firmware (.bin)
   └── Configura parámetros (FRSIZE, FRINTERV)

2. DESCUBRIMIENTO
   ├── COBSCWorker inicia búsqueda UDP en red local
   ├── Los ONTs en modo bootloader responden con MACHINE_INFO_S
   └── Se registra: BoardSN, 21SN, MAC

3. VERIFICACIÓN
   ├── CIMachineCheckPolicy verifica compatibilidad de hardware
   ├── Se verifica versión actual vs versión del paquete
   └── Se aplica MachineFilter si está configurado

4. TRANSFERENCIA
   ├── CCtrlPktSender envía paquete de control inicial
   ├── CDataPktSender fragmenta y envía firmware por UDP
   ├── Cada frame tiene FRSIZE bytes, enviado cada FRINTERV ms
   └── Se verifica CRC32 (PKCRC) del paquete completo

5. FINALIZACIÓN
   ├── El ONT verifica la firma HWNP del firmware
   ├── Escribe en flash según FlashMode
   ├── Opcionalmente borra configuración (DeleteCfg)
   └── Reinicia automáticamente
```

#### Firmware Embebido

El ejecutable contiene **7 imágenes HWNP** embebidas en la sección de recursos, además de
scripts de shell que se ejecutan en el ONT durante la actualización:

- Scripts de verificación de versión (`ParseVersion`, variables `var_etc_version_V/R/C/S`)
- Scripts de migración entre versiones (R6→R12→R13→R15→R16)
- Scripts de gestión de `hw_boardinfo.xml` y `cfgtool`
- Variables de configuración: `BoardInfo.eponkey`, `BoardInfo.snpassword`, `BoardInfo.loid`

**Versiones de firmware soportadas:**
- V100R006C00SPC130
- V200R006C00SPC130
- V300R013C00SPC106
- V300R013C10SPC108
- V500R020C00SPC060 (con SIGNINFO)

#### Log de Auditoría

El programa genera logs con el formato:
```
Time, BoardSN, 21SN, MAC, OBSCResult, CheckResult, UpgradeType, VersionPkg, VersionPkgSize
```

Los archivos de log se guardan como `OSBCToolClient.log` y `OBSC_Debug.log`.

---

## 2. 1211.exe (v1.12) — Versión Anterior / Herramienta de Desbloqueo

### Información del Archivo

| Campo | Valor |
|-------|-------|
| Tamaño | 2,366,464 bytes (2.26 MB) |
| MD5 | `efafefa8c2b53c17f19631d75f19cea3` |
| SHA-256 | `a3b6b88c4bee07b58800bcd3d545d5ee8ad805c0ea0111fb9e4b8ae9e109a94a` |
| Tipo | PE32 ejecutable (GUI) Intel 80386 |
| Compilador | MSVC 10.0 (Visual Studio 2010) |
| Fecha compilación | 2014-08-15 01:55:16 UTC |
| Estado | **EMPAQUETADO** (protegido con packer desconocido) |

### Estructura PE

```
Sección       DirVirtual  TamVirtual  TamReal     Entropía  Notas
lS8TSGXu      0x00001000  0x0020DC2C  0x00000000  0.00      VIRTUAL (desempaquetado en runtime)
HWB8zP1w      0x0020F000  0x00002000  0x00001600  5.99      Código del loader
QrVbjeUa      0x00211000  0x00216000  0x00215200  7.79      DATOS EMPAQUETADOS
LEXmTy1n      0x00427000  0x00001000  0x00000600  3.14      Datos auxiliares
niBTgJWZ      0x00428000  0x00029000  0x00028600  3.76      Recursos (parcialmente legibles)
sfW0L9wz      0x00451000  0x00001000  0x00000400  6.23      Configuración del packer
.text         0x00452000  0x00002000  0x00002000  0.48      Stub del entry point
```

### Análisis de Empaquetado

El ejecutable **1211.exe** está protegido con un packer de software desconocido. Las evidencias son:

1. **Nombres de sección aleatorios**: `lS8TSGXu`, `HWB8zP1w`, `QrVbjeUa`, `LEXmTy1n`, `niBTgJWZ`, `sfW0L9wz`
   — No son nombres estándar de compiladores conocidos

2. **Sección virtual vacía**: La primera sección (`lS8TSGXu`) tiene 2.1 MB de tamaño virtual
   pero 0 bytes en disco — se descomprime en memoria al ejecutarse

3. **Alta entropía**: La sección `QrVbjeUa` (2.1 MB) tiene entropía 7.79 — indica datos
   comprimidos/cifrados que contienen el programa real

4. **Imports mínimos**: Solo 1 función por cada DLL importada — típico de packers que resuelven
   imports dinámicamente en tiempo de ejecución

5. **Entry point en sección inusual**: El punto de entrada (0x0020F2FD) está en `HWB8zP1w`,
   la segunda sección, que contiene el código de desempaquetado

### Flujo de Ejecución

```
1. Windows carga 1211.exe
2. Entry point en HWB8zP1w (sección del loader)
3. El loader:
   a. Descomprime QrVbjeUa → lS8TSGXu (2.1 MB de código MFC + ONTFrameWork)
   b. Resuelve imports dinámicamente (LoadLibrary + GetProcAddress)
   c. Reconstruye la Import Address Table
   d. Salta al OEP (Original Entry Point) real
4. El programa real se ejecuta como la herramienta OBSC/ONT
```

### Bibliotecas Importadas (19 DLLs)

Las mismas DLLs base que ONT_V100R002C00SPC253.exe, pero con solo 1 import visible por DLL
(el packer oculta los imports reales):

- kernel32.dll (Sleep), iphlpapi.dll (GetAdaptersInfo), USER32.dll, GDI32.dll,
  MSIMG32.dll, COMDLG32.dll, WINSPOOL.DRV, ADVAPI32.dll, SHELL32.dll,
  COMCTL32.dll, SHLWAPI.dll, ole32.dll, OLEAUT32.dll, oledlg.dll,
  WS2_32.dll (inet_ntoa), OLEACC.dll, gdiplus.dll, IMM32.dll, WINMM.dll

### Funcionalidad (deducida)

Aunque el código está empaquetado, por el conjunto de DLLs importadas y el contexto de uso,
1211.exe es una **versión anterior (2014)** de la misma herramienta OBSC de Huawei:

- Interfaz gráfica MFC (GUI Windows)
- Comunicación UDP/IP con dispositivos ONT
- Gestión de adaptadores de red (iphlpapi)
- Envío de firmware por protocolo OBSC propietario
- Generación de logs OSBC_LOG_*.log

---

## 3. Paquete de Desbloqueo (DESBLOQUEIO R22)

### Contenido del RAR

```
DESBLOQUEIO R22 HG8145V5 E HG8145V5V2/
├── METODO DE DESBLOQUEIO R22.txt     — Instrucciones de desbloqueo
├── DONGRAD R20/
│   └── HG8145V5_V2_HG8145V5.bin     — Firmware V2 (downgrade) [49 MB, HWNP]
├── FERRAMENTA HUAWEI/
│   ├── 1211.exe                       — Herramienta OBSC v1.12
│   └── OSBC_LOG_*.log                 — Logs de sesiones anteriores
└── UNLOCK/
    ├── 1-TELNET.bin                   — Parche para habilitar Telnet [1.8 MB, HWNP]
    └── 2-UNLOCK.bin                   — Parche de desbloqueo [183 KB, HWNP]
```

### Archivos de Firmware

| Archivo | Tamaño | Magic | SHA-256 (parcial) |
|---------|--------|-------|-------------------|
| HG8145V5_V2_HG8145V5.bin | 49,026,072 | HWNP | `3a5466532817d0ea...` |
| 1-TELNET.bin | 1,845,780 | HWNP | `101e1c0cd2d220c5...` |
| 2-UNLOCK.bin | 182,972 | HWNP | `67ad540f6c257f51...` |

Todos los archivos tienen cabecera **HWNP** (0x504E5748), el formato estándar de firmware
Huawei que este repositorio puede analizar con `hw_fmw`.

### Método de Desbloqueo (3 pasos)

Traducción del método original en portugués:

**Paso 1 — Downgrade a firmware V2:**
- Abrir la herramienta 1211.exe
- **Cambiar parámetros**: de 1200→1400 (FRSIZE) y de 10ms→5ms (FRINTERV)
- Seleccionar `HG8145V5_V2_HG8145V5.bin`
- Esperar 8-9 minutos hasta que indique éxito
- El ONT se congela y reinicia

**Paso 2 — Habilitar Telnet:**
- Seleccionar `1-TELNET.bin`
- Esperar a que indique éxito

**Paso 3 — Aplicar desbloqueo:**
- Detener la herramienta
- Seleccionar `2-UNLOCK.bin`
- El ONT parpadeará y reiniciará automáticamente
- Detener la herramienta — el ONT está desbloqueado

### Análisis de Logs OSBC

Los logs incluidos muestran sesiones reales de actualización:

```
Formato: FECHA [BoardSN][21SN] Estado
Ejemplo: 2025-02-19 20:33:39 [029TTYRYQ7023137][2102314BUGRYQ7921338] Start upgrade!
```

**Códigos de resultado observados:**
| Código | Significado |
|--------|-------------|
| `0x0` | Éxito |
| `0xf720404f` | Error de verificación (firmware incompatible) |
| `0xf7204050` | Error de verificación |
| `0xf7204007` | Error de comunicación |
| `0xf7204028` | Timeout de transferencia |
| `0xf7204045` | Error de flash |

---

## 4. Comparación entre Versiones

| Característica | ONT_V100R002C00SPC253.exe | 1211.exe (v1.12) |
|---------------|---------------------------|------------------|
| Compilación | 2021-03-03 (MSVC 14.0) | 2014-08-15 (MSVC 10.0) |
| Tamaño | 8.68 MB | 2.26 MB |
| Empaquetado | No | Sí (packer desconocido) |
| Secciones | 8 (estándar) | 7 (nombres aleatorios) |
| Framework | MFC + POCO + OpenSSL | MFC (empaquetado) |
| Protocolo | OBSC (UDP) | OBSC (UDP) |
| Firmware embebido | Sí (7 imágenes HWNP) | No |
| Seguridad | Control Flow Guard, certificados | Básica |
| Versiones fw soportadas | V100→V500 | V100→V300 (estimado) |

---

## 5. Herramienta de Análisis

Este repositorio incluye `tools/analyze_exe.py`, una herramienta Python de análisis estático
para ejecutables PE32 que no requiere dependencias externas.

```bash
# Analizar un ejecutable
python3 tools/analyze_exe.py ruta/al/archivo.exe
```

La herramienta realiza:
- Verificación de cabeceras DOS/PE
- Análisis de secciones con cálculo de entropía
- Enumeración de imports
- Extracción de cadenas relevantes
- Detección de packers/compiladores
- Generación de hashes (MD5, SHA-256)

---

## 6. Notas de Seguridad

- **ONT_V100R002C00SPC253.exe** es una herramienta oficial de Huawei compilada con protecciones
  modernas (Control Flow Guard, certificados). Contiene firmware embebido firmado con HWNP.

- **1211.exe** está empaquetado, lo que dificulta el análisis estático. El empaquetado puede
  ser para protección de propiedad intelectual o para ofuscación. Se recomienda precaución
  al ejecutar binarios empaquetados de fuentes no oficiales.

- Los archivos de firmware (.bin) utilizan el formato HWNP con verificación CRC32 y soporte
  de firmas RSA, analizables con las herramientas de este repositorio (`hw_fmw`, `hw_verify`).
