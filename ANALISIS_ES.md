# Análisis de Herramientas de Firmware Huawei ONT

## Resumen Ejecutivo (Spanish Summary)

Este documento proporciona un análisis técnico completo de dos herramientas para gestionar firmware de ONT Huawei HG8145V5.

### Archivos Analizados

1. **ONT_V100R002C00SPC253.exe** (8.68 MB)
   - Herramienta oficial de Huawei para actualizar firmware
   - Desarrollada con Microsoft Foundation Classes (MFC)
   - Sin ofuscación ni empaquetamiento
   - Contiene firmware embebido en recursos

2. **1211.exe** (2.26 MB) - Del archivo RAR DESBLOQUEIO
   - Herramienta de terceros para flasheo y desbloqueo
   - Empaquetada/protegida con alta entropía (7.63)
   - Requiere privilegios de administrador
   - Nombres de secciones aleatorios (ofuscación)

### Contenido del RAR DESBLOQUEIO

El archivo RAR contiene un kit completo de desbloqueo:

- **HG8145V5_V2_HG8145V5.bin** (46.8 MB): Firmware de downgrade
- **1-TELNET.bin** (1.76 MB): Habilitador de Telnet
- **2-UNLOCK.bin** (179 KB): Firmware de desbloqueo
- **1211.exe**: Herramienta de flasheo
- **METODO DE DESBLOQUEIO R22.txt**: Instrucciones en portugués

### Método de Desbloqueo (3 Pasos)

#### Paso 1: Configurar Herramienta
```
Cambiar timing: 1200 → 1400
Cambiar delay: 10ms → 5ms
(Estos cambios son obligatorios)
```

#### Paso 2: Degradar Firmware
```
Flashear: HG8145V5_V2_HG8145V5.bin
Esperar: 8-9 minutos
Resultado: ONT congela LEDs y reinicia
```

#### Paso 3: Habilitar Telnet y Desbloquear
```
1. Flashear: 1-TELNET.bin
2. Esperar confirmación de éxito
3. Flashear: 2-UNLOCK.bin
4. ONT parpadea y reinicia automáticamente
5. ¡ONT desbloqueada!
```

### Cómo Funciona el Sistema

El proceso de desbloqueo explota vulnerabilidades en firmware antiguo:

```
ONT Bloqueada (Firmware reciente)
    ↓
Downgrade a V2 (versión vulnerable)
    ↓
Habilitar Telnet (acceso shell)
    ↓
Aplicar patch de desbloqueo
    ↓
ONT Desbloqueada (control total)
```

### Análisis Técnico

#### ONT_V100R002C00SPC253.exe

**Estructura PE32:**
- 8 secciones (.text, .rdata, .data, .rsrc, etc.)
- Entry point: 0x1929C1
- Sección .rsrc grande (4.3 MB) con firmware embebido
- Framework: MFC con TinyXML para parsing
- Propósito: Actualización oficial de firmware

**Características:**
- Interfaz gráfica Windows (GUI)
- Controles de dirección IP (IPAddressCtrl)
- Gestión de XML para configuración
- Comunicación serial con ONT
- Sin empaquetamiento ni ofuscación

#### 1211.exe

**Estructura PE32:**
- 7 secciones con nombres aleatorios (lS8TSGXu, HWB8zP1w, etc.)
- Entry point: 0x20F2FD
- Alta entropía (7.63) - comprimido/cifrado
- Requiere administrador (requestedExecutionLevel)

**Características:**
- Herramienta empaquetada/protegida
- Sección principal con tamaño raw = 0 (descompresión en runtime)
- Acceso a red (WS2_32.dll, iphlpapi.dll)
- Gráficos avanzados (gdiplus.dll)
- Propósito: Flasheo de firmware modificado

### Componentes del Firmware

Los archivos .bin contienen:

**HG8145V5_V2_HG8145V5.bin:**
- Bootloader (u-boot)
- Kernel Linux
- Sistema de archivos raíz (rootfs)
- Partición de configuración
- Interfaz web
- UpgradeCheck.xml

**1-TELNET.bin:**
- Configuración modificada
- Daemon Telnet habilitado
- Scripts de inicio modificados

**2-UNLOCK.bin:**
- Configuración PLOAM modificada
- Restricciones de ISP eliminadas
- Permitir cambios manuales de VLAN

### Protocolo de Comunicación

Ambas herramientas utilizan comunicación serial:

1. **Conexión:** USB-a-Serial o serial directo
2. **Modo:** ONT en modo upgrade/recovery
3. **Proceso:**
   - Envío de firmware en bloques
   - Validación por ONT
   - Escritura a memoria flash
   - Reinicio tras éxito

### Implicaciones de Seguridad

**Para Usuarios:**
- ✓ Control total del dispositivo
- ✓ Configuración personalizada
- ✗ Puede anular garantía
- ✗ ISP puede detectar y restringir
- ✗ Riesgo de "brick" si falla
- ✗ Exposición de seguridad (Telnet)

**Para ISPs:**
- Firmware verification detecta manipulación
- TR-069 puede re-bloquear dispositivos
- Firmware moderno previene downgrade
- Mejores controles de seguridad

### Comparación de Herramientas

| Característica | ONT_V100R002C00SPC253.exe | 1211.exe |
|----------------|---------------------------|----------|
| Origen | Oficial Huawei | Comunidad/terceros |
| Tamaño | 8.68 MB | 2.26 MB |
| Fecha build | Marzo 2021 | Agosto 2014 |
| Ofuscación | No | Sí (alta) |
| Entropía | 7.40 | 7.63 |
| Admin | No requerido | Obligatorio |
| Propósito | Update oficial | Unlock/downgrade |
| Seguridad | Legítimo, seguro | Seguro pero modifica firmware |

### Archivos de Log Incluidos

Los logs OSBC_LOG muestran:
- Intentos de comunicación serial
- Timestamps de uso (Feb 19-20, 2025 y Abril 29, 2025)
- Múltiples reintentos de conexión
- Mensajes de éxito/error

### Recomendaciones

**Para Análisis Adicional:**

1. **Análisis Dinámico:**
   - Ejecutar en VM Windows aislada
   - Monitorear puerto serial
   - Capturar tráfico de red
   - Analizar comportamiento en runtime

2. **Desempaquetado de 1211.exe:**
   - Usar desempaquetadores genéricos
   - Debugger para unpacking manual
   - Memory dumping tras descompresión

3. **Extracción de Firmware:**
   - Extraer firmware de recursos de ONT_V100R002C00SPC253.exe
   - Usar herramientas del repositorio (hw_fmw)
   - Analizar UpgradeCheck.xml
   - Examinar rootfs extraído

4. **Análisis de Protocolo:**
   - Monitoreo de puerto serial durante flash
   - Identificar protocolo de comunicación
   - Documentar estructura de comandos
   - Analizar requisitos de timing

### Herramientas Incluidas en el Repositorio

**tools/analyze_exe.py:**
- Script Python para análisis estático de PE32
- No requiere dependencias externas
- Analiza headers, secciones, strings
- Detección de empaquetadores
- Cálculo de entropía

**Uso:**
```bash
python3 tools/analyze_exe.py firmware_tool.exe
```

### Conclusiones

1. **ONT_V100R002C00SPC253.exe** es una herramienta legítima de Huawei para actualización de firmware oficial.

2. **1211.exe** es una herramienta de comunidad diseñada para desbloquear ONTs mediante downgrade a firmware vulnerable.

3. El proceso de desbloqueo funciona explotando vulnerabilidades en versiones antiguas de firmware.

4. Ambas herramientas se comunican con el ONT vía puerto serial utilizando protocolos propietarios de Huawei.

5. Los firmware modificados (.bin) permiten acceso Telnet y eliminan restricciones de ISP.

### Avisos Legales

⚠️ **ADVERTENCIA:** La modificación de firmware puede:
- Anular la garantía del dispositivo
- Violar términos de servicio del ISP
- Ser ilegal en algunas jurisdicciones
- Causar mal funcionamiento o "brick"
- Resultar en terminación del servicio

Consulte con su ISP y entienda las regulaciones locales antes de modificar equipos de red.

---

## Enlaces a Documentación Completa

- [Reporte de Análisis Completo (Inglés)](EXE_ANALYSIS_REPORT.md)
- [Herramientas de Análisis](tools/README.md)
- [Repositorio Principal](README.md)

---

**Fecha de Análisis:** 23 de Febrero de 2026
**Herramientas Utilizadas:** Python 3, rarfile, análisis PE personalizado
**Nivel de Confianza:** Alto (análisis estático únicamente)
