# tools/ — Herramientas de Análisis

## analyze_exe.py

Herramienta de análisis estático para ejecutables Windows PE32/PE32+.
No requiere dependencias externas (solo librería estándar de Python 3).

### Uso

```bash
python3 tools/analyze_exe.py <ruta_al_exe>
```

### Funcionalidades

- Verificación de cabeceras DOS/PE (MZ, PE signature)
- Información del archivo (tamaño, MD5, SHA-256)
- Cabecera COFF: máquina, secciones, timestamp, características
- Cabecera opcional: PE32/PE32+, entry point, image base, subsistema
- Análisis de secciones con cálculo de entropía Shannon
- Enumeración de DLLs importadas
- Extracción de cadenas relevantes (firmware, red, seguridad)
- Detección de packers: UPX, NSIS, MPRESS, Themida, VMProtect
- Detección de compiladores: MSVC, Borland Delphi, MFC
- Detección de frameworks: POCO C++ Libraries
- Marcado de secciones empaquetadas (entropía > 7.5) y virtuales

### Ejemplo

```
$ python3 tools/analyze_exe.py firmware_tool.exe

========================================================================
  PE ANALYSIS REPORT: firmware_tool.exe
========================================================================

  File Size  : 9,101,312 bytes (8.68 MB)
  MD5        : dcf146eae9125b175c0fc448e2e246a7
  SHA-256    : c882032e2dcd1a3ea2fc5e359e7c22a94d024fb0ae7e7be2f1cefd341796f8ec

  Machine    : i386
  Sections   : 8
  PE Type    : PE32
  Subsystem  : GUI

  Section        VirtAddr   VirtSize    RawSize  Entropy      Chars
  --------------------------------------------------------------
  .text        0x00001000 0x0030C5CA 0x0030C600    6.64 0x60000020
  .rsrc        0x00437000 0x004521E0 0x00452200    7.81 0x40000040 [PACKED]
  ...

  Imported DLLs (21):
    - WS2_32.dll
    - KERNEL32.dll
    ...

  Detections:
    * MFC (Microsoft Foundation Classes)
    * POCO C++ Libraries
```
