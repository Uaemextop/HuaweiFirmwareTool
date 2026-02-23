# Guía de Usuario - ONT Flasher GUI (Español)

## Introducción

ONT Flasher GUI es una herramienta de código abierto con interfaz gráfica para flashear firmware en dispositivos ONT (Terminal de Red Óptica) Huawei.

## Instalación Rápida

1. Descarga `ONT-Flasher-GUI.exe` desde [Releases](https://github.com/Uaemextop/HuaweiFirmwareTool/releases)
2. Ejecuta como administrador
3. ¡Listo para usar!

## Uso Básico

### Proceso de Flasheo Simple

1. **Selecciona Puerto COM:**
   - Abre el menú desplegable "COM Port"
   - Selecciona tu puerto (ej: COM3)
   - Haz clic en "Refresh" si no aparece

2. **Elige Firmware:**
   - Haz clic en "Browse..."
   - Selecciona tu archivo .bin
   - Confirma la selección

3. **Configura Timing:**
   - Para HG8145V5 desbloqueo: 1400ms timeout, 5ms delay
   - Para operación estándar: 1200ms timeout, 10ms delay

4. **Inicia Flasheo:**
   - Haz clic en "Flash Firmware"
   - Confirma la operación
   - Espera 5-10 minutos
   - **¡No desconectes durante el proceso!**

## Presets Rápidos

En la pestaña **Configuration**:

- **HG8145V5 Unlock**: Para desbloqueo (1400ms, 5ms)
- **HG8245 Standard**: Configuración estándar
- **Custom**: Personalizado

## Características Avanzadas

### Configuración de Protocolo

En pestaña **Advanced**:

- **Max Retry Count**: Reintentos por chunk (1-10)
- **Chunk Size**: Tamaño de transferencia (128-4096 bytes)
- **Debug Mode**: Registro detallado del protocolo
- **Dry Run**: Simula sin escribir al dispositivo

### Guardar/Cargar Configuración

1. Configura todas las opciones
2. **Configuration** → **Save Configuration**
3. Guarda archivo .ini
4. Para cargar: **Load Configuration**

## Solución de Problemas

### No se encuentran puertos COM

**Soluciones:**
1. Verifica conexión física
2. Instala drivers CH340/FTDI
3. Prueba otro puerto USB
4. Revisa Administrador de Dispositivos
5. Haz clic en "Refresh"

### Falla la conexión

**Soluciones:**
1. Verifica puerto COM correcto
2. Cierra otros programas seriales
3. Prueba diferentes baudrates
4. Reinicia el dispositivo

### Falla el flasheo

**Soluciones:**
1. Verifica todas las conexiones
2. Comprueba integridad del firmware
3. Reduce chunk size a 512 bytes
4. Aumenta timeout
5. Activa "Verify"
6. Revisa logs para errores específicos

## Preguntas Frecuentes

**¿Es seguro?**
La herramienta es segura, pero flashear firmware siempre tiene riesgos. Sigue todas las precauciones.

**¿Anula la garantía?**
Posiblemente sí. Verifica los términos de tu garantía.

**¿Cuánto tarda?**
Típicamente 5-15 minutos dependiendo del tamaño y configuración.

**¿Necesito permisos de administrador?**
Sí, Windows requiere permisos para acceder a puertos seriales.

## Advertencias Importantes

⚠️ **NUNCA:**
- Interrumpas el proceso de flasheo
- Uses firmware incompatible
- Desconectes durante la operación
- Apagues el dispositivo mientras flashea

✅ **SIEMPRE:**
- Haz backup del firmware actual
- Verifica compatibilidad
- Usa alimentación estable
- Prueba con "Dry Run" primero

## Soporte

- [Documentación Técnica](../../EXE_ANALYSIS_REPORT.md)
- [Análisis Español](../../ANALISIS_ES.md)
- [GitHub Issues](https://github.com/Uaemextop/HuaweiFirmwareTool/issues)

---

**Recuerda: ¡Siempre haz backup y nunca interrumpas el flasheo!**
