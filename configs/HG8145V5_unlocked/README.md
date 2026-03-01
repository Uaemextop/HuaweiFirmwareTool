# HG8145V5 Config Unlock

Configuraciones `hw_ctree.xml` original y desbloqueada para Huawei HG8145V5.

## Archivos

| Archivo | Descripción |
|---------|-------------|
| `hw_ctree_original.xml` | Config original (UserGroup vacío, solo `exit` disponible) |
| `hw_ctree_unlocked.xml` | Config desbloqueada (todos los 600+ comandos habilitados) |

## Cambios realizados (5 líneas)

| Cambio | Antes | Después | Efecto |
|--------|-------|---------|--------|
| `UserGroup` | `""` | `"4294967295"` | Desbloquea los 600+ comandos CLI |
| `UserLevel` (root web) | `"1"` | `"0"` | Eleva root a admin en interfaz web |
| `FTPLanEnable` | `"0"` | `"1"` | Habilita FTP en LAN |
| `FtpEnable` | `"0"` | `"1"` | Habilita servicio FTP |
| `EnableCWMP` | ya `"0"` | `"0"` | Evita que ISP resetee config vía TR-069 |

**Nota:** `AccessInterface=""` (vacío) es correcto — significa que el usuario
puede hacer login desde **cualquier interfaz** (LAN, WAN, Serial). Si se
establece un valor como `"LAN"`, se **restringe** el acceso solo a esa interfaz.

## ¿Se pierde al reiniciar?

**NO.** Un reinicio normal lee `/mnt/jffs2/hw_ctree.xml` (tu config modificada).

Solo se pierde si:
- Haces **factory reset** → copia `hw_default_ctree.xml` sobre `hw_ctree.xml`
- El ISP hace **push vía TR-069** → por eso deshabilitamos CWMP
- **Actualización de firmware** → nuevo rootfs con defaults

Para sobrevivir factory resets, modifica también `hw_default_ctree.xml`
(ver sección 7 de `decompiled/CLI_SECURITY_ANALYSIS.md`).

## Cómo usar

```bash
# 1. Construir aescrypt2
cd decompiled && cmake -B build && cmake --build build && cd ..

# 2. Encriptar la config modificada
AESCRYPT2_KEY_INDEX=1 ./decompiled/build/aescrypt2 0 \
    configs/HG8145V5_unlocked/hw_ctree_unlocked.xml \
    hw_ctree_encrypted.xml

# 3. Subir hw_ctree_encrypted.xml al router como hw_ctree.xml
# 4. En el CLI ejecutar: save data
```

## Generar tu propia config desbloqueada

```bash
# Desde tu hw_ctree.xml desencriptado:
python3 tools/ctree_modifier.py -i tu_config.xml --unlock-all root -o desbloqueada.xml
```
