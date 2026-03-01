# HG8145V5 Config Unlock

Configuraciones `hw_ctree.xml` original y desbloqueada para Huawei HG8145V5.

## Archivos

| Archivo | Formato | Descripción |
|---------|---------|-------------|
| `hw_ctree_original.xml` | XML plano | Config original (UserGroup vacío, solo `exit` disponible) |
| `hw_ctree_unlocked.xml` | XML plano | Config desbloqueada (para editar manualmente) |
| `hw_ctree_unlocked_key0.xml` | AES encriptado | Key 0 – V300R017 (HG8245Q, HG8247H) |
| `hw_ctree_unlocked_key1.xml` | AES encriptado | **Key 1 – V500R019C10SPC310 (HG8145V5 Telmex)** |
| `hw_ctree_unlocked_key2.xml` | AES encriptado | Key 2 – V500R019C00SPC050 (HG8246M, HG8247H5) |
| `hw_ctree_unlocked_key3.xml` | AES encriptado | Key 3 – V500R019C10SPC386 (HG8145V5 Totalplay) |
| `hw_ctree_unlocked_key4.xml` | AES encriptado | Key 4 – V500R020C00SPC240 (HG8145V5 Claro-RD) |
| `hw_ctree_unlocked_key5.xml` | AES encriptado | Key 5 – V500R020C10SPC212 (HG8145V5 General) |
| `GUIA_SUBIR_CONFIG.md` | Documentación | Guía paso a paso para subir via TFTP/Web/FTP |

## Cambios realizados (9 modificaciones)

| Cambio | Antes | Después | Efecto |
|--------|-------|---------|--------|
| `UserGroup` | `""` | `"4294967295"` | Desbloquea los 600+ comandos CLI |
| `UserLevel` (root web) | `"1"` | `"0"` | Eleva root a admin en interfaz web |
| `SSHLanEnable` | `"0"` | `"1"` | Habilita SSH en LAN |
| `FTPLanEnable` | `"0"` | `"1"` | Habilita FTP en LAN |
| `TELNETLanEnable` | `"0"` | `"1"` | Habilita Telnet en LAN |
| `FtpEnable` | `"0"` | `"1"` | Habilita servicio FTP |
| `EnableCWMP` | ya `"0"` | `"0"` | Evita que ISP resetee config vía TR-069 |
| `ResetFlag` | `"1"` | `"0"` | **Evita que se resetee a fábrica al importar** |
| `PeriodicInformEnable` | `"1"` | `"0"` | Detiene check-ins periódicos al ISP |

**Nota:** `AccessInterface=""` (vacío) es correcto — significa que el usuario
puede hacer login desde **cualquier interfaz** (LAN, WAN, Serial). Si se
establece un valor como `"LAN"`, se **restringe** el acceso solo a esa interfaz.

## ⚠️ POR QUÉ SE RESETEA AL SUBIR POR WEB

Si subes el XML **sin encriptar** o sin `ResetFlag="0"`, el modem:
1. Detecta config inválida (no encriptada) → reinicia automáticamente
2. `ResetFlag="1"` fuerza restauración de fábrica → pierde tus cambios
3. El ISP puede hacer push vía TR-069 (CWMP) → resetea UserGroup/UserLevel

**La config ya incluye `ResetFlag="0"` para prevenir esto.**

## Procedimiento correcto de subida

### Método 1: Vía web (config encriptada)

```bash
# 1. Construir aescrypt2
cd decompiled && cmake -B build && cmake --build build && cd ..

# 2. Modificar la config (o usar la pre-hecha)
python3 tools/ctree_modifier.py -i tu_config_decrypted.xml --unlock-all root -o modified.xml

# 3. Encriptar (OBLIGATORIO antes de subir por web)
AESCRYPT2_KEY_INDEX=1 ./decompiled/build/aescrypt2 0 modified.xml hw_ctree_encrypted.xml

# 4. Subir hw_ctree_encrypted.xml como "hw_ctree.xml" en la web del router
#    Ir a: Mantenimiento → Gestión de archivos de configuración → Importar
```

### Método 2: Vía TFTP (sin interfaz web)

```bash
# 1. Iniciar servidor TFTP en tu PC (192.168.100.x)
# 2. Colocar hw_ctree_encrypted.xml como hw_ctree.xml en el directorio TFTP
# 3. En el CLI del router:
tftp -g -l /mnt/jffs2/hw_ctree.xml -r hw_ctree.xml 192.168.100.2
save data
reboot
```

### Método 3: Vía FTP (si ya está habilitado)

```bash
# Conectar por FTP al router y reemplazar /mnt/jffs2/hw_ctree.xml
ftp 192.168.100.1
# Subir el archivo encriptado
put hw_ctree_encrypted.xml hw_ctree.xml
# En el CLI: save data && reboot
```

## ¿Se pierde al reiniciar?

**NO.** Un reinicio normal lee `/mnt/jffs2/hw_ctree.xml` (tu config modificada).

Solo se pierde si:
- Haces **factory reset** → copia `hw_default_ctree.xml` sobre `hw_ctree.xml`
- El ISP hace **push vía TR-069** → por eso deshabilitamos CWMP y PeriodicInform
- **Actualización de firmware** → nuevo rootfs con defaults

Para sobrevivir factory resets, modifica también `hw_default_ctree.xml`
(ver sección 7 de `decompiled/CLI_SECURITY_ANALYSIS.md`).

## Generar tu propia config desbloqueada

```bash
# Desde tu hw_ctree.xml desencriptado:
python3 tools/ctree_modifier.py -i tu_config.xml --unlock-all root -o desbloqueada.xml

# Opciones individuales:
python3 tools/ctree_modifier.py -i config.xml \
    --set-usergroup root 0xFFFFFFFF \
    --set-web-level root 0 \
    --enable-ssh --enable-ftp --enable-telnet \
    --disable-cwmp --disable-reset-flag --disable-periodic-inform \
    -o config_mod.xml
```
