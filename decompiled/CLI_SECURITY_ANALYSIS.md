# HG8145V5 / EG8145V5 — Análisis de Seguridad CLI y Guía de Desbloqueo

> Generado por análisis de binarios ARM32 del rootfs EG8145V5-V500R022C00SPC340B019
> Binarios analizados: `clid` (199KB), `busybox` (652KB), `busybox.suid` (79KB), `shellconfig` (13KB)

---

## Diagnóstico: ¿Por qué solo aparecen `exit` y `getcustomerinfo.sh`?

La causa raíz es el atributo `UserGroup=""` (vacío) en la configuración del usuario CLI:

```xml
<X_HW_CLIUserInfoInstance InstanceID="1" Username="root"
    UserGroup="" .../>
```

El binario `clid` usa una **máscara de bits** para controlar el acceso a comandos:
- Cada comando tiene un `CmdGroup` (ej: `0x00004010`)
- Cada usuario tiene un `UserGroup`
- **Verificación**: `(CmdGroup & UserGroup) != 0` → comando visible
- Si `UserGroup=""` → se parsea como `0x0` → **NINGÚN comando visible**

### Sobre `AccessInterface=""`

`AccessInterface=""` (vacío) es **correcto** — significa que el usuario puede hacer login
desde **cualquier interfaz** (LAN, WAN, Serial). Si le pones un valor como `"LAN"`,
**restringiría** el acceso solo a esa interfaz. El factory default también lo deja vacío.

---

## 1. Sistema de Niveles de Acceso (CmdGroup Bitmask)

| Bitmask | Nivel | Comandos |
|---------|-------|----------|
| `0x00000010` | Usuario básico | Solo lectura, muy limitado |
| `0x00002000` | Carrier/ISP | Comandos del operador |
| `0x00004000` | Admin parcial | Configuración básica |
| `0x00004010` | Admin + básico | Mayoría de `display` (346 comandos) |
| `0x10000000` | Factory/oculto | `preplugin integrity check` |
| `0x80000000` | Super admin | 141 comandos privilegiados |
| `0x80002000` | Super + carrier | Diagnóstico avanzado |
| `0x80004000` | Super + admin | Configuración completa |
| `0x80004010` | Super + admin + básico | Casi todo |
| `0xFFFFFFFF` | **TODOS** | **600+ comandos desbloqueados** |

---

## 2. Análisis de Binarios: login, su, passwd

### busybox.suid (8 applets SUID)
```
arping, login, passwd, ping, ping6, su, traceroute, traceroute6
```

### Flujo de `su` en busybox.suid:
```
su → getuid() → verifica si es root
   → lee /etc/passwd y /etc/shadow
   → crypt() para verificar password
   → setresuid/setresgid → execv("/bin/sh")
```

### Flujo de `login` en busybox.suid:
```
login → pide usuario y password
      → verifica contra /etc/shadow
      → setuid/setgid → exec(shell)
```

### Flujo de shell WAP (`clid`):
```
Telnet → clid → HW_CLI_CheckLoginUser()
             → HW_CLI_CheckAccessAuthority()
                → lee UserGroup del XML
                → compara con CmdGroup de cada comando
             → HW_CLI_Shell() → SSP_ExecSysCmd("/bin/sh")

Comando "su" en WAP:
  → HW_CLI_SU_Mode()
  → HW_CLI_VerifySuPassword() (usa /etc/wap/su_pub_key)
  → Si OK: SSP_PRIVILEGE_ForceSetCapability() + SSP_PRIVILEGE_RaiseChildFull()
  → Prompt cambia a "SU_root>"
```

---

## 3. Modo de Prueba de Equipo (Backdoor)

El binario `clid` contiene las cadenas:
- `huaweiequiptestmode-on`
- `huaweiequiptestmode-off`

**Activación**: Crear el archivo `/mnt/jffs2/equiptestmode`
```bash
# Si tienes acceso shell:
touch /mnt/jffs2/equiptestmode
# Reiniciar el servicio CLI o el dispositivo
```

**Funciones relacionadas:**
- `HW_CLI_SetEquipTestMode` / `HW_CLI_RPC_SetEquipTestMode`
- `HW_CLI_GetCliUserGroupInEquipMode` — establece UserGroup especial
- `HW_SSP_IsDebugMode` — verifica modo debug

En este modo, los límites de UserGroup son ignorados parcialmente.

---

## 4. Feature Flags que Controlan el Shell

| Flag | Descripción |
|------|-------------|
| `FT_CLI_DEFAULT_TO_SHELL` | CLI entra directamente a shell Linux |
| `SSMP_FT_TDE_OPEN_SHELL` | Habilita shell abierto |
| `SSMP_FT_TDE_AUTH_SU_CMD` | Autenticación para comando `su` |
| `SSMP_SPEC_CLI_CUSTOMIZE_CMDLIST` | Archivo con lista de comandos custom |
| `FT_CLI_SECURITY_ACCESS` | Control de acceso de seguridad |

Estas flags son leídas del config por `HW_CLI_FeatureChangeInit()`.

---

## 5. SOLUCIÓN: Modificar hw_ctree.xml

### Método Automático (recomendado)

```bash
# 1. Desencriptar
AESCRYPT2_KEY_INDEX=1 ./decompiled/build/aescrypt2 1 hw_ctree.xml decrypted.xml

# 2. Desbloquear TODO con un solo comando
python3 tools/ctree_modifier.py -i decrypted.xml --unlock-all root -o modified.xml

# 3. Re-encriptar
AESCRYPT2_KEY_INDEX=1 ./decompiled/build/aescrypt2 0 modified.xml hw_ctree_new.xml
```

Esto aplica 6 cambios:
1. `UserGroup` → `4294967295` (0xFFFFFFFF) — todos los comandos
2. `UserLevel` web → `0` (admin)
3. SSH LAN → habilitado
4. FTP LAN → habilitado
5. Telnet LAN → habilitado
6. Servicio FTP → habilitado

### Método Manual (XML)

Cambiar `UserGroup=""` por `UserGroup="4294967295"`:

**ANTES:**
```xml
<X_HW_CLIUserInfoInstance InstanceID="1" Username="root"
    Userpassword="$2ODa^Us..." UserGroup=""
    ModifyPWDFlag="0" EncryptMode="2" Salt="mb0kqaQR..."
    AccessInterface=""/>
```

**DESPUÉS:**
```xml
<X_HW_CLIUserInfoInstance InstanceID="1" Username="root"
    Userpassword="$2ODa^Us..." UserGroup="4294967295"
    ModifyPWDFlag="0" EncryptMode="2" Salt="mb0kqaQR..."
    AccessInterface=""/>
```

> **Nota:** `AccessInterface=""` se deja vacío intencionalmente.
> Vacío = acceso desde cualquier interfaz. Ponerle un valor lo restringiría.

Opcionalmente, también cambiar:
```xml
<!-- Elevar root a admin en web -->
<X_HW_WebUserInfoInstance ... UserName="root" ... UserLevel="0" .../>

<!-- Habilitar FTP en AclServices -->
<AclServices ... FTPLanEnable="1" .../>

<!-- Habilitar servicio FTP -->
<X_HW_ServiceManage FtpEnable="1" .../>
```

---

## 6. Comandos Disponibles Después del Desbloqueo

Con `UserGroup="4294967295"` tendrás acceso a **600+ comandos**, incluyendo:

### Comandos Críticos
| Comando | Descripción |
|---------|-------------|
| `shell` | Entra a shell Linux (/bin/sh) |
| `su` | Escalar a modo super admin |
| `display password` | Muestra contraseñas almacenadas |
| `set userpasswd` | Cambia contraseñas |
| `display current-configuration` | Dump completo de configuración |
| `load cfg` | Cargar configuración desde archivo |
| `backup cfg` | Respaldar configuración |
| `save data` | Guardar config a flash |
| `reset` | Reset de fábrica |
| `restore default configuration` | Restaurar defaults |
| `ssh remote` | SSH a host remoto |
| `telnet remote` | Telnet a host remoto |
| `display version` | Ver versión de firmware |
| `display sn` | Ver número de serie |
| `display loidpwd` | Ver LOID/password del ISP |
| `set sn` | Cambiar número de serie |
| `set loidpwd` | Cambiar LOID/password |
| `display macaddress` | Ver MAC addresses |
| `display waninfo all detail` | Info completa de WAN |
| `display pppconn` | Ver conexiones PPPoE |
| `set wlan psk` | Cambiar contraseña WiFi |
| `diagnose` | Entrar a modo diagnóstico |

### Secuencia Recomendada de Comandos
```
WAP> su
Password: [contraseña su]
SU_root> shell
/bin/sh

# O si su no funciona, estos comandos están disponibles directamente:
WAP> display current-configuration
WAP> display password
WAP> display loidpwd
WAP> set userpasswd
WAP> backup cfg
```

---

## 7. ¿Se Restaura UserGroup="" al Reiniciar?

**Respuesta corta: NO, un reinicio normal NO borra los cambios.** Pero hay situaciones que sí los borran:

### Cómo funciona la persistencia

El firmware maneja **4 copias** del config:

| Archivo | Ubicación | Tipo |
|---------|-----------|------|
| `hw_ctree.xml` | `/mnt/jffs2/` | **Config activa** (flash persistente, encriptado AES) |
| `hw_ctree_bak.xml` | `/mnt/jffs2/` | Backup automático de la activa |
| `hw_default_ctree.xml` | `/mnt/jffs2/` | Factory default del ISP (en flash) |
| `hw_default_ctree.xml` | `/etc/wap/` | Factory default del firmware (read-only en rootfs) |

### Flujo al reiniciar (boot normal):
```
1. Monta /mnt/jffs2/ (flash persistente UBIFS)
2. Lee /mnt/jffs2/hw_ctree.xml (TU config modificada)
3. Descifra con aescrypt2 → carga en RAM
4. ✅ UserGroup="4294967295" SE MANTIENE
```

### Cuándo SÍ se pierde el UserGroup:

| Situación | ¿Se pierde? | Solución |
|-----------|-------------|----------|
| Reinicio normal | ❌ No | Config se lee de /mnt/jffs2/ |
| `save data` y reinicio | ❌ No | Ya guardado en flash |
| Factory reset (botón/web) | ⚠️ **SÍ** | Copia `hw_default_ctree.xml` → `hw_ctree.xml` |
| TR-069/CWMP push del ISP | ⚠️ **SÍ** | El ISP puede sobrescribir UserGroup |
| Actualización de firmware | ⚠️ **SÍ** | Nuevo rootfs con default config |
| Corrupción de flash | ⚠️ **SÍ** | Se restaura desde backup/default |

### Cómo hacer los cambios PERMANENTES:

#### Paso 1: Guardar con `save data` (OBLIGATORIO)
Después de subir el config modificado, ejecuta en CLI:
```
WAP> save data
```
Esto graba la config de RAM a `/mnt/jffs2/hw_ctree.xml` (flash).

#### Paso 2: Deshabilitar CWMP/TR-069 (IMPORTANTE)
El ISP puede usar TR-069 para resetear tu config remotamente.
```bash
# Ya incluido en --unlock-all, pero verificar:
python3 tools/ctree_modifier.py -i decrypted.xml --disable-cwmp
```
Esto pone `EnableCWMP="0"` → el ISP no puede modificar tu config.

#### Paso 3: Modificar también hw_default_ctree.xml (sobrevive factory reset)
```bash
# Descifrar el default
AESCRYPT2_KEY_INDEX=1 ./decompiled/build/aescrypt2 1 \
    hw_default_ctree.xml default_dec.xml

# Desbloquear
python3 tools/ctree_modifier.py -i default_dec.xml --unlock-all root \
    -o default_mod.xml

# Re-encriptar
AESCRYPT2_KEY_INDEX=1 ./decompiled/build/aescrypt2 0 \
    default_mod.xml hw_default_ctree.xml

# Subir AMBOS archivos al router:
#   hw_ctree.xml          → /mnt/jffs2/hw_ctree.xml
#   hw_default_ctree.xml  → /mnt/jffs2/hw_default_ctree.xml
```

#### Paso 4: Evitar actualizaciones automáticas de firmware
Las actualizaciones OTA reemplazan `/etc/wap/hw_default_ctree.xml` (en rootfs read-only).
Si el ISP fuerza un factory reset después de actualizar, se restaura el default del firmware.

---

## 8. Escalación de Privilegios Sin Modificar Config

Si **no puedes** modificar hw_ctree.xml, estas son alternativas:

### Método A: Equipment Test Mode (requiere acceso físico)
1. Acceder al puerto serial/UART del router
2. Crear archivo: `touch /mnt/jffs2/equiptestmode`
3. Reiniciar: los comandos de modo equipo se habilitan

### Método B: Desde el shell limitado
Si logras acceso shell (aunque limitado):
```bash
# BusyBox tiene 166 applets
busybox ash          # Shell interactivo
busybox wget         # Descargar archivos
busybox ftpget       # FTP client
busybox telnet       # Cliente telnet
busybox tftp         # TFTP client

# Si busybox.suid está accesible:
/sbin/busybox.suid su    # Intentar su
/sbin/busybox.suid passwd # Cambiar password
```

### Método C: Vía Web (telecomadmin)
Si conoces la contraseña de `telecomadmin` (UserLevel=0, admin):
1. Login web → Configuración avanzada
2. El usuario telecomadmin tiene `SuperModeValue` (hash de password su)

---

## 9. BusyBox: 166 Applets Disponibles

```
addgroup adduser arch arp ash awk basename blkid brctl bzip2 cat chgrp
chmod chown chpasswd chroot clear cmp cp crond crontab cut date dd
delgroup deluser depmod df dhcprelay diff dirname dmesg du echo egrep
eject expr factor false fgrep find free ftpget ftpput fuser getopt getty
grep gunzip gzip halt head hexdump hostname hwclock id ifconfig init
insmod ip ipaddr ipcrm ipcs iplink iproute iprule iptunnel kill killall
killall5 klogd link linuxrc ln logger logread losetup ls lsmod lspci
lsusb lzcat lzma makedevs md5sum mdev mkdir mkfs.ext2 mkfs.vfat mknod
mkswap modprobe more mount mountpoint mv netstat nice nl nologin nproc
ntpd paste pidof printenv printf ps pwd readlink realpath reboot renice
resume rm rmdir rmmod route sed seq setconsole sh shred sleep sort
start-stop-daemon stat strings stty sum swapoff swapon sync sysctl
syslogd tac tail tar taskset tc tee telnet test tftp tftpd time top
touch tr true ts tty udpsvd umount uname uniq unlzma unzip uptime
usleep vconfig wc wget which whoami xargs zcat
```

---

## 10. Archivos Clave del Firmware

| Archivo | Descripción |
|---------|-------------|
| `/bin/clid` | Demonio CLI WAP (controla acceso a comandos) |
| `/bin/busybox` | BusyBox v1.32.1 (166 applets) |
| `/sbin/busybox.suid` | BusyBox SUID (su, login, passwd, ping) |
| `/bin/shellconfig` | Utilidad de configuración del shell |
| `/etc/wap/hw_cli.xml` | Árbol de comandos CLI (600+ comandos) |
| `/etc/wap/hw_shell_cli.xml` | Comandos shell (encriptado) |
| `/etc/wap/hw_diag_cli.xml` | Comandos de diagnóstico (encriptado) |
| `/etc/wap/su_pub_key` | Clave pública para verificación de su |
| `/mnt/jffs2/equiptestmode` | Flag de modo de prueba de equipo |
| `/mnt/jffs2/hw_ctree.xml` | Configuración principal (encriptada AES) |
| `/var/shellProcRet.txt` | Resultado de último comando shell |
| `/var/flagshellcmdrunning` | Flag de comando shell en ejecución |

---

## 11. Pipeline Completo: Descifrar → Modificar → Cifrar → Subir

```bash
# Paso 1: Construir herramientas
cd decompiled && cmake -B build && cmake --build build && cd ..

# Paso 2: Desencriptar (key index 1 para HG8145V5)
AESCRYPT2_KEY_INDEX=1 ./decompiled/build/aescrypt2 1 hw_ctree.xml decrypted.xml

# Paso 3: Verificar contenido actual
python3 tools/ctree_modifier.py -i decrypted.xml --list-users
python3 tools/ctree_modifier.py -i decrypted.xml --list-services

# Paso 4: Desbloquear todo
python3 tools/ctree_modifier.py -i decrypted.xml --unlock-all root -o modified.xml

# Paso 5: Re-encriptar
AESCRYPT2_KEY_INDEX=1 ./decompiled/build/aescrypt2 0 modified.xml hw_ctree_new.xml

# Paso 6: Subir al router
# Opción A: Via backup/restore en la web
# Opción B: Via TFTP si está habilitado
# Opción C: Via acceso serial/UART
```

## Config Modificada Lista para Usar

La config desbloqueada está disponible en:
- `configs/HG8145V5_unlocked/hw_ctree_unlocked.xml`

Solo necesitas encriptarla y subirla al router.
