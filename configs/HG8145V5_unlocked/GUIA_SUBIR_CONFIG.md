# Guía: Subir hw_ctree.xml modificado al HG8145V5

## Archivos incluidos

| Archivo | Formato | Descripción |
|---------|---------|-------------|
| `hw_ctree_unlocked.xml` | XML plano | Config desencriptada (para editar) |
| `hw_ctree_unlocked_key0.xml` | AES encriptado | Key 0 – V300R017 |
| `hw_ctree_unlocked_key1.xml` | AES encriptado | **Key 1 – V500R019C10SPC310 (Telmex)** |
| `hw_ctree_unlocked_key2.xml` | AES encriptado | Key 2 – V500R019C00SPC050 |
| `hw_ctree_unlocked_key3.xml` | AES encriptado | Key 3 – V500R019C10SPC386 (Totalplay) |
| `hw_ctree_unlocked_key4.xml` | AES encriptado | Key 4 – V500R020C00SPC240 (Claro-RD) |
| `hw_ctree_unlocked_key5.xml` | AES encriptado | Key 5 – V500R020C10SPC212 |
| `hw_ctree_original.xml` | XML plano | Config original sin modificar |

## ⚠️ IMPORTANTE: El router solo acepta archivos ENCRIPTADOS

Si subes el `.xml` plano por la web, el router:
1. Rechaza el archivo (no tiene formato AES válido)
2. Se reinicia automáticamente
3. Restaura la config de fábrica → pierdes todo

**Siempre sube el archivo `hw_ctree_unlocked_keyN.xml`** encriptado que corresponda
a tu firmware (ej: `key1` para Telmex), no el XML plano.

---

## Método 1: TFTP desde Telnet/CLI (recomendado)

### Requisitos
- Acceso Telnet al router (puerto 23)
- PC con servidor TFTP (misma red LAN, ej: 192.168.100.2)

### Paso 1: Instalar servidor TFTP en tu PC

**Windows:**
```
Descargar Tftpd64: https://pjo2.github.io/tftpd64/
1. Ejecutar Tftpd64
2. Seleccionar la carpeta donde está `hw_ctree_unlocked_key1.xml` (o el keyN de tu firmware)
3. Verificar que escucha en 192.168.100.x
```

**Linux:**
```bash
sudo apt install tftpd-hpa
# Copiar el archivo encriptado
sudo cp hw_ctree_unlocked_key1.xml /srv/tftp/hw_ctree.xml
sudo systemctl restart tftpd-hpa
```

**macOS:**
```bash
# Copiar al directorio TFTP
sudo cp hw_ctree_unlocked_key1.xml /private/tftpboot/hw_ctree.xml
sudo launchctl load -F /System/Library/LaunchDaemons/tftp.plist
```

### Paso 2: Conectar por Telnet al router

```bash
telnet 192.168.100.1
# Usuario: root
# Password: (tu contraseña)
```

### Paso 3: Descargar config via TFTP

En el CLI del router (WAP>):
```
WAP>su
SU_WAP>shell

# Descargar la config encriptada desde tu PC
tftp -g -l /mnt/jffs2/hw_ctree.xml -r hw_ctree.xml 192.168.100.2

# Verificar que se descargó correctamente
ls -la /mnt/jffs2/hw_ctree.xml

# Guardar y reiniciar
exit
SU_WAP>save data
SU_WAP>reboot
```

**Nota:** Reemplaza `192.168.100.2` con la IP de tu PC.

### Paso 4: Para sobrevivir factory resets (opcional)

También sube la config como default:
```
tftp -g -l /mnt/jffs2/hw_default_ctree.xml -r hw_ctree.xml 192.168.100.2
```

---

## Método 2: Web (interfaz de administración)

### Paso 1: Acceder a la interfaz web
```
http://192.168.100.1
# Usuario: root o telecomadmin
# Password: (tu contraseña)
```

### Paso 2: Importar configuración
1. Ir a **Sistema** → **Gestión de archivos de configuración**
   (o **System** → **Configuration File Management**)
2. Seleccionar **Importar archivo de configuración** / **Import Configuration File**
3. Seleccionar `hw_ctree_unlocked_key1.xml` (el archivo **encriptado** para tu firmware)
4. Hacer clic en **Importar** / **Import**
5. El router se reiniciará automáticamente

### Paso 3: Verificar
Después del reinicio, conectar por Telnet:
```bash
telnet 192.168.100.1
# Login como root
# Ejecutar: ?
# Deberías ver 600+ comandos disponibles (no solo exit y getcustomerinfo.sh)
```

---

## Método 3: FTP (si ya está habilitado)

```bash
# Conectar por FTP al router
ftp 192.168.100.1
# Usuario: root
# Password: (tu contraseña)

# Subir el archivo encriptado
ftp> binary
ftp> cd /mnt/jffs2/
ftp> put hw_ctree_unlocked_key1.xml hw_ctree.xml
ftp> bye

# Luego por Telnet:
telnet 192.168.100.1
WAP>su
SU_WAP>save data
SU_WAP>reboot
```

---

## Cómo crear tu propia config encriptada

Si quieres modificar la config tú mismo:

### 1. Desencriptar tu config actual
```bash
# Construir aescrypt2
cd decompiled && cmake -B build && cmake --build build && cd ..

# Desencriptar (key index 1 para HG8145V5 Telmex R020)
AESCRYPT2_KEY_INDEX=1 ./decompiled/build/aescrypt2 1 \
    tu_hw_ctree.xml config_decrypted.xml
```

### 2. Modificar
```bash
# Desbloquear todo (UserGroup, SSH, FTP, Telnet, CWMP, ResetFlag)
python3 tools/ctree_modifier.py -i config_decrypted.xml \
    --unlock-all root -o config_modified.xml
```

### 3. Encriptar
```bash
# Encriptar para subir al router
AESCRYPT2_KEY_INDEX=1 ./decompiled/build/aescrypt2 0 \
    config_modified.xml hw_ctree_encrypted.xml
```

### 4. Subir al router
Usar cualquiera de los 3 métodos de arriba con `hw_ctree_encrypted.xml`.

---

## Claves AES por versión de firmware

| Índice | Versión firmware | Uso |
|--------|-----------------|-----|
| 0 | V300R017 | HG8245C / modelos antiguos |
| 1 | V500R019C10SPC310 | **HG8145V5 Telmex R020** |
| 2 | V500R019C00SPC050 | EG8145V5 variante |
| 3 | V500R019C10SPC386 | HG8145V5 variante nueva |
| 4 | V500R020C00SPC240 | EG8145V5 R020 |
| 5 | V500R020C10SPC212 | HN8145XR |

Si no sabes cuál usar, prueba cada una. Solo la correcta produce un XML válido al desencriptar:
```bash
for i in 0 1 2 3 4 5; do
    echo "--- Key $i ---"
    AESCRYPT2_KEY_INDEX=$i ./decompiled/build/aescrypt2 1 \
        tu_hw_ctree.xml /tmp/test_$i.xml 2>&1
    head -1 /tmp/test_$i.xml 2>/dev/null
done
# La clave correcta mostrará: <InternetGatewayDevice ...>
```

---

## Solución de problemas

### "El router se reinicia al subir el archivo"
- Estás subiendo el XML plano sin encriptar. Debes subir el archivo encriptado (`_keyN.xml`).
- O el `ResetFlag` está en `"1"`. Usa `--unlock-all` que lo cambia a `"0"`.

### "Después de reiniciar se restaura UserGroup=''"
- El ISP puede estar enviando push via TR-069/CWMP. Verifica `EnableCWMP="0"`.
- Hiciste factory reset. Modifica también `hw_default_ctree.xml`.
- Subiste el archivo sin encriptar → el router rechazó y restauró backup.

### "No puedo conectar por Telnet"
- Verifica que el puerto 23 esté abierto: `nmap -p 23 192.168.100.1`
- La config original puede tener `TELNETLanEnable="0"`. Usa la web primero.

### "No encuentro la opción de importar config en la web"
- Accede como `telecomadmin` (nivel admin), no como usuario regular.
- La ruta varía por firmware: busca en Sistema/Mantenimiento/Administración.
