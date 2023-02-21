##### SharpHound / Data Ingestion 
```powershell
## SharpHound / Data Ingestion Cheatsheet
```powershell
## Using sharphound executable
./SharpHound.exe --CollectionMethod All

## Using Powershell
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All

## Using Python https://github.com/fox-it/BloodHound.py
bloodhound-python -c All -u '<USERNAME>' -p '<PASSWORD>' -d domain.local
```

