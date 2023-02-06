
##### [BloodHound](https://attack.mitre.org/software/S0521) is an Active Directory (AD) reconnaissance tool that can reveal hidden relationships and identify attack paths within an AD environment

## Installation

```bash
## Apt-get bloodhound 
sudo apt-get install bloodhound

## Start the neo4j service
neo4j console

## Start bloodhound
bloodhound

## default creds are neo4j:neo4j but you need to change the pw before it will allow you log in. Go here to change pw: http://localhost:7474 
```

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

