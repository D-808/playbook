
```powershell
## Get basic information of the domain
Get-NetDomain -Domain <target>

## Get the domains' SID
Get-DomainSID

## Get list of domain controllers
Get-NetDomainController -Domain <target>

## Access C disk of a computer (check local admin)
ls \\<COMPUTERNAME>\c$

## Find a specific file
Get-Childitem -Path C:\ -Force -Include <FILENAME OR WORD TO SEARCH> -Recurse -ErrorAction SilentlyContinue
```
