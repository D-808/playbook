### Setup
```powershell
## Start pwsh and bypass execution policy to allow scripts to run
powershell -ep bypass
## Import powerview to your pwsh session
. .\powerview.ps1
```

### User Enum
```powershell
## Get the list of users
Get-NetUser
## Fitler by username
Get-NetUser -Username user01                          
## Grab the cn (common-name) from the list of users
Get-NetUser | select cn                           
## Grab the name from the list of users
Get-NetUser | select name
## Get actively logged users on a computer (needs local admin rights on the target)
Get-NetLoggedon -ComputerName <servername>
## List all properties
Get-UserProperty                                      
## Display when the passwords were set last time
Get-UserProperty –Properties pwdlastset               
## Display when the accounts were created
Get-UserProperty -Properties whencreated
## Save all Domain Users to a file
  Get-DomainUser | Out-File -FilePath .\DomainUsers.txt
## Will return specific properties of a specific user
  Get-DomainUser -Identity [username] -Properties DisplayName, MemberOf | Format-List
## Enumerate user logged on a machine
Get-NetLoggedon -ComputerName <ComputerName>
## Enumerate domain machines of the current/specified domain where specific users are logged into
Find-DomainUserLocation -Domain <DomainName> | Select-Object UserName, SessionFromName
```

### User Hunting
```powershell
## Find all machines on the current domain where the current user has local admin access
Find-LocalAdminAccess -Verbose
## Find local admins on all machines of the domain
Find-DomainLocalGroupMember -Verbose
## Enumerates the local group memberships for all reachable machines the <domain>
Find-DomainLocalGroupMember -Domain <domain>
## Looks for machines where a domain administrator is logged on
Invoke-UserHunter                                                 
## Confirm access to the machine as an administrator
Invoke-UserHunter -CheckAccess                                    
```

### Domain Admin Enum
```powershell
## Get the current domain
Get-NetDomain                                         
## Get items from another domain
Get-NetDomain -Domain corporate.local                 
## Get the domain SID for the current domain
Get-DomainSID                                         
## Get domain policy for current domain
Get-DomainPolicy                                      
## See Attributes of the Domain Admins Group
Get-NetGroup -GroupName "Domain Admins" -FullData   
## Get Members of the Domain Admins group
Get-NetGroupMember -GroupName "Domain Admins"
```

### Computer Enumeration
```powershell
## Domain Controller
 Get-DomainController -Domain <DomainName>
## Get the list of computers in the current domain
Get-NetComputer
## Get the list of computers in the current domain with complete data 
Get-NetComputer -FullData
## Get the list of computers grabbing their operating system
Get-NetComputer -FullData | select operatingsystem
## Get the list of computers grabbing their name
Get-NetComputer -FullData | select name
## Send a ping to check if the computers are alive (They could be alive but still not responding to any ICMP echo request)
Get-NetComputer -Ping                             
```

### Groups and Members Enumeration
```powershell
## Information about groups
Get-NetGroup
## Get all groups that contain the word "admin" in the group name 
Get-NetGroup *Admin*                                                       
## Get all members of the "Domain Admins" group
Get-NetGroupMember -GroupName "Domain Admins" -Recurse                     
## Query the root domain as the "Enterprise Admins" group exists only in the root of a forest
Get-NetGroupMember -GroupName "Enterprise Admins" –Domain domainxxx.local  
## Get group membership for "user01"
Get-NetGroup -UserName "user01"                                            
```

### Shares Enumeration
```powershell
## Find shares on hosts in the current domain                   
Invoke-ShareFinder -Verbose                                             
## Find sensitive files on computers in the current domain
Invoke-FileFinder -Verbose                                              
## Search file servers. Lot of users use to be logged in this kind of server
Get-NetFileServer                                                       
## Find shares excluding standard, print and ipc.
Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC –Verbose
## Enumerate Domain Shares the current user has access
Find-DomainShare -CheckShareAccess
## Find interesting shares in the domain, ignore default shares, and check access
Find-DomainShare -ExcludeStandard -ExcludePrint -ExcludeIPC -CheckShareAccess
```


### OUI and GPO Enumeration
```powershell
## Get the organizational units in a domain
Get-NetOU
## Get the organizational units in a domain with name
Get-NetOU | select name
## Get the organizational units in a domain with full data
Get-NetOU -FullData                                                         
## Get all computers from "ouiexample". Ouiexample --> organizational Units
Get-NetOU "ouiexample" | %{Get-NetComputer -ADSpath $_}                     
## Retrieve the list of GPOs present in the current domain
Get-NetGPO
## Retrieve the list of GPOs present in the current domain with displayname
Get-NetGPO| select displayname
##Get list of GPO in the target computer
Get-NetGPO -ComputerName <ComputerName> | select displayname
## Find users who have local admin rights over the machine
Find-GPOComputerAdmin –Computername <ComputerName>
## Get machines where the given user in member of a specific group
Find-GPOLocation -Identity <user> -Verbose
## Enumerate GPO applied on the example OU
Get-NetGPO -ADSpath 'LDAP://cn={example},CN=example'                        
```
### ACLs Enumeration
```powershell
## Enumerates the ACLs for the users group
Get-ObjectAcl -SamAccountName "users" -ResolveGUIDs                         
## Enumerates the ACLs for the Domain Admins group
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs                 
## Get the acl associated with a specific prefix
Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose               
## Find interesting ACLs
Invoke-ACLScanner -ResolveGUIDs                                             
## Check for modify rights/permissions for the user group
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "user"}     
## Check for modify rights/permissions for the RDPUsers group
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "RDPusers"} 
## Check for modify rights/permissions for the RDPUsers group
Invoke-ACLScanner | select ObjectDN,ActiveDirectoryRights,IdentityReferenceName
## Search of interesting ACL's for the current user
Invoke-ACLScanner | Where-Object {$_.IdentityReference –eq [System.Security.Principal.WindowsIdentity]::GetCurrent().Name}
```
### Domain Trust Mapping
```powershell
## Get the list of all trusts within the current domain
Get-NetDomainTrust                                                          
## Get the list of all trusts within the indicated domain
Get-NetDomainTrust -Domain us.domain.corporation.local
## Get the list of all trusts for each domain it finds
Get-DomainTrustMapping
```

### Domain Forest Enumeration
```powershell
## Get all domains in the current forest
Get-NetForestDomain                                                                
## Get all domains in the current forest
Get-NetForestDomain -Forest corporation.local                                      
## Map all trusts
Get-NetForestDomain -Verbose | Get-NetDomainTrust                                  
## Map only external trusts
Get-NetForestDomain -Verbose | Get-NetDomainTrust | ?{$_.TrustType -eq 'External'}
```
