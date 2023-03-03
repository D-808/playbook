
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

## GenericAll Abuse
```powershell
## If you have GenericAll Permissions over a user, change their pw
## User password change
Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock {net user mickey.mouse newpassword /domain}
```
### GUI Graph Queries
```powershell
## Find All edges any owned user has on a computer
match p=shortestPath((m:User)-[r]->(b:Computer)) WHERE m.owned RETURN p
## Find All Users with an SPN/Find all Kerberoastable Users
match (n:User)WHERE n.hasspn=true
## Find workstations a user can RDP into
match p=(g:Group)-[:CanRDP]->(c:Computer) where g.objectid ENDS WITH '-513'  AND NOT c.operatingsystem CONTAINS 'Server' return p
## Find servers a user can RDP into
match p=(g:Group)-[:CanRDP]->(c:Computer) where  g.objectid ENDS WITH '-513'  AND c.operatingsystem CONTAINS 'Server' return p
## Find all computers with Unconstrained Delegation
match (c:Computer {unconstraineddelegation:true}) return c
## Find users that logged in within the last 30 days
match (u:User) WHERE u.lastlogon < (datetime().epochseconds - (30 * 86400)) and NOT u.lastlogon IN [-1.0, 0.0] return u
## Find all sessions any user in a specific domain
match p=(m:Computer)-[r:HasSession]->(n:User {domain: "corporate.local"}) RETURN p
## Find the active user sessions on all domain computers
match p1=shortestPath(((u1:User)-[r1:MemberOf*1..]->(g1:Group))) MATCH p2=(c:Computer)-[*1]->(u1) return p2
## View all groups that contain the word 'administrators'
match (n:Group) WHERE n.name CONTAINS "administrators" return n
## Find if unprivileged users have rights to add members into groups
match (n:User {admincount:False}) MATCH p=allShortestPaths((n)-[r:AddMember*1..]->(m:Group)) return p
```

### Console Queries
```powershell
## Find what groups can RDP
match p=(m:Group)-[r:CanRDP]->(n:Computer) RETURN m.name, n.name ORDER BY m.name
## Find what groups can reset passwords 
match p=(m:Group)-[r:ForceChangePassword]->(n:User) RETURN m.name, n.name ORDER BY m.name
## Find what groups have local admin rights
match p=(m:Group)-[r:AdminTo]->(n:Computer) RETURN m.name, n.name ORDER BY m.name
## Find all connections to a different domain/forest
match (n)-[r]->(m) WHERE NOT n.domain = m.domain RETURN LABELS(n)[0],n.name,TYPE(r),LABELS(m)[0],m.name
## Kerberoastable Users with most privileges
match (u:User {hasspn:true}) OPTIONAL MATCH (u)-[:AdminTo]->(c1:Computer) OPTIONAL MATCH (u)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c2:Computer) WITH u,COLLECT(c1) + COLLECT(c2) AS tempVar UNWIND tempVar AS comps RETURN u.name,COUNT(DISTINCT(comps)) ORDER BY COUNT(DISTINCT(comps)) DESC
## Find users that logged in within the last 30 days
match (u:User) WHERE u.lastlogon < (datetime().epochseconds - (30 * 86400)) and NOT u.lastlogon IN [-1.0, 0.0] RETURN u.name, u.lastlogon order by u.lastlogon
## Find constrained delegation
match (u:User)-[:AllowedToDelegate]->(c:Computer) RETURN u.name,COUNT(c) ORDER BY COUNT(c) DESC
## Enumerate all properties
match (n:Computer) return properties(n)
```