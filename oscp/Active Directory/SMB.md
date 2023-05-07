## Enumeration 

```bash
## List shares with null session
crackmapexec smb <ip> --shares
## Try list with randon username
crackmapexec smb <ip> -u 'myusername' --shares
## List shares with authorization 
crackmapexec smb <ip> -u 'username' -p 'p@s$w0Rd'
````

## smbclient
```bash
## List shares on a machine using NULL Session
smbclient -L //0.0.0.0 -N

## Access a share with no authentication
smbclient -N //0.0.0.0/<name-of-share>

## List shares on a machine using a valid username + password
smbclient -L //0.0.0.0 -U username%password

## Connect to a valid share with username + password
smbclient //0.0.0.0/<share$> -U username%password

## List files on a specific share
smbclient //0.0.0.0/<share$> -c 'ls' password -U username

## List files on a specific share folder inside the share
smbclient //0.0.0.0/<share$> -c 'cd folder; ls' password -U username

## Download a file from a specific share folder
smbclient //0.0.0.0/<share$> -c 'cd folder;get desired_file_name' password -U username

## Copy a file to a specific share folder
smbclient //0.0.0.0>/<share$> -c 'put /var/www/my_local_file.txt .\target_folder\target_file.txt' password -U username

## Create a folder in a specific share folder
smbclient //0.0.0.0/<share$> -c 'mkdir .\target_folder\new_folder' password -U username
```

## Enum4linux
```bash
## Verbose mode, shows the underlying commands being executed by enum4linux
enum4linux -v target-ip

## Runs all options apart from dictionary based share name guessing
enum4linux -a target-ip

## Lists usernames, if the server allows it - (RestrictAnonymous = 0)
enum4linux -U target-ip

## With credentials, you can pull a full list of users regardless of the RestrictAnonymous option
enum4linux -u administrator -p password -U target-ip

## Pulls usernames from the default RID range (500-550,1000-1050)
enum4linux -r target-ip

## Pull usernames using a custom RID range
enum4linux -R 600-660 target-ip

## Lists groups. if the server allows it, you can also specify username -u and password -p
enum4linux -G target-ip

## List Windows shares, again you can also specify username -u and password -p
enum4linux -S target-ip

## Perform a dictionary attack, if the server doesn't let you retrieve a share list 
enum4linux -s shares.txt target-ip

## Pulls OS information using smbclient, this can pull the service pack version on some versions of Windows
enum4linux -o target-ip

## Pull information about printers known to the remove device.
enum4linux -i target-ip
```

