```bash
## Scan IP range to see what hosts are up
for ip in $(seq 1 254); do ping -c 1 0.0.0.$ip > /dev/null; [ $? -eq 0 ] && echo "0.0.0.$ip UP" || : ; done
```

## nmap

```bash
## Scan IP range to see what hosts are up
nmap -T5 -sP 192.168.0.0-255

## Check every port to see if open
nmap --top-ports 65535 192.168.0.0

## Find out more info about specific ports and save to .txt fil
nmap -sC -sV -p 21,22,80,443 -oN nmap-results.txt 192.168.0.0

## Scan UDP ports
nmap -sU 0.0.0.0

## Scan Smb ports with scripts
nmap --script smb-enum-shares -p 139,445 0.0.0.0

## Linux executable (ELF) of nmap
## https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap
```

## Dig
```bash
##To run dig (domain information groper)
dig [domain]

## To just get the ip address
dig [domain] +nocomments +noauthority +noadditional +nostats 
OR
dig [domain] +noall +answer
OR
dig [domain] +short

## To use a specific query type
dig -t [query type] [domain] [options]
OR
dig [domain] [query type] [options]

## To view ALL DNS record types use query ANY
dig -t ANY [domain] [options]
OR
dig [domain] ANY [options]

## To do a DNS reverse look up 
dig -x [ip address] +short

## To use a specific DNS server
dig @[specific DNS] [domain]

## To do a bulk DNS query (where file.txt has all the domains, one to a line)
dig [domain1] [options] [domain2] [options]
OR
dit -f file.txt [options]
```

## #DNS Enum
```bash
dnsenum <DOMAIN>
dnsenum --dnsserver 0.0.0.0 -enum www.guinness.com
```

## #Sublist3r - subdomain enumeration
```bash
## Parameters for sublist3r
Short  		Long Form	 	Description

-d			 	–domain 		Domain name to enumerate subdomains of
-b 				–bruteforce 	Enable the subbrute bruteforce module
-p 				–ports 			Scan the found subdomains against specific tcp ports
-v 				–verbose 		Enable the verbose mode and display results in realtime
-t 				–threads 		Number of threads to use for subbrute bruteforce
-e 				–engines 		Specify a comma-separated list of search engines
-o 				–output 			Save the results to text file
-h				–help 			show the help message and exit
```

```bash
## Enumerate guinness.com for subdomain w/ bing search eng + time delay of 3secs 
sublist3r -d guinness.com -t 3 -e bing

## Enumerate subdomains of specific domain
sublist3r -d guinness.com

## Enumerate subdomains of specific domain and show only subdomains which have open ports 80 and 443
sublist3r -d guinness.com -p 80,443

## Enumerate subdomains of specific domain and show the results in realtime
sublist3r -v -d guinness.com

## Enumerate subdomains and enable the bruteforce module
sublist3r -b -d guinness.com

## Enumerate subdomains and use specific engines such Google, Yahoo and Virustotal engines
sublist3r -e google,yahoo,virustotal -d guinness.com
```
