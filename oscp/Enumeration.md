
```bash
## Scan IP range to see what hosts are up
for ip in $(seq 1 254); do ping -c 1 10.185.0.$ip > /dev/null; [ $? -eq 0 ] && echo "10.185.0.$ip UP" || : ; done
```

## Nmap

```bash
## Scan IP range to see what hosts are up
nmap -T5 -sP 192.168.0.0-255

## Check every port to see if open
nmap --top-ports 65535

## Find out more info about specific ports and save to .txt fil
nmap -sC -sV -p 21,22,80,443 -oN nmap-results.txt
```

