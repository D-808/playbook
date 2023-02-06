
## FFUF
```bash
##Fuzz Faster You Fool Command Examples

## Show only 200 Responses in output
ffuf -w /opt/SecLists/wordlist.txt -u http://0.0.0.0:8088/FUZZ -mc 200

## Extensions
ffuf -u http://0.0.0.0/FUZZ/ -w dict.txt -e .php

## Filter out spectic responses in output
ffuf -u http://0.0.0.0/FUZZ/ -w dict.txt -fc 302

## Add a time delay to each GET request sent to server
ffuf -u http://0.0.0.0/FUZZ/ -w dict.txt -p 1
```

```bash
##Fuzz Faster You Fool
Matching
    -mc - Match response codes
    -ml - match amount of lines in response
    -mr - Match regex pattern
    -mw - Match amount of words in response
    -ms - Match reponse size

Filtering
    -fc - Filter response codes
    -fl - Filter by amount of lines in response
    -fr - Filter regex pattern
    -fw - Filter amount of words in response
    -fs - Filter response size

Input
    -mode - Multi-wordlist operation mode. modes: clusterbomb, pitchfork
    -request - File containing the raw http request
    -request-proto - Protocol to use along with raw request
    -w - Wordlist

Output
    -o - Output file
    -of - Output file format. (json, html, md, csv, all)
```

## Wpscan
```bash
## Basic usage
wpscan --url http://target.ie --verbose

## enumerate vulnerable plugins, users, vulrenable themes, timthumbs
wpscan --url "target" --enumerate vp,u,vt,tt --follow-redirection --verbose --log target.log

```