# Subdomain Takeover Scanner

A Python tool to detect subdomain takeover vulnerabilities using:

- Certificate Transparency logs (crt.sh)
- DNS brute forcing
- CNAME analysis
- Cloud service fingerprinting

## Features
- Fast multithreaded scanning
- Detects AWS S3, GitHub Pages, Heroku, Azure, Fastly
- Easy CLI usage

## Installation
```
git clone https://github.com/vivek-kr-pandit/SubHijack
cd SubHijack
```
## Usage
```
python3 subhijack.py -d example.com -w wordlist.txt
```
## Disclaimer
For educational and authorized testing only.
