#!/usr/bin/env python3


import requests
import dns.resolver
import argparse
import concurrent.futures
import re

# -----------------------------
# Fingerprints for detection
# -----------------------------
FINGERPRINTS = {
    "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
    "GitHub Pages": ["There isn't a GitHub Pages site here"],
    "Heroku": ["No such app"],
    "Azure": ["The resource you are looking for has been removed"],
    "Fastly": ["Fastly error: unknown domain"]
}

# -----------------------------
# CT Logs Enumeration
# -----------------------------
def enumerate_ct(domain):
    print(f"[+] Fetching CT logs for {domain}...")
    url = f"https://crt.sh/json?q={domain}"
    subdomains = set()

    try:
        resp = requests.get(url, timeout=10)
        data = resp.json()
        for entry in data:
            names = entry.get("name_value", "").split("\n")
            for name in names:
                if domain in name:
                    subdomains.add(name.strip())
    except Exception as e:
        print(f"[-] CT fetch error: {e}")

    return subdomains


# DNS Brute Force

def brute_force(domain, wordlist):
    print("[+] Starting DNS brute force...")
    subdomains = set()

    resolver = dns.resolver.Resolver()

    with open(wordlist, "r") as f:
        words = f.read().splitlines()

    def resolve(sub):
        full = f"{sub}.{domain}"
        try:
            resolver.resolve(full, "A")
            return full
        except:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(resolve, words)

    for r in results:
        if r:
            subdomains.add(r)

    return subdomains


# Check for CNAME

def get_cname(subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME")
        for rdata in answers:
            return str(rdata.target).rstrip('.')
    except:
        return None

=
# Check takeover vulnerability
=
def check_takeover(subdomain):
    cname = get_cname(subdomain)
    if not cname:
        return None

    try:
        resp = requests.get(f"http://{subdomain}", timeout=8)
        content = resp.text

        for service, patterns in FINGERPRINTS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return (subdomain, cname, service)
    except:
        pass

    return None


# Main

def main():
    parser = argparse.ArgumentParser(description="Subdomain Takeover Scanner")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-w", "--wordlist", help="Wordlist for brute force")

    args = parser.parse_args()

    all_subs = set()

    # CT enumeration
    ct_subs = enumerate_ct(args.domain)
    all_subs.update(ct_subs)

    # Brute force
    if args.wordlist:
        brute_subs = brute_force(args.domain, args.wordlist)
        all_subs.update(brute_subs)

    print(f"[+] Total subdomains found: {len(all_subs)}")

    # Check takeovers
    print("[+] Checking for takeover vulnerabilities...")

    vulnerable = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        results = executor.map(check_takeover, all_subs)

    for res in results:
        if res:
            vulnerable.append(res)

    # Output results
    print("\n=== Potential Takeovers ===")
    for sub, cname, service in vulnerable:
        print(f"[!] {sub} -> {cname} ({service})")

    print(f"\n[+] Done. Found {len(vulnerable)} potential takeovers.")


if __name__ == "__main__":
    main()
