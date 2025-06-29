#!/bin/python3

import dns.resolver
import whois
import requests
import argparse
import threading
import json

# Semaphore to limit concurrent requests
semaphore = threading.Semaphore(5)

def get_dns_records(domain):
    """Retrieve DNS records for a given domain."""
    records = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    resolver = dns.resolver.Resolver()

    for record in record_types:
        try:
            answers = resolver.resolve(domain, record)
            records[record] = [answer.to_text() for answer in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers):
            records[record] = []
    return records

def get_whois_info(domain):
    """Retrieve WHOIS information for a given domain."""
    try:
        w = whois.whois(domain)
        return w.text
    except Exception as e:
        return f"WHOIS lookup failed: {str(e)}"

def fetch_from_url(url, domain, subdomains):
    """Helper function to fetch subdomains from a specific URL."""
    with semaphore:
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                if "crt.sh" in url:
                    for entry in response.json():
                        subdomains.add(entry["name_value"].strip())
                elif "hackertarget.com" in url:
                    for line in response.text.strip().split("\n"):
                        parts = line.split(",")
                        if len(parts) > 1:
                            subdomains.add(parts[0].strip())
        except Exception:
            pass

def passive_subdomain_enum(domain):
    """Perform passive subdomain enumeration using OSINT sources."""
    sources = [
        f"https://crt.sh/?q={domain}&output=json",
        f"https://api.hackertarget.com/hostsearch/?q={domain}"
    ]
    subdomains = set()
    threads = []

    for url in sources:
        thread = threading.Thread(target=fetch_from_url, args=(url, domain, subdomains))
        thread.start()
        threads.append(thread)

    for t in threads:
        t.join()

    return sorted(list(subdomains))

def save_to_file(data, filename):
    """Save results to a JSON file."""
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Results saved to {filename}")
    except IOError as e:
        print(f"[-] Failed to write to file: {e}")

def main():
    parser = argparse.ArgumentParser(description="Passive Recon Tool")
    parser.add_argument("domain", help="Target domain for reconnaissance")
    parser.add_argument("-o", "--output", help="Save output to file (JSON)")

    args = parser.parse_args()
    domain = args.domain

    print(f"\n[+] Reconnaissance for: {domain}\n")

    print("[+] DNS Records:")
    dns_data = get_dns_records(domain)
    for record, values in dns_data.items():
        print(f"  {record}: {', '.join(values) if values else 'No record found'}")

    print("\n[+] WHOIS Information:")
    whois_data = get_whois_info(domain)
    print(whois_data.strip())

    print("\n[+] Passive Subdomain Enumeration:")
    subdomains = passive_subdomain_enum(domain)
    if subdomains:
        print("  " + "\n  ".join(subdomains))
    else:
        print("  No subdomains found.")

    if args.output:
        output_data = {
            "domain": domain,
            "dns_records": dns_data,
            "whois": whois_data,
            "subdomains": subdomains
        }
        save_to_file(output_data, args.output)

if __name__ == "__main__":
    main()
