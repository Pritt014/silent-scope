# silent-scope
SilentScope is a lightweight passive reconnaissance tool built in Python. It gathers DNS records, WHOIS data, and subdomains using open OSINT sources—without sending direct probes to the target infrastructure. Ideal for red teamers, threat analysts, and cybersecurity researchers conducting safe, stealthy intelligence collection.

# 🕵️‍♂️ Passive Recon Tool

## 🚀 Features

- 🔍 DNS record resolution (`A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`)
- 📜 WHOIS information retrieval
- 🌐 Passive subdomain enumeration via:
  - [crt.sh](w) (Certificate Transparency logs)
  - [hackertarget.com](w)
- ⛓️ Threaded enumeration with controlled concurrency (via `Semaphore`)
- 💾 Optional export of results in JSON format
- 🧩 Modular, readable, and easily extendable Python code

---

## 🧠 Use Cases

- Red Team reconnaissance
- OSINT investigations
- Threat intelligence gathering
- Attack surface mapping

---

### 🔧 Prerequisites

- Python modules:
  - `dnspython`
  - `python-whois`
  - `requests`
    
Before running the tool, ensure the following are set up:

* ✅ You are using **Python 3.6+**
* ✅ You have **pip** installed for managing Python packages
* ✅ You have an active internet connection (for OSINT lookups)
* ✅ You have permission or legal scope to investigate the target domain

To check your Python version:

```bash
python3 --version
```

To install `pip` (if not installed):

```bash
sudo apt update
sudo apt install python3-pip
```

---

## 🛠️ Usage

```bash
python3 passive_recon.py <domain> [-o OUTPUT_FILE]
```

### ✅ Example:

```bash
python3 passive_recon.py example.com
```

```bash
python3 passive_recon.py example.com -o results.json
```
---

## 📂 Output

- Results printed in terminal:
  - DNS records
  - WHOIS raw output
  - Enumerated subdomains

- If `-o` is used, a structured JSON file like this is created:

```json
{
  "domain": "example.com",
  "dns_records": {
    "A": ["93.184.216.34"],
    "MX": [],
    ...
  },
  "whois": "...",
  "subdomains": [
    "dev.example.com",
    "test.example.com"
  ]
}
```
---

## 🔐 Legal Disclaimer

This tool is for **educational and authorized security testing** purposes only. Unauthorized scanning or enumeration of domains without consent may violate laws or terms of service. Use responsibly.

---

## 👨‍💻 Author

Pritt Nyerere – Cybersecurity Analyst | Pentester | Security Engineer

---

## 📜 License

This project is licensed under the MIT License. See `LICENSE` for details.
```
