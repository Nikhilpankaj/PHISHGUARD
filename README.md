# PHISHGUARD – Phishing URL Detection Tool 🛡️

**PHISHGUARD** is a Python-based phishing URL detection and analysis tool designed to identify suspicious and potentially malicious URLs using multiple heuristic security indicators.

The tool analyzes URL structure, hostname characteristics, suspicious keywords, URL encoding, ports, redirects, domain entropy, and other phishing-related indicators to generate a **risk score from 0–100** and classify URLs as **LOW RISK, SUSPICIOUS / MEDIUM RISK, or PHISHING / HIGH RISK**.

## 🔍 Key Features

* 🔎 Heuristic-based phishing URL detection
* 📊 Risk scoring from **0–100**
* 🌐 IP address and IPv6 hostname detection
* 🔤 Punycode and Unicode hostname detection
* 🚨 Suspicious keyword detection
* 🔗 URL shortener detection
* 🌍 Suspicious TLD detection
* 🔐 HTTPS analysis
* ⚠️ Suspicious port detection
* 🧩 URL encoding and obfuscation detection
* 🔀 Redirect-chain analysis
* 🧭 Optional DNS resolution
* 🧠 Domain entropy analysis
* 📁 Batch URL scanning from a text file
* 📄 JSON report generation
* 📊 CSV report generation
* 📴 Offline mode for disabling network-based checks

## 📈 Risk Classification

| Score      | Classification              |
| ---------- | --------------------------- |
| **0–29**   | 🟢 LOW RISK                 |
| **30–59**  | 🟡 SUSPICIOUS / MEDIUM RISK |
| **60–100** | 🔴 PHISHING / HIGH RISK     |

The detector combines multiple indicators rather than relying on a single characteristic.

## 🚀 Usage

### Scan a single URL

```bash
python3 phishguard.py -u https://example.com
```

### Scan URLs from a file

```bash
python3 phishguard.py -f urls.txt
```

### Enable DNS analysis

```bash
python3 phishguard.py -u https://example.com --dns
```

### Analyze redirects

```bash
python3 phishguard.py -u https://example.com --redirects
```

### Offline analysis

```bash
python3 phishguard.py -u https://example.com --offline
```

### Export results to JSON

```bash
python3 phishguard.py -u https://example.com --json results.json
```

### Export results to CSV

```bash
python3 phishguard.py -u https://example.com --csv results.csv
```

## 🧪 Detection Techniques

PHISHGUARD checks indicators such as:

* Excessively long URLs
* Missing HTTPS
* IP-based hostnames
* `@`-symbol URL obfuscation
* Punycode domains
* Unicode hostnames
* Excessive subdomains
* Multiple hostname hyphens/digits
* Phishing-related keywords
* URL shorteners
* Suspicious TLDs
* Encoded characters
* Nested URLs
* Redirect parameters
* Suspicious ports
* Deep URL paths
* Excessive query parameters
* High domain entropy
* Redirect chains

## 📄 Output & Reporting

For each analyzed URL, PHISHGUARD provides the URL, hostname, risk score, classification, detected indicators, and optional DNS/redirect information. Results can also be exported in **JSON or CSV** format for further analysis.

## ⚠️ Disclaimer

PHISHGUARD is a **heuristic phishing detection tool**. A high risk score does not automatically prove that a URL is malicious, and a low score does not guarantee that a URL is safe.

Use this tool only on URLs that you are authorized to analyze.

## 🛠️ Technology

* **Python 3**
* `argparse`
* `urllib`
* `ipaddress`
* `socket`
* `requests`
* JSON / CSV

## 🎯 Purpose

This project is intended for **cybersecurity learning, phishing analysis, URL investigation, VAPT practice, and security research** in authorized environments.

## AUTHOR

Nikhil Kumar Pankaj
