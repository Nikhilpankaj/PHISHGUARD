 #!/usr/bin/env python3
"""
PHISHGUARD - Phishing URL Detector

Features:
- Heuristic URL analysis
- IP/IPv6 detection
- Punycode and Unicode hostname checks
- Suspicious keywords/TLDs
- URL shortener detection
- Port/path/query analysis
- Domain entropy analysis
- Optional DNS resolution
- Optional redirect-chain analysis
- Batch scanning from a text file
- JSON and CSV reporting
- Clear risk scoring and explanations

Use only on URLs you are authorized to analyze.
Network features are optional and can be disabled with --offline.
"""

import argparse
import csv
import ipaddress
import json
import math
import re
import socket
import sys
from collections import Counter
from urllib.parse import urlparse, unquote

try:
    import requests
except ImportError:
    requests = None


SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification",
    "account", "secure", "security", "update",
    "confirm", "password", "credential", "bank",
    "payment", "wallet", "unlock", "suspend",
    "recover", "support", "auth", "authenticate",
    "reset", "billing", "invoice", "webmail"
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "is.gd", "ow.ly", "cutt.ly", "rb.gy",
    "buff.ly", "rebrand.ly", "shorturl.at"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "work", "link",
    "zip", "mov", "tk", "ml", "ga", "cf",
    "gq", "icu", "cam", "buzz"
}

SUSPICIOUS_PORTS = {
    21, 22, 23, 25, 110, 143, 445, 1433,
    3306, 3389, 4444, 5900, 8080, 8443
}

MAX_REDIRECTS = 5
REQUEST_TIMEOUT = 7


def normalize_url(url):
    """Add a scheme if the user did not provide one."""
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def calculate_entropy(value):
    """Calculate Shannon entropy for a string."""
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def add_indicator(score, reasons, points, message):
    score += points
    reasons.append((points, message))
    return score


def analyze_url(url, resolve_dns=False, follow_redirects=False):
    """Analyze a URL and return a structured result."""
    original_url = url.strip()
    normalized = normalize_url(original_url)

    result = {
        "url": original_url,
        "normalized_url": normalized,
        "score": 0,
        "classification": "LOW RISK",
        "reasons": [],
        "hostname": "",
        "ip_address": False,
        "resolved_ips": [],
        "redirect_chain": [],
        "final_url": normalized,
    }

    try:
        parsed = urlparse(normalized)
    except ValueError as exc:
        result["score"] = 100
        result["classification"] = "INVALID / HIGH RISK"
        result["reasons"] = [f"URL parsing failed: {exc}"]
        return result

    hostname = (parsed.hostname or "").lower().rstrip(".")
    result["hostname"] = hostname

    if not hostname:
        result["score"] = 100
        result["classification"] = "INVALID / HIGH RISK"
        result["reasons"] = ["No valid hostname found"]
        return result

    decoded_url = unquote(normalized).lower()
    score = 0
    reasons = []

    # 1. URL length
    if len(normalized) > 200:
        score = add_indicator(score, reasons, 15, "Extremely long URL")
    elif len(normalized) > 150:
        score = add_indicator(score, reasons, 10, "Very long URL")
    elif len(normalized) > 100:
        score = add_indicator(score, reasons, 5, "Long URL")

    # 2. HTTPS
    if parsed.scheme.lower() != "https":
        score = add_indicator(score, reasons, 10, "URL does not use HTTPS")

    # 3. IP address hostname
    if is_ip_address(hostname):
        result["ip_address"] = True
        score = add_indicator(score, reasons, 25, "Hostname is an IP address")

    # 4. @ symbol
    if "@" in normalized:
        score = add_indicator(
            score, reasons, 25,
            "Contains @ symbol (possible URL obfuscation)"
        )

    # 5. Punycode / IDN
    if "xn--" in hostname:
        score = add_indicator(score, reasons, 20, "Contains Punycode hostname")

    # 6. Non-ASCII hostname
    if any(ord(char) > 127 for char in hostname):
        score = add_indicator(
            score, reasons, 15,
            "Hostname contains non-ASCII/Unicode characters"
        )

    # 7. Too many subdomains
    dot_count = hostname.count(".")
    if dot_count >= 4:
        score = add_indicator(score, reasons, 15, "Excessive number of subdomains")
    elif dot_count >= 3:
        score = add_indicator(score, reasons, 10, "Many subdomains")

    # 8. Hyphens
    hyphen_count = hostname.count("-")
    if hyphen_count >= 5:
        score = add_indicator(score, reasons, 12, "Excessive hyphens in hostname")
    elif hyphen_count >= 3:
        score = add_indicator(score, reasons, 8, "Many hyphens in hostname")

    # 9. Digits in hostname
    digit_count = sum(char.isdigit() for char in hostname)
    if digit_count >= 6:
        score = add_indicator(score, reasons, 10, "Many digits in hostname")

    # 10. Suspicious keywords
    found_keywords = sorted({
        keyword for keyword in SUSPICIOUS_KEYWORDS
        if keyword in decoded_url
    })

    if found_keywords:
        points = min(len(found_keywords) * 4, 20)
        score = add_indicator(
            score, reasons, points,
            "Suspicious keywords: " + ", ".join(found_keywords)
        )

    # 11. URL shortener
    if hostname in URL_SHORTENERS:
        score = add_indicator(
            score, reasons, 20,
            "Uses a URL shortening service"
        )

    # 12. Suspicious TLD
    if "." in hostname:
        tld = hostname.split(".")[-1]
        if tld in SUSPICIOUS_TLDS:
            score = add_indicator(
                score, reasons, 12,
                f"Suspicious/high-risk TLD: .{tld}"
            )

    # 13. Encoded characters
    if re.search(r"%[0-9a-fA-F]{2}", normalized):
        score = add_indicator(
            score, reasons, 8,
            "Contains URL-encoded characters"
        )

    # 14. Double slash in path
    if "//" in parsed.path:
        score = add_indicator(
            score, reasons, 8,
            "Contains double slash in path"
        )

    # 15. Another URL inside URL
    if re.search(r"https?://|https?%3a", decoded_url, re.IGNORECASE):
        score = add_indicator(
            score, reasons, 15,
            "Contains another URL inside the URL"
        )

    # 16. Suspicious redirect/query parameters
    suspicious_params = [
        "redirect", "redirect_url", "url", "next",
        "return", "returnurl", "continue", "dest",
        "destination", "target"
    ]

    query_lower = parsed.query.lower()
    found_params = [
        param for param in suspicious_params
        if re.search(rf"(?:^|[&;]){re.escape(param)}=", query_lower)
    ]

    if found_params:
        score = add_indicator(
            score, reasons, 10,
            "Potential redirect parameters: " + ", ".join(found_params)
        )

    # 17. Suspicious port
    try:
        port = parsed.port
    except ValueError:
        port = None

    if port:
        if port in SUSPICIOUS_PORTS:
            score = add_indicator(
                score, reasons, 8,
                f"Uses unusual/sensitive port: {port}"
            )
        elif port not in (80, 443):
            score = add_indicator(
                score, reasons, 4,
                f"Uses non-standard web port: {port}"
            )

    # 18. Path depth
    path_parts = [p for p in parsed.path.split("/") if p]
    if len(path_parts) >= 8:
        score = add_indicator(score, reasons, 10, "Very deep URL path")
    elif len(path_parts) >= 5:
        score = add_indicator(score, reasons, 5, "Deep URL path")

    # 19. Query length / parameter count
    query_params = [
        item for item in parsed.query.split("&")
        if item
    ]

    if len(query_params) >= 10:
        score = add_indicator(score, reasons, 10, "Large number of query parameters")
    elif len(query_params) >= 6:
        score = add_indicator(score, reasons, 5, "Many query parameters")

    if len(parsed.query) > 500:
        score = add_indicator(score, reasons, 8, "Very long query string")

    # 20. Domain entropy
    domain_without_tld = hostname.replace(".", "")
    entropy = calculate_entropy(domain_without_tld)

    if len(domain_without_tld) >= 15 and entropy >= 4.0:
        score = add_indicator(
            score, reasons, 10,
            f"High hostname entropy ({entropy:.2f})"
        )

    # 21. Repeated separators / suspicious symbols
    if re.search(r"[._-]{3,}", hostname):
        score = add_indicator(
            score, reasons, 8,
            "Repeated separators in hostname"
        )

    # 22. DNS resolution (optional)
    if resolve_dns:
        try:
            addresses = sorted({
                item[4][0]
                for item in socket.getaddrinfo(hostname, None)
                if item[4]
            })
            result["resolved_ips"] = addresses

            if not addresses:
                score = add_indicator(
                    score, reasons, 8,
                    "Hostname did not resolve to an IP address"
                )
        except socket.gaierror:
            result["resolved_ips"] = []
            score = add_indicator(
                score, reasons, 8,
                "DNS resolution failed"
            )
        except OSError:
            result["resolved_ips"] = []
            score = add_indicator(
                score, reasons, 4,
                "DNS lookup could not be completed"
            )

    # 23. Redirect-chain analysis (optional)
    if follow_redirects:
        if requests is None:
            reasons.append((0, "Redirect analysis unavailable: install requests"))
        else:
            try:
                response = requests.get(
                    normalized,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                    headers={"User-Agent": "PhishGuard/2.0 Security Scanner"},
                )

                chain = [r.url for r in response.history]
                chain.append(response.url)

                # Keep unique URLs while preserving order.
                result["redirect_chain"] = list(dict.fromkeys(chain))
                result["final_url"] = response.url

                if len(response.history) >= 3:
                    score = add_indicator(
                        score, reasons, 12,
                        f"Long redirect chain ({len(response.history)} redirects)"
                    )

                if response.url != normalized:
                    final_host = (urlparse(response.url).hostname or "").lower()
                    if final_host and final_host != hostname:
                        score = add_indicator(
                            score, reasons, 10,
                            "Final redirect destination uses a different hostname"
                        )

            except requests.RequestException as exc:
                reasons.append((0, f"Redirect analysis failed: {exc.__class__.__name__}"))

    # Final score
    score = min(max(score, 0), 100)

    if score >= 60:
        classification = "PHISHING / HIGH RISK"
    elif score >= 30:
        classification = "SUSPICIOUS / MEDIUM RISK"
    else:
        classification = "LOW RISK"

    result["score"] = score
    result["classification"] = classification
    result["reasons"] = [
        message for _, message in sorted(
            reasons, key=lambda item: item[0], reverse=True
        )
    ]

    return result


def print_result(result):
    print("\n" + "=" * 72)
    print("PHISHGUARD URL ANALYSIS")
    print("=" * 72)
    print(f"URL            : {result['url']}")
    print(f"Hostname       : {result['hostname']}")
    print(f"Risk Score     : {result['score']}/100")
    print(f"Classification : {result['classification']}")

    if result["resolved_ips"]:
        print("Resolved IPs   : " + ", ".join(result["resolved_ips"]))

    if result["redirect_chain"]:
        print("\nRedirect Chain:")
        for index, item in enumerate(result["redirect_chain"], 1):
            print(f"  {index}. {item}")

    print("\nDetection Indicators:")

    if result["reasons"]:
        for reason in result["reasons"]:
            print(f"  [!] {reason}")
    else:
        print("  [+] No suspicious indicators detected.")

    print("=" * 72)


def read_urls_from_file(filename):
    with open(filename, "r", encoding="utf-8") as file:
        urls = []
        for line in file:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
        return urls


def write_json(results, filename):
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)


def write_csv(results, filename):
    with open(filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([
            "url", "hostname", "score", "classification",
            "resolved_ips", "final_url", "reasons"
        ])

        for result in results:
            writer.writerow([
                result["url"],
                result["hostname"],
                result["score"],
                result["classification"],
                "; ".join(result["resolved_ips"]),
                result["final_url"],
                "; ".join(result["reasons"])
            ])


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="PHISHGUARD - Phishing URL Detection Tool"
    )

    source = parser.add_mutually_exclusive_group()

    source.add_argument(
        "-u", "--url",
        help="URL to analyze"
    )

    source.add_argument(
        "-f", "--file",
        help="Text file containing URLs (one URL per line)"
    )

    parser.add_argument(
        "--offline",
        action="store_true",
        help="Disable DNS and redirect network checks"
    )

    parser.add_argument(
        "--dns",
        action="store_true",
        help="Resolve hostname using DNS"
    )

    parser.add_argument(
        "--redirects",
        action="store_true",
        help="Follow redirects and analyze the redirect chain"
    )

    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Save results as JSON"
    )

    parser.add_argument(
        "--csv",
        metavar="FILE",
        help="Save results as CSV"
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    print("=" * 72)
    print("             PHISHGUARD - PHISHING URL DETECTOR")
    print("                         Version 2.0")
    print("=" * 72)

    urls = []

    if args.url:
        urls = [args.url]
    elif args.file:
        try:
            urls = read_urls_from_file(args.file)
        except OSError as exc:
            print(f"[ERROR] Could not read file: {exc}")
            sys.exit(1)
    else:
        try:
            entered = input("\nEnter URL: ").strip()
        except KeyboardInterrupt:
            print("\nExiting.")
            return

        if entered:
            urls = [entered]
        else:
            print("Please enter a URL.")
            return

    if not urls:
        print("No URLs to analyze.")
        return

    use_dns = args.dns and not args.offline
    use_redirects = args.redirects and not args.offline

    results = []

    for url in urls:
        result = analyze_url(
            url,
            resolve_dns=use_dns,
            follow_redirects=use_redirects
        )
        results.append(result)

        if len(urls) == 1:
            print_result(result)

    if len(urls) > 1:
        print("\n" + "=" * 90)
        print("BATCH SCAN RESULTS")
        print("=" * 90)
        print(f"{'SCORE':<8}{'CLASSIFICATION':<28}URL")
        print("-" * 90)

        for result in results:
            print(
                f"{result['score']:<8}"
                f"{result['classification']:<28}"
                f"{result['url']}"
            )

        print("=" * 90)

    if args.json:
        try:
            write_json(results, args.json)
            print(f"[+] JSON report saved to: {args.json}")
        except OSError as exc:
            print(f"[ERROR] Could not write JSON report: {exc}")

    if args.csv:
        try:
            write_csv(results, args.csv)
            print(f"[+] CSV report saved to: {args.csv}")
        except OSError as exc:
            print(f"[ERROR] Could not write CSV report: {exc}")

    print("\nNote: PHISHGUARD is a heuristic detector.")
    print("A high score does not by itself prove that a URL is malicious.")


if __name__ == "__main__":
    main()
