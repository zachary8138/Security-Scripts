# Security-Scripts
A collection of scripts I've used for pentesting, security checks, and various other infosec related tasks.  

## advanced_sqli_scanner.py

This is a helpful little HTTP scanner that sends SQL injection payloads into URLs (query parameters), classifies attempts by injection style (e.g. error-based, UNION, boolean blind, time-based), and uses response analysis plus heuristics to flag likely issues, with confidence scores and optional DB fingerprinting.


Enable JSON output using the --json flag: ```python advanced_sqli_scanner.py -u http://example.com/page.php?id= --json```

To save the JSON output to a file ```python advanced_sqli_scanner.py -u http://example.com/page.php?id= --json -o results.json```

JSON output that includes scan metadata and detected vulnerabilties: ```{
    "scan_info": {
        "target": "http://example.com/page.php?id=",
        "timestamp": "2026-04-05T12:00:00",
        "total_vulnerabilities": 2
    },
    "results": [
        {
            "url": "http://example.com/page.php?id=1' OR '1'='1",
            "payload": "' OR 1=1 -- ",
            "injection_type": "error_based",
            "database_type": "MySQL",
            "confidence": 0.9,
            "response_time": 0.45,
            "status_code": 200,
            "error_message": null,
            "timestamp": "2026-04-05T12:00:01"
        }
    ]
}```

Read the contents of your JSON file: ```cat results.json | jq '.results[] | {url, confidence}'```

## HTTP Security Header Checker.pl 

Provides a quick way to scan a website to check if it implements recommended security headers such as HSTS, CSP, and X-Frame-Options. This helps identify potential misconfigurations that could expose the site to attacks like clickjacking, XSS, or protocol downgrade attacks.
```perl Secure_header_check.pl -u https://example.com```

Use the --json option to automate checks in a CI/CD workflow. For example, fail a deployment if critical security headers are missing.

```perl Secure_header_check.pl -u https://staging.example.com --json > header_report.json```

Combine the script with a list of URLs to audit multiple sites at once, useful for agencies, pentesters, or security teams managing multiple clients:

```cat domains.txt | xargs -I {} perl Secure_header_check.pl -u {} --json```

Enable verbose mode to see all headers, including non-critical ones, which is helpful during debugging or fine-tuning a site’s security headers:

```perl Secure_header_check.pl -u https://example.com -v```

#### WiFi-Deauth.py

Small 802.11 deauthentication/disassociation helper built with Scapy.  It injects frames from a wireless interface in monitor mode (requires root).
Make sure you're using your own lab hardware or obtain written permission before using.  Unauthorized use is not legal in all jurisdictions.

#### When it’s useful

- **Wireless security assessments** — Check whether clients drop or reconnect when management frames are spoofed, and how the environment behaves under stress.
- **802.11w / PMF awareness** — If clients and APs use **protected management frames**, deauth/disassoc may have **no effect**; the script helps you observe that in practice (not detect it automatically).
- **Roam / resilience testing** — See how devices and apps behave when the link is torn down and re-established.
- **Tooling and lab workflows** — Pair with channel setup (`iw`, `airmon-ng`, etc.), captures, and your own notes; use **`--dry-run`** to verify frame layout before transmitting.

#### Requirements

- Python 3  
- [Scapy](https://scapy.net/)  
- A Wi-Fi adapter that supports **monitor mode** and **injection**  
- Interface on the **same channel** as the target BSS (configure outside the script)

#### Ways to use it

```bash
# Target one client (STA) from a spoofed “AP” perspective (default direction)
sudo python3 WiFi-Deauth.py <STA_MAC> <BSSID> -i wlan0mon

# Continuous until Ctrl+C
sudo python3 WiFi-Deauth.py <STA_MAC> <BSSID> -c 0 --inter 0.05

# Broadcast (all associated clients on that BSSID) — one MAC argument
sudo python3 WiFi-Deauth.py --broadcast <BSSID> -i wlan0mon

# Disassociation, or both deauth + disassoc per cycle
sudo python3 WiFi-Deauth.py <STA_MAC> <BSSID> --frame disassoc
sudo python3 WiFi-Deauth.py <STA_MAC> <BSSID> --frame both

# Reverse direction (STA → AP) when the other direction is ignored
sudo python3 WiFi-Deauth.py <STA_MAC> <BSSID> --sta-to-ap

# Inspect frames without transmitting (no root needed)
python3 WiFi-Deauth.py <STA_MAC> <BSSID> --dry-run

# Interfaces Scapy can see
python3 WiFi-Deauth.py --list-ifaces
```

BSSID can also be passed as **`-b` / `--bssid`** when that’s clearer than positionals. Full options: **`python3 WiFi-Deauth.py --help`**.

#### Limitations

- Does not set **channel** or put the card in **monitor mode** for you.  
- **802.11w**, driver behavior, and distance all affect whether frames have any impact.  
- Use only where you are **legally and ethically** allowed to do so.


