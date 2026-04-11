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

## WiFi-Deauth.py

Small 802.11 deauthentication/disassociation helper built with Scapy.  It injects frames from a wireless interface in monitor mode (requires root).
Make sure you're using your own lab hardware or obtain written permission before using.  Unauthorized use is not legal in all jurisdictions.

#### When it’s useful

  **Wireless security assessments** — Check whether clients drop or reconnect when management frames are spoofed, and how the environment behaves under stress.
  **802.11w / PMF awareness** — If clients and APs use **protected management frames**, deauth/disassoc may have **no effect**; the script helps you observe that in practice (not detect it automatically).
  **Roam / resilience testing** — See how devices and apps behave when the link is torn down and re-established.
  **Tooling and lab workflows** — Pair with channel setup (`iw`, `airmon-ng`, etc.), captures, and your own notes; use **`--dry-run`** to verify frame layout before transmitting.

#### Requirements

  Python 3  
  [Scapy](https://scapy.net/)  
  A Wi-Fi adapter that supports **monitor mode** and **injection**  
  Interface on the **same channel** as the target BSS (configure outside the script)

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

  Does not set **channel** or put the card in **monitor mode** for you.  
  **802.11w**, driver behavior, and distance all affect whether frames have any impact.  
  Use only where you are **legally and ethically** allowed to do so.

## net_probe.py

#### Features

Host Discovery: Performs a ping scan (-sn) to identify live hosts on a specified network range.

TCP Port Scanning: Scans a user-defined set of TCP ports (default set includes common ports like SSH, HTTP, FTP, and more).

Customizable: You can specify the range of ports to scan and the timing template for the scan (to balance between speed and accuracy).

Flexible Output Formats: Outputs results in either human-readable text format or structured JSON format.

File Output: Optionally, save the results to a file (supports both text and JSON formats).

#### Prerequisites
nmap: The tool requires nmap to be installed on your system. It must be available on the system’s PATH.

Installation on Linux: ```sudo apt-get install nmap```

Installation on macOS: ```brew install nmap```

Installation on Windows: https://nmap.org/download.html

python-nmap: A Python library to interface with nmap.

Install via pip: ```pip install python-nmap```

#### Usage
This script can be run from the command line and requires at least the network range to be specified. Optionally, you can specify custom ports, timing, output format, and output file.

## Basic Command
``` python network_probe.py <network_range> ```

## Example:
``` python network_probe.py 192.168.1.0/24 ```

This will scan the entire 192.168.1.0/24 network for live hosts and report their open ports using the default list of ports.

## Optional Arguments:
 -p, --ports: Specify a comma-separated list or range of ports to scan (e.g., 22,80,443 or 1-1024).

## Example:
```python network_probe.py 192.168.1.0/24 -p 22,80,443```
Choose a timing template from 0 to 5, where 0 is the slowest and 5 is the fastest. Default is 3.

## Example:
```python network_probe.py 192.168.1.0/24 -T 4```
```python network_probe.py 192.168.1.0/24 -f json```
```python network_probe.py 192.168.1.0/24 -o output.json```
```python network_probe.py 192.168.1.0/24 -o output.json```
```python network_probe.py 192.168.1.0/24 -q```

## Full Command Example
```python network_probe.py 192.168.1.0/24 -p 22,80,443 -T 4 -f json -o scan_results.json```

## Troubleshooting

nmap not found: Ensure that nmap is installed and available in your system's PATH. You can verify this by running nmap --version in your terminal.

Permission Issues: Ensure you have the necessary permissions to execute nmap and access network interfaces.

Install python-nmap: If the script reports missing python-nmap, you can install it via pip: ```pip install python-nmap```




 


