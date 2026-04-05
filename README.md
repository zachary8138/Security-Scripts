# Security-Scripts
A collection of scripts I've used for pentesting, security checks, and various other infosec related tasks.  

#### advanced_sqli_scanner.py

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

#### HTTP Security Header Checker.pl 

Provides a quick way to scan a website to check if it implements recommended security headers such as HSTS, CSP, and X-Frame-Options. This helps identify potential misconfigurations that could expose the site to attacks like clickjacking, XSS, or protocol downgrade attacks.
```perl Secure_header_check.pl -u https://example.com```

Use the --json option to automate checks in a CI/CD workflow. For example, fail a deployment if critical security headers are missing.

```perl Secure_header_check.pl -u https://staging.example.com --json > header_report.json```

Combine the script with a list of URLs to audit multiple sites at once, useful for agencies, pentesters, or security teams managing multiple clients:

```cat domains.txt | xargs -I {} perl Secure_header_check.pl -u {} --json```

Enable verbose mode to see all headers, including non-critical ones, which is helpful during debugging or fine-tuning a site’s security headers:

```perl Secure_header_check.pl -u https://example.com -v```
