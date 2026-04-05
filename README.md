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

