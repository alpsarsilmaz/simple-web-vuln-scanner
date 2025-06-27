import requests
import urllib.parse
import re
import time
import argparse
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import threading
from concurrent.futures import ThreadPoolExecutor
import json

class VulnerabilityScanner:
    def __init__(self, target_url, timeout=10, threads=5):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnScanner/1.0 (Educational Purpose)'
        })
        self.vulnerabilities = []
        self.crawled_urls = set()
        
    def log_vulnerability(self, vuln_type, url, description, severity="Medium"):
        """Log discovered vulnerability"""
        vulnerability = {
            'type': vuln_type,
            'url': url,
            'description': description,
            'severity': severity,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        self.vulnerabilities.append(vulnerability)
        print(f"[{severity.upper()}] {vuln_type}: {description}")
        print(f"URL: {url}\n")

    def safe_request(self, url, method='GET', data=None, params=None):
        """Make a safe HTTP request with error handling"""
        try:
            if method.upper() == 'POST':
                response = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True)
            else:
                response = self.session.get(url, params=params, timeout=self.timeout, allow_redirects=True)
            return response
        except requests.exceptions.RequestException as e:
            print(f"Request failed for {url}: {str(e)}")
            return None

    def crawl_links(self, base_url, max_depth=2, current_depth=0):
        """Simple web crawler to discover pages"""
        if current_depth >= max_depth or base_url in self.crawled_urls:
            return []
        
        self.crawled_urls.add(base_url)
        links = []
        
        response = self.safe_request(base_url)
        if not response:
            return links
            
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(base_url, href)
                
                if urlparse(full_url).netloc == urlparse(self.target_url).netloc:
                    links.append(full_url)
                    
        except Exception as e:
            print(f"Error parsing HTML from {base_url}: {str(e)}")
            
        return links

    def check_sql_injection(self, url):
        """Test for SQL injection vulnerabilities"""
        print(f"Testing SQL injection on: {url}")
        
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1' OR '1'='1' --",
            "admin'--",
            "' OR 'x'='x",
        ]
        
        parsed_url = urlparse(url)
        if parsed_url.query:
            for payload in payloads:
                params = urllib.parse.parse_qs(parsed_url.query)
                for param in params:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    
                    response = self.safe_request(url, params=test_params)
                    if response and self._detect_sql_error(response.text):
                        self.log_vulnerability(
                            "SQL Injection",
                            f"{url}?{param}={payload}",
                            f"Possible SQL injection in parameter '{param}'",
                            "High"
                        )

    def _detect_sql_error(self, response_text):
        """Detect SQL error messages in response"""
        sql_errors = [
            "mysql_fetch_array()",
            "ORA-[0-9]+",
            "Microsoft OLE DB Provider",
            "SQLServer JDBC Driver",
            "PostgreSQL query failed",
            "Warning: mysql_",
            "MySQLSyntaxErrorException",
            "valid MySQL result",
            "check the manual that corresponds to your MySQL",
            "Unknown column",
            "SQL syntax.*MySQL",
            "Warning.*mysql_.*",
        ]
        
        for error in sql_errors:
            if re.search(error, response_text, re.IGNORECASE):
                return True
        return False

    def check_xss(self, url):
        """Test for Cross-Site Scripting (XSS) vulnerabilities"""
        print(f"Testing XSS on: {url}")
        
        payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "<svg onload=alert('XSS')>",
        ]
        
        parsed_url = urlparse(url)
        if parsed_url.query:
            for payload in payloads:
                params = urllib.parse.parse_qs(parsed_url.query)
                for param in params:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    
                    response = self.safe_request(url, params=test_params)
                    if response and payload.lower() in response.text.lower():
                        self.log_vulnerability(
                            "Cross-Site Scripting (XSS)",
                            f"{url}?{param}={payload}",
                            f"Possible XSS vulnerability in parameter '{param}'",
                            "High"
                        )

    def check_directory_traversal(self, url):
        """Test for directory traversal vulnerabilities"""
        print(f"Testing directory traversal on: {url}")
        
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
        ]
        
        parsed_url = urlparse(url)
        if parsed_url.query:
            for payload in payloads:
                params = urllib.parse.parse_qs(parsed_url.query)
                for param in params:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    
                    response = self.safe_request(url, params=test_params)
                    if response and self._detect_directory_traversal(response.text):
                        self.log_vulnerability(
                            "Directory Traversal",
                            f"{url}?{param}={payload}",
                            f"Possible directory traversal in parameter '{param}'",
                            "Medium"
                        )

    def _detect_directory_traversal(self, response_text):
        """Detect directory traversal indicators"""
        indicators = [
            "root:x:",
            "[boot loader]",
            "# This file controls the state of SELinux",
            "daemon:x:",
            "bin:x:",
        ]
        
        for indicator in indicators:
            if indicator in response_text:
                return True
        return False

    def check_security_headers(self, url):
        """Check for missing security headers"""
        print(f"Checking security headers for: {url}")
        
        response = self.safe_request(url)
        if not response:
            return
            
        headers = response.headers
        
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-XSS-Protection': 'XSS protection header missing',
            'X-Content-Type-Options': 'MIME type sniffing prevention missing',
            'Strict-Transport-Security': 'HTTPS enforcement missing',
            'Content-Security-Policy': 'Content Security Policy missing',
            'Referrer-Policy': 'Referrer policy not set'
        }
        
        for header, description in security_headers.items():
            if header not in headers:
                self.log_vulnerability(
                    "Missing Security Header",
                    url,
                    f"{description}: {header}",
                    "Low"
                )

    def check_information_disclosure(self, url):
        """Check for information disclosure"""
        print(f"Checking information disclosure for: {url}")
        
        sensitive_paths = [
            "/robots.txt",
            "/.git/config",
            "/backup.sql",
            "/config.php.bak",
            "/web.config",
            "/.env",
            "/phpinfo.php",
            "/admin",
            "/dashboard",
        ]
        
        for path in sensitive_paths:
            test_url = self.target_url + path
            response = self.safe_request(test_url)
            
            if response and response.status_code == 200:
                if self._is_sensitive_content(response.text, path):
                    self.log_vulnerability(
                        "Information Disclosure",
                        test_url,
                        f"Sensitive file accessible: {path}",
                        "Medium"
                    )

    def _is_sensitive_content(self, content, path):
        """Check if content contains sensitive information"""
        sensitive_patterns = {
            '/robots.txt': ['Disallow:', 'User-agent:'],
            '/.git/config': ['[core]', 'repositoryformatversion'],
            '/.env': ['DB_PASSWORD', 'API_KEY', 'SECRET'],
            '/phpinfo.php': ['PHP Version', 'System'],
        }
        
        if path in sensitive_patterns:
            return any(pattern in content for pattern in sensitive_patterns[path])
        
        return len(content) > 100 

    def scan_target(self):
        """Main scanning function"""
        print(f"Starting vulnerability scan for: {self.target_url}")
        print("=" * 50)

        print("Crawling website...")
        urls_to_scan = [self.target_url]
        discovered_urls = self.crawl_links(self.target_url)
        urls_to_scan.extend(discovered_urls[:10]) 
        
        print(f"Found {len(urls_to_scan)} URLs to scan")
        print("-" * 30)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for url in urls_to_scan:
                executor.submit(self.check_sql_injection, url)
                executor.submit(self.check_xss, url)
                executor.submit(self.check_directory_traversal, url)
                executor.submit(self.check_security_headers, self.target_url)
                executor.submit(self.check_information_disclosure, self.target_url)

    def generate_report(self, output_file=None):
        """Generate vulnerability report"""
        print("\n" + "=" * 50)
        print("VULNERABILITY SCAN REPORT")
        print("=" * 50)
        
        if not self.vulnerabilities:
            print("No vulnerabilities found!")
            return

        severity_count = {"High": 0, "Medium": 0, "Low": 0}
        
        for vuln in self.vulnerabilities:
            severity_count[vuln['severity']] += 1
            
        print(f"Total vulnerabilities found: {len(self.vulnerabilities)}")
        print(f"High: {severity_count['High']}, Medium: {severity_count['Medium']}, Low: {severity_count['Low']}")
        print("-" * 30)

        vuln_types = {}
        for vuln in self.vulnerabilities:
            if vuln['type'] not in vuln_types:
                vuln_types[vuln['type']] = []
            vuln_types[vuln['type']].append(vuln)
            
        for vuln_type, vulns in vuln_types.items():
            print(f"\n{vuln_type.upper()} ({len(vulns)} found):")
            for vuln in vulns:
                print(f"  [{vuln['severity']}] {vuln['description']}")
                print(f"  URL: {vuln['url']}")
                print()
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(self.vulnerabilities, f, indent=2)
            print(f"Detailed report saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Simple Vulnerability Scanner for Educational Purposes')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads to use')
    parser.add_argument('--output', help='Output file for detailed report (JSON format)')
    
    args = parser.parse_args()
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'http://' + args.url
        
    print("Simple Vulnerability Scanner v1.0")
    print("Educational Tool - Use Responsibly!")
    print("Only scan websites you own or have permission to test")
    print()
    scanner = VulnerabilityScanner(args.url, args.timeout, args.threads)
    
    try:
        scanner.scan_target()
        scanner.generate_report(args.output)
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"Error during scanning: {str(e)}")

if __name__ == "__main__":
    main()