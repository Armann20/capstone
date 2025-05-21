#!/usr/bin/env python3
import requests
import argparse
import json
import re
from termcolor import colored
from datetime import datetime
import hashlib
import os
import sys
from vulners import VulnersApi

class AdvancedHeaderTester:
    def __init__(self, target_url, proxy=None, auth_cookie=None, vulners_key=None):
        self.target_url = target_url
        self.proxy = {'http': proxy, 'https': proxy} if proxy else None
        self.auth_cookie = auth_cookie
        self.vulnerabilities = []
        self.session = requests.Session()
        self.vulners_api = VulnersApi(api_key=vulners_key) if vulners_key else None
        self.baseline_response = None
        self.security_headers = {
            'Content-Security-Policy': {'severity': 'High', 'description': 'Prevents XSS and injection attacks'},
            'Strict-Transport-Security': {'severity': 'High', 'description': 'Enforces HTTPS connections'},
            'X-Content-Type-Options': {'severity': 'Medium', 'description': 'Prevents MIME type sniffing'},
            'X-Frame-Options': {'severity': 'Medium', 'description': 'Prevents clickjacking attacks'},
            'Referrer-Policy': {'severity': 'Medium', 'description': 'Controls referrer information'},
            'Permissions-Policy': {'severity': 'Medium', 'description': 'Controls browser features'},
            'Cross-Origin-Embedder-Policy': {'severity': 'Low', 'description': 'Controls cross-origin embeddings'},
            'Cross-Origin-Opener-Policy': {'severity': 'Low', 'description': 'Prevents cross-origin window access'},
            'Cross-Origin-Resource-Policy': {'severity': 'Low', 'description': 'Controls cross-origin resource loads'}
        }

    def establish_baseline(self):
        """Establish baseline response for comparison"""
        try:
            self.baseline_response = self.session.get(
                self.target_url,
                proxies=self.proxy,
                cookies={'session': self.auth_cookie} if self.auth_cookie else None,
                timeout=15
            )
        except requests.exceptions.RequestException as e:
            print(colored(f"Baseline establishment failed: {e}", 'red'))
            sys.exit(1)

    def calculate_response_fingerprint(self, response):
        """Create unique fingerprint for response comparison"""
        fingerprint_data = {
            'status': response.status_code,
            'length': len(response.content),
            'headers': str(sorted(response.headers.items())),
            'body_hash': hashlib.sha256(response.content).hexdigest()[:16]
        }
        return json.dumps(fingerprint_data, sort_keys=True)

    def test_header_manipulation(self):
        """Advanced header manipulation tests with behavioral analysis"""
        header_tests = [
            # IP Spoofing
            ('X-Forwarded-For', ['127.0.0.1', '192.168.1.1', '10.0.0.1', '::1', 'invalid']),
            ('X-Real-IP', ['203.0.113.5', '::1', 'invalid']),
            ('Forwarded', 'for=192.0.2.60;proto=http;by=203.0.113.43'),
            
            # Cache Poisoning
            ('X-Forwarded-Host', ['evil.com', 'localhost']),
            ('Host', ['attacker.com', 'localhost:9999']),
            
            # Request Smuggling
            ('Transfer-Encoding', 'chunked'),
            ('Content-Length', '100'),
            
            # Protocol Manipulation
            ('X-Forwarded-Proto', ['https', 'ftp']),
            
            # CORS Exploitation
            ('Origin', ['https://evil.com', 'null', 'http://attacker.net']),
            ('Access-Control-Request-Method', 'PUT'),
            
            # CSRF Bypass
            ('X-Requested-With', 'XMLHttpRequest'),
            ('X-CSRF-Token', 'invalid'),
            
            # Clickjacking
            ('X-Frame-Options', 'ALLOW-FROM https://attacker.com'),
            
            # Open Redirect
            ('Referer', ['https://evil.com', 'http://attacker.net']),
            ('Location', '/redirect?url=https://evil.com'),
            
            # Web Cache Deception
            ('X-Original-URL', '/profile'),
            ('X-Rewrite-URL', '/account')
        ]

        for header, values in header_tests:
            if not isinstance(values, list):
                values = [values]
                
            for value in values:
                try:
                    headers = {header: value}
                    response = self.session.get(
                        self.target_url,
                        headers=headers,
                        proxies=self.proxy,
                        cookies={'session': self.auth_cookie} if self.auth_cookie else None,
                        timeout=15
                    )
                    
                    self.analyze_response(response, header, value)
                    self.check_cors_vulnerability(response)
                    self.check_cache_poisoning(response, header, value)
                    self.check_open_redirect(response)

                except requests.exceptions.RequestException as e:
                    print(colored(f"Header test failed for {header}: {e}", 'red'))

    def analyze_response(self, response, header, value):
        """Advanced response analysis with baseline comparison"""
        test_fingerprint = self.calculate_response_fingerprint(response)
        baseline_fingerprint = self.calculate_response_fingerprint(self.baseline_response)

        # Check for significant response differences
        if test_fingerprint != baseline_fingerprint:
            diff_score = self.calculate_diff_score(response, self.baseline_response)
            confidence = 'Medium' if diff_score > 30 else 'Low'
            
            self.vulnerabilities.append({
                'type': 'Header Manipulation',
                'severity': 'High',
                'confidence': confidence,
                'message': f'Behavioral change detected via {header}: {value}',
                'header': header,
                'value': value,
                'status_code': response.status_code,
                'response_diff': diff_score,
                'baseline': json.loads(baseline_fingerprint),
                'test_response': json.loads(test_fingerprint)
            })

    def calculate_diff_score(self, response_a, response_b):
        """Calculate percentage difference between two responses"""
        length_diff = abs(len(response_a.content) - len(response_b.content))
        content_diff = sum(a != b for a, b in zip(response_a.content, response_b.content))
        return (content_diff + length_diff) / (len(response_a.content) + 1) * 100

    def check_cors_vulnerability(self, response):
        """Advanced CORS vulnerability checks"""
        if 'Access-Control-Allow-Origin' in response.headers:
            acao = response.headers['Access-Control-Allow-Origin']
            acac = 'Access-Control-Allow-Credentials' in response.headers
            
            if acao == '*' and acac:
                self.vulnerabilities.append({
                    'type': 'CORS Misconfiguration',
                    'severity': 'Critical',
                    'message': 'Insecure CORS configuration with Allow-Credentials',
                    'headers': dict(response.headers)
                })

    def check_cache_poisoning(self, response, header, value):
        """Detect cache poisoning vulnerabilities"""
        if 'X-Cache' in response.headers and 'Hit' in response.headers['X-Cache']:
            self.vulnerabilities.append({
                'type': 'Cache Poisoning',
                'severity': 'High',
                'message': f'Potential cache poisoning via {header}',
                'header': header,
                'value': value
            })

    def check_open_redirect(self, response):
        """Detect open redirect vulnerabilities"""
        if 300 <= response.status_code < 400:
            location = response.headers.get('Location', '')
            if '//evil.com' in location or location.startswith('http://'):
                self.vulnerabilities.append({
                    'type': 'Open Redirect',
                    'severity': 'Medium',
                    'message': f'Potential open redirect to {location}',
                    'status_code': response.status_code,
                    'location': location
                })

    def analyze_server_header(self):
        """Advanced server header analysis with CVE lookup using updated Vulners API"""
        server_header = self.baseline_response.headers.get('Server', '')
        
        if server_header:
            # Always add server information to report
            self.vulnerabilities.append({
                'type': 'Server Information',
                'severity': 'Info',
                'message': f'Server header detected: {server_header}',
                'header_value': server_header
            })

            if self.vulners_api:
                # Extract server name and version for CVE checks
                match = re.match(r'([a-zA-Z-]+)/?([\d.]+)', server_header)
                if match:
                    server_name = match.group(1).lower()
                    version = match.group(2)

                    try:
                        results = self.vulners_api.audit_software(
                            software_name=server_name,
                            software_version=version
                        )
                        
                        vulnerabilities = results.get('vulnerabilities', [])
                        if vulnerabilities:
                            self.vulnerabilities.append({
                                'type': 'Vulnerable Server',
                                'severity': 'Critical',
                                'message': f'Found {len(vulnerabilities)} CVEs for {server_header}',
                                'server': server_name,
                                'version': version,
                                'cves': [{
                                    'id': vuln.get('id'),
                                    'cvss': vuln.get('cvss', {}).get('score'),
                                    'description': vuln.get('description')[:100] + '...' 
                                        if vuln.get('description') else ''
                                } for vuln in vulnerabilities[:5]]
                            })
                            
                    except Exception as e:
                        print(colored(f"Vulners API error: {str(e)[:200]}", 'yellow'))

    def generate_report(self):
        """Generate advanced security report"""
        report = [
            colored("\n=== Advanced Header Security Report ===", 'cyan', attrs=['bold']),
            f"Target URL: {self.target_url}",
            f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Baseline Fingerprint: {self.calculate_response_fingerprint(self.baseline_response)[:50]}...\n"
        ]

        if not self.vulnerabilities:
            report.append(colored("No vulnerabilities found!", 'green'))
            return '\n'.join(report)

        # Sort vulnerabilities by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        sorted_vulns = sorted(self.vulnerabilities, 
                            key=lambda x: severity_order.get(x['severity'], 5))

        for vuln in sorted_vulns:
            # Set appropriate color based on severity
            if vuln['severity'] == 'Critical':
                color = 'red'
            elif vuln['severity'] == 'High':
                color = 'magenta'
            elif vuln['severity'] == 'Info':
                color = 'blue'
            else:
                color = 'yellow'

            report.append(colored(
                f"\n[{vuln['severity']}] {vuln['type']} "
                f"(Confidence: {vuln.get('confidence', 'N/A')})", 
                color
            ))
            
            report.append(f"• Description: {vuln['message']}")
            
            if vuln['type'] == 'Server Information':
                report.append(f"• Server Header: {vuln['header_value']}")
                
            if 'header' in vuln:
                report.append(f"• Tested Header: {vuln['header']} = {vuln['value']}")
                
            if 'cves' in vuln:
                report.append("• Associated CVEs:")
                for cve in vuln['cves']:
                    report.append(f"  - {cve['id']} (CVSS: {cve['cvss']}): {cve['description']}")
                    
            if 'recommendation' in vuln:
                report.append(colored(f"• Recommendation: {vuln['recommendation']}", 'green'))
                
            report.append(colored("-" * 50, 'white'))

        return '\n'.join(report)

    def check_security_headers(self):
        """Detailed security header analysis"""
        missing_headers = []
        insecure_headers = []
        
        for header, meta in self.security_headers.items():
            header_value = self.baseline_response.headers.get(header, '')
            
            if not header_value:
                missing_headers.append(header)
                continue
                
            # Special checks for specific headers
            if header == 'Content-Security-Policy' and "'unsafe-inline'" in header_value:
                insecure_headers.append("CSP contains unsafe-inline")
            if header == 'Strict-Transport-Security' and 'max-age=0' in header_value:
                insecure_headers.append("HSTS disabled with max-age=0")
                
        if missing_headers:
            self.vulnerabilities.append({
                'type': 'Missing Security Headers',
                'severity': 'High',
                'message': f'Missing critical security headers: {", ".join(missing_headers)}',
                'recommendation': 'Implement missing headers based on security best practices'
            })
            
        if insecure_headers:
            self.vulnerabilities.append({
                'type': 'Insecure Header Configuration',
                'severity': 'Medium',
                'message': f'Insecure header configurations: {"; ".join(insecure_headers)}'
            })

    

def main():
    parser = argparse.ArgumentParser(description="Advanced Header Security Auditor")
    parser.add_argument("url", help="Target URL to test")
    parser.add_argument("--proxy", help="HTTP proxy to use")
    parser.add_argument("--cookie", help="Authentication session cookie")
    parser.add_argument("--vulners-key", 
                      help="Vulners.com API key (get from https://vulners.com)",
                      default=os.getenv('VULNERS_API_KEY'))
    
    args = parser.parse_args()

    if not args.vulners_key:
        print(colored("Warning: Running without Vulners API key - CVE checks disabled", 'yellow'))

    tester = AdvancedHeaderTester(
        args.url, 
        proxy=args.proxy,
        auth_cookie=args.cookie,
        vulners_key=args.vulners_key
    )
    
    print(colored("[*] Establishing baseline response...", 'yellow'))
    tester.establish_baseline()
    
    print(colored("[*] Testing header manipulation vulnerabilities...", 'yellow'))
    tester.test_header_manipulation()
    
    print(colored("[*] Analyzing server headers...", 'yellow'))
    tester.analyze_server_header()
    
    print(colored("[*] Checking security headers...", 'yellow'))
    tester.check_security_headers()
    
    print(tester.generate_report())

if __name__ == "__main__":
    main()