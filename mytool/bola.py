#!/usr/bin/env python3
import json
import requests
import random
import string
from urllib.parse import urljoin
from termcolor import colored
import argparse
import concurrent.futures

class BOLATester:
    def __init__(self, openapi_file, base_url, auth_tokens=None):
        self.base_url = base_url
        self.auth_tokens = auth_tokens or {}
        self.endpoints = []
        self.vulnerabilities = []
        
        with open(openapi_file, 'r') as f:
            self.openapi = json.load(f)
            
        self._parse_endpoints()
        
    def _parse_endpoints(self):
        """Extract endpoints with potential ID parameters from OpenAPI spec"""
        for path, methods in self.openapi.get('paths', {}).items():
            for method, spec in methods.items():
                parameters = spec.get('parameters', [])
                id_params = [p for p in parameters if 'id' in p['name'].lower()]
                
                if id_params:
                    self.endpoints.append({
                        'path': path,
                        'method': method.upper(),
                        'parameters': id_params,
                        'security': spec.get('security', [])
                    })

    def _generate_ids(self):
        """Generate test IDs for different scenarios"""
        return {
            'same_id_different_case': '1001'.swapcase(),
            'numeric_id': 1002,
            'string_id': '1003a',
            'uuid': '00000000-0000-0000-0000-000000000000',
            'sql_injection': "1004' OR '1'='1",
            'non_existent_id': ''.join(random.choices(string.ascii_letters + string.digits, k=8)),
            'previous_id': 1000,
            'next_id': 1005
        }

    def _make_request(self, method, url, auth_type='user', params=None, json_data=None):
        """Send HTTP request with appropriate authentication"""
        headers = {}
        if auth_type in self.auth_tokens:
            headers['Authorization'] = f'Bearer {self.auth_tokens[auth_type]}'
            
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=json_data,
                timeout=10
            )
            return response
        except requests.exceptions.RequestException as e:
            print(colored(f"Request failed: {e}", 'red'))
            return None

    def _test_id_manipulation(self, endpoint):
        """Test different ID manipulation techniques"""
        test_ids = self._generate_ids()
        original_id = 1001  # Base ID for testing
        
        for test_name, test_id in test_ids.items():
            test_path = endpoint['path'].replace('{id}', str(test_id))
            url = urljoin(self.base_url, test_path)
            
            # Test with different authentication levels
            for auth_type in ['user', 'admin', 'none']:
                response = self._make_request(
                    method=endpoint['method'],
                    url=url,
                    auth_type=auth_type
                )
                
                if response and response.status_code == 200:
                    self.vulnerabilities.append({
                        'type': 'ID Manipulation',
                        'endpoint': endpoint['path'],
                        'method': endpoint['method'],
                        'test_case': test_name,
                        'auth_type': auth_type,
                        'status_code': response.status_code,
                        'response_length': len(response.content)
                    })

    def _test_parameter_injection(self, endpoint):
        """Test different parameter injection points"""
        params = {
            'id': 1001,
            'user_id': 1001,
            'document_id': 1001,
            'account_id': 1001
        }
        
        # Test different parameter locations
        for param_location in ['path', 'query', 'body']:
            test_params = None
            test_json = None
            
            if param_location == 'path':
                url = urljoin(self.base_url, endpoint['path'].replace('{id}', '1001'))
            elif param_location == 'query':
                url = urljoin(self.base_url, endpoint['path'].replace('{id}', '1001'))
                test_params = params
            else:
                url = urljoin(self.base_url, endpoint['path'].replace('{id}', '1001'))
                test_json = params
                
            response = self._make_request(
                method=endpoint['method'],
                url=url,
                auth_type='user',
                params=test_params,
                json_data=test_json
            )
            
            if response and response.status_code == 200:
                self.vulnerabilities.append({
                    'type': 'Parameter Injection',
                    'endpoint': endpoint['path'],
                    'method': endpoint['method'],
                    'param_location': param_location,
                    'status_code': response.status_code,
                    'response_length': len(response.content)
                })

    def _test_response_differentiation(self, endpoint):
        """Check if responses differ between authorized and unauthorized requests"""
        base_url = urljoin(self.base_url, endpoint['path'].replace('{id}', '1001'))
        
        # Get authorized response
        auth_response = self._make_request(
            method=endpoint['method'],
            url=base_url,
            auth_type='user'
        )
        
        # Get unauthorized response
        unauth_response = self._make_request(
            method=endpoint['method'],
            url=base_url,
            auth_type='none'
        )
        
        if auth_response and unauth_response:
            if auth_response.status_code == unauth_response.status_code:
                if auth_response.content == unauth_response.content:
                    self.vulnerabilities.append({
                        'type': 'Response Differentiation',
                        'endpoint': endpoint['path'],
                        'method': endpoint['method'],
                        'issue': 'Identical responses for authenticated and unauthenticated requests'
                    })

    def _test_batch_requests(self, endpoint):
        """Test batch ID processing vulnerabilities"""
        batch_url = urljoin(self.base_url, endpoint['path'].replace('{id}', 'batch'))
        batch_ids = [1001, 1002, 1003, 1004]
        
        response = self._make_request(
            method=endpoint['method'],
            url=batch_url,
            auth_type='user',
            json_data={'ids': batch_ids}
        )
        
        if response and response.status_code == 200:
            try:
                data = response.json()
                if isinstance(data, list) and len(data) == len(batch_ids):
                    self.vulnerabilities.append({
                        'type': 'Batch Processing',
                        'endpoint': endpoint['path'],
                        'method': endpoint['method'],
                        'issue': 'Successful batch access without proper authorization'
                    })
            except json.JSONDecodeError:
                pass

    def test_endpoint(self, endpoint):
        """Run all BOLA tests for a single endpoint"""
        self._test_id_manipulation(endpoint)
        self._test_parameter_injection(endpoint)
        self._test_response_differentiation(endpoint)
        self._test_batch_requests(endpoint)

    def run_tests(self, max_workers=5):
        """Run tests with concurrent execution"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self.test_endpoint, endpoint) for endpoint in self.endpoints]
            concurrent.futures.wait(futures)

    def print_report(self):
        """Generate colored vulnerability report"""
        print(colored("\n=== BOLA Vulnerability Report ===", 'cyan', attrs=['bold']))
        
        if not self.vulnerabilities:
            print(colored("\nNo BOLA vulnerabilities found", 'green'))
            return
            
        for vuln in self.vulnerabilities:
            print(colored(f"\n[!] {vuln['type']} Vulnerability", 'red'))
            print(f"Endpoint: {vuln['endpoint']}")
            print(f"Method: {vuln['method']}")
            
            if 'test_case' in vuln:
                print(f"Test Case: {vuln['test_case']}")
            if 'param_location' in vuln:
                print(f"Parameter Location: {vuln['param_location']}")
            if 'auth_type' in vuln:
                print(f"Authentication Used: {vuln['auth_type'].upper()}")
                
            print(f"Status Code: {vuln['status_code']}")
            print(f"Response Length: {vuln['response_length']} bytes")
            
            if 'issue' in vuln:
                print(colored(f"Issue: {vuln['issue']}", 'yellow'))
            
            print(colored("-" * 50, 'white'))

def main():
    parser = argparse.ArgumentParser(description="BOLA Vulnerability Tester")
    parser.add_argument("openapi_file", help="Path to OpenAPI specification JSON file")
    parser.add_argument("base_url", help="Base URL of the target API")
    parser.add_argument("--auth-token", help="Authentication token (Bearer format)")
    parser.add_argument("--admin-token", help="Admin authentication token")
    parser.add_argument("--workers", type=int, default=5, 
                      help="Number of concurrent workers")
    
    args = parser.parse_args()
    
    auth_tokens = {}
    if args.auth_token:
        auth_tokens['user'] = args.auth_token
    if args.admin_token:
        auth_tokens['admin'] = args.admin_token
    
    tester = BOLATester(
        openapi_file=args.openapi_file,
        base_url=args.base_url,
        auth_tokens=auth_tokens
    )
    
    print(colored("[*] Starting BOLA tests...", 'yellow'))
    tester.run_tests(max_workers=args.workers)
    tester.print_report()

if __name__ == "__main__":
    main()
