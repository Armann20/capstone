#!/usr/bin/env python3
import sys
import json
import argparse
import re
import random
import string
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import requests

# Configure threading lock for safe printing
print_lock = threading.Lock()

# Constants
METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
MAX_WORKERS = 10
TIMEOUT = 5
BASE_HEADERS = {'Content-Type': 'application/json'}
TEST_DATA_TEMPLATES = {
    'products': {'name': 'Test Product', 'price': 19.99, 'image_url': 'https://example.com/product.jpg'},
    'orders': {'items': [{'product_id': 1, 'quantity': 2}], 'total': 39.98},
    'users': {'username': 'testuser', 'email': 'user@example.com', 'password': 'SecurePass123!'}
}

def load_documented_endpoints(spec):
    """Load and parse documented endpoints from OpenAPI spec"""
    core = spec.get('content', spec)
    documented = {}
    for path in core.get('paths', {}):
        methods = [m.upper() for m in core['paths'][path] if m.upper() in METHODS]
        documented[path] = methods
    return documented

def generate_random_value(field_name):
    """Generate context-aware random values based on field name patterns"""
    field_lower = field_name.lower()
    generators = {
        'email': lambda: f"{''.join(random.choices(string.ascii_lowercase, k=8))}@example.com",
        'name': lambda: ''.join(random.choices(string.ascii_letters, k=10)),
        'price': lambda: round(random.uniform(1, 1000), 2),
        'url': lambda: f"https://example.com/{''.join(random.choices(string.ascii_lowercase, k=8))}",
        'id': lambda: random.randint(1000, 9999),
        'description': lambda: ''.join(random.choices(string.ascii_letters + ' ', k=20)),
    }
    for pattern, fn in generators.items():
        if pattern in field_lower:
            return fn()
    return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

def get_template_data(url):
    """Get appropriate test data based on endpoint pattern"""
    path = urlparse(url).path.lower()
    for pattern in TEST_DATA_TEMPLATES:
        if pattern in path:
            return TEST_DATA_TEMPLATES[pattern].copy()
    return {'test': 'data'}

def handle_validation_errors(url, method, headers, response):
    """Handle validation errors by generating compliant payloads"""
    try:
        errors = response.json()
        payload = get_template_data(url)
        
        # Enhance payload with required fields
        for field in errors.keys():
            if field not in payload:
                payload[field] = generate_random_value(field)
        
        # Retry with valid payload
        retry_response = requests.request(
            method, url,
            headers=headers,
            json=payload,
            timeout=TIMEOUT,
            allow_redirects=False
        )
        
        return retry_response, payload
    except Exception as e:
        return response, None

def test_endpoint(url, method, spec, documented, debug, headers):
    """Test endpoint with full response logging and Allow header handling"""
    results = []
    try:
        path = urlparse(url).path.rstrip('/')
        
        with print_lock:
            print(f"\n{'='*50}")
            print(f"Testing: {method} {url}")

        # Initial request
        json_data = get_template_data(url) if method in ['POST', 'PUT', 'PATCH'] else None
        response = requests.request(
            method, url,
            headers=headers,
            json=json_data,
            timeout=TIMEOUT,
            allow_redirects=False
        )

        # Print full response details
        with print_lock:
            print(f"\nInitial Response:")
            print(f"Status Code: {response.status_code}")
            print(f"Headers: {json.dumps(dict(response.headers), indent=2)}")
            print(f"Body:\n{response.text}")
            
            if json_data:
                print(f"\nSent Payload:")
                print(json.dumps(json_data, indent=2))

        # Handle validation errors
        retry_payload = None
        if response.status_code == 400:
            response, retry_payload = handle_validation_errors(url, method, headers, response)
            with print_lock:
                if retry_payload:
                    print(f"\nRetry Response:")
                    print(f"Status Code: {response.status_code}")
                    print(f"Headers: {json.dumps(dict(response.headers), indent=2)}")
                    print(f"Body:\n{response.text}")
                    print(f"\nRetry Payload:")
                    print(json.dumps(retry_payload, indent=2))

        # Process Allow header for 405 responses
        allowed_methods = []
        if response.status_code == 405 and 'Allow' in response.headers:
            allowed_methods = [m.upper() for m in response.headers['Allow'].split(', ')]
            with print_lock:
                print(f"\nDiscovered Allowed Methods: {', '.join(allowed_methods)}")

        # Detection logic
        is_valid_endpoint = (
            response.status_code in [200, 201, 400] or 
            response.status_code >= 500
        )
        
        # Find matching spec path
        spec_path = None
        for path_template in documented:
            pattern = re.sub(r'\{[^}]+\}', '[^/]+', path_template).rstrip('/')
            if re.match(f'^{pattern}$', path):
                spec_path = path_template
                break

        # Add result for current method
        if is_valid_endpoint and spec_path:
            if method not in documented.get(spec_path, []):
                results.append({
                    'method': method,
                    'path': spec_path,
                    'status': response.status_code,
                    'request_payload': json_data,
                    'response_body': response.text,
                    'retry_payload': retry_payload
                })

        # Add results for allowed methods from header
        if spec_path and allowed_methods:
            for allowed_method in allowed_methods:
                if allowed_method in METHODS and allowed_method not in documented.get(spec_path, []):
                    results.append({
                        'method': allowed_method,
                        'path': spec_path,
                        'status': 200,  # Assume valid until proven otherwise
                        'allowed_header': True,
                        'response_body': f"Method allowed according to 'Allow' header (originally discovered via {method} request)"
                    })

        return results

    except requests.RequestException as e:
        with print_lock:
            print(f"\nRequest failed: {str(e)}")
        return []

def update_openapi(spec, findings):
    """Update OpenAPI spec with discovered endpoints and allowed methods"""
    core = spec.get('content', spec)
    for finding in findings:
        path = finding['path']
        method = finding['method'].lower()
        
        if path not in core['paths']:
            core['paths'][path] = {}
        
        if method not in core['paths'][path]:
            endpoint_def = {
                'x-discovered': True,
                'responses': {}
            }

            if finding.get('allowed_header'):
                endpoint_def['responses']['default'] = {
                    "description": "Method allowed according to 'Allow' header",
                    "content": {
                        "text/plain": {
                            "example": finding['response_body']
                        }
                    }
                }
            else:
                endpoint_def['responses'][str(finding['status'])] = {
                    "description": "Automatically discovered endpoint",
                    "content": {
                        "text/plain": {
                            "example": finding.get('response_body', '')
                        }
                    }
                }

            if finding.get('retry_payload'):
                endpoint_def['requestBody'] = {
                    'content': {
                        'application/json': {
                            'schema': {
                                'type': 'object',
                                'properties': {
                                    field: {'type': 'string' if isinstance(val, str) else 'number' if isinstance(val, (int, float)) else 'boolean'}
                                    for field, val in finding['retry_payload'].items()
                                },
                                'required': list(finding['retry_payload'].keys())
                            }
                        }
                    }
                }

            core['paths'][path][method] = endpoint_def
    return spec

def main():
    parser = argparse.ArgumentParser(description='🔍 API Endpoint Discovery Tool')
    parser.add_argument('host', help='Base URL of the API')
    parser.add_argument('spec', help='Path to OpenAPI spec file')
    parser.add_argument('--jwt', help='JWT authentication token')
    parser.add_argument('--debug', action='store_true', help='Enable verbose debugging')
    args = parser.parse_args()

    # Load OpenAPI spec
    with open(args.spec, 'r') as f:
        spec = json.load(f)

    # Configure headers
    headers = BASE_HEADERS.copy()
    if args.jwt:
        headers['Authorization'] = f'Bearer {args.jwt}'

    # Generate test URLs
    base_url = args.host.rstrip('/')
    core = spec.get('content', spec)
    urls = [
        f"{base_url}/{re.sub(r'\{[^}]+\}', '1', path).lstrip('/')}"
        for path in core.get('paths', {})
    ]

    # Execute tests
    findings = []
    with ThreadPoolExecutor(MAX_WORKERS) as executor:
        futures = [
            executor.submit(test_endpoint, url, method, spec, load_documented_endpoints(spec), args.debug, headers)
            for url in urls
            for method in METHODS
        ]
        
        for future in as_completed(futures):
            results = future.result()
            if results:
                findings.extend(results)

    # Update spec and save results
    if findings:
        updated_spec = update_openapi(spec, findings)
        with open(args.spec, 'w') as f:
            json.dump(updated_spec, f, indent=2)
        print(f"\n🎉 Successfully added {len(findings)} new endpoints to {args.spec}")
    else:
        print("\n🔎 No new endpoints discovered")

if __name__ == '__main__':
    main()