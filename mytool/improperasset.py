import json
import requests
import random
import sys
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin

class APITester:
    def __init__(self, openapi_file):
        self.spec = self._load_spec(openapi_file)
        self.base_url = self._get_base_url()
        self.endpoints = self._parse_endpoints()
        self.results = []
    
    def _load_spec(self, file_path):
        with open(file_path) as f:
            spec = json.load(f)
        return spec.get('content', spec)

    def _get_base_url(self):
        servers = self.spec.get('servers', [{}])
        return servers[0].get('url', '').rstrip('/')

    def _parse_endpoints(self):
        endpoints = []
        for path, methods in self.spec.get('paths', {}).items():
            for method, details in methods.items():
                if method.lower() not in ['post', 'put', 'patch']:
                    continue
                
                endpoint = {
                    'url': urljoin(self.base_url, path),
                    'method': method.upper(),
                    'schema': self._get_request_schema(details)
                }
                endpoints.append(endpoint)
        return endpoints

    def _get_request_schema(self, details):
        try:
            return details['requestBody']['content']['application/json']['schema']
        except KeyError:
            return None

    def _generate_request_body(self, schema):
        """Generate valid request body based on schema"""
        if '$ref' in schema:
            schema = self._resolve_reference(schema['$ref'])
            
        body = {}
        required = schema.get('required', [])
        properties = schema.get('properties', {})
        
        for prop, config in properties.items():
            # Use example if available
            if 'example' in config:
                body[prop] = config['example']
                continue
                
            # Generate dummy data based on type
            prop_type = config.get('type', 'string')
            if prop_type == 'string':
                body[prop] = f"test_{prop}_{random.randint(1000,9999)}"
            elif prop_type == 'integer':
                body[prop] = random.randint(1,100)
            elif prop_type == 'boolean':
                body[prop] = True
            elif prop_type == 'number':
                body[prop] = round(random.uniform(1.0, 100.0), 2)
            # Add more types as needed
        
        # Ensure required fields are present
        for req in required:
            if req not in body:
                body[req] = "REQUIRED_FIELD_MISSING"
                
        return body

    def _resolve_reference(self, ref):
        """Resolve $ref pointers"""
        parts = ref.split('/')[2:]  # Skip '#/components/schemas'
        component = self.spec['components']
        for part in parts:
            component = component[part]
        return component

    def _test_endpoint(self, endpoint):
        """Test an endpoint with generated request body"""
        try:
            if not endpoint['schema']:
                return  # Skip endpoints without request schema
                
            payload = self._generate_request_body(endpoint['schema'])
            response = requests.request(
                method=endpoint['method'],
                url=endpoint['url'],
                json=payload,
                timeout=10
            )
            
            self.results.append({
                'endpoint': endpoint['url'],
                'method': endpoint['method'],
                'payload': payload,
                'status': response.status_code,
                'response': response.text[:500]  # Truncate long responses
            })
            
        except Exception as e:
            self.results.append({
                'endpoint': endpoint['url'],
                'error': str(e)
            })

    def run_tests(self, max_workers=5):
        """Run tests with concurrency"""
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self._test_endpoint, ep) 
                      for ep in self.endpoints]
            for future in futures:
                future.result()

    def print_results(self):
        """Display test results"""
        for result in self.results:
            print(f"\n{result['method']} {result['endpoint']}")
            if 'error' in result:
                print(f"  🔴 Error: {result['error']}")
                continue
                
            print(f"  Payload: {json.dumps(result['payload'], indent=2)}")
            print(f"  Status: {result['status']}")
            print(f"  Response: {result.get('response', '')}")

# Usage
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python improperasset.py <openapi_file>")
        sys.exit(1)
    
    tester = APITester(sys.argv[1])
    tester.run_tests()
    tester.print_results()