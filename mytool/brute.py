from typing import List, Dict
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
import requests

HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
SUFFIXES = ['', '.json', '.xml', '.yaml', '/v1', '/test']
BASE_URL = 'http://localhost:8888'

def get_existing_endpoints(spec: Dict) -> set:
    """Extract existing endpoints and methods from API spec dict"""
    endpoints = set()
    for path, methods in spec.get('paths', {}).items():
        for method in methods.keys():
            if method.upper() in HTTP_METHODS:
                endpoints.add((path, method.upper()))
    return endpoints

def generate_combinations(base_path: str, wordlist: List[str]) -> List[str]:
    """Generate path combinations with wordlist entries"""
    combinations = []
    base_parts = base_path.strip('/').split('/')
    
    for i in range(len(base_parts) + 1):
        for word in wordlist:
            new_parts = base_parts[:i] + [word] + base_parts[i:]
            combinations.append('/' + '/'.join(new_parts))
    
    for word in wordlist:
        combinations.append(f'/{word}{base_path}')
        combinations.append(f'{base_path}/{word}')
    
    return combinations

def bruteforce(spec_dict: Dict, wordlist: List[str], 
               delay: float = 0.1, timeout: float = 5, 
               headers: Dict = None, workers: int = 10, 
               verbose: bool = False) -> List[Dict]:
    """Perform brute-force attack against localhost:8888"""
    existing_endpoints = get_existing_endpoints(spec_dict)
    session = requests.Session()
    found_endpoints = []
    lock = threading.Lock()

    def test_endpoint(path: str, method: str):
        try:
            time.sleep(delay)
            url = urljoin(BASE_URL, path)  # Use hardcoded base URL
            
            request_headers = headers.copy() if headers else {}
            request_headers.update({
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
                'Accept': '*/*'
            })
            
            response = session.request(
                method=method,
                url=url,
                headers=request_headers,
                timeout=timeout,
                verify=False
            )
            
            if response.status_code not in [404, 405, 403, 401]:
                content_length = len(response.content)
                with lock:
                    found_endpoints.append({
                        'method': method,
                        'path': path,
                        'url': url,
                        'status_code': response.status_code,
                        'content_length': content_length
                    })
        except Exception as e:
            if verbose:
                print(f"Error testing {method} {url}: {str(e)}")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        # Test combinations of existing endpoints
        for base_path, method in existing_endpoints:
            for combo in generate_combinations(base_path, wordlist):
                for suffix in SUFFIXES:
                    full_path = f"{combo}{suffix}"
                    for m in HTTP_METHODS:
                        executor.submit(test_endpoint, full_path, m)

        # Test raw wordlist entries from api.txt
        for word in wordlist:
            for suffix in SUFFIXES:
                full_path = f"/{word}{suffix}"
                for m in HTTP_METHODS:
                    executor.submit(test_endpoint, full_path, m)

        # Test parameterized endpoints
        for base_path, method in existing_endpoints:
            if '{' in base_path:
                for word in wordlist:
                    test_path = base_path.replace('{id}', word).replace('{uuid}', word)
                    for m in HTTP_METHODS:
                        executor.submit(test_endpoint, test_path, m)

    return found_endpoints