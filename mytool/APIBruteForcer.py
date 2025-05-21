import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
import requests
from collections import defaultdict

def find_api_endpoints(target_url, max_depth=2, custom_wordlist=None, max_threads=20,
                     methods=('GET', 'POST', 'HEAD'), headers=None, follow_redirects=False,
                     request_timeout=10, retries=2, rate_limit_delay=0.1, debug=True):

    session = requests.Session()
    results = []
    visited_paths = set()
    discovered = set()
    baseline = None

    HTML_PATTERNS = re.compile(
        r'<!DOCTYPE html|<html\b|</head>|<body\b|</html>|<script\b|react-root|div id="root"',
        re.IGNORECASE
    )
    JSON_PATTERNS = re.compile(r'^{|"[\w_]+":|\[.*\]$', re.DOTALL)

    final_headers = headers or {}
    final_headers.setdefault('User-Agent', 
        'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0')

    default_wordlist = [
        'api', 'v1', 'v2','v3', 'graphql', 'rest', 'auth', 
        'token', 'admin', 'users', 'health', 'swagger'
    ]

    def generate_variations(path):
        variations = set()
        base_path = path.strip('/')
        
        for ext in ['', '.json', '.xml']:
            variations.add(f"{base_path}{ext}")
            for param in ['', '?debug=true', '?format=json']:
                variations.add(f"{base_path}{ext}{param}")
        
        return variations

    def get_baseline():
        try:
            test_url = urljoin(target_url, '/invalid-path-1234/')
            resp = session.get(
                test_url,
                headers=final_headers,
                timeout=request_timeout,
                allow_redirects=follow_redirects
            )
            return {
                'status': resp.status_code,
                'content': resp.text,
                'is_html': bool(HTML_PATTERNS.search(resp.text)),
                'is_json': bool(JSON_PATTERNS.search(resp.text[:100]))
            }
        except Exception:
            return {'status': 0, 'content': '', 'is_html': False, 'is_json': False}

    def analyze_response(resp):
        """Determine if response is an API endpoint or HTML page"""
        content_type = resp.headers.get('Content-Type', '')
        content = resp.text

        # Check for API indicators
        is_json = 'application/json' in content_type or JSON_PATTERNS.match(content)
        is_xml = 'application/xml' in content_type or content.strip().startswith('<?xml')
        is_api_response = is_json or is_xml
        
        # Check for HTML indicators
        is_html = 'text/html' in content_type or bool(HTML_PATTERNS.search(content))
        
        # Compare with baseline
        similar_to_baseline = (
            resp.status_code == baseline['status'] and
            bool(HTML_PATTERNS.search(content)) == baseline['is_html'] and
            bool(JSON_PATTERNS.search(content)) == baseline['is_json']
        )

        return {
            'is_api': is_api_response and not similar_to_baseline,
            'is_html': is_html,
            'is_error_page': similar_to_baseline
        }

    def test_endpoint(method, url):
        for attempt in range(retries + 1):
            try:
                resp = session.request(
                    method=method,
                    url=url,
                    headers=final_headers,
                    timeout=request_timeout,
                    allow_redirects=follow_redirects
                )
                analysis = analyze_response(resp)
                
                if analysis['is_error_page']:
                    return None
                
                if resp.status_code == 200 and analysis['is_api']:
                    return {
                        'method': method,
                        'url': resp.url,
                        'status': resp.status_code,
                        'type': 'API',
                        'content_type': resp.headers.get('Content-Type'),
                        'length': len(resp.content)
                    }
                
                if resp.status_code in [401, 403, 405] and not analysis['is_html']:
                    return {
                        'method': method,
                        'url': resp.url,
                        'status': resp.status_code,
                        'type': 'Auth',
                        'content_type': resp.headers.get('Content-Type'),
                        'length': len(resp.content)
                    }

            except (requests.ConnectionError, requests.Timeout):
                if attempt < retries:
                    time.sleep(1)
                    continue
            except Exception:
                break
        return None

    try:
        baseline = get_baseline()
        session.headers.update(final_headers)
        wordlist = custom_wordlist or default_wordlist

        # BFS queue with path components
        queue = defaultdict(list)
        queue[0].append('')  # Start with root path
        visited_paths.add('')

        for current_depth in range(max_depth + 1):
            current_paths = queue[current_depth]
            if not current_paths:
                if debug:
                    print(f"Depth {current_depth}: No paths to process")
                continue

            if debug:
                print(f"\n[+] Processing depth {current_depth} with {len(current_paths)} base paths")

            # Generate all candidate URLs for this depth
            candidate_map = {}
            candidates = []
            
            for base_path in current_paths:
                for word in wordlist:
                    # Generate new base path
                    new_base = urljoin(f"{base_path}/", word) if base_path else word
                    if new_base in visited_paths:
                        continue
                    
                    # Generate variations for this base path
                    variations = generate_variations(new_base)
                    for variation in variations:
                        full_url = urljoin(target_url, variation)
                        if full_url not in candidate_map:
                            candidate_map[full_url] = new_base
                            candidates.append(full_url)

            if debug:
                print(f"Generated {len(candidates)} candidate URLs")

            # Test all candidates
            valid_base_paths = set()
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for full_url in candidates:
                    for method in methods:
                        if (method, full_url) not in discovered:
                            futures.append(executor.submit(test_endpoint, method, full_url))
                            discovered.add((method, full_url))
                            if rate_limit_delay > 0:
                                time.sleep(rate_limit_delay)

                # Process results
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)
                        found_url = result['url']
                        base_path = candidate_map.get(found_url)
                        
                        if base_path and base_path not in visited_paths:
                            valid_base_paths.add(base_path)
                            if debug:
                                parsed = urlparse(found_url)
                                print(f"Found: {result['method']} {parsed.path} ({result['status']})")

            # Add discovered base paths to next depth
            next_depth = current_depth + 1
            if next_depth <= max_depth:
                for path in valid_base_paths:
                    if path not in visited_paths:
                        visited_paths.add(path)
                        queue[next_depth].append(path)
                if debug:
                    print(f"Added {len(valid_base_paths)} new base paths for depth {next_depth}")

        # Filter duplicates
        seen = set()
        unique_results = []
        for res in results:
            identifier = (res['method'], res['url'], res['status'])
            if identifier not in seen:
                seen.add(identifier)
                unique_results.append(res)

        return unique_results

    except Exception as e:
        if debug:
            print(f"[!] Error: {str(e)}")
        return []
    finally:
        session.close()

if __name__ == "__main__":
    target = "http://127.0.0.1:8888"
    endpoints = find_api_endpoints(target)
    
    print("\nValid API endpoints:")
    for endpoint in endpoints:
        if endpoint['type'] == 'API':
            parsed = urlparse(endpoint['url'])
            print(f"[{endpoint['method']}] {parsed.path} ({endpoint['status']})")