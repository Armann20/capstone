from flask import Flask, request, jsonify
import requests
from urllib.parse import urlparse, urlunparse
import jwt
import base64
import subprocess
import os
import re
from typing import Dict, List, Union, Callable, Any
import time
import statistics
import copy
from app import *
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlunparse
import requests
from difflib import SequenceMatcher

# Add these imports at the top
def create_test_env(filename):
    return  uploaded_specs[filename]['endpoints']
    




methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
check_req_method = 1,

# Changing the request method

def send_request_with_method(url, method, body=None):
    try:
        headers = {'Content-Type': 'application/json'}      
        if method == 'GET':
            response = requests.request(method, url, headers=headers)
        else:
            response = requests.request(method, url, json=body, headers=headers)
        if response.status_code in [404, 405, 400]:
            print(f"Skipping {response.status_code} response for {method}: {url}")
            return   
        print(f"Response for {method}: {response.status_code} - {response.text[:100]}")        
        if response.status_code not in [404, 405, 400]:
            log_response_for_later(method, response)
    except requests.exceptions.RequestException as error:
        print(f"Error for {method}: {error}")

def log_response_for_later(method, response):
    print(f"Logging response for {method} with status code {response.status_code} for later use.")

def parameter_method_change():
    initial_method = request.method
    url = request.url
    body = request.get_json() if request.is_json else None 

    for method in methods:
        if method != initial_method:
            print(f"Trying method: {method}")
            send_request_with_method(url, method, body)
    return "Request methods tested successfully!"


# Improper asset managment

def detect_improper_asset_management(endpoints, versions=None, concurrency=10, 
                                    similarity_threshold=0.95, timeout=15, 
                                    retries=2, compare_responses=True):
    """
    Detect improper asset management by testing different API versions.
    
    Args:
        endpoints (list): List of discovered endpoints (URL strings or dictionaries)
        versions (list): Version strings to test (default: common API versions)
        concurrency (int): Number of concurrent requests
        similarity_threshold (float): Response similarity threshold to flag differences
        timeout (int): Request timeout in seconds
        retries (int): Number of retries for failed requests
        compare_responses (bool): Compare response content similarity
    
    Returns:
        list: Vulnerabilities found with detailed comparisons
    """
    
    # Default version list
    versions = versions or ['v1', 'v2', 'v3', 'v4', 'beta', 'alpha', 'test', 'staging',
                          'prod', 'latest', 'old', 'new', 'v0', 'v5', 'canary', 'dev']
    
    vulnerabilities = []
    
    # Session setup for connection pooling
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    
    def version_pattern(path):
        """Find version-like patterns in URL path"""
        pattern = r'/(?:v(?:er(?:sion)?)?|ver|version)?\d+(?:\.\d+)*(?:[a-z]*)|beta|alpha|test|staging|prod|dev)(/|$)'
        return re.findall(pattern, path, re.I)    
    def modify_version(url, orig_version, new_version):
        """Replace version in URL path"""
        parsed = urlparse(url)
        new_path = parsed.path.replace(f"/{orig_version}/", f"/{new_version}/", 1)
        new_path = new_path.replace(f"/{orig_version}", f"/{new_version}", 1)
        return urlunparse(parsed._replace(path=new_path))
    
    def response_fingerprint(response):
        """Create comparable response fingerprint"""
        return {
            'status': response.status_code,
            'length': len(response.content),
            'content_type': response.headers.get('Content-Type', ''),
            'body_hash': hash(response.text.strip())
        }
    
    def similarity(a, b):
        """Calculate response similarity ratio"""
        return SequenceMatcher(None, a, b).ratio()
    
    def test_endpoint(original_url):
        """Test single endpoint for version mismatches"""
        findings = []
        
        try:
            # Get original response
            orig_resp = session.get(original_url, timeout=timeout)
            orig_fp = response_fingerprint(orig_resp)
        except requests.RequestException:
            return []
        
        # Find version candidates in path
        parsed = urlparse(original_url)
        versions_in_path = [v[0] for v in version_pattern(parsed.path)]
        
        if not versions_in_path:
            return []
        
        # Generate test candidates
        test_urls = []
        for orig_version in versions_in_path:
            for test_version in versions:
                if test_version.lower() != orig_version.lower():
                    test_url = modify_version(original_url, orig_version, test_version)
                    test_urls.append((test_url, orig_version, test_version))
        
        # Test all variants
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            future_to_url = {
                executor.submit(session.get, url, timeout=timeout): (url, ov, tv)
                for url, ov, tv in test_urls
            }
            
            for future in as_completed(future_to_url):
                test_url, orig_v, test_v = future_to_url[future]
                try:
                    test_resp = future.result()
                    test_fp = response_fingerprint(test_resp)
                    
                    # Analyze response
                    if test_resp.status_code == 200:
                        is_similar = True
                        if compare_responses:
                            content_similarity = similarity(orig_resp.text, test_resp.text)
                            is_similar = content_similarity >= similarity_threshold
                        
                        if not is_similar or test_fp['status'] != orig_fp['status']:
                            findings.append({
                                'original_url': original_url,
                                'tested_url': test_url,
                                'original_version': orig_v,
                                'tested_version': test_v,
                                'original_response': orig_fp,
                                'test_response': test_fp,
                                'similarity': content_similarity if compare_responses else None
                            })
                except Exception:
                    continue
        
        return findings
    
    # Process all endpoints
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_endpoint = {
            executor.submit(test_endpoint, 
                            ep['url'] if isinstance(ep, dict) else ep): ep 
            for ep in endpoints
        }
        
        for future in as_completed(future_to_endpoint):
            ep = future_to_endpoint[future]
            try:
                results = future.result()
                if results:
                    vulnerabilities.extend(results)
            except Exception as e:
                continue
    
    # Filter unique vulnerabilities
    unique_vulns = []
    seen = set()
    for vuln in vulnerabilities:
        identifier = f"{vuln['original_url']}-{vuln['tested_url']}"
        if identifier not in seen:
            seen.add(identifier)
            unique_vulns.append(vuln)
    
    return unique_vulns

# Injections
            

def check_injection_vulnerabilities(
    base_request: Dict[str, Any],
    injection_payloads: List[str] = None,
    sensitive_errors: List[str] = None
) -> List[Dict[str, Union[str, Dict]]]:
    """
    Tests for injection vulnerabilities by fuzzing request parameters.
    
    Args:
        base_request: Dictionary containing request details:
            {
                "method": "GET/POST/PUT/etc",
                "url": "http://example.com/api",
                "params": {"q": "test"},
                "headers": {"Content-Type": "application/json"},
                "json": {"key": "value"},
                "data": "raw data"
            }
        injection_payloads: List of payloads to test (default provided)
        sensitive_errors: List of error patterns indicating vulnerabilities
        
    Returns:
        List of vulnerability findings with details
    """
    
    # Default injection payloads
    default_payloads = [
        ';%00', '--', '-- -', '""', "' OR '1", "' OR 1 -- -",
        '" OR "" = "', '" OR 1 = 1 -- -', "' OR '' = '", 'OR 1=1',
        '%00', '$gt', '{"$gt":""}', '{"$gt":-1}', '$ne', '{"$ne":""}',
        '{"$ne":-1}', '$nin', '{"$nin":1}', '{"$nin":[1]}',
        '{"$where": "sleep(1000)"}', '|', '||', '&', '&&', "'", '"', ';',
        "'\"", '%00', '0x00', '//', ';%', '!', '?', '[]', '%5B%5D',
        '%09', '%0a', '%0b', '%0c', '%0e'
    ]
    
    # Default error patterns indicating potential vulnerabilities
    default_errors = [
        "SQL syntax", "unclosed quotation mark", "unexpected end",
        "syntax error", "mongo", "mongodb", "parse error",
        "execution timeout", "ECONNRESET", "command injection",
        "eval()", "TypeError", "ReferenceError", "500 Internal Server Error",
        "invalid query", "query failed"
    ]
    
    payloads = injection_payloads or default_payloads
    error_patterns = sensitive_errors or default_errors
    findings = []
    
    # Get all parameter locations to test
    param_locations = ["params", "json", "data", "headers"]
    
    for location in param_locations:
        original_params = copy.deepcopy(base_request.get(location, {}))
        
        if not original_params:
            continue
            
        if location == "data" and isinstance(original_params, bytes):
            continue  # Skip binary data
            
        for param in list(original_params.keys()):
            for payload in payloads:
                # Create modified request
                test_request = copy.deepcopy(base_request)
                
                # Handle different parameter locations
                if location == "json":
                    if isinstance(test_request.get("json"), dict):
                        test_request["json"][param] = payload
                elif location == "data":
                    if isinstance(test_request.get("data"), dict):
                        test_request["data"][param] = payload
                elif location in ["params", "headers"]:
                    test_request[location][param] = payload
                
                try:
                    # Send the request
                    response = requests.request(
                        method=test_request["method"],
                        url=test_request["url"],
                        params=test_request.get("params"),
                        headers=test_request.get("headers"),
                        json=test_request.get("json"),
                        data=test_request.get("data")
                    )
                    
                    # Check for indicators of vulnerability
                    vuln_indicated = False
                    indicators = []
                    
                    # Check status code
                    if response.status_code >= 500:
                        indicators.append(f"5xx status ({response.status_code})")
                    
                    # Check response content
                    content = response.text.lower()
                    for error in error_patterns:
                        if error.lower() in content:
                            indicators.append(f"Error pattern: {error}")
                            vuln_indicated = True
                    
                    # Check response time
                    if response.elapsed.total_seconds() > 5:
                        indicators.append("Long response time")
                        vuln_indicated = True
                    
                    # Check content length variance
                    baseline_length = len(str(original_params.get(param, "")))
                    test_length = len(str(payload))
                    if abs(len(content) - baseline_length) > 1000:
                        indicators.append("Significant content length change")
                        vuln_indicated = True
                    
                    if vuln_indicated:
                        findings.append({
                            "location": location,
                            "parameter": param,
                            "payload": payload,
                            "status": response.status_code,
                            "response_time": response.elapsed.total_seconds(),
                            "indicators": indicators,
                            "response_sample": content[:200] + "..." if len(content) > 200 else content
                        })
                        
                except Exception as e:
                    findings.append({
                        "location": location,
                        "parameter": param,
                        "payload": payload,
                        "error": str(e),
                        "indicators": ["Request failed"]
                    })
    
    return findings




# SSRF
            



# JWT attacks







def jwt_attacks(request, response):
    # Check if 'Bearer' token is present in the response headers
    if 'Bearer' in response.headers.get('Authorization', ''):
        token = response.headers['Authorization'].split(' ')[1]
        
        # Split the token into its parts (header, payload, signature)
        try:
            header, payload, signature = token.split('.')
        except ValueError:
            print("Invalid JWT token format")
            return

        # Decode the header and payload
        header_decoded = base64.urlsafe_b64decode(header + '==').decode('utf-8')
        payload_decoded = base64.urlsafe_b64decode(payload + '==').decode('utf-8')
        
        print(f"Decoded JWT Header: {header_decoded}")
        print(f"Decoded JWT Payload: {payload_decoded}")

        # Test for "None" Algorithm Vulnerability
        if '"alg":"none"' in header_decoded:
            print("Warning: Token uses 'none' algorithm (vulnerable to algorithm attack)")

        # Example: Check for the presence of algorithm and downgrade attempt
        if '"alg":"RS256"' in header_decoded:
            print("Token uses RS256, potentially vulnerable to algorithm downgrade attacks.")
        
        try:
            # Decode the JWT with the "none" algorithm (this simulates the attack)
            decoded_token_none_algo = jwt.decode(token, options={"verify_signature": False}, algorithms=["none"])
            print(f"Decoded JWT token with 'none' algorithm: {decoded_token_none_algo}")
        except jwt.ExpiredSignatureError:
            print("JWT token has expired")
        except jwt.InvalidTokenError:
            print("Invalid JWT token")
        
        # Claims Manipulation (example of checking for user roles, ID, etc.)
        if '"role":"admin"' in payload_decoded:
            print("Warning: Token payload includes privileged roles (vulnerable to manipulation)")
    
    # Attempt to use Hashcat to crack the JWT key (only works for symmetric algorithms like HS256)
    try:
        print("Attempting to crack the JWT signing key with Hashcat...")
        
        # Save the token into a file (assuming the token is in the correct format)
        with open("jwt.txt", "w") as file:
            file.write(f"{token}\n")
        
        # Specify the relative path to rockyou.txt inside ../wordlist
        wordlist_path = os.path.join('..', 'wordlist', 'rockyou.txt')
        
        # Check if the wordlist file exists
        if not os.path.exists(wordlist_path):
            print(f"Error: Wordlist file '{wordlist_path}' does not exist!")
            return

        # Run Hashcat to crack the JWT key (use rockyou.txt dictionary file)
        # Ensure that Hashcat is installed and available in your PATH
        result = subprocess.run(
            ['hashcat', '-m', '16500', 'jwt.txt', wordlist_path, '--show'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Output the result from Hashcat
        if result.returncode == 0:
            print("Hashcat result:\n", result.stdout)
        else:
            print("Hashcat error:\n", result.stderr)
        
    except Exception as e:
        print(f"Error while attempting to crack JWT key: {e}")








# Excessive data exposure

def check_excessive_data_exposure(response_data: Union[Dict, List], 
                                 custom_sensitive_fields: List[str] = None,
                                 custom_regex_patterns: Dict[str, str] = None) -> List[dict]:
    """
    Scans API response for sensitive data exposure.
    
    Args:
        response_data: Parsed JSON response (dict/list)
        custom_sensitive_fields: Optional list of custom sensitive field names
        custom_regex_patterns: Optional dict of {pattern_name: regex_pattern}
        
    Returns:
        List of issues found with path and reason
    """
    
    # Default sensitive field names
    default_sensitive_fields = [
        "password", "password_hash", "ssn", "social_security", "credit_card",
        "cvv", "dob", "date_of_birth", "address", "phone_number", "email",
        "auth_token", "jwt", "api_key", "secret", "private_key", "salary",
        "tax_id", "health_record", "license_number", "driver_license",
        "passport", "biometric_data", "pin", "security_answer", "iban",
        "account_number", "admin", "session_id"
    ]
    
    # Default regex patterns for sensitive values
    default_regex_patterns = {
        "ssn": r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b",
        "credit_card": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
        "phone_arm": r"\b\d{3}[-.]?\d{2}[-.]?\d{2}[-.]?\d{2}\b",
        "jwt": r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b",
        "api_key": r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b"
    }

    # Merge with custom inputs if provided
    sensitive_fields = default_sensitive_fields + (custom_sensitive_fields or [])
    regex_patterns = {**default_regex_patterns, **(custom_regex_patterns or {})}

    issues = []
    compiled_patterns = {name: re.compile(pattern) for name, pattern in regex_patterns.items()}

    def _scan(data, path: str = "") -> None:
        nonlocal issues
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                
                # Check field names
                if any(sf.lower() == key.lower() for sf in sensitive_fields):
                    issues.append({
                        "path": current_path,
                        "reason": f"Sensitive field name detected: '{key}'"
                    })
                
                # Check values
                _check_value(value, current_path)
                
                # Recursive scan
                _scan(value, current_path)
                
        elif isinstance(data, list):
            for index, item in enumerate(data):
                current_path = f"{path}[{index}]"
                _check_value(item, current_path)
                _scan(item, current_path)

    def _check_value(value, current_path: str) -> None:
        if isinstance(value, str):
            for pattern_name, pattern in compiled_patterns.items():
                if pattern.search(value):
                    issues.append({
                        "path": current_path,
                        "reason": f"Sensitive value pattern detected: '{pattern_name}'"
                    })
        elif isinstance(value, (bool, int, float)):
            return  # Skip non-string primitives

    _scan(response_data)
    return issues




# Mass asssignment 





# User enumeration (timing attacks)
        
def detect_timing_attack(
    usernames: List[str],
    request_function: Callable[[str], float],
    num_samples: int = 10,
    z_threshold: float = 2.0
) -> Dict[str, List[str]]:
    """
    Detects potential username enumeration via timing attacks.
    
    Args:
        usernames: List of usernames to test
        request_function: Function that takes username and returns response time
        num_samples: Number of timing samples per username (default: 10)
        z_threshold: Z-score threshold for anomaly detection (default: 2.0)
        
    Returns:
        {
            "potential_valid_users": [list of usernames],
            "timing_stats": {username: {"mean": x, "stddev": y}},
            "z_scores": {username: z_score}
        }
    """
    
    # Collect timing data
    timing_data = {}
    
    for user in usernames:
        times = []
        for _ in range(num_samples):
            try:
                elapsed = request_function(user)
                times.append(elapsed)
            except Exception as e:
                print(f"Error testing {user}: {str(e)}")
                continue
        if times:
            timing_data[user] = {
                "mean": statistics.mean(times),
                "stddev": statistics.stdev(times) if len(times) > 1 else 0
            }

    # Calculate Z-scores for anomaly detection
    all_means = [data["mean"] for data in timing_data.values()]
    global_mean = statistics.mean(all_means)
    global_stdev = statistics.stdev(all_means) if len(all_means) > 1 else 0

    z_scores = {}
    for user, data in timing_data.items():
        if global_stdev == 0:
            z_scores[user] = 0
        else:
            z_scores[user] = (data["mean"] - global_mean) / global_stdev

    # Identify potential valid users
    potential_valid = [
        user for user, score in z_scores.items()
        if score > z_threshold
    ]

    return {
        "potential_valid_users": potential_valid,
        "timing_stats": timing_data,
        "z_scores": z_scores
    }

