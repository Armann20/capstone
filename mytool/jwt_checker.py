#!/usr/bin/env python3
import subprocess
import os
import json
import re
import argparse
import base64
import tempfile
from termcolor import colored

# Configuration
JWT_TOOL_PATH = os.path.join('jwt_tool', 'jwt_tool.py')
WORDLIST_PATH = os.path.join('wordlist', 'rockyou.txt')
TIMEOUT = 3600  # 1 hour timeout for brute-force

def check_dependencies():
    """Verify required components exist"""
    missing = []
    if not os.path.exists(JWT_TOOL_PATH):
        missing.append(f"jwt_tool.py not found at {os.path.abspath(JWT_TOOL_PATH)}")
    if not os.path.exists(WORDLIST_PATH):
        missing.append(f"Wordlist not found at {os.path.abspath(WORDLIST_PATH)}")
    # Check if hashcat is available
    try:
        subprocess.run(['hashcat', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError:
        missing.append("hashcat is not functioning correctly")
    except FileNotFoundError:
        missing.append("hashcat is not installed or not in PATH")
    return missing

def get_algorithm(token):
    """Extract JWT algorithm from header"""
    try:
        header = token.split('.')[0]
        header += "=" * ((4 - len(header) % 4) % 4)  # Add padding
        decoded = base64.b64decode(header).decode()
        return json.loads(decoded).get('alg', '')
    except:
        return ''

def run_jwt_tool(command):
    """Execute jwt_tool command with error handling"""
    try:
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=TIMEOUT
        )
        return process.stdout, process.stderr, process.returncode
    except subprocess.TimeoutExpired:
        return None, "Operation timed out", 1
    except Exception as e:
        return None, str(e), 1

def parse_vulnerabilities(output):
    """Extract vulnerabilities from jwt_tool output"""
    vulns = []
    critical_patterns = [
        r'CVE-\d+-\d+',
        'None algorithm',
        'Signature bypass',
        'Key confusion',
        'Unverified signature',
        'Weak key'
    ]
    
    for pattern in critical_patterns:
        matches = re.findall(pattern, output, re.IGNORECASE)
        vulns.extend([{'name': m, 'severity': 'Critical'} for m in matches])
    
    vuln_lines = [line.strip() for line in output.split('\n') 
                 if line.strip().startswith(('[!]', '[+]'))]
    
    for line in vuln_lines:
        if '[!]' in line:
            vulns.append({'name': line[4:], 'severity': 'High'})
        elif '[+]' in line:
            vulns.append({'name': line[4:], 'severity': 'Medium'})
    
    seen = set()
    return [v for v in vulns if not (v['name'] in seen or seen.add(v['name']))]

def scan_token(token):
    """Perform vulnerability scanning"""
    result = {'header': {}, 'payload': {}, 'vulnerabilities': [], 'warnings': []}
    
    output, err, code = run_jwt_tool(['python3', JWT_TOOL_PATH, token])
    
    if code != 0:
        result['error'] = f"Scan failed: {err}"
        return result
    
    header_match = re.search(r'Token header values:\n(.*?)\n\n', output, re.DOTALL)
    if header_match:
        for line in header_match.group(1).split('\n'):
            if '[+]' in line:
                key, val = line.split('=', 1)
                result['header'][key.strip()[4:]] = json.loads(val.strip())
    
    payload_match = re.search(r'Token payload values:\n(.*?)\n\n', output, re.DOTALL)
    if payload_match:
        for line in payload_match.group(1).split('\n'):
            if '[+]' in line:
                key, val = line.split('=', 1)
                result['payload'][key.strip()[4:]] = json.loads(val.strip())
    
    result['vulnerabilities'] = parse_vulnerabilities(output)
    result['warnings'] = re.findall(r'WARNING: (.+)', output)
    
    return result

def brute_force_token(token):
    """Perform dictionary attack using hashcat"""
    result = {
        'status': 'failed', 
        'secret': None, 
        'error': None
    }

    algorithm = get_algorithm(token).upper()
    if not algorithm.startswith('HS'):
        result['error'] = f"Unsupported algorithm for hashcat: {algorithm}"
        return result

    mode = 16500  # Hashcat mode for JWT (HS256/HS384/HS512)

    with tempfile.NamedTemporaryFile(mode='w', delete=True) as token_file:
        token_file.write(token)
        token_file.flush()

        cmd = [
            'hashcat',
            '-m', str(mode),
            '-a', '0',
            token_file.name,
            WORDLIST_PATH,
            '--quiet',
            '--potfile-disable',
            '-O',
            '--force'
        ]

        try:
            process = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=TIMEOUT
            )
        except subprocess.TimeoutExpired:
            result['error'] = "Brute-force timed out"
            return result
        except Exception as e:
            result['error'] = str(e)
            return result

        show_cmd = [
            'hashcat',
            '-m', str(mode),
            token_file.name,
            '--show',
            '--quiet'
        ]
        show_process = subprocess.run(
            show_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if show_process.returncode == 0 and show_process.stdout.strip():
            secret = show_process.stdout.split(':')[1].strip()
            result['secret'] = secret
            result['status'] = 'success'
        else:
            error_msg = process.stderr.strip() or "Secret not found"
            result['error'] = error_msg

    return result

def print_report(scan_data, brute_data):
    """Display formatted results"""
    print(colored("\n=== JWT Security Report ===", 'cyan', attrs=['bold']))
    
    if scan_data.get('vulnerabilities'):
        print(colored("\n[ Critical Vulnerabilities ]", 'red', attrs=['bold']))
        for vuln in [v for v in scan_data['vulnerabilities'] if v['severity'] == 'Critical']:
            print(f" - {vuln['name']}")
            
        print(colored("\n[ Other Findings ]", 'yellow', attrs=['bold']))
        for vuln in [v for v in scan_data['vulnerabilities'] if v['severity'] != 'Critical']:
            print(f" - {vuln['name']} ({vuln['severity']})")
    else:
        print(colored("\nNo vulnerabilities found", 'green'))
    
    if brute_data:
        print(colored("\n[ Brute-Force Results ]", 'magenta', attrs=['bold']))
        if brute_data['status'] == 'success':
            print(colored(f"✅ Secret found: {brute_data['secret']}", 'green'))
        else:
            print(colored("❌ No secret found", 'red'))
        if brute_data.get('error'):
            print(colored(f"Error: {brute_data['error']}", 'red'))
    
    print(colored("\n[ Token Details ]", 'blue', attrs=['bold']))
    print("Header:")
    print(json.dumps(scan_data.get('header', {}), indent=2))
    print("\nPayload:")
    print(json.dumps(scan_data.get('payload', {}), indent=2))
    
    if scan_data.get('warnings'):
        print(colored("\n[ Warnings ]", 'yellow', attrs=['bold']))
        for warn in scan_data['warnings']:
            print(f" - {warn}")

def main():
    parser = argparse.ArgumentParser(
        description='JWT Security Scanner with Brute-Force Capabilities',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('token', help='JWT token to analyze')
    parser.add_argument('-b', '--brute', action='store_true',
                      help='Enable brute-force attack')
    args = parser.parse_args()
    
    missing = check_dependencies()
    if missing:
        print(colored("Missing requirements:", 'red'))
        for item in missing:
            print(f" - {item}")
        return
    
    if args.brute:
        algorithm = get_algorithm(args.token)
        if not algorithm.startswith('HS'):
            print(colored("\n❌ Brute-force only works for HMAC-based algorithms (HS256/HS384/HS512)", 'red'))
            print(colored(f"Detected algorithm: {algorithm}", 'yellow'))
            return
    
    print(colored("\n🚀 Starting JWT analysis...", 'cyan'))
    scan_data = scan_token(args.token)
    
    brute_data = None
    if args.brute:
        print(colored("\n💥 Starting brute-force attack with Hashcat...", 'yellow'))
        brute_data = brute_force_token(args.token)
    
    print_report(scan_data, brute_data if args.brute else None)

if __name__ == "__main__":
    main()