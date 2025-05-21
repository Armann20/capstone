from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pathlib import Path
from brute import bruteforce
from headers import AdvancedHeaderTester
#from flask_wtf.csrf import CSRFProtect
import yaml
import json
import uuid
import logging
from urllib.parse import urlparse
from collections import defaultdict
from werkzeug.utils import secure_filename
import re
from datetime import datetime
import requests
from werkzeug.datastructures import Headers
from functools import partial
import concurrent.futures
from main import *
from APIBruteForcer import *
import subprocess
import os
from concurrent.futures import ThreadPoolExecutor
import pprint
from datetime import datetime
import sqlite3


from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, FieldList, FormField, TextAreaField
from wtforms.validators import DataRequired, Optional
DB_PATH = Path(__file__).parent / 'test_results.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS test_runs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  spec_id TEXT,
                  selected_tests TEXT,
                  findings TEXT,
                  stats TEXT,
                  created_at DATETIME)''')
    conn.commit()
    conn.close()

init_db()


class ParameterForm(FlaskForm):
    class Meta:
        csrf = False  # Disable CSRF for this form
        
    name = StringField('Name', validators=[DataRequired()])
    value = StringField('Value', validators=[DataRequired()])
    param_type = SelectField('Type', choices=[
        ('string', 'String'),
        ('number', 'Number'),
        ('boolean', 'Boolean'),
        ('file', 'File')
    ])

class RequestForm(FlaskForm):
    class Meta:
        csrf = False 
        
    method = SelectField('Method', choices=[
        ('GET', 'GET'),
        ('POST', 'POST'),
        ('PUT', 'PUT'),
        ('DELETE', 'DELETE')
    ], validators=[DataRequired()])
    url = StringField('URL', validators=[DataRequired()])
    path_params = FieldList(FormField(ParameterForm))
    query_params = FieldList(FormField(ParameterForm))
    headers = FieldList(FormField(ParameterForm))
    body = TextAreaField('Request Body')

def store_test_run(spec_id, selected_tests, findings, stats):
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('''INSERT INTO test_runs 
                    (spec_id, selected_tests, findings, stats, created_at)
                    VALUES (?, ?, ?, ?, ?)''',
                (spec_id,
                json.dumps(selected_tests),
                json.dumps(findings),
                json.dumps(stats),
                datetime.utcnow()))
        conn.commit()
    except Exception as e:
        print(f"Database error: {str(e)}")
    finally:
        if conn:
            conn.close()
           
def cleanup_old_records():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Keep last 100 records
    c.execute('''DELETE FROM test_runs 
                 WHERE id NOT IN 
                 (SELECT id FROM test_runs ORDER BY id DESC LIMIT 100)''')
    conn.commit()
    conn.close()

# Run cleanup on app start
cleanup_old_records()
# ============================
# Python version of APISploit
# ============================
class APISploit:
    def __init__(self, base_url=''):
        self.base_url = base_url.strip('/')
        self.endpoints = []         # List of endpoints loaded from the spec
        self.selected_endpoint = {} # Holds currently selected endpoint data
        self.method = 'GET'         # Default HTTP method

    def load_stored_endpoints(self, endpoints):
        """Store endpoints into the instance."""
        self.endpoints = endpoints

    def display_endpoints(self):
        """Return the stored endpoints."""
        return self.endpoints

    def select_endpoint(self, method, path):
        """
        Select an endpoint based on method and path.
        Returns the full URL combining the base_url and path.
        """
        self.selected_endpoint = {'method': method.upper(), 'path': path}
        if self.base_url:
            # Ensure exactly one slash between base URL and path
            full_url = f"{self.base_url}/{path.lstrip('/')}"
        else:
            full_url = path
        return full_url

    def send_request(self, url, method=None, body=None):
        """
        Sends an API request to the given URL using the provided method and JSON body.
        Returns the JSON response if successful.
        """
        import requests
        if method is None:
            method = self.selected_endpoint.get('method', 'GET') if self.selected_endpoint else 'GET'
        method = method.upper()
        headers = {'Content-Type': 'application/json'}
        try:
            if method == 'GET':
                response = requests.request(method, url, headers=headers)
            else:
                response = requests.request(method, url, json=body, headers=headers)
            if response.status_code in [404, 405, 400]:
                print(f"Skipping {response.status_code} response for {method}: {url}")
                return None
            print(f"Response for {method}: {response.status_code} - {response.text[:100]}")
            return response.json()
        except requests.exceptions.RequestException as error:
            print(f"Error for {method}: {error}")
            return None

    def set_method(self, method):
        """Update the current method."""
        self.method = method.upper()

# ==============================
# End of APISploit class
# ==============================

# -------------------------------
# Flask App Setup and Configuration
# -------------------------------
def init_db():
    conn = sqlite3.connect('test_results.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS test_results
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  spec_id TEXT,
                  findings TEXT,
                  stats TEXT,
                  timestamp DATETIME)''')
    conn.commit()
    conn.close()

init_db()

def save_test_results(spec_id, findings, stats):
    conn = sqlite3.connect('test_results.db')
    c = conn.cursor()
    c.execute('''INSERT INTO test_results 
                 (spec_id, findings, stats, timestamp)
                 VALUES (?, ?, ?, ?)''',
              (spec_id, 
               json.dumps(findings),
               json.dumps(stats),
               datetime.now()))
    conn.commit()
    conn.close()
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app = Flask(__name__)
#csrf = CSRFProtect(app)
pprint.pprint(app.url_map)
app.secret_key = 'secretkey'
CORS(app)
app.config['VULNERS_API_KEY'] = os.environ.get('VULNERS_API_KEY')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['ALLOWED_EXTENSIONS'] = {'json', 'yaml', 'yml', 'har'}
app.secret_key = 'my_secret_key'  # Needed for flash messages

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "500 per hour"]
)

# Allowed proxy domains (if needed)
ALLOWED_DOMAINS = {
    'example.com',
    'api.example.com',
    'jsonplaceholder.typicode.com'
}

# Global dictionary to store uploaded specifications
uploaded_specs = defaultdict(dict)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def process_spec_files():
    tests_folder = os.path.join(os.path.dirname(__file__), 'tests')
    
    for filename in os.listdir(tests_folder):
        if filename.endswith('.json'):
            file_path = os.path.join(tests_folder, filename)
            print(f"Processing {filename}...")
            
            try:
                # Run extract.py as subprocess
                result = subprocess.run(
                    ["python3", "extract.py", file_path],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    # Parse output
                    params = []
                    for line in result.stdout.split('\n'):
                        if line.startswith('- '):
                            params.append(line[2:].strip())
                    
                    # Update the spec data
                    spec_name = filename[:-5]  # Remove .json
                    if spec_name in uploaded_specs:
                        uploaded_specs[spec_name]['unique_params'] = params
                        print(f"Updated {spec_name} with {len(params)} parameters")
                
            except Exception as e:
                print(f"Error processing {filename}: {str(e)}")
TEST_UPLOAD_FOLDER = 'user_uploads'
ALLOWED_TEST_EXTENSIONS = {'txt', 'csv'}

def allowed_test_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_TEST_EXTENSIONS
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/check-url', methods=['GET'])
def check_url():
    target_url = request.args.get('url')
    if not target_url:
        return jsonify({'error': 'No URL provided'}), 400
    try:
        response = requests.get(target_url, timeout=5)
        return jsonify({'status': response.status_code})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
def parse_openapi(content):
    endpoints = []
    for path, methods in content.get('paths', {}).items():
        # Get path-level parameters
        path_parameters = methods.get('parameters', [])
        
        for method, details in methods.items():
            if method.lower() not in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']:
                continue  # Skip non-method keys like 'parameters', 'servers', etc.
            
            # Combine path-level and method-level parameters
            method_parameters = path_parameters + details.get('parameters', [])
            
            endpoint = {
                'method': method.upper(),
                'path': path,
                'summary': details.get('summary', details.get('description', '')),
                'parameters': [],
                'requestBody': details.get('requestBody', {}),
                'responses': details.get('responses', {})
            }
            
            # Process parameters
            for param in method_parameters:
                endpoint['parameters'].append({
                    'name': param.get('name'),
                    'in': param.get('in'),  # path, query, header, cookie
                    'required': param.get('required', False),
                    'description': param.get('description', ''),
                    'schema': param.get('schema', {'type': 'string'})
                })
            
            endpoints.append(endpoint)
    
    return endpoints

def parse_postman(content):
    def resolve_variables(value, variables):
        return re.sub(r'{{(.*?)}}', lambda m: variables.get(m.group(1), ''), value)
    def process_items(items, variables, base_path=''):
        endpoints = []
        for item in items:
            if 'item' in item:
                endpoints += process_items(item['item'], variables, f"{base_path}/{item.get('name', '')}")
            else:
                request_item = item.get('request', {})
                url = request_item.get('url', {})
                variables = {var['key']: var['value'] for var in request_item.get('variable', [])}
                if isinstance(url, dict):
                    raw_url = url.get('raw', '')
                    if not raw_url and 'path' in url:
                        raw_url = '/'.join(url.get('path', ['/']))
                    path = urlparse(resolve_variables(raw_url, variables)).path
                else:
                    path = urlparse(resolve_variables(url, variables)).path
                endpoints.append({
                    'method': request_item.get('method', 'GET').upper(),
                    'path': f"{base_path}{path}",
                    'summary': item.get('name'),
                    'headers': {h['key']: h['value'] for h in request_item.get('header', [])},
                    'body': resolve_variables(request_item.get('body', {}).get('raw', ''), variables),
                    'variables': variables
                })
        return endpoints
    if not isinstance(content, dict) or 'info' not in content or 'item' not in content:
        raise ValueError("Invalid Postman collection")
    collection_vars = {var['key']: var['value'] for var in content.get('variable', [])}
    return process_items(content['item'], collection_vars)

def parse_har(content):
    endpoints = []
    seen = set()
    for entry in content.get('log', {}).get('entries', []):
        request_item = entry.get('request', {})
        url = urlparse(request_item.get('url', ''))
        method = request_item.get('method', 'GET').upper()
        key = f"{method}-{url.path}"
        if key not in seen:
            endpoints.append({
                'method': method,
                'path': url.path,
                'summary': f"{entry.get('startedDateTime', '')} - {request_item.get('httpVersion', '')}",
                'headers': {h['name']: h['value'] for h in request_item.get('headers', [])},
                'body': request_item.get('postData', {}).get('text'),
                'queryParams': {p['name']: p['value'] for p in request_item.get('queryString', [])}
            })
            seen.add(key)
    return endpoints
def test_authentication(endpoint, base_url):
    result = {
        'method': endpoint['method'],
        'endpoint': endpoint['path'],
        'category': 'Authentication',
        'testType': 'Missing Authentication',
        'resolution': 'Implement authentication checks',
        'status': None,
        'description': '',
        'cvssScore': 0.0,
        'cvssRating': 'INFO'
    }

    try:
        # Construct full URL safely
        path = endpoint['path'].lstrip('/')
        url = f"{base_url.rstrip('/')}/{path}"
        
        response = requests.request(
            method=endpoint['method'],
            url=url,
            headers={},
            timeout=5
        )
        
        result['status'] = response.status_code
        
        if 200 <= response.status_code < 300:
            result.update({
                'cvssScore': 9.8,
                'cvssRating': 'CRITICAL',
                'description': 'Unauthenticated access allowed to protected endpoint'
            })
        elif response.status_code == 401:
            return None  # No vulnerability
        else:
            result.update({
                'cvssScore': 7.5 if response.status_code >= 500 else 5.3,
                'cvssRating': 'HIGH' if response.status_code >= 500 else 'MEDIUM',
                'description': f'Unexpected response code {response.status_code} from protected endpoint'
            })

    except Exception as e:
        result.update({
            'cvssScore': 5.3,
            'cvssRating': 'MEDIUM',
            'description': f'Test failed: {str(e)}'
        })
        logger.error(f"Test failed for {endpoint['method']} {endpoint['path']}: {str(e)}")

    return result

def run_security_tests(spec_name):
    """Main function to run all security tests"""
    spec = uploaded_specs.get(spec_name)
    if not spec:
        return []
    
    base_url = spec.get('base_url', '')
    endpoints = spec['endpoints']
    
    # Get endpoints that should require authentication
    test_targets = [
        e for e in endpoints
        if any(sec.get('type', '').lower() in ['apikey', 'oauth2'] 
              for sec in e.get('security', []))
    ]
    
    # Run tests concurrently
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [
            executor.submit(test_authentication, endpoint, base_url)
            for endpoint in test_targets
        ]
        results = [f.result() for f in futures]
    
    # Filter out None values (passed tests)
    return [r for r in results if r is not None]


@app.route('/')
def index():
    return render_template('index.html')
# Add this function to load existing specs
def load_existing_specs():
    if not os.path.exists(UPLOAD_FOLDER):
        return
        
    for filename in os.listdir(UPLOAD_FOLDER):
        if filename.endswith('.json'):
            sanitized_name = filename[:-5]
            spec_file_path = os.path.join(UPLOAD_FOLDER, filename)
            
            try:
                with open(spec_file_path, 'r') as f:
                    data = json.load(f)
                
                # Add validation for required fields
                required_fields = {'original_filename', 'type', 'endpoints', 'timestamp'}
                if not required_fields.issubset(data.keys()):
                    logger.warning(f"Skipping invalid file: {filename}")
                    continue
                
                # Store using sanitized name as key
                uploaded_specs[sanitized_name] = data
                logger.info(f"Loaded existing spec: {data['original_filename']}")
                
            except Exception as e:
                logger.error(f"Error loading {filename}: {str(e)}")

# Call this when the app starts
load_existing_specs()

# Add the new route
@app.route('/spec/<string:unique_id>') 
def show_requests(unique_id):
    spec_data = uploaded_specs.get(unique_id)
    if not spec_data:
        flash("Specification not found", "error")
        return redirect(url_for('index'))
    
    form = RequestForm()
    # Format timestamp for display
    try:
        timestamp = datetime.fromisoformat(spec_data['timestamp'])
        formatted_time = timestamp.strftime('%b %d, %Y %I:%M %p')
    except:
        formatted_time = "Unknown time"
    
    # Prepare uploaded files list with formatted timestamps
    uploaded_files = []
    for uid, data in uploaded_specs.items():
        try:
            file_time = datetime.fromisoformat(data['timestamp'])
            display_time = file_time.strftime('%b %d, %Y %I:%M %p')
        except:
            display_time = "Unknown time"
            
        uploaded_files.append({
            'id': uid,
            'filename': data['original_filename'],
            'type': data['type'],
            'timestamp': display_time,
            'current': uid == unique_id
        })
    
    # Sort files by timestamp (newest first)
    uploaded_files.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Calculate method counts
    method_counts = defaultdict(int)
    for endpoint in spec_data['endpoints']:
        method_counts[endpoint['method'].upper()] += 1
    
    # Build endpoint hierarchy
    def build_hierarchy(endpoints):
        root = {'methods': {}, 'children': {}}
        for endpoint in endpoints:
            path = endpoint['path'].strip('/')
            segments = path.split('/') if path else []
            current_node = root
            for seg in segments:
                if seg not in current_node['children']:
                    current_node['children'][seg] = {'methods': {}, 'children': {}}
                current_node = current_node['children'][seg]
            method = endpoint['method'].upper()
            current_node['methods'][method] = {
                'summary': endpoint.get('summary', ''),
                'parameters': endpoint.get('parameters', []),
                'responses': endpoint.get('responses', {})
            }
        return root
    
    return render_template('requests.html',
                           spec_data=spec_data,
                           base_url=spec_data.get('base_url', ''),
                           form=form,
                           filename=spec_data['original_filename'],
                           spec_type=spec_data['type'],
                           method_counts=method_counts,
                           hierarchy=build_hierarchy(spec_data['endpoints']),
                           uploaded_files=uploaded_files,
                           current_id=unique_id,
                           current_time=formatted_time,
                           spec_id=unique_id)
@app.route('/upload', methods=['POST'])
@limiter.limit("10 per minute")
def upload_file():
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    try:
        if 'file' not in request.files:
            flash("No file uploaded", "error")
            return redirect(url_for('index'))
        
        file = request.files['file']
        if file.filename == '':
            flash("No selected file", "error")
            return redirect(url_for('index'))
        
        if not allowed_file(file.filename):
            flash("File type not allowed", "error")
            return redirect(url_for('index'))

        # Get and validate application name
        app_name = request.form.get('app_name', '').strip()
        if not app_name:
            flash("Application name is required", "error")
            return redirect(url_for('index'))
        
        # Sanitize application name for filename
        base_name = secure_filename(app_name)
        if not base_name:
            base_name = "untitled"
        
        filename = f"{base_name}.json"
        file_path = os.path.join(UPLOAD_FOLDER, filename)

        # Check for existing file
        if os.path.exists(file_path):
            flash(f"Filename '{base_name}' already exists. Please choose a different application name.", "error")
            return redirect(url_for('index'))

        content = file.read().decode('utf-8')
        parsed = None
        file_type = 'unknown'
        endpoints = []
        unique_params = []

        # Try parsing as OpenAPI (YAML or JSON)
        try:
            if file.filename.lower().endswith(('.yaml', '.yml')):
                parsed = yaml.safe_load(content)
            else:
                parsed = json.loads(content)
            
            if parsed and 'openapi' in parsed:
                endpoints = parse_openapi(parsed)
                file_type = 'openapi'
            else:
                parsed = None
        except Exception as e:
            logger.debug(f"OpenAPI parse attempt failed: {str(e)}")

        # Try parsing as Postman
        if file_type == 'unknown':
            try:
                parsed = json.loads(content)
                endpoints = parse_postman(parsed)
                file_type = 'postman'
            except Exception as e:
                logger.debug(f"Postman parse attempt failed: {str(e)}")

        # Try parsing as HAR
        if file_type == 'unknown':
            try:
                parsed = json.loads(content)
                endpoints = parse_har(parsed)
                file_type = 'har'
            except Exception as e:
                logger.debug(f"HAR parse attempt failed: {str(e)}")

        if file_type == 'unknown':
            flash("Unsupported file format. Supported formats: OpenAPI, Postman, HAR", "error")
            return redirect(url_for('index'))

        # Store initial metadata
        uploaded_specs[base_name] = {
            'type': file_type,
            'original_filename': f"{app_name}",
            'content': parsed,
            'endpoints': endpoints,
            'unique_params': [],
            'timestamp': datetime.now().isoformat(),
            'base_url': request.form.get('base_url', '')
        }

        # Save to uploads folder
        with open(file_path, 'w') as f:
            json.dump(uploaded_specs[base_name], f)

        # Write to tests folder
        extract_endpoints_with_tags(base_name)

        # Process parameters for OpenAPI specs
        if file_type == 'openapi':
            tests_folder = os.path.join(os.path.dirname(__file__), 'tests')
            spec_file = os.path.join(tests_folder, f"{base_name}.json")
            
            try:
                # Run extract.py on the test file
                result = subprocess.run(
                    ["python3", "extract.py", spec_file],
                    capture_output=True,
                    text=True,
                    check=True
                )

                # Parse extract.py output
                params = []
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.startswith('- '):
                            params.append(line[2:].strip())
                            
                    # Update parameters in spec data
                    uploaded_specs[base_name]['unique_params'] = params
                    
                    # Update the uploaded file with parameters
                    with open(file_path, 'w') as f:
                        json.dump(uploaded_specs[base_name], f)
                        
            except subprocess.CalledProcessError as e:
                logger.error(f"extract.py failed: {e.stderr}")
            except Exception as e:
                logger.error(f"Error processing parameters: {str(e)}")

        flash("File uploaded successfully", "success")
        return redirect(url_for('show_requests', unique_id=base_name))
    
    except Exception as e:
        logger.error(f"Upload error: {str(e)}", exc_info=True)
        flash(f"Upload error: {str(e)}", "error")
        return redirect(url_for('index'))
    

# Additional routes (e.g. /proxy, /specs, /test_request) can now access the global `uploaded_specs` variable.
@app.route('/proxy-request', methods=['POST'])
@limiter.limit("10/minute")
def proxy_request():
    try:
        # Get and validate request data
        try:
            data = request.get_json()
        except Exception as e:
            return jsonify(error=f"Invalid JSON request: {str(e)}"), 400

        if not data:
            return jsonify(error="No data provided"), 400
            
        # Validate required fields
        required_fields = ['spec_id', 'method', 'url']
        for field in required_fields:
            if field not in data:
                return jsonify(error=f"Missing required field: {field}"), 400

        # Get specification
        spec_id = data['spec_id']
        spec = uploaded_specs.get(spec_id)
        if not spec:
            return jsonify(error="Specification not found"), 404

        # Validate HTTP method
        method = data['method'].upper()
        if method not in {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'}:
            return jsonify(error="Invalid HTTP method"), 400

        # Validate URL format
        try:
            parsed_url = urlparse(data['url'])
            if not parsed_url.scheme or not parsed_url.netloc:
                return jsonify(error="Invalid URL format"), 400
        except Exception as e:
            return jsonify(error=f"Invalid URL: {str(e)}"), 400

        # Prepare request components
        headers = data.get('headers', {})
        body = data.get('body')
        timeout = min(int(data.get('timeout', 10)), 30)  # Max 30s timeout

        try:
            # Send request to external API
            response = requests.request(
                method=method,
                url=data['url'],
                headers=headers,
                json=body if body and method in {'POST', 'PUT', 'PATCH'} else None,
                timeout=timeout
            )
        except requests.exceptions.RequestException as e:
            return jsonify(error=f"Request failed: {str(e)}"), 500

        # Handle response parsing safely
        response_data = {
            'status': response.status_code,
            'headers': dict(response.headers),
            'content_type': response.headers.get('Content-Type', ''),
            'body': None
        }

        if response.content:
            content_type = response.headers.get('Content-Type', '')
            if 'application/json' in content_type:
                try:
                    response_data['body'] = response.json()
                except json.JSONDecodeError:
                    response_data['body'] = response.text
            else:
                response_data['body'] = response.text

        # Store new endpoint if successful
        if 200 <= response.status_code < 300:
            try:
                parsed_url = urlparse(data['url'])
                requested_path = parsed_url.path
                
                # Check for existing endpoint
                endpoint_exists = any(
                    ep['method'] == method and 
                    ep['path'] == requested_path
                    for ep in spec['endpoints']
                )

                if not endpoint_exists:
                    new_endpoint = {
                        'method': method,
                        'path': requested_path,
                        'summary': 'Discovered through testing',
                        'parameters': [],
                        'requestBody': {},
                        'responses': {
                            str(response.status_code): {
                                'description': 'Automatically discovered response'
                            }
                        }
                    }
                    
                    spec['endpoints'].append(new_endpoint)
                    uploaded_specs[spec_id] = spec
                    
                    # Persist to filesystem
                    filename = f"{spec_id}.json"
                    file_path = os.path.join(UPLOAD_FOLDER, filename)
                    with open(file_path, 'w') as f:
                        json.dump(spec, f, indent=4)
                    
                    response_data['new_endpoint'] = {
                        'method': method,
                        'path': requested_path
                    }

            except Exception as e:
                logger.error(f"Error saving new endpoint: {str(e)}")

        return jsonify(response_data)

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        return jsonify(error=f"Internal server error: {str(e)}"), 500
        
@app.route('/debug-specs')
def debug_specs():
     return uploaded_specs['test5']['endpoints']

@app.route('/get-endpoint-params', methods=['POST'])
def get_endpoint_params():
    data = request.json
    method = data.get('method')
    path = data.get('path')
    
    # Find the endpoint in your spec
    spec = uploaded_specs.get(data.get('spec_id'))
    endpoint = next((ep for ep in spec['endpoints'] 
                   if ep['method'] == method and ep['path'] == path), None)
    
    if not endpoint:
        return jsonify({'error': 'Endpoint not found'}), 404
    
    # Extract parameters from the endpoint definition
    parameters = {
        'path': [],
        'query': [],
        'header': [],
        'body': {}
    }
    
    # Add path parameters
    if 'parameters' in endpoint:
        for param in endpoint.get('parameters', []):
            if param['in'] == 'path':
                parameters['path'].append({
                    'name': param['name'],
                    'required': param.get('required', False),
                    'type': param.get('schema', {}).get('type', 'string')
                })
    
    # Add similar logic for query params and headers
    # ...
    
    return jsonify(parameters)

@app.route('/send-request', methods=['POST'])
def send_request():
    try:
        # Get form data
        method = request.form.get('method', 'GET').upper()
        url = request.form.get('url', '')
        
        # Get parameters from form
        path_params = {}
        for param in request.form.getlist('path_params-name'):
            path_params[param] = request.form.get(f'path_params-value-{param}')
        
        query_params = {}
        for param in request.form.getlist('query_params-name'):
            query_params[param] = request.form.get(f'query_params-value-{param}')
        
        headers = {}
        for header in request.form.getlist('headers-name'):
            headers[header] = request.form.get(f'headers-value-{header}')
        
        body = request.form.get('body', None)
        
        # Validate URL
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Prepare request data
        request_data = {
            'method': method,
            'url': url,
            'headers': headers,
            'params': query_params
        }
        
        # Add body if present and method supports it
        if body and method in ['POST', 'PUT', 'PATCH']:
            try:
                # Try to parse as JSON if content-type is json
                if headers.get('Content-Type', '').lower() == 'application/json':
                    request_data['json'] = json.loads(body)
                else:
                    request_data['data'] = body
            except json.JSONDecodeError:
                request_data['data'] = body
        
        # Send the request
        response = requests.request(**request_data)
        
        # Prepare response data
        response_data = {
            'status': response.status_code,
            'headers': dict(response.headers),
            'body': response.text  # Return as text to handle non-JSON responses
        }
        
        # Try to parse as JSON if possible
        try:
            response_data['body'] = response.json()
        except ValueError:
            pass
            
        return jsonify(response_data)
        
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500


@app.route('/runSelectedTests', methods=['POST'])
def run_selected_tests():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        # Validate required parameters
        spec_id = data.get('spec_id')
        selected_tests = data.get('tests', [])
        endpoint = data.get('endpoint')
        
        if not all([spec_id, selected_tests, endpoint]):
            return jsonify({"error": "Missing required parameters (spec_id, tests, endpoint)"}), 400
            
        # Validate endpoint structure
        if not all(k in endpoint for k in ['method', 'path']):
            return jsonify({"error": "Endpoint must contain method and path"}), 400

        # Retrieve specification
        spec = uploaded_specs.get(spec_id)
        if not spec:
            return jsonify({"error": "Specification not found"}), 404

        findings = []
        base_url = spec.get('base_url', '')
        
        # Configuration from request or defaults
        test_config = {
            'headers': data.get('headers', {}),
            'delay': data.get('delay', 0.1),
            'timeout': data.get('timeout', 5),
            'workers': data.get('workers', 1)  # Single worker for single endpoint
        }

        try:
            # Build the full URL for the endpoint
            full_url = urljoin(base_url, endpoint['path'])
            
            # Prepare common request parameters
            req_params = {
                'method': endpoint['method'],
                'url': full_url,
                'headers': test_config['headers'],
                'timeout': test_config['timeout']
            }

            # Execute selected tests for this endpoint
            for test_type in selected_tests:
                if test_type == 'headers':
                    tester = AdvancedHeaderTester(
                        target_url=full_url,
                        vulners_key=app.config.get('VULNERS_API_KEY')
                    )
                    tester.establish_baseline()
                    tester.test_header_manipulation()
                    tester.analyze_server_header()
                    tester.check_security_headers()
                    
                    for vuln in tester.vulnerabilities:
                        findings.append(format_header_finding(vuln, endpoint))

                elif test_type == 'sql':
                    # Run SQLi tests specifically on this endpoint
                    findings += run_sqli_tests(
                        spec_id,
                        test_payloads=data.get('injection_payloads', []),
                        endpoint=endpoint
                    )

                elif test_type == 'auth':
                    # Test authentication on this specific endpoint
                    findings += run_auth_tests(
                        spec_id,
                        credentials=data.get('credentials', []),
                        endpoint=endpoint
                    )

                elif test_type == 'ssrf':
                    # SSRF test for this endpoint
                    findings += test_ssrf(
                        endpoint,
                        test_config['headers'],
                        data.get('ssrf_payloads', [])
                    )

                # Add other test types as needed...

        except Exception as e:
            logger.error(f"Endpoint test failed: {str(e)}")
            return jsonify({
                "error": f"Test failed for {endpoint['method']} {endpoint['path']}: {str(e)}"
            }), 500

        # Calculate statistics
        stats = calculate_stats(findings)
        
        return jsonify({
            "status": "completed",
            "endpoint": endpoint,
            "findings": findings,
            "stats": stats,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Selected test failed: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

def format_header_finding(vuln, endpoint):
    return {
        'type': vuln['type'],
        'severity': vuln['severity'].capitalize(),
        'message': vuln['message'],
        'details': {
            'method': endpoint['method'],
            'path': endpoint['path'],
            'cvss': get_cvss_score(vuln),
            'test_type': 'Header Analysis'
        }
    }

def calculate_stats(findings):
    return {
        'total': len(findings),
        'critical': sum(1 for f in findings if f['severity'].lower() == 'critical'),
        'high': sum(1 for f in findings if f['severity'].lower() == 'high'),
        'medium': sum(1 for f in findings if f['severity'].lower() == 'medium'),
        'low': sum(1 for f in findings if f['severity'].lower() == 'low')
    }



@app.route('/extract_endpoints_with_tags')
def extract_endpoints_with_tags(base_name):
    """Extract endpoints from OpenAPI specs and add vulnerability tagging metadata,
       and write/update a file in the tests folder with the spec."""
    spec_name = base_name
    endpoints = []
    
    try:
        spec = uploaded_specs[spec_name]
    except KeyError:
        return jsonify({"error": f"Specification '{spec_name}' not found"}), 404
    
    # Process each endpoint to extract required fields and build metadata
    for endpoint in spec.get('endpoints', []):
        # Base structure with safe access
        endpoint_data = {
            "method": endpoint.get("method", "UNKNOWN"),
            "path": endpoint.get("path", "/unknown"),
            "parameters": endpoint.get("parameters", []),
            "summary": endpoint.get("summary", ""),
            "tags": [0],
            "vulnerability_status": "untested",  # Ensure this is set
            "severity": None,
            "requestBody": None,
            "responses": {}
        }


        # Safely process requestBody
        request_body = endpoint.get('requestBody', {})
        if request_body:
            content = request_body.get('content', {})
            if content:
                content_type, media_type = next(iter(content.items()), (None, None))
                if media_type:
                    schema = media_type.get('schema', {})
                    endpoint_data["requestBody"] = {
                        "content_type": content_type,
                        "schema_ref": schema.get('$ref'),
                        "schema": schema if not schema.get('$ref') else None
                    }

        # Safely process responses
        for status_code, response in endpoint.get('responses', {}).items():
            response_content = response.get('content', {})
            response_data = {"content_type": None, "schema_ref": None, "schema": None}
            
            if response_content:
                content_type, media_type = next(iter(response_content.items()), (None, None))
                if media_type and 'schema' in media_type:
                    schema = media_type['schema']
                    response_data = {
                        "content_type": content_type,
                        "schema_ref": schema.get('$ref'),
                        "schema": schema if not schema.get('$ref') else None
                    }
            
            endpoint_data["responses"][status_code] = response_data

        endpoints.append(endpoint_data)

    # ----- Write or update spec file in the tests folder -----
    tests_folder = 'tests'
    # Create the tests folder if it doesn't exist
    if not os.path.exists(tests_folder):
        os.makedirs(tests_folder)
    
    # Build the file path based on the spec name
    file_path = os.path.join(tests_folder, f"{spec_name}.json")
    
    # Write (or update) the spec file; writing the entire spec object
    with open(file_path, 'w') as f:
        json.dump(spec, f, indent=4)
    # -------------------------------------------------------------

    return jsonify(endpoints)


@app.context_processor
def inject_uploaded_specs():
    return dict(uploaded_specs=uploaded_specs)

@app.route('/dashboard/<spec_name>')
def vulnerability_dashboard(spec_name):
    try:
        spec = uploaded_specs[spec_name]
        endpoints = spec['endpoints']
        
        severity_counts = {
            'total': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'untested': 0
        }
        
        for endpoint in endpoints:
            severity = endpoint.get('severity', 'untested').lower()
            if severity == 'critical':
                severity_counts['critical'] += 1
                severity_counts['total'] += 1
            elif severity == 'high':
                severity_counts['high'] += 1
                severity_counts['total'] += 1
            elif severity == 'medium':
                severity_counts['medium'] += 1
                severity_counts['total'] += 1
            elif severity == 'low':
                severity_counts['low'] += 1
                severity_counts['total'] += 1
            elif severity == 'untested':
                severity_counts['untested'] += 1
        
        filename = spec['original_filename']
        short_name = filename.split(' ')[0] if filename else spec_name
        
        return render_template('vulnerability_dashboard.html',
                                endpoints=endpoints,
                                spec_name=spec_name,
                                filename=filename,
                                short_name=short_name,
                                severity_counts=severity_counts)
    
    except KeyError:
        flash(f"Specification '{spec_name}' not found", "error")
        return redirect(url_for('index'))

@app.route('/run-tests', methods=['POST'])
def run_tests():
    try:
        # Parse form data (for file support)
        spec_id = request.form.get('spec_id')
        selected_tests = request.form.getlist('tests')
        
        if not selected_tests:
            logger.error("No tests selected")
            return jsonify({"error": "At least one test must be selected"}), 400

        spec = uploaded_specs.get(spec_id)
        if not spec:
            logger.error(f"Specification not found: {spec_id}")
            return jsonify({"error": "Specification not found"}), 404

        findings = []

        # Run header security tests
        if 'headers' in selected_tests:
            logger.info("Running header security tests")
            try:
                tester = AdvancedHeaderTester(
                    target_url=base_url,
                    vulners_key=app.config.get('VULNERS_API_KEY')
                )
                tester.establish_baseline()
                tester.test_header_manipulation()
                tester.analyze_server_header()
                tester.check_security_headers()
                
                # Format findings for dashboard
                for vuln in tester.vulnerabilities:
                    findings.append({
                        'type': vuln['type'],
                        'severity': vuln['severity'].capitalize(),
                        'message': vuln['message'],
                        'details': {
                            'method': 'GET',  # Header tests use GET by default
                            'path': '/',       # Base URL path
                            'cvss': self.get_cvss_score(vuln),
                            'test_type': 'Header Analysis'
                        }
                    })
            except Exception as e:
                logger.error(f"Header test failed: {str(e)}")
                findings.append({
                    'type': 'Header Test Error',
                    'severity': 'High',
                    'message': f'Header tests failed: {str(e)}'
                })

        # Process files
        file_data = {}
        for file_field in ['bruteforce_file', 'endpoints_file', 'injection_file', 'jwt_file']:
            if file_field in request.files:
                file = request.files[file_field]
                if file.filename and allowed_test_file(file.filename):
                    content = file.read().decode('utf-8')
                    file_data[file_field] = {
                        'content': content,
                        'lines': len(content.splitlines())
                    }
                    logger.info(f"Processed {file_field} with {file_data[file_field]['lines']} lines")

        # Authentication tests
        if 'auth' in selected_tests:
            logger.info("Running authentication tests")
            content = file_data.get('bruteforce_file', {}).get('content')
            findings += run_auth_tests(spec_id, content) if content else run_auth_tests(spec_id)
            
        
        # New endpoint discovery tests
        if 'findnew' in selected_tests:
            logger.info("Running endpoint discovery tests")
            base_url = spec.get('base_url', '')
            if not base_url:
                return jsonify({"error": "Base URL required for findnew tests"}), 400

            # Try to get wordlist from endpoints_file or use default
            endpoints_content = None
            if 'endpoints_file' in file_data:
                endpoints_content = file_data['endpoints_file'].get('content')
            
            if not endpoints_content:
                logger.info("Using default wordlist from wordlist/api.txt")
                try:
                    with open('wordlist/api.txt', 'r') as f:
                        endpoints_content = f.read()
                except IOError as e:
                    error_msg = f"Default wordlist not found: {str(e)}"
                    logger.error(error_msg)
                    return jsonify({
                        "error": "No endpoints file provided and default wordlist missing (wordlist/api.txt)"
                    }), 400

            wordlist = [line.strip() for line in endpoints_content.splitlines() if line.strip()]
            if not wordlist:
                return jsonify({"error": "Wordlist is empty (both provided and default)"}), 400

            # Get custom headers
            try:
                headers = json.loads(request.form.get('headers', '{}'))
            except json.JSONDecodeError:
                headers = {}

            # Run brute force discovery
            try:
                found_endpoints = bruteforce(
                    spec_dict=spec,
                    base_url=base_url,
                    wordlist=wordlist,
                    headers=headers,
                    delay=0.1,
                    timeout=5,
                    workers=10,
                    verbose=app.config.get('DEBUG', False)
                )
            except Exception as e:
                logger.error(f"Bruteforce failed: {str(e)}")
                findings.append({
                    'type': 'Discovery Error',
                    'severity': 'High',
                    'message': f'Endpoint discovery failed: {str(e)}'
                })
            else:
                for endpoint in found_endpoints:
                    severity = 'Medium'
                    if endpoint['status_code'] in [200, 201]:
                        severity = 'High'
                    elif endpoint['status_code'] in [403, 401]:
                        severity = 'Low'
                    
                    findings.append({
                        'type': 'New Endpoint',
                        'severity': severity,
                        'message': f"Discovered {endpoint['method']} {endpoint['path']} ({endpoint['status_code']})",
                        'details': endpoint
                    })


        # SQL Injection tests
        if 'sql' in selected_tests:
            logger.info("Running SQL injection tests")
            content = file_data.get('injection_file', {}).get('content')
            findings += run_sqli_tests(spec_id, content) if content else run_sqli_tests(spec_id)

        stats = {
            'total_tested': len(findings),
            'critical': sum(1 for f in findings if f['severity'].lower() == 'critical'),
            'high': sum(1 for f in findings if f['severity'].lower() == 'high'),
            'medium': sum(1 for f in findings if f['severity'].lower() == 'medium'),
            'low': sum(1 for f in findings if f['severity'].lower() == 'low')
        }

        save_test_results(spec_id, findings, stats)
        # Return final result
        return jsonify({
            'status': 'completed',
            'spec_id': spec_id,
            'selected_tests': selected_tests,
            'findings': findings,
            'stats': stats,
            'timestamp': datetime.now().isoformat()
        })

    except KeyError as ke:
        logger.error(f"Missing key in request: {str(ke)}")
        return jsonify({"error": f"Missing parameter: {str(ke)}"}), 400
    except Exception as e:
        logger.error(f"Test execution failed: {str(e)}", exc_info=True)
        return jsonify({"error": f"Test failed: {str(e)}"}), 500
def run_auth_tests(spec_id, brute_content=None):
    spec = uploaded_specs.get(spec_id)
    if not spec:
        logger.error(f"Specification not found for auth tests: {spec_id}")
        return []

    base_url = spec.get('base_url', '')
    if not base_url:
        logger.error("Base URL required for authentication tests")
        return []

    findings = []
    session = requests.Session()
    session.verify = False  # Disable SSL verification for testing

    # Get security schemes from OpenAPI spec
    security_schemes = spec.get('components', {}).get('securitySchemes', {})

    for path, path_item in spec.get('paths', {}).items():
        for method, operation in path_item.items():
            if method.lower() not in ['get', 'post', 'put', 'delete', 'patch']:
                continue

            # Get security requirements for this operation
            operation_security = operation.get('security', [])
            global_security = spec.get('security', [])
            security_requirements = operation_security or global_security

            if not security_requirements:
                continue  # No auth required by spec

            # Test endpoint without any authentication
            try:
                url = urljoin(base_url, path)
                response = session.request(
                    method=method.upper(),
                    url=url,
                    headers={'User-Agent': 'SecurityScanner/1.0'},
                    timeout=10
                )

                if response.status_code < 400:
                    findings.append(create_auth_finding(
                        method, path, response,
                        "Endpoint accessible without authentication",
                        "Missing Authentication"
                    ))

                # Test with invalid credentials
                invalid_headers = generate_invalid_headers(security_requirements, security_schemes)
                response_invalid = session.request(
                    method=method.upper(),
                    url=url,
                    headers=invalid_headers,
                    timeout=10
                )

                if response_invalid.status_code < 400:
                    findings.append(create_auth_finding(
                        method, path, response_invalid,
                        "Endpoint accessible with invalid authentication",
                        "Weak Authentication Validation"
                    ))

            except Exception as e:
                logger.error(f"Auth test failed for {method} {path}: {str(e)}")

    return findings

def generate_invalid_headers(security_requirements, security_schemes):
    headers = {}
    for requirement in security_requirements:
        for scheme_name, _ in requirement.items():
            scheme = security_schemes.get(scheme_name, {})
            scheme_type = scheme.get('type', '')
            name = scheme.get('name', 'Authorization')
            location = scheme.get('in', 'header')

            if location.lower() != 'header':
                continue

            if scheme_type == 'http' and scheme.get('scheme', '') == 'bearer':
                headers[name] = 'Bearer invalid_token_123'
            elif scheme_type == 'apiKey':
                headers[name] = 'invalid_api_key_123'
            elif scheme_type == 'http' and scheme.get('scheme', '') == 'basic':
                headers[name] = 'Basic ' + base64.b64encode(b'invalid:credentials').decode()
            else:
                headers[name] = 'invalid_auth_header'

    return headers

def create_auth_finding(method, path, response, message, vuln_type):
    return {
        'type': vuln_type,
        'severity': 'High',
        'message': f'{method} {path} - {message} (Status: {response.status_code})',
        'details': {
            'endpoint': f'{method} {path}',
            'status_code': response.status_code,
            'response_time': response.elapsed.total_seconds(),
            'headers': dict(response.headers),
            'body_sample': response.text[:500],
            'vulnerability': 'Authentication Bypass Possible',
            'recommendation': 'Implement proper authentication and authorization checks'
        }
    }    
def get_cvss_score(vuln):
    if vuln['type'] == 'Vulnerable Server' and vuln.get('cves'):
        return max([cve.get('cvss', 0) for cve in vuln['cves']])
    return {
        'Critical': 9.0,
        'High': 7.0,
        'Medium': 5.0,
        'Low': 3.0
    }.get(vuln['severity'], 0.0)
@app.route('/dashboard')
def dashboard():
    # Get all test runs with proper error handling
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM test_runs ORDER BY created_at DESC')
        raw_runs = c.fetchall()
    except Exception as e:
        print(f"Database error: {str(e)}")
        raw_runs = []
    finally:
        if conn:
            conn.close()

    # Process results
    test_runs = []
    for run in raw_runs:
        try:
            test_runs.append({
                'id': run['id'],
                'spec_id': run['spec_id'],
                'selected_tests': json.loads(run['selected_tests']),
                'findings': json.loads(run['findings']),
                'stats': json.loads(run['stats']),
                'created_at': datetime.strptime(run['created_at'], '%Y-%m-%d %H:%M:%S.%f')
            })
        except json.JSONDecodeError:
            continue  # Skip invalid entries

    return render_template('vulnerability_dashboard.html', test_runs=test_runs)

@app.template_filter('first_word')
def first_word_filter(s):
    return s.split(' ')[0]


if __name__ == '__main__':
    app.run(debug=True)


