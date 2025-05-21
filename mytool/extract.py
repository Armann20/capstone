import json
import sys
from collections import defaultdict

def extract_unique_parameters(openapi_file):
    """Extract all unique parameter names from OpenAPI spec"""
    with open(openapi_file, 'r') as f:
        try:
            spec = json.load(f)
            api_spec = spec.get('content', spec)  # Handle wrapped formats
        except json.JSONDecodeError:
            print("Error: Invalid JSON file")
            sys.exit(1)

    unique_params = set()

    for path, methods in api_spec.get('paths', {}).items():
        if not isinstance(methods, dict):
            continue  # Skip if methods isn't a dictionary
            
        for method, details in methods.items():
            if not isinstance(details, dict):
                continue  # Skip if details isn't a dictionary

            # Handle parameters (could be list or dict)
            parameters = details.get('parameters', [])
            if isinstance(parameters, list):
                for param in parameters:
                    if isinstance(param, dict) and param.get('in') in ['path', 'query']:
                        unique_params.add(param['name'])
            elif isinstance(parameters, dict):
                if parameters.get('in') in ['path', 'query']:
                    unique_params.add(parameters['name'])

            # Request body parameters
            if 'requestBody' in details:
                content = details['requestBody'].get('content', {})
                for media_type in content.values():
                    if isinstance(media_type, dict) and 'schema' in media_type:
                        schema = media_type['schema']
                        if isinstance(schema, dict):
                            if 'properties' in schema:
                                if isinstance(schema['properties'], dict):
                                    unique_params.update(schema['properties'].keys())
                            if 'required' in schema and isinstance(schema['required'], list):
                                unique_params.update(schema['required'])

    return sorted(unique_params)

def main():
    if len(sys.argv) != 2:
        print("Usage: python unique_params.py <openapi_file>")
        sys.exit(1)

    params = extract_unique_parameters(sys.argv[1])
    
    print("UNIQUE PARAMETERS FOUND:")
    print("=" * 30)
    for param in params:
        print(f"- {param}")

if __name__ == "__main__":
    main()