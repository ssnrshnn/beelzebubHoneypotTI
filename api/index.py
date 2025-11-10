"""
Vercel serverless function handler for Flask app
Minimal implementation to avoid import crashes
"""
import sys
import os

# Add parent directory to Python path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Import with comprehensive error handling
app = None
import_error = None
import traceback

try:
    # Set working directory to ensure templates/static are found
    os.chdir(parent_dir)
    from app import app
    print("Successfully imported app", file=sys.stderr)
except ImportError as e:
    import_error = f"ImportError: {str(e)}"
    traceback.print_exc(file=sys.stderr)
    # Try to create minimal Flask app
    try:
        from flask import Flask
        app = Flask(__name__)
        @app.route('/')
        def error():
            return f"Import Error: {import_error}<pre>{traceback.format_exc()}</pre>", 500
    except Exception as e2:
        print(f"Failed to create error app: {e2}", file=sys.stderr)
        app = None
except Exception as e:
    import_error = f"Error: {str(e)}"
    traceback.print_exc(file=sys.stderr)
    try:
        from flask import Flask
        app = Flask(__name__)
        @app.route('/')
        def error():
            return f"Error loading app: {import_error}<pre>{traceback.format_exc()}</pre>", 500
    except:
        app = None

def handler(request):
    """
    Vercel serverless function handler
    """
    # Check if app was imported successfully
    if app is None:
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'text/plain; charset=utf-8'},
            'body': f'Application failed to load. Import error: {import_error or "Unknown error"}'
        }
    
    try:
        # Get request attributes - handle different Vercel request formats
        method = 'GET'
        path = '/'
        query_string = ''
        headers = {}
        body = b''
        
        # Try different ways to access request
        if hasattr(request, 'method'):
            method = request.method or 'GET'
        elif hasattr(request, 'httpMethod'):
            method = request.httpMethod or 'GET'
            
        if hasattr(request, 'path'):
            path = request.path or '/'
        elif hasattr(request, 'rawPath'):
            path = request.rawPath or '/'
        elif hasattr(request, 'url'):
            from urllib.parse import urlparse
            parsed = urlparse(request.url)
            path = parsed.path or '/'
            query_string = parsed.query or ''
        
        if hasattr(request, 'query_string'):
            query_string = request.query_string or ''
        elif hasattr(request, 'rawQueryString'):
            query_string = request.rawQueryString or ''
            
        if hasattr(request, 'headers'):
            headers = request.headers or {}
        elif hasattr(request, 'multiValueHeaders'):
            # Convert multiValueHeaders to single value headers
            headers = {}
            for k, v in (request.multiValueHeaders or {}).items():
                headers[k] = v[0] if isinstance(v, list) and v else v
        
        if hasattr(request, 'body'):
            body = request.body or b''
        elif hasattr(request, 'rawBody'):
            body = request.rawBody or b''
        
        # Build WSGI environ
        import io
        environ = {
            'REQUEST_METHOD': method.upper(),
            'SCRIPT_NAME': '',
            'PATH_INFO': path,
            'QUERY_STRING': query_string,
            'CONTENT_TYPE': headers.get('content-type', ''),
            'CONTENT_LENGTH': str(len(body)),
            'SERVER_NAME': headers.get('host', 'localhost'),
            'SERVER_PORT': '80',
            'SERVER_PROTOCOL': 'HTTP/1.1',
            'wsgi.version': (1, 0),
            'wsgi.url_scheme': 'https' if headers.get('x-forwarded-proto') == 'https' else 'http',
            'wsgi.input': io.BytesIO(body) if body else io.BytesIO(b''),
            'wsgi.errors': sys.stderr,
            'wsgi.multithread': False,
            'wsgi.multiprocess': True,
            'wsgi.run_once': False,
        }
        
        # Add headers
        for key, value in headers.items():
            key_upper = key.upper().replace('-', '_')
            if key_upper not in ('CONTENT_TYPE', 'CONTENT_LENGTH'):
                environ[f'HTTP_{key_upper}'] = value
        
        # Response storage
        status = [None]
        response_headers = [None]
        
        def start_response(response_status, headers_list):
            status[0] = response_status
            response_headers[0] = headers_list
        
        # Call Flask app
        body_iter = app(environ, start_response)
        
        # Collect response
        body_parts = []
        for chunk in body_iter:
            if chunk:
                body_parts.append(chunk if isinstance(chunk, bytes) else str(chunk).encode('utf-8'))
        
        body_bytes = b''.join(body_parts)
        
        # Parse status
        status_code = 200
        if status[0]:
            try:
                status_code = int(status[0].split()[0])
            except:
                pass
        
        # Convert headers
        headers_dict = {k: v for k, v in (response_headers[0] or [])}
        
        return {
            'statusCode': status_code,
            'headers': headers_dict,
            'body': body_bytes.decode('utf-8', errors='ignore')
        }
        
    except Exception as e:
        import traceback
        error_msg = f"Handler Error: {str(e)}\n{traceback.format_exc()}"
        print(error_msg, file=sys.stderr)
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'text/plain; charset=utf-8'},
            'body': error_msg
        }
