"""
Vercel serverless function handler for Flask app
"""
import sys
import os
import io
import traceback

# Add parent directory to Python path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)

# Try to import app, but handle errors gracefully
try:
    from app import app
except Exception as e:
    # If import fails, create a minimal error handler
    print(f"Error importing app: {e}", file=sys.stderr)
    print(traceback.format_exc(), file=sys.stderr)
    
    # Create a minimal Flask app for error reporting
    from flask import Flask
    app = Flask(__name__)
    
    @app.route('/')
    def error():
        return f"Error loading application: {str(e)}", 500

def handler(request):
    """
    Vercel serverless function handler
    """
    try:
        # Vercel request object attributes
        method = getattr(request, 'method', 'GET') or 'GET'
        path = getattr(request, 'path', '/') or '/'
        query_string = getattr(request, 'query_string', '') or ''
        headers = getattr(request, 'headers', {}) or {}
        body = getattr(request, 'body', b'') or b''
        url = getattr(request, 'url', '') or ''
        
        # Extract path from URL if path is not set correctly
        if not path or path == '/' and url:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                path = parsed.path or '/'
                query_string = parsed.query or ''
            except:
                pass
        
        # Build WSGI environ
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
        
        # Add all headers to environ
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
        
        # Collect response body
        body_parts = []
        try:
            for chunk in body_iter:
                if chunk:
                    if isinstance(chunk, bytes):
                        body_parts.append(chunk)
                    else:
                        body_parts.append(str(chunk).encode('utf-8'))
        except Exception as e:
            print(f"Error reading body: {e}", file=sys.stderr)
        
        body_bytes = b''.join(body_parts)
        
        # Parse status code
        status_code = 200
        if status[0]:
            try:
                status_code = int(status[0].split()[0])
            except:
                status_code = 200
        
        # Convert headers to dict
        headers_dict = {}
        if response_headers[0]:
            headers_dict = {k: v for k, v in response_headers[0]}
        
        # Return response
        return {
            'statusCode': status_code,
            'headers': headers_dict,
            'body': body_bytes.decode('utf-8', errors='ignore')
        }
        
    except Exception as e:
        error_msg = f"Handler Error: {str(e)}\n{traceback.format_exc()}"
        print(error_msg, file=sys.stderr)
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'text/plain; charset=utf-8'},
            'body': error_msg
        }
