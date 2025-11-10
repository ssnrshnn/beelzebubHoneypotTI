"""
Vercel serverless function handler for Flask app
"""
import sys
import os
import io
import json

# Add parent directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

def handler(request):
    """
    Vercel serverless function handler
    """
    try:
        # Get request attributes (Vercel format)
        method = getattr(request, 'method', 'GET')
        path = getattr(request, 'path', '/')
        query_string = getattr(request, 'query_string', '') or ''
        headers = getattr(request, 'headers', {}) or {}
        body = getattr(request, 'body', b'') or b''
        
        # Build WSGI environ
        environ = {
            'REQUEST_METHOD': method,
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
        
        # Add all headers
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
        for chunk in body_iter:
            if chunk:
                if isinstance(chunk, bytes):
                    body_parts.append(chunk)
                else:
                    body_parts.append(chunk.encode('utf-8'))
        
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
        import traceback
        error_msg = f"Handler Error: {str(e)}\n{traceback.format_exc()}"
        print(error_msg, file=sys.stderr)
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'text/plain'},
            'body': error_msg
        }
