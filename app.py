#!/usr/bin/env python3
"""
Beelzebub Honeypot Dashboard
A comprehensive dashboard for analyzing honeypot logs with advanced filtering
"""

from flask import Flask, render_template, jsonify, request, Response
from datetime import datetime, timedelta
import json
from collections import Counter, defaultdict
import re
import csv
import io
import os
import tempfile

# Set Flask app with explicit paths for Vercel compatibility
app = Flask(
    __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path='/static'
)

# Global variable to cache log data
log_data = []
LOG_FILE = 'beelzebub.log'


def load_logs_from_content(content):
    """Load and parse log data from string content"""
    global log_data
    log_data = []
    
    for line_num, line in enumerate(content.split('\n'), 1):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            entry['line_number'] = line_num
            log_data.append(entry)
        except json.JSONDecodeError:
            print(f"Warning: Could not parse line {line_num}")
            continue
    
    return log_data


def load_logs():
    """Load and parse log file from multiple sources (URL, env var, or local file)"""
    global log_data
    log_data = []
    
    # Try loading from URL first (for Vercel/external storage)
    log_url = os.environ.get('LOG_FILE_URL')
    if log_url:
        try:
            import requests
            response = requests.get(log_url, timeout=30)
            if response.status_code == 200:
                print(f"Loading log file from URL: {log_url}")
                return load_logs_from_content(response.text)
        except ImportError:
            print("requests library not available for URL loading")
        except Exception as e:
            print(f"Error loading from URL: {e}")
    
    # Try loading from environment variable (for small files)
    log_content = os.environ.get('BEELZEBUB_LOG_CONTENT')
    if log_content:
        try:
            import base64
            # Check if it's base64 encoded
            if log_content.startswith('base64:'):
                decoded = base64.b64decode(log_content[7:]).decode('utf-8')
                print("Loading log file from environment variable (base64)")
                return load_logs_from_content(decoded)
            else:
                print("Loading log file from environment variable")
                return load_logs_from_content(log_content)
        except Exception as e:
            print(f"Error loading from environment variable: {e}")
    
    # Fallback to local file (for development)
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            print(f"Loading log file from local file: {LOG_FILE}")
            content = f.read()
            return load_logs_from_content(content)
    except FileNotFoundError:
        print(f"Warning: {LOG_FILE} not found. No log data loaded.")
        print("Tip: Set LOG_FILE_URL or BEELZEBUB_LOG_CONTENT environment variable, or upload a log file via /api/upload-log")
    
    return log_data


def parse_datetime(dt_str):
    """Parse ISO datetime string"""
    try:
        return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
    except:
        return None


@app.route('/api/upload-log', methods=['POST'])
def upload_log():
    """Upload log file via POST request"""
    global log_data
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Read file content
    try:
        content = file.read().decode('utf-8')
        load_logs_from_content(content)
        return jsonify({
            'message': 'Log file uploaded successfully',
            'entries': len(log_data)
        })
    except Exception as e:
        return jsonify({'error': f'Error processing file: {str(e)}'}), 500


@app.route('/api/log-status')
def log_status():
    """Check if log data is loaded"""
    return jsonify({
        'loaded': len(log_data) > 0,
        'entries': len(log_data)
    })


@app.route('/')
def index():
    """Render main dashboard page"""
    # Lazy load logs on first request if not already loaded
    global log_data
    if not log_data:
        try:
            load_logs()
        except Exception as e:
            print(f"Warning: Could not load logs: {e}")
    return render_template('index.html')


@app.route('/api/logs')
def get_logs():
    """Get filtered log entries with pagination"""
    # Get filter parameters
    protocol = request.args.get('protocol', '')
    level = request.args.get('level', '')
    source_ip = request.args.get('source_ip', '')
    description = request.args.get('description', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    search = request.args.get('search', '')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    
    # Filter logs
    filtered_logs = log_data.copy()
    
    # Apply filters
    if protocol:
        filtered_logs = [log for log in filtered_logs 
                        if log.get('event', {}).get('Protocol', '') == protocol]
    
    if level:
        filtered_logs = [log for log in filtered_logs 
                        if log.get('level', '') == level]
    
    if source_ip:
        filtered_logs = [log for log in filtered_logs 
                        if log.get('event', {}).get('SourceIp', '') == source_ip]
    
    if description:
        filtered_logs = [log for log in filtered_logs 
                        if description.lower() in log.get('event', {}).get('Description', '').lower()]
    
    # Date range filter
    if start_date:
        start_dt = datetime.fromisoformat(start_date)
        filtered_logs = [log for log in filtered_logs 
                        if parse_datetime(log.get('time', '')) and 
                        parse_datetime(log.get('time', '')) >= start_dt]
    
    if end_date:
        end_dt = datetime.fromisoformat(end_date)
        filtered_logs = [log for log in filtered_logs 
                        if parse_datetime(log.get('time', '')) and 
                        parse_datetime(log.get('time', '')) <= end_dt]
    
    # Search across multiple fields
    if search:
        search_lower = search.lower()
        filtered_logs = [log for log in filtered_logs 
                        if search_lower in json.dumps(log).lower()]
    
    # Pagination
    total = len(filtered_logs)
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_logs = filtered_logs[start_idx:end_idx]
    
    return jsonify({
        'logs': paginated_logs,
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': (total + per_page - 1) // per_page
    })


@app.route('/api/statistics')
def get_statistics():
    """Get overall statistics"""
    stats = {
        'total_events': len(log_data),
        'protocols': Counter(),
        'levels': Counter(),
        'source_ips': Counter(),
        'descriptions': Counter(),
        'http_methods': Counter(),
        'top_paths': Counter(),
        'user_agents': Counter(),
        'timeline': defaultdict(int),
        'ports': Counter(),
        'status_codes': Counter()
    }
    
    for entry in log_data:
        # Basic stats
        level = entry.get('level', 'unknown')
        stats['levels'][level] += 1
        
        # Event stats
        event = entry.get('event', {})
        if event:
            protocol = event.get('Protocol', 'unknown')
            stats['protocols'][protocol] += 1
            
            source_ip = event.get('SourceIp', 'unknown')
            if source_ip != 'unknown':
                stats['source_ips'][source_ip] += 1
            
            description = event.get('Description', 'unknown')
            stats['descriptions'][description] += 1
            
            http_method = event.get('HTTPMethod', '')
            if http_method:
                stats['http_methods'][http_method] += 1
            
            request_uri = event.get('RequestURI', '')
            if request_uri:
                stats['top_paths'][request_uri] += 1
            
            user_agent = event.get('UserAgent', '')
            if user_agent:
                # Truncate long user agents
                ua_short = user_agent[:50] + '...' if len(user_agent) > 50 else user_agent
                stats['user_agents'][ua_short] += 1
            
            status = event.get('Status', '')
            if status:
                stats['status_codes'][status] += 1
        
        # Port stats
        port = entry.get('port', '')
        if port:
            stats['ports'][port] += 1
        
        # Timeline
        timestamp = entry.get('time', '')
        if timestamp:
            dt = parse_datetime(timestamp)
            if dt:
                date_key = dt.strftime('%Y-%m-%d %H:00')
                stats['timeline'][date_key] += 1
    
    # Convert to lists for JSON
    return jsonify({
        'total_events': stats['total_events'],
        'protocols': dict(stats['protocols'].most_common(10)),
        'levels': dict(stats['levels']),
        'top_ips': dict(stats['source_ips'].most_common(10)),
        'descriptions': dict(stats['descriptions'].most_common(10)),
        'http_methods': dict(stats['http_methods']),
        'top_paths': dict(stats['top_paths'].most_common(20)),
        'top_user_agents': dict(stats['user_agents'].most_common(10)),
        'timeline': dict(sorted(stats['timeline'].items())),
        'ports': dict(stats['ports'].most_common(10)),
        'status_codes': dict(stats['status_codes'].most_common(10))
    })


@app.route('/api/filter-options')
def get_filter_options():
    """Get available filter options"""
    protocols = set()
    levels = set()
    source_ips = set()
    descriptions = set()
    
    for entry in log_data:
        levels.add(entry.get('level', ''))
        event = entry.get('event', {})
        if event:
            protocols.add(event.get('Protocol', ''))
            source_ips.add(event.get('SourceIp', ''))
            descriptions.add(event.get('Description', ''))
    
    return jsonify({
        'protocols': sorted(list(protocols - {''})),
        'levels': sorted(list(levels - {''})),
        'source_ips': sorted(list(source_ips - {''})),
        'descriptions': sorted(list(descriptions - {''}))
    })


@app.route('/api/event/<int:line_number>')
def get_event_detail(line_number):
    """Get detailed information about a specific event"""
    for entry in log_data:
        if entry.get('line_number') == line_number:
            return jsonify(entry)
    
    return jsonify({'error': 'Event not found'}), 404


@app.route('/api/ip-analysis/<ip>')
def analyze_ip(ip):
    """Analyze activities from a specific IP"""
    ip_logs = [log for log in log_data 
               if log.get('event', {}).get('SourceIp', '') == ip]
    
    stats = {
        'total_requests': len(ip_logs),
        'protocols': Counter(),
        'descriptions': Counter(),
        'paths': Counter(),
        'methods': Counter(),
        'timeline': defaultdict(int),
        'first_seen': None,
        'last_seen': None
    }
    
    for entry in ip_logs:
        event = entry.get('event', {})
        if event:
            stats['protocols'][event.get('Protocol', 'unknown')] += 1
            stats['descriptions'][event.get('Description', 'unknown')] += 1
            stats['paths'][event.get('RequestURI', '')] += 1
            stats['methods'][event.get('HTTPMethod', '')] += 1
        
        timestamp = entry.get('time', '')
        if timestamp:
            dt = parse_datetime(timestamp)
            if dt:
                if not stats['first_seen'] or dt < stats['first_seen']:
                    stats['first_seen'] = dt
                if not stats['last_seen'] or dt > stats['last_seen']:
                    stats['last_seen'] = dt
                
                date_key = dt.strftime('%Y-%m-%d %H:%M')
                stats['timeline'][date_key] += 1
    
    return jsonify({
        'ip': ip,
        'total_requests': stats['total_requests'],
        'protocols': dict(stats['protocols']),
        'descriptions': dict(stats['descriptions']),
        'top_paths': dict(stats['paths'].most_common(10)),
        'methods': dict(stats['methods']),
        'timeline': dict(sorted(stats['timeline'].items())),
        'first_seen': stats['first_seen'].isoformat() if stats['first_seen'] else None,
        'last_seen': stats['last_seen'].isoformat() if stats['last_seen'] else None
    })


@app.route('/api/all-ips')
def get_all_ips():
    """Get all unique IP addresses with statistics"""
    ip_stats = defaultdict(lambda: {
        'count': 0,
        'first_seen': None,
        'last_seen': None,
        'protocols': set(),
        'descriptions': set()
    })
    
    for entry in log_data:
        event = entry.get('event', {})
        source_ip = event.get('SourceIp', '')
        
        if source_ip and source_ip != 'unknown':
            stats = ip_stats[source_ip]
            stats['count'] += 1
            
            timestamp = entry.get('time', '')
            if timestamp:
                dt = parse_datetime(timestamp)
                if dt:
                    if not stats['first_seen'] or dt < stats['first_seen']:
                        stats['first_seen'] = dt
                    if not stats['last_seen'] or dt > stats['last_seen']:
                        stats['last_seen'] = dt
            
            protocol = event.get('Protocol', '')
            if protocol:
                stats['protocols'].add(protocol)
            
            description = event.get('Description', '')
            if description:
                stats['descriptions'].add(description)
    
    # Convert to list format
    result = []
    for ip, stats in ip_stats.items():
        result.append({
            'ip': ip,
            'count': stats['count'],
            'first_seen': stats['first_seen'].isoformat() if stats['first_seen'] else None,
            'last_seen': stats['last_seen'].isoformat() if stats['last_seen'] else None,
            'protocols': sorted(list(stats['protocols'])),
            'descriptions': sorted(list(stats['descriptions']))
        })
    
    # Sort by count descending
    result.sort(key=lambda x: x['count'], reverse=True)
    
    return jsonify(result)


@app.route('/api/credentials')
def get_credentials():
    """Get username and password combinations with pagination"""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    
    # Simple aggregation: count attempts per credential combination
    cred_counts = defaultdict(lambda: {'count': 0, 'source_ips': set()})
    
    for entry in log_data:
        event = entry.get('event', {})
        user = event.get('User', '')
        password = event.get('Password', '')
        source_ip = event.get('SourceIp', '')
        
        if user or password:
            # Create a key for the credential combination
            cred_key = f"{user or '(empty)'}|||{password or '(empty)'}"
            cred_counts[cred_key]['count'] += 1
            if source_ip:
                cred_counts[cred_key]['source_ips'].add(source_ip)
    
    # Convert to list format
    result = []
    for cred_key, stats in cred_counts.items():
        user, password = cred_key.split('|||')
        result.append({
            'username': user if user != '(empty)' else '',
            'password': password if password != '(empty)' else '',
            'count': stats['count'],
            'source_ips': sorted(list(stats['source_ips']))
        })
    
    # Sort by count descending
    result.sort(key=lambda x: x['count'], reverse=True)
    
    # Pagination
    total = len(result)
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_result = result[start_idx:end_idx]
    
    return jsonify({
        'credentials': paginated_result,
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': (total + per_page - 1) // per_page
    })


@app.route('/api/export/ips/<format>')
def export_ips(format):
    """Export all IP addresses in specified format"""
    if format not in ['txt', 'csv', 'json']:
        return jsonify({'error': 'Invalid format'}), 400
    
    # Get all IPs (same logic as /api/all-ips but without pagination)
    ip_stats = defaultdict(lambda: {
        'count': 0,
        'first_seen': None,
        'last_seen': None,
        'protocols': set(),
        'descriptions': set()
    })
    
    for entry in log_data:
        event = entry.get('event', {})
        source_ip = event.get('SourceIp', '')
        
        if source_ip and source_ip != 'unknown':
            stats = ip_stats[source_ip]
            stats['count'] += 1
            
            timestamp = entry.get('time', '')
            if timestamp:
                dt = parse_datetime(timestamp)
                if dt:
                    if not stats['first_seen'] or dt < stats['first_seen']:
                        stats['first_seen'] = dt
                    if not stats['last_seen'] or dt > stats['last_seen']:
                        stats['last_seen'] = dt
            
            protocol = event.get('Protocol', '')
            if protocol:
                stats['protocols'].add(protocol)
            
            description = event.get('Description', '')
            if description:
                stats['descriptions'].add(description)
    
    # Convert to list and sort
    result = []
    for ip, stats in ip_stats.items():
        result.append({
            'ip': ip,
            'count': stats['count'],
            'first_seen': stats['first_seen'].isoformat() if stats['first_seen'] else '',
            'last_seen': stats['last_seen'].isoformat() if stats['last_seen'] else '',
            'protocols': ', '.join(sorted(stats['protocols'])),
            'descriptions': ', '.join(sorted(stats['descriptions']))
        })
    
    result.sort(key=lambda x: x['count'], reverse=True)
    
    # Format and return
    if format == 'txt':
        output = io.StringIO()
        for item in result:
            output.write(f"{item['ip']}\n")
        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/plain',
            headers={'Content-Disposition': 'attachment; filename=ip_addresses.txt'}
        )
    
    elif format == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['IP Address', 'Request Count', 'First Seen', 'Last Seen', 'Protocols', 'Services'])
        for item in result:
            writer.writerow([
                item['ip'],
                item['count'],
                item['first_seen'],
                item['last_seen'],
                item['protocols'],
                item['descriptions']
            ])
        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=ip_addresses.csv'}
        )
    
    elif format == 'json':
        return Response(
            json.dumps(result, indent=2),
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename=ip_addresses.json'}
        )


@app.route('/api/export/credentials/<format>')
def export_credentials(format):
    """Export all credentials in specified format"""
    if format not in ['txt', 'csv', 'json']:
        return jsonify({'error': 'Invalid format'}), 400
    
    # Get all credentials (same logic as /api/credentials but without pagination)
    cred_counts = defaultdict(lambda: {'count': 0, 'source_ips': set()})
    
    for entry in log_data:
        event = entry.get('event', {})
        user = event.get('User', '')
        password = event.get('Password', '')
        source_ip = event.get('SourceIp', '')
        
        if user or password:
            cred_key = f"{user or '(empty)'}|||{password or '(empty)'}"
            cred_counts[cred_key]['count'] += 1
            if source_ip:
                cred_counts[cred_key]['source_ips'].add(source_ip)
    
    # Convert to list and sort
    result = []
    for cred_key, stats in cred_counts.items():
        user, password = cred_key.split('|||')
        result.append({
            'username': user if user != '(empty)' else '',
            'password': password if password != '(empty)' else '',
            'count': stats['count'],
            'source_ips': ', '.join(sorted(stats['source_ips']))
        })
    
    result.sort(key=lambda x: x['count'], reverse=True)
    
    # Format and return
    if format == 'txt':
        output = io.StringIO()
        for item in result:
            output.write(f"{item['username']}:{item['password']}\n")
        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/plain',
            headers={'Content-Disposition': 'attachment; filename=credentials.txt'}
        )
    
    elif format == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Username', 'Password', 'Attempts', 'Source IPs'])
        for item in result:
            writer.writerow([
                item['username'],
                item['password'],
                item['count'],
                item['source_ips']
            ])
        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=credentials.csv'}
        )
    
    elif format == 'json':
        return Response(
            json.dumps(result, indent=2),
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename=credentials.json'}
        )


# Initialize log data on import (for Vercel)
# Note: In serverless, this runs on cold start
# Only load if explicitly requested to avoid errors on import
# Disable auto-loading on import to prevent crashes - load on first request instead
# if os.environ.get('VERCEL') or os.environ.get('LOG_FILE_URL') or os.environ.get('BEELZEBUB_LOG_CONTENT'):
#     try:
#         print("Vercel/serverless environment detected. Loading logs...")
#         load_logs()
#         print(f"Loaded {len(log_data)} log entries")
#     except Exception as e:
#         print(f"Warning: Could not load logs on import: {e}")
#         # Continue without logs - user can upload later

if __name__ == '__main__':
    print("Loading log data...")
    load_logs()
    print(f"Loaded {len(log_data)} log entries")
    print("Starting dashboard server...")
    app.run(debug=True, host='0.0.0.0', port=5000)

