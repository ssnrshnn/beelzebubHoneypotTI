#!/usr/bin/env python3
"""
Beelzebub Honeypot Dashboard
A comprehensive dashboard for analyzing honeypot logs with advanced filtering
"""

from flask import Flask, render_template, jsonify, request, Response
from datetime import datetime, timedelta, timezone
import json
from collections import Counter, defaultdict
import re
import csv
import io
import ipaddress
import os
import glob

app = Flask(__name__)

# Global variable to cache log data
log_data = []
LOG_DIR = 'logs'


def normalize_log_entry(entry, log_file_path):
    """
    Normalize log entry from different formats to a consistent structure.
    Handles:
    - Old format (with nested 'event')
    - New format (flat structure)
    - Suricata EVE JSON format
    """
    # Extract protocol and port from filename (e.g., 'logs/ssh-22.log' -> protocol='SSH', port='22')
    filename = os.path.basename(log_file_path)
    protocol_from_file = None
    port_from_file = None
    
    # Parse filename pattern: protocol-port.log
    match = re.match(r'^([a-zA-Z]+)-(\d+)\.log$', filename)
    if match:
        protocol_from_file = match.group(1).upper()
        port_from_file = match.group(2)
    
    # Handle Suricata EVE JSON format
    if 'event_type' in entry and 'timestamp' in entry:
        event_type = entry.get('event_type', '')
        src_ip = entry.get('src_ip', '')
        dest_ip = entry.get('dest_ip', '')
        src_port = entry.get('src_port', '')
        dest_port = entry.get('dest_port', '')
        proto = entry.get('proto', 'TCP')
        
        # Skip stats events (not useful for dashboard)
        if event_type == 'stats':
            return None
        
        # Determine protocol from event_type or proto
        protocol = event_type.upper() if event_type in ['SSH', 'HTTP', 'FTP', 'SMTP', 'TLS', 'DNS', 'SMB', 'RDP'] else proto
        
        # Build description based on event type
        description = f"Suricata {event_type.upper()}"
        if event_type == 'alert' and 'alert' in entry:
            alert = entry.get('alert', {})
            description = alert.get('signature', description)
            category = alert.get('category', '')
            if category:
                description += f" - {category}"
        elif event_type == 'http' and 'http' in entry:
            http = entry.get('http', {})
            description = f"HTTP {http.get('http_method', '')} {http.get('url', '')}"
        elif event_type == 'ssh' and 'ssh' in entry:
            ssh = entry.get('ssh', {})
            client = ssh.get('client', {})
            description = f"SSH Connection - {client.get('software_version', 'Unknown Client')}"
        
        normalized = {
            'level': 'info' if event_type != 'alert' else 'warning',
            'time': entry.get('timestamp', ''),
            'port': str(dest_port) if dest_port else port_from_file or '',
            'event': {
                'Protocol': protocol,
                'SourceIp': src_ip,
                'SourcePort': str(src_port) if src_port else '',
                'DestIp': dest_ip,
                'DestPort': str(dest_port) if dest_port else '',
                'Description': description,
            },
            'log_file': filename,
            'log_protocol': protocol,
            'log_port': str(dest_port) if dest_port else port_from_file or '',
            'suricata_event_type': event_type,
            'suricata_flow_id': entry.get('flow_id'),
        }
        
        # Add HTTP-specific fields
        if event_type == 'http' and 'http' in entry:
            http = entry.get('http', {})
            normalized['event']['HTTPMethod'] = http.get('http_method', '')
            normalized['event']['RequestURI'] = http.get('url', '')
            normalized['event']['UserAgent'] = http.get('http_user_agent', '')
            normalized['event']['Status'] = str(http.get('status', ''))
            normalized['event']['Hostname'] = http.get('hostname', '')
        
        # Add SSH-specific fields
        if event_type == 'ssh' and 'ssh' in entry:
            ssh = entry.get('ssh', {})
            client = ssh.get('client', {})
            server = ssh.get('server', {})
            normalized['event']['SSHClient'] = client.get('software_version', '')
            normalized['event']['SSHServer'] = server.get('software_version', '')
        
        # Add alert-specific fields
        if event_type == 'alert' and 'alert' in entry:
            alert = entry.get('alert', {})
            normalized['event']['AlertSignature'] = alert.get('signature', '')
            normalized['event']['AlertCategory'] = alert.get('category', '')
            normalized['event']['AlertSeverity'] = str(alert.get('severity', ''))
            normalized['level'] = 'error' if alert.get('severity', 0) >= 2 else 'warning'
        
        # Remove None/empty values from event
        normalized['event'] = {k: v for k, v in normalized['event'].items() if v}
        return normalized
    
    # Handle new format (flat structure)
    elif 'protocol' in entry and 'source_ip' in entry:
        normalized = {
            'level': entry.get('level', 'info'),
            'time': entry.get('time', ''),
            'port': entry.get('port', port_from_file or ''),
            'event': {
                'Protocol': entry.get('protocol', protocol_from_file or ''),
                'SourceIp': entry.get('source_ip', ''),
                'SourcePort': entry.get('source_port', ''),
                'Description': entry.get('description', ''),
                'Command': entry.get('command', ''),
                'User': entry.get('user', ''),
                'Password': entry.get('password', ''),
                'RequestURI': entry.get('request_uri', ''),
                'HTTPMethod': entry.get('http_method', ''),
                'UserAgent': entry.get('user_agent', ''),
                'Status': entry.get('status', ''),
            },
            'log_file': filename,
            'log_protocol': protocol_from_file or entry.get('protocol', ''),
            'log_port': port_from_file or entry.get('port', '')
        }
        # Remove None values from event
        normalized['event'] = {k: v for k, v in normalized['event'].items() if v}
        return normalized
    
    # Handle old format (nested event structure) - for backward compatibility
    elif 'event' in entry:
        normalized = entry.copy()
        normalized['log_file'] = filename
        normalized['log_protocol'] = protocol_from_file or normalized.get('event', {}).get('Protocol', '')
        normalized['log_port'] = port_from_file or normalized.get('port', '')
        return normalized
    
    # Unknown format - try to preserve as-is
    else:
        normalized = entry.copy()
        normalized['log_file'] = filename
        normalized['log_protocol'] = protocol_from_file or ''
        normalized['log_port'] = port_from_file or ''
        return normalized


def parse_suricata_fast_log(log_file):
    """
    Parse Suricata fast.log (plain text alert format)
    Format: timestamp [**] [sid:gid:rev] signature [**] [Classification] [Priority] {proto} src_ip:src_port -> dest_ip:dest_port
    """
    entries = []
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                # Parse fast.log format
                # Example: 12/05/2025-12:29:18.574479  [**] [1:2403346:104960] ET CINS Active Threat Intelligence Poor Reputation IP group 47 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 35.203.210.254:56066 -> 91.99.22.171:1800
                match = re.match(
                    r'(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+(.+?)\s+\[\*\*\]\s+\[Classification:\s*(.+?)\]\s+\[Priority:\s*(\d+)\]\s+\{(\w+)\}\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+):(\d+)',
                    line
                )
                
                if match:
                    timestamp_str, gid, sid, rev, signature, classification, priority, proto, src_ip, src_port, dest_ip, dest_port = match.groups()
                    
                    # Convert timestamp to ISO format
                    try:
                        # Parse: 12/05/2025-12:29:18.574479
                        dt = datetime.strptime(timestamp_str, '%m/%d/%Y-%H:%M:%S.%f')
                        timestamp = dt.replace(tzinfo=timezone.utc).isoformat()
                    except:
                        timestamp = datetime.now(timezone.utc).isoformat()
                    
                    entry = {
                        'timestamp': timestamp,
                        'event_type': 'alert',
                        'src_ip': src_ip,
                        'src_port': int(src_port),
                        'dest_ip': dest_ip,
                        'dest_port': int(dest_port),
                        'proto': proto,
                        'alert': {
                            'signature': signature,
                            'category': classification,
                            'severity': int(priority),
                            'gid': int(gid),
                            'signature_id': int(sid),
                            'rev': int(rev)
                        }
                    }
                    entries.append(entry)
    except Exception as e:
        print(f"Error parsing {os.path.basename(log_file)}: {str(e)}")
    
    return entries


def load_logs():
    """Load and parse all log files from logs directory"""
    global log_data
    log_data = []
    
    # Find all .log and .json files in logs directory
    log_pattern = os.path.join(LOG_DIR, '*.log')
    json_pattern = os.path.join(LOG_DIR, '*.json')
    log_files = glob.glob(log_pattern) + glob.glob(json_pattern)
    
    if not log_files:
        print(f"Warning: No log files found in {LOG_DIR}/ directory")
        return log_data
    
    total_lines = 0
    
    for log_file in sorted(log_files):
        try:
            filename = os.path.basename(log_file)
            
            # Handle Suricata fast.log (plain text format)
            if filename == 'fast.log':
                fast_entries = parse_suricata_fast_log(log_file)
                for entry in fast_entries:
                    normalized_entry = normalize_log_entry(entry, log_file)
                    if normalized_entry:  # Skip None entries (like stats)
                        total_lines += 1
                        normalized_entry['line_number'] = total_lines
                        log_data.append(normalized_entry)
                
                if len(fast_entries) > 0:
                    print(f"Loaded {len(fast_entries)} entries from {filename}")
                continue
            
            # Handle JSON files (including Suricata eve.json)
            with open(log_file, 'r', encoding='utf-8') as f:
                file_line_num = 0
                for line in f:
                    line = line.strip()
                    if not line:  # Skip empty lines
                        continue
                    
                    try:
                        entry = json.loads(line)
                        # Normalize entry to consistent format
                        normalized_entry = normalize_log_entry(entry, log_file)
                        
                        # Skip None entries (like Suricata stats events)
                        if normalized_entry is None:
                            continue
                        
                        # Add global line number for reference
                        total_lines += 1
                        normalized_entry['line_number'] = total_lines
                        log_data.append(normalized_entry)
                        file_line_num += 1
                    except json.JSONDecodeError:
                        # Skip non-JSON lines silently
                        # Only show warning if we've successfully parsed some lines (mixed format)
                        if file_line_num > 0 and file_line_num < 3:
                            print(f"Warning: Could not parse line {file_line_num + 1} in {filename}")
                        continue
                
                if file_line_num > 0:
                    print(f"Loaded {file_line_num} entries from {filename}")
                # Don't print anything for files with 0 entries (non-JSON format files)
        except FileNotFoundError:
            print(f"Warning: {log_file} not found")
            continue
        except Exception as e:
            print(f"Error reading {log_file}: {str(e)}")
            continue
    
    print(f"Total: Loaded {len(log_data)} log entries from {len(log_files)} files")
    return log_data


def parse_datetime(dt_str):
    """Parse ISO datetime string"""
    try:
        return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
    except:
        return None


@app.route('/')
def index():
    """Render main dashboard page"""
    return render_template('index.html')

@app.route('/events')
def events():
    """Render events page (Filters + Event Logs)"""
    return render_template('events.html')


@app.route('/api/logs')
def get_logs():
    """Get filtered log entries with pagination"""
    try:
        # Get filter parameters with error handling
        protocol = request.args.get('protocol', '')
        level = request.args.get('level', '')
        source_ip = request.args.get('source_ip', '')
        description = request.args.get('description', '')
        port = request.args.get('port', '')
        start_date = request.args.get('start_date', '')
        end_date = request.args.get('end_date', '')
        search = request.args.get('search', '')
        # Limit search string length to prevent DoS
        if len(search) > 500:
            search = search[:500]
        
        ssh_command_type = request.args.get('ssh_command_type', '')
        # Exclude parameters
        exclude_protocol = request.args.get('exclude_protocol', '')
        exclude_level = request.args.get('exclude_level', '')
        exclude_source_ip = request.args.get('exclude_source_ip', '')
        exclude_description = request.args.get('exclude_description', '')
        exclude_port = request.args.get('exclude_port', '')
        exclude_start_date = request.args.get('exclude_start_date', '')
        exclude_end_date = request.args.get('exclude_end_date', '')
        exclude_ssh_command_type = request.args.get('exclude_ssh_command_type', '')
        
        # Validate pagination parameters
        try:
            page = max(1, int(request.args.get('page', 1)))
        except (ValueError, TypeError):
            page = 1
        
        try:
            per_page = max(1, min(1000, int(request.args.get('per_page', 50))))  # Limit to 1000 per page
        except (ValueError, TypeError):
            per_page = 50
        
        # Filter logs
        filtered_logs = log_data.copy()
        
        # Apply include filters
        if protocol:
            # Handle Suricata protocol format (SURICATA_ALERT, SURICATA_SSH, etc.)
            if protocol.startswith('SURICATA_'):
                suricata_type = protocol.replace('SURICATA_', '').lower()
                filtered_logs = [log for log in filtered_logs 
                                if log.get('suricata_event_type', '').lower() == suricata_type]
            else:
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
        
        # Port filter
        if port:
            filtered_logs = [log for log in filtered_logs 
                            if str(port) == str(log.get('log_port') or log.get('port', '')) or
                            str(port) == str(log.get('event', {}).get('SourcePort', ''))]
        
        # SSH command type filter (only applies to SSH protocol logs)
        if ssh_command_type == 'with_commands':
            filtered_logs = [log for log in filtered_logs 
                            if log.get('event', {}).get('Protocol', '') == 'SSH' and
                            log.get('event', {}).get('Command', '').strip()]
        elif ssh_command_type == 'login_only':
            filtered_logs = [log for log in filtered_logs 
                            if log.get('event', {}).get('Protocol', '') == 'SSH' and
                            not log.get('event', {}).get('Command', '').strip()]
        
        # Date range filter with error handling
        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date)
                filtered_logs = [log for log in filtered_logs 
                                if parse_datetime(log.get('time', '')) and 
                                parse_datetime(log.get('time', '')) >= start_dt]
            except (ValueError, TypeError) as e:
                return jsonify({'error': f'Invalid start_date format: {str(e)}'}), 400
        
        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date)
                filtered_logs = [log for log in filtered_logs 
                                if parse_datetime(log.get('time', '')) and 
                                parse_datetime(log.get('time', '')) <= end_dt]
            except (ValueError, TypeError) as e:
                return jsonify({'error': f'Invalid end_date format: {str(e)}'}), 400
        
        # Apply exclude filters
        if exclude_protocol:
            # Handle Suricata protocol format (SURICATA_ALERT, SURICATA_SSH, etc.)
            if exclude_protocol.startswith('SURICATA_'):
                suricata_type = exclude_protocol.replace('SURICATA_', '').lower()
                filtered_logs = [log for log in filtered_logs 
                                if log.get('suricata_event_type', '').lower() != suricata_type]
            else:
                filtered_logs = [log for log in filtered_logs 
                                if log.get('event', {}).get('Protocol', '') != exclude_protocol]
        
        if exclude_level:
            filtered_logs = [log for log in filtered_logs 
                            if log.get('level', '') != exclude_level]
        
        if exclude_source_ip:
            filtered_logs = [log for log in filtered_logs 
                            if log.get('event', {}).get('SourceIp', '') != exclude_source_ip]
        
        if exclude_description:
            # Exclude description filter only applies to non-Suricata entries
            filtered_logs = [log for log in filtered_logs 
                            if log.get('suricata_event_type') is not None or
                            exclude_description.lower() not in log.get('event', {}).get('Description', '').lower()]
        
        # Exclude port filter
        if exclude_port:
            filtered_logs = [log for log in filtered_logs 
                            if str(exclude_port) != str(log.get('log_port') or log.get('port', '')) and
                            str(exclude_port) != str(log.get('event', {}).get('SourcePort', ''))]
        
        # Exclude SSH command type filter
        if exclude_ssh_command_type == 'with_commands':
            filtered_logs = [log for log in filtered_logs 
                            if not (log.get('event', {}).get('Protocol', '') == 'SSH' and
                                    log.get('event', {}).get('Command', '').strip())]
        elif exclude_ssh_command_type == 'login_only':
            filtered_logs = [log for log in filtered_logs 
                            if not (log.get('event', {}).get('Protocol', '') == 'SSH' and
                                    not log.get('event', {}).get('Command', '').strip())]
        
        # Exclude date range filter with error handling
        if exclude_start_date:
            try:
                exclude_start_dt = datetime.fromisoformat(exclude_start_date)
                filtered_logs = [log for log in filtered_logs 
                                if not parse_datetime(log.get('time', '')) or 
                                parse_datetime(log.get('time', '')) < exclude_start_dt]
            except (ValueError, TypeError) as e:
                return jsonify({'error': f'Invalid exclude_start_date format: {str(e)}'}), 400
        
        if exclude_end_date:
            try:
                exclude_end_dt = datetime.fromisoformat(exclude_end_date)
                filtered_logs = [log for log in filtered_logs 
                                if not parse_datetime(log.get('time', '')) or 
                                parse_datetime(log.get('time', '')) > exclude_end_dt]
            except (ValueError, TypeError) as e:
                return jsonify({'error': f'Invalid exclude_end_date format: {str(e)}'}), 400
        
        # Search across multiple fields with error handling
        if search:
            try:
                search_lower = search.lower()
                filtered_logs = [log for log in filtered_logs 
                                if search_lower in json.dumps(log).lower()]
            except Exception as e:
                # If JSON serialization fails, fall back to simple string search
                search_lower = search.lower()
                filtered_logs = [log for log in filtered_logs 
                                if search_lower in str(log).lower()]
        
        # Sort by time descending (newest first)
        try:
            def get_log_time(log):
                dt = parse_datetime(log.get('time', ''))
                return dt if dt else datetime.min.replace(tzinfo=timezone.utc)
            filtered_logs.sort(key=get_log_time, reverse=True)
        except Exception as e:
            # If sorting fails, return unsorted
            pass

        # Pagination with bounds checking
        total = len(filtered_logs)
        start_idx = max(0, (page - 1) * per_page)
        end_idx = min(total, start_idx + per_page)
        paginated_logs = filtered_logs[start_idx:end_idx]
        
        return jsonify({
            'logs': paginated_logs,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': max(1, (total + per_page - 1) // per_page) if total > 0 else 1
        })
    
    except Exception as e:
        app.logger.error(f'Error in get_logs: {str(e)}', exc_info=True)
        return jsonify({'error': 'An error occurred while processing your request', 'details': str(e)}), 500


# Cache for statistics (can be invalidated when logs reload)
_stats_cache = None
_stats_cache_time = None
CACHE_TTL_SECONDS = 60  # Cache statistics for 60 seconds

@app.route('/api/statistics')
def get_statistics():
    """Get overall statistics"""
    global _stats_cache, _stats_cache_time
    
    try:
        # Return cached statistics if available and not expired
        if _stats_cache and _stats_cache_time:
            cache_age = (datetime.now(timezone.utc) - _stats_cache_time).total_seconds()
            if cache_age < CACHE_TTL_SECONDS:
                return jsonify(_stats_cache)
        
        # Recalculate statistics
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
        result = {
            'total_events': stats['total_events'],
            'unique_ips': len(stats['source_ips']),
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
        }
        
        # Cache the result
        _stats_cache = result
        _stats_cache_time = datetime.now(timezone.utc)
        
        return jsonify(result)
    
    except Exception as e:
        app.logger.error(f'Error in get_statistics: {str(e)}', exc_info=True)
        return jsonify({'error': 'An error occurred while generating statistics', 'details': str(e)}), 500


@app.route('/api/filter-options')
def get_filter_options():
    """Get available filter options"""
    try:
        protocols = set()
        levels = set()
        source_ips = set()
        descriptions = set()
        ports = set()
        
        for entry in log_data:
            levels.add(entry.get('level', ''))
            event = entry.get('event', {})
            
            # Check if this is a Suricata entry
            is_suricata = entry.get('suricata_event_type') is not None
            
            if event:
                protocol = event.get('Protocol', '')
                if protocol:
                    protocols.add(protocol)
                
                source_ip = event.get('SourceIp', '')
                if source_ip:
                    source_ips.add(source_ip)
                
                # Only add descriptions for non-Suricata entries (honeypot services)
                # Suricata entries should be filtered by event type, not description
                if not is_suricata:
                    description = event.get('Description', '')
                    if description:
                        descriptions.add(description)
            
            # Add port from log metadata or event
            port = entry.get('log_port') or entry.get('port', '')
            if port:
                ports.add(str(port))
            
            # Add Suricata event types as protocols (for filtering)
            suricata_type = entry.get('suricata_event_type', '')
            if suricata_type and suricata_type != 'stats':
                protocols.add(f"SURICATA_{suricata_type.upper()}")
        
        return jsonify({
            'protocols': sorted(list(protocols - {''})),
            'levels': sorted(list(levels - {''})),
            'source_ips': sorted(list(source_ips - {''})),
            'descriptions': sorted(list(descriptions - {''})),
            'ports': sorted(list(ports - {''}))
        })
    except Exception as e:
        app.logger.error(f'Error in get_filter_options: {str(e)}', exc_info=True)
        return jsonify({'error': 'An error occurred while fetching filter options', 'details': str(e)}), 500


@app.route('/api/event/<int:line_number>')
def get_event_detail(line_number):
    """Get detailed information about a specific event"""
    try:
        # Validate line_number
        if line_number < 1:
            return jsonify({'error': 'Invalid line number'}), 400
        
        for entry in log_data:
            if entry.get('line_number') == line_number:
                return jsonify(entry)
        
        return jsonify({'error': 'Event not found'}), 404
    except Exception as e:
        app.logger.error(f'Error in get_event_detail: {str(e)}', exc_info=True)
        return jsonify({'error': 'An error occurred while fetching event details', 'details': str(e)}), 500


@app.route('/api/ip-analysis/<ip>')
def analyze_ip(ip):
    """Analyze activities from a specific IP"""
    try:
        # Validate IP address format
        try:
            # Try to parse as IPv4 or IPv6
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({'error': 'Invalid IP address format'}), 400
        
        # Additional security: prevent path traversal attempts
        if '..' in ip or '/' in ip or '\\' in ip:
            return jsonify({'error': 'Invalid IP address format'}), 400
        
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
    except Exception as e:
        app.logger.error(f'Error in analyze_ip: {str(e)}', exc_info=True)
        return jsonify({'error': 'An error occurred while analyzing IP address', 'details': str(e)}), 500


@app.route('/api/all-ips')
def get_all_ips():
    """Get all unique IP addresses with statistics"""
    try:
        # Validate pagination parameters
        try:
            page = max(1, int(request.args.get('page', 1)))
        except (ValueError, TypeError):
            page = 1
        
        try:
            per_page = max(1, min(1000, int(request.args.get('per_page', 50))))
        except (ValueError, TypeError):
            per_page = 50
        
        search = request.args.get('search', '').lower()
        # Limit search string length to prevent DoS
        if len(search) > 500:
            search = search[:500]
        
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
        
        # Apply search filter
        if search:
            result = [ip_data for ip_data in result 
                     if search in ip_data['ip'].lower() or
                     any(search in p.lower() for p in ip_data['protocols']) or
                     any(search in d.lower() for d in ip_data['descriptions'])]
        
        # Sort by count descending
        result.sort(key=lambda x: x['count'], reverse=True)
        
        # Pagination
        total = len(result)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated = result[start_idx:end_idx]
        
        return jsonify({
            'ips': paginated,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': max(1, (total + per_page - 1) // per_page) if total > 0 else 1
        })
    
    except Exception as e:
        app.logger.error(f'Error in get_all_ips: {str(e)}', exc_info=True)
        return jsonify({'error': 'An error occurred while fetching IP addresses', 'details': str(e)}), 500


@app.route('/api/credentials')
def get_credentials():
    """Get username and password combinations with pagination"""
    try:
        # Validate pagination parameters
        try:
            page = max(1, int(request.args.get('page', 1)))
        except (ValueError, TypeError):
            page = 1
        
        try:
            per_page = max(1, min(1000, int(request.args.get('per_page', 50))))
        except (ValueError, TypeError):
            per_page = 50
        
        search = request.args.get('search', '').lower()
        # Limit search string length to prevent DoS
        if len(search) > 500:
            search = search[:500]
        
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
        
        # Apply search filter
        if search:
            result = [cred for cred in result 
                     if search in cred['username'].lower() or
                     search in cred['password'].lower() or
                     any(search in ip.lower() for ip in cred['source_ips'])]
        
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
            'total_pages': max(1, (total + per_page - 1) // per_page) if total > 0 else 1
        })
    
    except Exception as e:
        app.logger.error(f'Error in get_credentials: {str(e)}', exc_info=True)
        return jsonify({'error': 'An error occurred while fetching credentials', 'details': str(e)}), 500


@app.route('/api/export/ips/<format>')
def export_ips(format):
    """Export IP addresses in specified format, respecting filters"""
    try:
        if format not in ['txt', 'csv', 'json']:
            return jsonify({'error': 'Invalid format'}), 400
        
        # Get filter parameters
        search = request.args.get('search', '').lower()
        # Limit search string length to prevent DoS
        if len(search) > 500:
            search = search[:500]
        
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
                'protocols': sorted(list(stats['protocols'])),
                'descriptions': sorted(list(stats['descriptions']))
            })
        
        # Apply search filter if provided
        if search:
            result = [ip_data for ip_data in result 
                     if search in ip_data['ip'].lower() or
                     any(search in p.lower() for p in ip_data['protocols']) or
                     any(search in d.lower() for d in ip_data['descriptions'])]
        
        result.sort(key=lambda x: x['count'], reverse=True)
        
        # Format and return
        if format == 'txt':
            output = io.StringIO()
            for item in result:
                output.write(f"{item['ip']}\n")
            output.seek(0)
            filename = 'ip_addresses_filtered.txt' if search else 'ip_addresses.txt'
            return Response(
                output.getvalue(),
                mimetype='text/plain',
                headers={'Content-Disposition': f'attachment; filename={filename}'}
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
                    ', '.join(item['protocols']) if isinstance(item['protocols'], list) else item['protocols'],
                    ', '.join(item['descriptions']) if isinstance(item['descriptions'], list) else item['descriptions']
                ])
            output.seek(0)
            filename = 'ip_addresses_filtered.csv' if search else 'ip_addresses.csv'
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename={filename}'}
            )
        
        elif format == 'json':
            filename = 'ip_addresses_filtered.json' if search else 'ip_addresses.json'
            return Response(
                json.dumps(result, indent=2),
                mimetype='application/json',
                headers={'Content-Disposition': f'attachment; filename={filename}'}
            )
    
    except Exception as e:
        app.logger.error(f'Error in export_ips: {str(e)}', exc_info=True)
        return jsonify({'error': 'An error occurred while exporting IP addresses', 'details': str(e)}), 500


@app.route('/api/export/credentials/<format>')
def export_credentials(format):
    """Export credentials in specified format, respecting filters"""
    try:
        if format not in ['txt', 'csv', 'json']:
            return jsonify({'error': 'Invalid format'}), 400
        
        # Get filter parameters
        search = request.args.get('search', '').lower()
        # Limit search string length to prevent DoS
        if len(search) > 500:
            search = search[:500]
        
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
                'source_ips': sorted(list(stats['source_ips']))
            })
        
        # Apply search filter if provided
        if search:
            result = [cred for cred in result 
                     if search in cred['username'].lower() or
                     search in cred['password'].lower() or
                     any(search in ip.lower() for ip in cred['source_ips'])]
        
        result.sort(key=lambda x: x['count'], reverse=True)
        
        # Format and return
        if format == 'txt':
            output = io.StringIO()
            for item in result:
                output.write(f"{item['username']}:{item['password']}\n")
            output.seek(0)
            filename = 'credentials_filtered.txt' if search else 'credentials.txt'
            return Response(
                output.getvalue(),
                mimetype='text/plain',
                headers={'Content-Disposition': f'attachment; filename={filename}'}
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
                    ', '.join(item['source_ips']) if isinstance(item['source_ips'], list) else item['source_ips']
                ])
            output.seek(0)
            filename = 'credentials_filtered.csv' if search else 'credentials.csv'
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename={filename}'}
            )
        
        elif format == 'json':
            filename = 'credentials_filtered.json' if search else 'credentials.json'
            return Response(
                json.dumps(result, indent=2),
                mimetype='application/json',
                headers={'Content-Disposition': f'attachment; filename={filename}'}
            )
    
    except Exception as e:
        app.logger.error(f'Error in export_credentials: {str(e)}', exc_info=True)
        return jsonify({'error': 'An error occurred while exporting credentials', 'details': str(e)}), 500


@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    try:
        return jsonify({
            'status': 'healthy',
            'log_entries': len(log_data),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200
    except Exception as e:
        app.logger.error(f'Error in health_check: {str(e)}', exc_info=True)
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 500


if __name__ == '__main__':
    import socket
    
    print("Loading log data...")
    load_logs()
    print(f"Loaded {len(log_data)} log entries")
    print("Starting dashboard server...")
    
    # Check if port is available, try alternative ports if needed
    port = 5000
    max_attempts = 5
    port_available = False
    
    for attempt in range(max_attempts):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        
        if result != 0:
            # Port is available
            port_available = True
            break
        
        if attempt == 0:
            print(f"⚠️  Port {port} is already in use. Trying alternative ports...")
        port += 1
    
    if not port_available:
        print(f"❌ Error: Could not find an available port (tried {5000}-{port-1})")
        print("Please stop the process using port 5000 or specify a different port.")
        exit(1)
    
    if port != 5000:
        print(f"ℹ️  Using port {port} instead of 5000")
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
        except:
            local_ip = "localhost"
        print(f"Dashboard will be available at:")
        print(f"  - Local:   http://localhost:{port}")
        print(f"  - Network: http://{local_ip}:{port}")
    
    # Disable debug mode in production for security
    # Set FLASK_ENV=development in your environment to enable debug mode
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=debug_mode, host='0.0.0.0', port=port)

