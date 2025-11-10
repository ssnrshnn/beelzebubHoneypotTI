// Global variables
let currentPage = 1;
let perPage = 50;
let credPage = 1;
let credPerPage = 50;
let charts = {};

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    loadStatistics();
    loadFilterOptions();
    loadLogs();
    setupEventListeners();
    setupTabNavigation();
    loadAllIPs();
    loadCredentials();
});

// Setup tab navigation
function setupTabNavigation() {
    const tabs = document.querySelectorAll('.nav-tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const targetTab = tab.getAttribute('data-tab');
            
            // Remove active class from all tabs
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Show selected tab content
            const targetContent = document.getElementById(`${targetTab}-tab`);
            if (targetContent) {
                targetContent.classList.add('active');
            }
            
            // Load data if needed
            if (targetTab === 'ips') {
                loadAllIPs();
            } else if (targetTab === 'credentials') {
                credPage = 1; // Reset to first page when switching to credentials tab
                loadCredentials();
            }
        });
    });
}

// Setup event listeners
function setupEventListeners() {
    document.getElementById('refreshBtn').addEventListener('click', () => {
        const activeTab = document.querySelector('.nav-tab.active')?.getAttribute('data-tab');
        
        if (activeTab === 'dashboard') {
            loadStatistics();
            loadLogs();
        } else if (activeTab === 'ips') {
            loadAllIPs();
        } else if (activeTab === 'credentials') {
            loadCredentials();
        }
    });

    document.getElementById('applyFilters').addEventListener('click', () => {
        currentPage = 1;
        loadLogs();
    });

    document.getElementById('clearFilters').addEventListener('click', () => {
        document.getElementById('filterProtocol').value = '';
        document.getElementById('filterLevel').value = '';
        document.getElementById('filterIP').value = '';
        document.getElementById('filterDescription').value = '';
        document.getElementById('filterStartDate').value = '';
        document.getElementById('filterEndDate').value = '';
        document.getElementById('filterSearch').value = '';
        currentPage = 1;
        loadLogs();
    });

    document.getElementById('prevPage').addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            loadLogs();
        }
    });

    document.getElementById('nextPage').addEventListener('click', () => {
        currentPage++;
        loadLogs();
    });

    document.getElementById('perPage').addEventListener('change', (e) => {
        perPage = parseInt(e.target.value);
        currentPage = 1;
        loadLogs();
    });

    document.getElementById('prevCredPage').addEventListener('click', () => {
        if (credPage > 1) {
            credPage--;
            loadCredentials();
        }
    });

    document.getElementById('nextCredPage').addEventListener('click', () => {
        credPage++;
        loadCredentials();
    });

    // Modal close buttons
    document.querySelector('.close').addEventListener('click', () => {
        document.getElementById('eventModal').style.display = 'none';
    });

    document.querySelector('.close-ip').addEventListener('click', () => {
        document.getElementById('ipModal').style.display = 'none';
    });

    window.addEventListener('click', (e) => {
        if (e.target.id === 'eventModal') {
            document.getElementById('eventModal').style.display = 'none';
        }
        if (e.target.id === 'ipModal') {
            document.getElementById('ipModal').style.display = 'none';
        }
    });
}

// Load statistics
async function loadStatistics() {
    try {
        const response = await fetch('/api/statistics');
        const stats = await response.json();

        // Update stat cards
        document.getElementById('totalEvents').textContent = stats.total_events.toLocaleString();
        document.getElementById('uniqueIPs').textContent = Object.keys(stats.top_ips).length;
        document.getElementById('attackTypes').textContent = Object.keys(stats.descriptions).length;
        document.getElementById('protocolCount').textContent = Object.keys(stats.protocols).length;

        // Render charts
        renderTimelineChart(stats.timeline);
        renderProtocolChart(stats.protocols);
        renderLevelChart(stats.levels);
        renderMethodChart(stats.http_methods);
        renderIPList(stats.top_ips);
        renderUserAgentList(stats.top_user_agents);

    } catch (error) {
        console.error('Error loading statistics:', error);
    }
}

// Load filter options
async function loadFilterOptions() {
    try {
        const response = await fetch('/api/filter-options');
        const options = await response.json();

        populateSelect('filterProtocol', options.protocols);
        populateSelect('filterLevel', options.levels);
        populateSelect('filterIP', options.source_ips);
        populateSelect('filterDescription', options.descriptions);

    } catch (error) {
        console.error('Error loading filter options:', error);
    }
}

// Populate select dropdown
function populateSelect(elementId, options) {
    const select = document.getElementById(elementId);
    const currentValue = select.value;

    // Keep the first "All" option
    while (select.options.length > 1) {
        select.remove(1);
    }

    options.forEach(option => {
        const optionElement = document.createElement('option');
        optionElement.value = option;
        optionElement.textContent = option;
        select.appendChild(optionElement);
    });

    select.value = currentValue;
}

// Load logs
async function loadLogs() {
    const tbody = document.getElementById('logsTableBody');
    tbody.innerHTML = '<tr><td colspan="7" class="loading"><i class="fas fa-spinner fa-spin"></i> Loading logs...</td></tr>';

    try {
        const params = new URLSearchParams({
            page: currentPage,
            per_page: perPage,
            protocol: document.getElementById('filterProtocol').value,
            level: document.getElementById('filterLevel').value,
            source_ip: document.getElementById('filterIP').value,
            description: document.getElementById('filterDescription').value,
            start_date: document.getElementById('filterStartDate').value,
            end_date: document.getElementById('filterEndDate').value,
            search: document.getElementById('filterSearch').value
        });

        const response = await fetch(`/api/logs?${params}`);
        const data = await response.json();

        // Clear loading
        tbody.innerHTML = '';

        if (data.logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="loading">No logs found</td></tr>';
            return;
        }

        // Render logs
        data.logs.forEach(log => {
            const row = createLogRow(log);
            tbody.appendChild(row);
        });

        // Update pagination
        document.getElementById('pageInfo').textContent = 
            `Page ${data.page} of ${data.total_pages} (${data.total.toLocaleString()} events)`;

        document.getElementById('prevPage').disabled = data.page === 1;
        document.getElementById('nextPage').disabled = data.page === data.total_pages;

    } catch (error) {
        console.error('Error loading logs:', error);
        tbody.innerHTML = '<tr><td colspan="7" class="loading">Error loading logs</td></tr>';
    }
}

// Create log row
function createLogRow(log) {
    const row = document.createElement('tr');

    const time = new Date(log.time).toLocaleString();
    const level = log.level || 'unknown';
    const event = log.event || {};
    const protocol = event.Protocol || '-';
    const sourceIp = event.SourceIp || '-';
    const description = event.Description || log.msg || '-';
    const msg = log.msg || '-';

    row.innerHTML = `
        <td>${time}</td>
        <td><span class="badge badge-${getLevelClass(level)}">${level}</span></td>
        <td>${protocol}</td>
        <td>
            <div class="ip-cell-content">
                <span class="ip-address">${sourceIp}</span>
                ${sourceIp !== '-' ? `
                    <div class="ip-actions">
                        <button class="btn-ip" onclick="analyzeIP('${sourceIp}')" title="Analyze IP"><i class="fas fa-search"></i></button>
                        <button class="btn-threat btn-virustotal" onclick="openVirusTotal('${sourceIp}')" title="VirusTotal">
                            <img src="https://www.virustotal.com/favicon.ico" alt="VT" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                            <span class="cti-icon-fallback" style="display:none;">VT</span>
                        </button>
                        <button class="btn-threat btn-abuseipdb" onclick="openAbuseIPDB('${sourceIp}')" title="AbuseIPDB">
                            <img src="https://www.abuseipdb.com/favicon.ico" alt="AIPDB" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                            <span class="cti-icon-fallback" style="display:none;">AIPDB</span>
                        </button>
                        <button class="btn-threat btn-shodan" onclick="openShodan('${sourceIp}')" title="Shodan">
                            <img src="https://www.shodan.io/favicon.ico" alt="Shodan" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                            <span class="cti-icon-fallback" style="display:none;">S</span>
                        </button>
                        <button class="btn-threat btn-greynoise" onclick="openGreyNoise('${sourceIp}')" title="GreyNoise">
                            <img src="https://www.greynoise.io/favicon.ico" alt="GN" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                            <span class="cti-icon-fallback" style="display:none;">GN</span>
                        </button>
                        <button class="btn-threat btn-ipinfo" onclick="openIPInfo('${sourceIp}')" title="IPinfo.io">
                            <img src="https://ipinfo.io/favicon.ico" alt="IPinfo" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                            <span class="cti-icon-fallback" style="display:none;">IP</span>
                        </button>
                        <button class="btn-threat btn-talos" onclick="openTalos('${sourceIp}')" title="Talos Intelligence">
                            <img src="https://talosintelligence.com/favicon.ico" alt="Talos" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                            <span class="cti-icon-fallback" style="display:none;">T</span>
                        </button>
                    </div>
                ` : ''}
            </div>
        </td>
        <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${description}</td>
        <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${msg}</td>
        <td>
            <button class="btn-view" onclick="viewEventDetails(${log.line_number})">
                <i class="fas fa-eye"></i> View
            </button>
        </td>
    `;

    return row;
}

// Get level class for badge
function getLevelClass(level) {
    const levelMap = {
        'info': 'info',
        'warning': 'warning',
        'error': 'danger',
        'debug': 'success'
    };
    return levelMap[level.toLowerCase()] || 'info';
}

// View event details
async function viewEventDetails(lineNumber) {
    try {
        const response = await fetch(`/api/event/${lineNumber}`);
        const event = await response.json();

        const modal = document.getElementById('eventModal');
        const detailsDiv = document.getElementById('eventDetails');

        detailsDiv.innerHTML = renderEventDetails(event);
        modal.style.display = 'block';

    } catch (error) {
        console.error('Error loading event details:', error);
    }
}

// Render event details
function renderEventDetails(event) {
    let html = '<div class="detail-section">';
    html += '<h4>Basic Information</h4>';
    html += `<div class="detail-row"><div class="detail-label">Time:</div><div class="detail-value">${new Date(event.time).toLocaleString()}</div></div>`;
    html += `<div class="detail-row"><div class="detail-label">Level:</div><div class="detail-value">${event.level}</div></div>`;
    html += `<div class="detail-row"><div class="detail-label">Message:</div><div class="detail-value">${event.msg}</div></div>`;
    html += `<div class="detail-row"><div class="detail-label">Line Number:</div><div class="detail-value">${event.line_number}</div></div>`;
    html += '</div>';

    if (event.event) {
        const evt = event.event;

        html += '<div class="detail-section">';
        html += '<h4>Event Details</h4>';
        if (evt.Protocol) html += `<div class="detail-row"><div class="detail-label">Protocol:</div><div class="detail-value">${evt.Protocol}</div></div>`;
        if (evt.SourceIp) html += `<div class="detail-row"><div class="detail-label">Source IP:</div><div class="detail-value">${evt.SourceIp}</div></div>`;
        if (evt.SourcePort) html += `<div class="detail-row"><div class="detail-label">Source Port:</div><div class="detail-value">${evt.SourcePort}</div></div>`;
        if (evt.RemoteAddr) html += `<div class="detail-row"><div class="detail-label">Remote Address:</div><div class="detail-value">${evt.RemoteAddr}</div></div>`;
        if (evt.Description) html += `<div class="detail-row"><div class="detail-label">Description:</div><div class="detail-value">${evt.Description}</div></div>`;
        if (evt.Status) html += `<div class="detail-row"><div class="detail-label">Status:</div><div class="detail-value">${evt.Status}</div></div>`;
        html += '</div>';

        if (evt.HTTPMethod || evt.RequestURI) {
            html += '<div class="detail-section">';
            html += '<h4>HTTP Details</h4>';
            if (evt.HTTPMethod) html += `<div class="detail-row"><div class="detail-label">Method:</div><div class="detail-value">${evt.HTTPMethod}</div></div>`;
            if (evt.RequestURI) html += `<div class="detail-row"><div class="detail-label">Request URI:</div><div class="detail-value">${evt.RequestURI}</div></div>`;
            if (evt.HostHTTPRequest) html += `<div class="detail-row"><div class="detail-label">Host:</div><div class="detail-value">${evt.HostHTTPRequest}</div></div>`;
            if (evt.UserAgent) html += `<div class="detail-row"><div class="detail-label">User Agent:</div><div class="detail-value">${evt.UserAgent}</div></div>`;
            if (evt.Cookies) html += `<div class="detail-row"><div class="detail-label">Cookies:</div><div class="detail-value">${evt.Cookies}</div></div>`;
            if (evt.Body) html += `<div class="detail-row"><div class="detail-label">Body:</div><div class="detail-value"><pre style="background: #0f0c29; padding: 10px; border-radius: 6px; overflow-x: auto;">${evt.Body}</pre></div></div>`;
            html += '</div>';
        }

        if (evt.HeadersMap) {
            html += '<div class="detail-section">';
            html += '<h4>HTTP Headers</h4>';
            for (const [key, values] of Object.entries(evt.HeadersMap)) {
                html += `<div class="detail-row"><div class="detail-label">${key}:</div><div class="detail-value">${Array.isArray(values) ? values.join(', ') : values}</div></div>`;
            }
            html += '</div>';
        }

        if (evt.User || evt.Password) {
            html += '<div class="detail-section">';
            html += '<h4>Credentials</h4>';
            if (evt.User) html += `<div class="detail-row"><div class="detail-label">User:</div><div class="detail-value">${evt.User}</div></div>`;
            if (evt.Password) html += `<div class="detail-row"><div class="detail-label">Password:</div><div class="detail-value">${evt.Password}</div></div>`;
            html += '</div>';
        }

        if (evt.Command) {
            html += '<div class="detail-section">';
            html += '<h4>Command</h4>';
            html += `<div class="detail-row"><div class="detail-value"><pre style="background: #0f0c29; padding: 10px; border-radius: 6px; overflow-x: auto;">${evt.Command}</pre></div></div>`;
            if (evt.CommandOutput) html += `<div class="detail-row"><div class="detail-label">Output:</div><div class="detail-value"><pre style="background: #0f0c29; padding: 10px; border-radius: 6px; overflow-x: auto;">${evt.CommandOutput}</pre></div></div>`;
            html += '</div>';
        }
    }

    return html;
}

// Analyze IP
async function analyzeIP(ip) {
    try {
        const response = await fetch(`/api/ip-analysis/${encodeURIComponent(ip)}`);
        const analysis = await response.json();

        const modal = document.getElementById('ipModal');
        const titleSpan = document.getElementById('ipAnalysisTitle');
        const contentDiv = document.getElementById('ipAnalysisContent');

        titleSpan.textContent = ip;

        let html = '<div class="analysis-stats">';
        html += `<div class="analysis-stat"><div class="analysis-stat-label">Total Requests</div><div class="analysis-stat-value">${analysis.total_requests}</div></div>`;
        html += `<div class="analysis-stat"><div class="analysis-stat-label">First Seen</div><div class="analysis-stat-value" style="font-size: 1rem;">${analysis.first_seen ? new Date(analysis.first_seen).toLocaleString() : 'N/A'}</div></div>`;
        html += `<div class="analysis-stat"><div class="analysis-stat-label">Last Seen</div><div class="analysis-stat-value" style="font-size: 1rem;">${analysis.last_seen ? new Date(analysis.last_seen).toLocaleString() : 'N/A'}</div></div>`;
        html += '</div>';

        html += `
            <div class="detail-section">
                <h4>Threat Intelligence Lookups</h4>
                <div class="threat-intel-buttons">
                    <button class="btn-threat btn-virustotal" onclick="openVirusTotal('${ip}')" title="VirusTotal">
                        <img src="https://www.virustotal.com/favicon.ico" alt="VT" class="cti-icon-img-modal" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                        <span class="cti-icon-fallback" style="display:none;">VT</span>
                        <span class="cti-label">VirusTotal</span>
                    </button>
                    <button class="btn-threat btn-abuseipdb" onclick="openAbuseIPDB('${ip}')" title="AbuseIPDB">
                        <img src="https://www.abuseipdb.com/favicon.ico" alt="AIPDB" class="cti-icon-img-modal" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                        <span class="cti-icon-fallback" style="display:none;">AIPDB</span>
                        <span class="cti-label">AbuseIPDB</span>
                    </button>
                    <button class="btn-threat btn-shodan" onclick="openShodan('${ip}')" title="Shodan">
                        <img src="https://www.shodan.io/favicon.ico" alt="Shodan" class="cti-icon-img-modal" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                        <span class="cti-icon-fallback" style="display:none;">S</span>
                        <span class="cti-label">Shodan</span>
                    </button>
                    <button class="btn-threat btn-greynoise" onclick="openGreyNoise('${ip}')" title="GreyNoise">
                        <img src="https://www.greynoise.io/favicon.ico" alt="GN" class="cti-icon-img-modal" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                        <span class="cti-icon-fallback" style="display:none;">GN</span>
                        <span class="cti-label">GreyNoise</span>
                    </button>
                    <button class="btn-threat btn-ipinfo" onclick="openIPInfo('${ip}')" title="IPinfo.io">
                        <img src="https://ipinfo.io/favicon.ico" alt="IPinfo" class="cti-icon-img-modal" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                        <span class="cti-icon-fallback" style="display:none;">IP</span>
                        <span class="cti-label">IPinfo.io</span>
                    </button>
                    <button class="btn-threat btn-talos" onclick="openTalos('${ip}')" title="Talos Intelligence">
                        <img src="https://talosintelligence.com/favicon.ico" alt="Talos" class="cti-icon-img-modal" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                        <span class="cti-icon-fallback" style="display:none;">T</span>
                        <span class="cti-label">Talos</span>
                    </button>
                </div>
            </div>
        `;

        html += '<div class="detail-section">';
        html += '<h4>Protocols Used</h4>';
        for (const [protocol, count] of Object.entries(analysis.protocols)) {
            html += `<div class="detail-row"><div class="detail-label">${protocol}:</div><div class="detail-value">${count} requests</div></div>`;
        }
        html += '</div>';

        html += '<div class="detail-section">';
        html += '<h4>Services Targeted</h4>';
        for (const [desc, count] of Object.entries(analysis.descriptions)) {
            html += `<div class="detail-row"><div class="detail-label">${desc}:</div><div class="detail-value">${count} requests</div></div>`;
        }
        html += '</div>';

        if (Object.keys(analysis.methods).length > 0) {
            html += '<div class="detail-section">';
            html += '<h4>HTTP Methods</h4>';
            for (const [method, count] of Object.entries(analysis.methods)) {
                if (method) html += `<div class="detail-row"><div class="detail-label">${method}:</div><div class="detail-value">${count} requests</div></div>`;
            }
            html += '</div>';
        }

        html += '<div class="detail-section">';
        html += '<h4>Top Paths Accessed</h4>';
        for (const [path, count] of Object.entries(analysis.top_paths)) {
            if (path) html += `<div class="detail-row"><div class="detail-label">${path}:</div><div class="detail-value">${count} requests</div></div>`;
        }
        html += '</div>';

        contentDiv.innerHTML = html;
        modal.style.display = 'block';

    } catch (error) {
        console.error('Error analyzing IP:', error);
    }
}

// Render timeline chart
function renderTimelineChart(data) {
    const ctx = document.getElementById('timelineChart');
    
    if (charts.timeline) {
        charts.timeline.destroy();
    }

    const labels = Object.keys(data);
    const values = Object.values(data);

    charts.timeline = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Events',
                data: values,
                borderColor: 'rgba(102, 126, 234, 1)',
                backgroundColor: 'rgba(102, 126, 234, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    labels: {
                        color: '#ffffff'
                    }
                }
            },
            scales: {
                x: {
                    ticks: {
                        color: '#a8b2d1',
                        maxRotation: 45,
                        minRotation: 45
                    },
                    grid: {
                        color: 'rgba(168, 178, 209, 0.1)'
                    }
                },
                y: {
                    ticks: {
                        color: '#a8b2d1'
                    },
                    grid: {
                        color: 'rgba(168, 178, 209, 0.1)'
                    }
                }
            }
        }
    });
}

// Render protocol chart
function renderProtocolChart(data) {
    const ctx = document.getElementById('protocolChart');
    
    if (charts.protocol) {
        charts.protocol.destroy();
    }

    charts.protocol = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(data),
            datasets: [{
                data: Object.values(data),
                backgroundColor: [
                    'rgba(102, 126, 234, 0.8)',
                    'rgba(118, 75, 162, 0.8)',
                    'rgba(79, 172, 254, 0.8)',
                    'rgba(67, 233, 123, 0.8)',
                    'rgba(245, 87, 108, 0.8)'
                ],
                borderWidth: 2,
                borderColor: '#16213e'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#ffffff'
                    }
                }
            }
        }
    });
}

// Render level chart
function renderLevelChart(data) {
    const ctx = document.getElementById('levelChart');
    
    if (charts.level) {
        charts.level.destroy();
    }

    charts.level = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: Object.keys(data),
            datasets: [{
                data: Object.values(data),
                backgroundColor: [
                    'rgba(79, 172, 254, 0.8)',
                    'rgba(255, 165, 2, 0.8)',
                    'rgba(245, 87, 108, 0.8)',
                    'rgba(67, 233, 123, 0.8)'
                ],
                borderWidth: 2,
                borderColor: '#16213e'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#ffffff'
                    }
                }
            }
        }
    });
}

// Render method chart
function renderMethodChart(data) {
    const ctx = document.getElementById('methodChart');
    
    if (charts.method) {
        charts.method.destroy();
    }

    charts.method = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: Object.keys(data),
            datasets: [{
                label: 'Requests',
                data: Object.values(data),
                backgroundColor: 'rgba(102, 126, 234, 0.8)',
                borderColor: 'rgba(102, 126, 234, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    ticks: {
                        color: '#a8b2d1'
                    },
                    grid: {
                        color: 'rgba(168, 178, 209, 0.1)'
                    }
                },
                y: {
                    ticks: {
                        color: '#a8b2d1'
                    },
                    grid: {
                        color: 'rgba(168, 178, 209, 0.1)'
                    }
                }
            }
        }
    });
}

// Render IP list
function renderIPList(data) {
    const container = document.getElementById('ipList');
    container.innerHTML = '';

    const sortedIPs = Object.entries(data).sort((a, b) => b[1] - a[1]);

    sortedIPs.forEach(([ip, count]) => {
        const item = document.createElement('div');
        item.className = 'list-item';
        item.innerHTML = `
            <span class="list-item-label">${ip}</span>
            <span class="list-item-actions">
                <span class="list-item-value">${count}</span>
                <div class="threat-buttons-compact">
                    <button class="btn-threat btn-virustotal" onclick="openVirusTotal('${ip}'); event.stopPropagation();" title="VirusTotal">
                        <img src="https://www.virustotal.com/favicon.ico" alt="VT" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                        <span class="cti-icon-fallback" style="display:none;">VT</span>
                    </button>
                    <button class="btn-threat btn-abuseipdb" onclick="openAbuseIPDB('${ip}'); event.stopPropagation();" title="AbuseIPDB">
                        <img src="https://www.abuseipdb.com/favicon.ico" alt="AIPDB" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                        <span class="cti-icon-fallback" style="display:none;">AIPDB</span>
                    </button>
                    <button class="btn-threat btn-shodan" onclick="openShodan('${ip}'); event.stopPropagation();" title="Shodan">
                        <img src="https://www.shodan.io/favicon.ico" alt="Shodan" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                        <span class="cti-icon-fallback" style="display:none;">S</span>
                    </button>
                    <button class="btn-threat btn-greynoise" onclick="openGreyNoise('${ip}'); event.stopPropagation();" title="GreyNoise">
                        <img src="https://www.greynoise.io/favicon.ico" alt="GN" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                        <span class="cti-icon-fallback" style="display:none;">GN</span>
                    </button>
                    <button class="btn-threat btn-ipinfo" onclick="openIPInfo('${ip}'); event.stopPropagation();" title="IPinfo.io">
                        <img src="https://ipinfo.io/favicon.ico" alt="IPinfo" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                        <span class="cti-icon-fallback" style="display:none;">IP</span>
                    </button>
                    <button class="btn-threat btn-talos" onclick="openTalos('${ip}'); event.stopPropagation();" title="Talos Intelligence">
                        <img src="https://talosintelligence.com/favicon.ico" alt="Talos" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                        <span class="cti-icon-fallback" style="display:none;">T</span>
                    </button>
                </div>
            </span>
        `;
        item.addEventListener('click', (event) => {
            if (event.target.closest('.btn-threat')) {
                return;
            }
            analyzeIP(ip);
        });
        container.appendChild(item);
    });
}

// Render user agent list
function renderUserAgentList(data) {
    const container = document.getElementById('userAgentList');
    container.innerHTML = '';

    const sortedUAs = Object.entries(data).sort((a, b) => b[1] - a[1]);

    sortedUAs.forEach(([ua, count]) => {
        const item = document.createElement('div');
        item.className = 'list-item';
        item.innerHTML = `
            <span class="list-item-label" title="${ua}">${ua}</span>
            <span class="list-item-value">${count}</span>
        `;
        container.appendChild(item);
    });
}

// Threat Intelligence Lookup Functions
function openVirusTotal(ip) {
    if (!ip || ip === '-') return;
    const url = `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`;
    window.open(url, '_blank', 'noopener,noreferrer');
}

function openAbuseIPDB(ip) {
    if (!ip || ip === '-') return;
    const url = `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`;
    window.open(url, '_blank', 'noopener,noreferrer');
}

function openShodan(ip) {
    if (!ip || ip === '-') return;
    const url = `https://www.shodan.io/host/${encodeURIComponent(ip)}`;
    window.open(url, '_blank', 'noopener,noreferrer');
}

function openGreyNoise(ip) {
    if (!ip || ip === '-') return;
    const url = `https://www.greynoise.io/viz/ip/${encodeURIComponent(ip)}`;
    window.open(url, '_blank', 'noopener,noreferrer');
}

function openIPInfo(ip) {
    if (!ip || ip === '-') return;
    const url = `https://ipinfo.io/${encodeURIComponent(ip)}`;
    window.open(url, '_blank', 'noopener,noreferrer');
}

function openTalos(ip) {
    if (!ip || ip === '-') return;
    const url = `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(ip)}`;
    window.open(url, '_blank', 'noopener,noreferrer');
}

// Load all IP addresses
async function loadAllIPs() {
    const tbody = document.getElementById('allIPsTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = '<tr><td colspan="7" class="loading"><i class="fas fa-spinner fa-spin"></i> Loading IP addresses...</td></tr>';
    
    try {
        const response = await fetch('/api/all-ips');
        const ips = await response.json();
        
        tbody.innerHTML = '';
        
        if (ips.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="loading">No IP addresses found</td></tr>';
            return;
        }
        
        ips.forEach(ipData => {
            const row = document.createElement('tr');
            
            const firstSeen = ipData.first_seen ? new Date(ipData.first_seen).toLocaleString() : 'N/A';
            const lastSeen = ipData.last_seen ? new Date(ipData.last_seen).toLocaleString() : 'N/A';
            const protocols = ipData.protocols.length > 0 ? ipData.protocols.join(', ') : 'N/A';
            const descriptions = ipData.descriptions.length > 0 ? ipData.descriptions.slice(0, 2).join(', ') : 'N/A';
            
            row.innerHTML = `
                <td>
                    <div class="ip-list-cell">
                        <span class="ip-address">${ipData.ip}</span>
                        <div class="ip-list-actions">
                            <button class="btn-ip" onclick="analyzeIP('${ipData.ip}')" title="Analyze IP"><i class="fas fa-search"></i></button>
                            <button class="btn-threat btn-virustotal" onclick="openVirusTotal('${ipData.ip}')" title="VirusTotal">
                                <img src="https://www.virustotal.com/favicon.ico" alt="VT" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                                <span class="cti-icon-fallback" style="display:none;">VT</span>
                            </button>
                            <button class="btn-threat btn-abuseipdb" onclick="openAbuseIPDB('${ipData.ip}')" title="AbuseIPDB">
                                <img src="https://www.abuseipdb.com/favicon.ico" alt="AIPDB" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                                <span class="cti-icon-fallback" style="display:none;">AIPDB</span>
                            </button>
                            <button class="btn-threat btn-shodan" onclick="openShodan('${ipData.ip}')" title="Shodan">
                                <img src="https://www.shodan.io/favicon.ico" alt="Shodan" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                                <span class="cti-icon-fallback" style="display:none;">S</span>
                            </button>
                            <button class="btn-threat btn-greynoise" onclick="openGreyNoise('${ipData.ip}')" title="GreyNoise">
                                <img src="https://www.greynoise.io/favicon.ico" alt="GN" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                                <span class="cti-icon-fallback" style="display:none;">GN</span>
                            </button>
                            <button class="btn-threat btn-ipinfo" onclick="openIPInfo('${ipData.ip}')" title="IPinfo.io">
                                <img src="https://ipinfo.io/favicon.ico" alt="IPinfo" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                                <span class="cti-icon-fallback" style="display:none;">IP</span>
                            </button>
                            <button class="btn-threat btn-talos" onclick="openTalos('${ipData.ip}')" title="Talos Intelligence">
                                <img src="https://talosintelligence.com/favicon.ico" alt="Talos" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                                <span class="cti-icon-fallback" style="display:none;">T</span>
                            </button>
                        </div>
                    </div>
                </td>
                <td><span class="badge badge-info">${ipData.count.toLocaleString()}</span></td>
                <td>${firstSeen}</td>
                <td>${lastSeen}</td>
                <td><div class="badge-list">${ipData.protocols.map(p => `<span class="badge-item">${p}</span>`).join('') || '<span class="badge-item">N/A</span>'}</div></td>
                <td><div class="badge-list">${ipData.descriptions.slice(0, 2).map(d => `<span class="badge-item" title="${d}">${d.length > 30 ? d.substring(0, 30) + '...' : d}</span>`).join('') || '<span class="badge-item">N/A</span>'}</div></td>
                <td>
                    <button class="btn-view" onclick="analyzeIP('${ipData.ip}')">
                        <i class="fas fa-eye"></i> View
                    </button>
                </td>
            `;
            
            tbody.appendChild(row);
        });
        
    } catch (error) {
        console.error('Error loading IP addresses:', error);
        tbody.innerHTML = '<tr><td colspan="7" class="loading">Error loading IP addresses</td></tr>';
    }
}

// Load credentials
async function loadCredentials() {
    const tbody = document.getElementById('credentialsTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = '<tr><td colspan="4" class="loading"><i class="fas fa-spinner fa-spin"></i> Loading credentials...</td></tr>';
    
    try {
        const params = new URLSearchParams({
            page: credPage,
            per_page: credPerPage
        });
        
        const response = await fetch(`/api/credentials?${params}`);
        const data = await response.json();
        
        tbody.innerHTML = '';
        
        if (data.credentials.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="loading">No credentials found</td></tr>';
            return;
        }
        
        data.credentials.forEach(cred => {
            const row = document.createElement('tr');
            
            // Get the most common source IP (first one in sorted list, or show multiple if same count)
            const sourceIP = cred.source_ips.length > 0 ? cred.source_ips[0] : 'N/A';
            
            row.innerHTML = `
                <td><code style="background: var(--dark-bg); padding: 6px 12px; border-radius: 6px; font-size: 0.95rem; color: var(--text-primary);">${cred.username || '(empty)'}</code></td>
                <td><code style="background: var(--dark-bg); padding: 6px 12px; border-radius: 6px; font-size: 0.95rem; color: var(--text-primary);">${cred.password || '(empty)'}</code></td>
                <td><span class="badge badge-warning">${cred.count.toLocaleString()}</span></td>
                <td>
                    ${sourceIP !== 'N/A' ? `
                        <div class="ip-cell-content">
                            <span class="ip-address">${sourceIP}</span>
                            ${cred.source_ips.length > 1 ? `<span style="color: var(--text-secondary); font-size: 0.85rem;">(+${cred.source_ips.length - 1} more)</span>` : ''}
                            <div class="ip-actions">
                                <button class="btn-ip" onclick="analyzeIP('${sourceIP}')" title="Analyze IP"><i class="fas fa-search"></i></button>
                                <button class="btn-threat btn-virustotal" onclick="openVirusTotal('${sourceIP}')" title="VirusTotal">
                                    <img src="https://www.virustotal.com/favicon.ico" alt="VT" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                                    <span class="cti-icon-fallback" style="display:none;">VT</span>
                                </button>
                                <button class="btn-threat btn-abuseipdb" onclick="openAbuseIPDB('${sourceIP}')" title="AbuseIPDB">
                                    <img src="https://www.abuseipdb.com/favicon.ico" alt="AIPDB" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                                    <span class="cti-icon-fallback" style="display:none;">AIPDB</span>
                                </button>
                                <button class="btn-threat btn-shodan" onclick="openShodan('${sourceIP}')" title="Shodan">
                                    <img src="https://www.shodan.io/favicon.ico" alt="Shodan" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                                    <span class="cti-icon-fallback" style="display:none;">S</span>
                                </button>
                                <button class="btn-threat btn-greynoise" onclick="openGreyNoise('${sourceIP}')" title="GreyNoise">
                                    <img src="https://www.greynoise.io/favicon.ico" alt="GN" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                                    <span class="cti-icon-fallback" style="display:none;">GN</span>
                                </button>
                                <button class="btn-threat btn-ipinfo" onclick="openIPInfo('${sourceIP}')" title="IPinfo.io">
                                    <img src="https://ipinfo.io/favicon.ico" alt="IPinfo" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                                    <span class="cti-icon-fallback" style="display:none;">IP</span>
                                </button>
                                <button class="btn-threat btn-talos" onclick="openTalos('${sourceIP}')" title="Talos Intelligence">
                                    <img src="https://talosintelligence.com/favicon.ico" alt="Talos" class="cti-icon-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                                    <span class="cti-icon-fallback" style="display:none;">T</span>
                                </button>
                            </div>
                        </div>
                    ` : '<span style="color: var(--text-secondary);">N/A</span>'}
                </td>
            `;
            
            tbody.appendChild(row);
        });
        
        // Update pagination
        document.getElementById('credPageInfo').textContent = 
            `Page ${data.page} of ${data.total_pages} (${data.total.toLocaleString()} credentials)`;
        
        document.getElementById('prevCredPage').disabled = data.page === 1;
        document.getElementById('nextCredPage').disabled = data.page === data.total_pages;
        
    } catch (error) {
        console.error('Error loading credentials:', error);
        tbody.innerHTML = '<tr><td colspan="4" class="loading">Error loading credentials</td></tr>';
    }
}

// Export IP addresses
function exportIPs(format) {
    window.location.href = `/api/export/ips/${format}`;
}

// Export credentials
function exportCredentials(format) {
    window.location.href = `/api/export/credentials/${format}`;
}

