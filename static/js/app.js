// Global variables
let currentPage = 1;
let perPage = 50;
let credPage = 1;
let credPerPage = 50;
let ipPage = 1;
let ipPerPage = 50;
let charts = {};

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    // Only load what exists on the current page
    if (document.getElementById('timelineChart')) {
        loadStatistics();
    }
    if (document.getElementById('logsTableBody')) {
        loadFilterOptions().then(() => {
            // Load filters from URL parameters first (takes precedence over localStorage)
            const urlLoaded = loadFiltersFromURL();
            
            // If URL didn't have filters, try loading from localStorage
            if (!urlLoaded) {
                const loaded = loadFiltersFromStorage();
                if (loaded) {
                    // Auto-apply loaded filters
                    currentPage = 1;
                    loadLogs();
                } else {
                    loadLogs();
                }
            } else {
                // URL had filters, apply them
                currentPage = 1;
                loadLogs();
            }
        });
    }
    if (document.getElementById('allIPsTableBody')) {
        loadAllIPs();
    }
    if (document.getElementById('credentialsTableBody')) {
        loadCredentials();
    }
    setupEventListeners();
    if (document.querySelectorAll('.nav-tab').length > 0) {
        setupTabNavigation();
    }
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
                ipPage = 1; // Reset to first page when switching to IPs tab
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
    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            // Refresh what exists on the current page
            if (document.getElementById('timelineChart')) {
                loadStatistics();
            }
            if (document.getElementById('logsTableBody')) {
                loadLogs();
            }
            if (document.getElementById('allIPsTableBody')) {
                loadAllIPs();
            }
            if (document.getElementById('credentialsTableBody')) {
                loadCredentials();
            }
        });
    }

    const applyFiltersBtn = document.getElementById('applyFilters');
    if (applyFiltersBtn) {
        applyFiltersBtn.addEventListener('click', () => {
            currentPage = 1;
            // Save filters to localStorage
            saveFiltersToStorage();
            // Update URL with filters
            updateURLWithFilters();
            // Show loading state
            applyFiltersBtn.classList.add('loading');
            loadLogs().finally(() => {
                applyFiltersBtn.classList.remove('loading');
            });
        });
    }
    
    // Enter key support for all filter inputs
    const filterInputs = ['filterProtocol', 'filterLevel', 'filterIP', 'filterDescription', 'filterPort',
                          'filterStartDate', 'filterEndDate', 'filterSSHCommandType'];
    filterInputs.forEach(inputId => {
        const input = document.getElementById(inputId);
        if (input) {
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    const applyFiltersBtn = document.getElementById('applyFilters');
                    if (applyFiltersBtn) {
                        applyFiltersBtn.click();
                    }
                }
            });
        }
    });

    const clearFiltersBtn = document.getElementById('clearFilters');
    if (clearFiltersBtn) {
        clearFiltersBtn.addEventListener('click', () => {
            const filterProtocol = document.getElementById('filterProtocol');
            const filterLevel = document.getElementById('filterLevel');
            const filterIP = document.getElementById('filterIP');
            const filterDescription = document.getElementById('filterDescription');
            const filterStartDate = document.getElementById('filterStartDate');
            const filterEndDate = document.getElementById('filterEndDate');
            const filterSearch = document.getElementById('filterSearch');
            
            if (filterProtocol) filterProtocol.value = '';
            if (filterLevel) filterLevel.value = '';
            if (filterIP) filterIP.value = '';
            if (filterDescription) filterDescription.value = '';
            if (filterStartDate) filterStartDate.value = '';
            if (filterEndDate) filterEndDate.value = '';
            if (filterSearch) filterSearch.value = '';
            
            // Clear SSH command type filter
            const filterSSHCommandType = document.getElementById('filterSSHCommandType');
            if (filterSSHCommandType) filterSSHCommandType.value = '';
            
            // Clear exclude checkboxes
            const excludeProtocol = document.getElementById('excludeProtocol');
            const excludeLevel = document.getElementById('excludeLevel');
            const excludeIP = document.getElementById('excludeIP');
            const excludeDescription = document.getElementById('excludeDescription');
            const excludeStartDate = document.getElementById('excludeStartDate');
            const excludeEndDate = document.getElementById('excludeEndDate');
            const excludeSSHCommandType = document.getElementById('excludeSSHCommandType');
            
            if (excludeProtocol) excludeProtocol.checked = false;
            if (excludeLevel) excludeLevel.checked = false;
            if (excludeIP) excludeIP.checked = false;
            if (excludeDescription) excludeDescription.checked = false;
            if (excludeStartDate) excludeStartDate.checked = false;
            if (excludeEndDate) excludeEndDate.checked = false;
            if (excludeSSHCommandType) excludeSSHCommandType.checked = false;
            
            // Clear search inputs
            const clearSearchBtn = document.getElementById('clearSearchBtn');
            if (filterSearch && clearSearchBtn) {
                filterSearch.value = '';
                clearSearchBtn.style.display = 'none';
            }
            
            // Hide SSH filter if not SSH protocol
            toggleSSHCommandTypeFilter();
            
            // Clear localStorage
            localStorage.removeItem('beelzebub_filters');
            
            // Update active filter count
            updateActiveFilterCount();
            
            currentPage = 1;
            loadLogs();
        });
    }
    
    // Update active filter count badge
    updateActiveFilterCount();

    // Search input handlers for IPs
    const ipSearchInput = document.getElementById('ipSearchInput');
    const clearIPSearchBtn = document.getElementById('clearIPSearchBtn');
    if (ipSearchInput) {
        let ipSearchTimeout;
        const updateIPSearchClearBtn = () => {
            if (clearIPSearchBtn) {
                clearIPSearchBtn.style.display = ipSearchInput.value.trim() ? 'flex' : 'none';
            }
        };
        
        ipSearchInput.addEventListener('input', () => {
            updateIPSearchClearBtn();
            clearTimeout(ipSearchTimeout);
            ipSearchTimeout = setTimeout(() => {
                ipPage = 1;
                loadAllIPs();
            }, 300); // Debounce search
        });
        
        if (clearIPSearchBtn) {
            clearIPSearchBtn.addEventListener('click', () => {
                ipSearchInput.value = '';
                updateIPSearchClearBtn();
                ipPage = 1;
                loadAllIPs();
            });
        }
        
        // Enter key support
        ipSearchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                clearTimeout(ipSearchTimeout);
                ipPage = 1;
                loadAllIPs();
            }
        });
        
        updateIPSearchClearBtn();
    }

    // Search input handlers for Credentials
    const credSearchInput = document.getElementById('credSearchInput');
    const clearCredSearchBtn = document.getElementById('clearCredSearchBtn');
    if (credSearchInput) {
        let credSearchTimeout;
        const updateCredSearchClearBtn = () => {
            if (clearCredSearchBtn) {
                clearCredSearchBtn.style.display = credSearchInput.value.trim() ? 'flex' : 'none';
            }
        };
        
        credSearchInput.addEventListener('input', () => {
            updateCredSearchClearBtn();
            clearTimeout(credSearchTimeout);
            credSearchTimeout = setTimeout(() => {
                credPage = 1;
                loadCredentials();
            }, 300); // Debounce search
        });
        
        if (clearCredSearchBtn) {
            clearCredSearchBtn.addEventListener('click', () => {
                credSearchInput.value = '';
                updateCredSearchClearBtn();
                credPage = 1;
                loadCredentials();
            });
        }
        
        // Enter key support
        credSearchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                clearTimeout(credSearchTimeout);
                credPage = 1;
                loadCredentials();
            }
        });
        
        updateCredSearchClearBtn();
    }
    
    // Search input handler for Events page
    const filterSearch = document.getElementById('filterSearch');
    const clearSearchBtn = document.getElementById('clearSearchBtn');
    if (filterSearch) {
        const updateSearchClearBtn = () => {
            if (clearSearchBtn) {
                clearSearchBtn.style.display = filterSearch.value.trim() ? 'flex' : 'none';
            }
        };
        
        filterSearch.addEventListener('input', updateSearchClearBtn);
        
        if (clearSearchBtn) {
            clearSearchBtn.addEventListener('click', () => {
                filterSearch.value = '';
                updateSearchClearBtn();
            });
        }
        
        // Enter key support for search
        filterSearch.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                const applyFiltersBtn = document.getElementById('applyFilters');
                if (applyFiltersBtn) {
                    applyFiltersBtn.click();
                }
            }
        });
        
        updateSearchClearBtn();
    }

    const prevPageBtn = document.getElementById('prevPage');
    if (prevPageBtn) {
        prevPageBtn.addEventListener('click', () => {
            if (currentPage > 1) {
                currentPage--;
                loadLogs();
            }
        });
    }

    const nextPageBtn = document.getElementById('nextPage');
    if (nextPageBtn) {
        nextPageBtn.addEventListener('click', () => {
            currentPage++;
            loadLogs();
        });
    }

    const perPageSelect = document.getElementById('perPage');
    if (perPageSelect) {
        perPageSelect.addEventListener('change', (e) => {
            perPage = parseInt(e.target.value);
            currentPage = 1;
            loadLogs();
        });
    }

    const prevCredBtn = document.getElementById('prevCredPage');
    if (prevCredBtn) {
        prevCredBtn.addEventListener('click', () => {
            if (credPage > 1) {
                credPage--;
                loadCredentials();
            }
        });
    }

    const nextCredBtn = document.getElementById('nextCredPage');
    if (nextCredBtn) {
        nextCredBtn.addEventListener('click', () => {
            credPage++;
            loadCredentials();
        });
    }

    // All IPs pagination
    const prevIPsBtn = document.getElementById('prevIPsPage');
    const nextIPsBtn = document.getElementById('nextIPsPage');
    if (prevIPsBtn && nextIPsBtn) {
        prevIPsBtn.addEventListener('click', () => {
            if (ipPage > 1) {
                ipPage--;
                loadAllIPs();
            }
        });
        nextIPsBtn.addEventListener('click', () => {
            ipPage++;
            loadAllIPs();
        });
    }
    // Modal close buttons
    const modalClose = document.querySelector('.close');
    if (modalClose) {
        modalClose.addEventListener('click', () => {
            document.getElementById('eventModal').style.display = 'none';
        });
    }

    const modalCloseIp = document.querySelector('.close-ip');
    if (modalCloseIp) {
        modalCloseIp.addEventListener('click', () => {
            document.getElementById('ipModal').style.display = 'none';
        });
    }

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
        document.getElementById('uniqueIPs').textContent = (stats.unique_ips || 0).toLocaleString();
        document.getElementById('attackTypes').textContent = Object.keys(stats.descriptions).length;
        document.getElementById('protocolCount').textContent = Object.keys(stats.protocols).length;

        // Render charts
        renderTimelineChart(stats.timeline);
        renderProtocolChart(stats.protocols);
        renderMethodChart(stats.http_methods);
        renderDescriptionChart(stats.descriptions);
        renderPathChart(stats.top_paths);
        renderPortChart(stats.ports);
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
        populateSelect('filterPort', options.ports || []);
        
        // Setup protocol change listener to show/hide SSH command type filter
        const protocolSelect = document.getElementById('filterProtocol');
        if (protocolSelect) {
            protocolSelect.addEventListener('change', () => {
                toggleSSHCommandTypeFilter();
                updateActiveFilterCount();
            });
            // Check initial state
            toggleSSHCommandTypeFilter();
        }
        
        // Add change listeners to all filters to update count
        const allFilterInputs = ['filterProtocol', 'filterLevel', 'filterIP', 'filterDescription', 
                                 'filterStartDate', 'filterEndDate', 'filterSearch', 'filterSSHCommandType'];
        allFilterInputs.forEach(inputId => {
            const input = document.getElementById(inputId);
            if (input) {
                input.addEventListener('change', () => {
                    // Update exclude visual indicators
                    const excludeId = 'exclude' + inputId.replace('filter', '');
                    updateExcludeVisualIndicator(excludeId);
                    updateActiveFilterCount();
                });
                input.addEventListener('input', updateActiveFilterCount);
            }
        });
        
        // Add change listeners to exclude checkboxes
        const excludeCheckboxes = ['excludeProtocol', 'excludeLevel', 'excludeIP', 'excludeDescription',
                                   'excludeStartDate', 'excludeEndDate', 'excludeSSHCommandType'];
        excludeCheckboxes.forEach(checkboxId => {
            const checkbox = document.getElementById(checkboxId);
            if (checkbox) {
                checkbox.addEventListener('change', () => {
                    updateExcludeVisualIndicator(checkboxId);
                    updateActiveFilterCount();
                });
                // Update initial state
                updateExcludeVisualIndicator(checkboxId);
            }
        });
        
        // Load saved filters from localStorage
        const loaded = loadFiltersFromStorage();
        if (loaded) {
            // Apply filters if they were loaded
            updateActiveFilterCount();
        }
        
        return Promise.resolve();

    } catch (error) {
        console.error('Error loading filter options:', error);
        return Promise.reject(error);
    }
}

// Toggle SSH command type filter visibility based on protocol selection
function toggleSSHCommandTypeFilter() {
    const protocolSelect = document.getElementById('filterProtocol');
    const sshCommandTypeGroup = document.getElementById('sshCommandTypeGroup');
    
    if (protocolSelect && sshCommandTypeGroup) {
        const isSSH = protocolSelect.value === 'SSH';
        sshCommandTypeGroup.style.display = isSSH ? 'flex' : 'none';
        
        // Clear SSH command type filter if protocol is not SSH
        if (!isSSH) {
            const sshCommandTypeSelect = document.getElementById('filterSSHCommandType');
            const excludeSSHCommandType = document.getElementById('excludeSSHCommandType');
            if (sshCommandTypeSelect) sshCommandTypeSelect.value = '';
            if (excludeSSHCommandType) excludeSSHCommandType.checked = false;
        }
    }
}

// Populate select dropdown
function populateSelect(elementId, options) {
    const select = document.getElementById(elementId);
    if (!select) return;
    
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

// Count active filters
function countActiveFilters() {
    let count = 0;
    
    const filterProtocol = document.getElementById('filterProtocol');
    const filterLevel = document.getElementById('filterLevel');
    const filterIP = document.getElementById('filterIP');
    const filterDescription = document.getElementById('filterDescription');
    const filterStartDate = document.getElementById('filterStartDate');
    const filterEndDate = document.getElementById('filterEndDate');
    const filterSearch = document.getElementById('filterSearch');
    const filterSSHCommandType = document.getElementById('filterSSHCommandType');
    
    if (filterProtocol && filterProtocol.value) count++;
    if (filterLevel && filterLevel.value) count++;
    if (filterIP && filterIP.value) count++;
    if (filterDescription && filterDescription.value) count++;
    if (filterStartDate && filterStartDate.value) count++;
    if (filterEndDate && filterEndDate.value) count++;
    if (filterSearch && filterSearch.value.trim()) count++;
    if (filterSSHCommandType && filterSSHCommandType.value) count++;
    
    // Count exclude checkboxes
    const excludeProtocol = document.getElementById('excludeProtocol');
    const excludeLevel = document.getElementById('excludeLevel');
    const excludeIP = document.getElementById('excludeIP');
    const excludeDescription = document.getElementById('excludeDescription');
    const excludeStartDate = document.getElementById('excludeStartDate');
    const excludeEndDate = document.getElementById('excludeEndDate');
    const excludeSSHCommandType = document.getElementById('excludeSSHCommandType');
    
    if (excludeProtocol && excludeProtocol.checked && filterProtocol && filterProtocol.value) count++;
    if (excludeLevel && excludeLevel.checked && filterLevel && filterLevel.value) count++;
    if (excludeIP && excludeIP.checked && filterIP && filterIP.value) count++;
    if (excludeDescription && excludeDescription.checked && filterDescription && filterDescription.value) count++;
    if (excludeStartDate && excludeStartDate.checked && filterStartDate && filterStartDate.value) count++;
    if (excludeEndDate && excludeEndDate.checked && filterEndDate && filterEndDate.value) count++;
    if (excludeSSHCommandType && excludeSSHCommandType.checked && filterSSHCommandType && filterSSHCommandType.value) count++;
    
    return count;
}

// Update active filter count badge
function updateActiveFilterCount() {
    const count = countActiveFilters();
    const badge = document.getElementById('activeFilterCount');
    if (badge) {
        if (count > 0) {
            badge.textContent = count;
            badge.style.display = 'inline-block';
        } else {
            badge.style.display = 'none';
        }
    }
}

// Update visual indicator for exclude checkboxes
function updateExcludeVisualIndicator(checkboxId) {
    const checkbox = document.getElementById(checkboxId);
    if (!checkbox) return;
    
    const filterGroup = checkbox.closest('.filter-group');
    if (filterGroup) {
        if (checkbox.checked && checkboxId.startsWith('exclude')) {
            // Check if corresponding filter has a value
            const filterId = checkboxId.replace('exclude', 'filter');
            const filterInput = document.getElementById(filterId);
            if (filterInput && filterInput.value) {
                filterGroup.classList.add('exclude-active');
            } else {
                filterGroup.classList.remove('exclude-active');
            }
        } else {
            filterGroup.classList.remove('exclude-active');
        }
    }
}

// Load filters from URL parameters
function loadFiltersFromURL() {
    try {
        const urlParams = new URLSearchParams(window.location.search);
        
        // Only load from URL if we're on the events page
        if (!document.getElementById('logsTableBody')) {
            return false;
        }
        
        const filterProtocol = document.getElementById('filterProtocol');
        const filterLevel = document.getElementById('filterLevel');
        const filterIP = document.getElementById('filterIP');
        const filterDescription = document.getElementById('filterDescription');
        const filterPort = document.getElementById('filterPort');
        const filterStartDate = document.getElementById('filterStartDate');
        const filterEndDate = document.getElementById('filterEndDate');
        const filterSearch = document.getElementById('filterSearch');
        const filterSSHCommandType = document.getElementById('filterSSHCommandType');
        
        // Load filter values from URL
        if (filterProtocol && urlParams.has('protocol')) filterProtocol.value = urlParams.get('protocol');
        if (filterLevel && urlParams.has('level')) filterLevel.value = urlParams.get('level');
        if (filterIP && urlParams.has('source_ip')) filterIP.value = urlParams.get('source_ip');
        if (filterDescription && urlParams.has('description')) filterDescription.value = urlParams.get('description');
        if (filterPort && urlParams.has('port')) filterPort.value = urlParams.get('port');
        if (filterStartDate && urlParams.has('start_date')) filterStartDate.value = urlParams.get('start_date');
        if (filterEndDate && urlParams.has('end_date')) filterEndDate.value = urlParams.get('end_date');
        if (filterSearch && urlParams.has('search')) filterSearch.value = urlParams.get('search');
        if (filterSSHCommandType && urlParams.has('ssh_command_type')) filterSSHCommandType.value = urlParams.get('ssh_command_type');
        
        // Load exclude checkboxes
        const excludeProtocol = document.getElementById('excludeProtocol');
        const excludeLevel = document.getElementById('excludeLevel');
        const excludeIP = document.getElementById('excludeIP');
        const excludeDescription = document.getElementById('excludeDescription');
        const excludePort = document.getElementById('excludePort');
        const excludeStartDate = document.getElementById('excludeStartDate');
        const excludeEndDate = document.getElementById('excludeEndDate');
        const excludeSSHCommandType = document.getElementById('excludeSSHCommandType');
        
        if (excludeProtocol && urlParams.has('exclude_protocol')) excludeProtocol.checked = urlParams.get('exclude_protocol') === 'true';
        if (excludeLevel && urlParams.has('exclude_level')) excludeLevel.checked = urlParams.get('exclude_level') === 'true';
        if (excludeIP && urlParams.has('exclude_source_ip')) excludeIP.checked = urlParams.get('exclude_source_ip') === 'true';
        if (excludeDescription && urlParams.has('exclude_description')) excludeDescription.checked = urlParams.get('exclude_description') === 'true';
        if (excludePort && urlParams.has('exclude_port')) excludePort.checked = urlParams.get('exclude_port') === 'true';
        if (excludeStartDate && urlParams.has('exclude_start_date')) excludeStartDate.checked = urlParams.get('exclude_start_date') === 'true';
        if (excludeEndDate && urlParams.has('exclude_end_date')) excludeEndDate.checked = urlParams.get('exclude_end_date') === 'true';
        if (excludeSSHCommandType && urlParams.has('exclude_ssh_command_type')) excludeSSHCommandType.checked = urlParams.get('exclude_ssh_command_type') === 'true';
        
        // Load pagination
        if (urlParams.has('page')) {
            const page = parseInt(urlParams.get('page'));
            if (!isNaN(page) && page > 0) {
                currentPage = page;
            }
        }
        
        // Update SSH filter visibility
        toggleSSHCommandTypeFilter();
        
        // Update search clear buttons
        const clearSearchBtn = document.getElementById('clearSearchBtn');
        if (filterSearch && clearSearchBtn) {
            clearSearchBtn.style.display = filterSearch.value.trim() ? 'flex' : 'none';
        }
        
        // Update exclude visual indicators
        const excludeCheckboxes = ['excludeProtocol', 'excludeLevel', 'excludeIP', 'excludeDescription',
                                   'excludeStartDate', 'excludeEndDate', 'excludeSSHCommandType'];
        excludeCheckboxes.forEach(checkboxId => {
            updateExcludeVisualIndicator(checkboxId);
        });
        
        return urlParams.toString().length > 0;
    } catch (e) {
        console.warn('Failed to load filters from URL:', e);
        return false;
    }
}

// Update URL with current filter state (for sharing)
function updateURLWithFilters() {
    try {
        const params = new URLSearchParams();
        
        const filterProtocol = document.getElementById('filterProtocol');
        const filterLevel = document.getElementById('filterLevel');
        const filterIP = document.getElementById('filterIP');
        const filterDescription = document.getElementById('filterDescription');
        const filterPort = document.getElementById('filterPort');
        const filterStartDate = document.getElementById('filterStartDate');
        const filterEndDate = document.getElementById('filterEndDate');
        const filterSearch = document.getElementById('filterSearch');
        const filterSSHCommandType = document.getElementById('filterSSHCommandType');
        
        if (filterProtocol && filterProtocol.value) params.append('protocol', filterProtocol.value);
        if (filterLevel && filterLevel.value) params.append('level', filterLevel.value);
        if (filterIP && filterIP.value) params.append('source_ip', filterIP.value);
        if (filterDescription && filterDescription.value) params.append('description', filterDescription.value);
        if (filterPort && filterPort.value) params.append('port', filterPort.value);
        if (filterStartDate && filterStartDate.value) params.append('start_date', filterStartDate.value);
        if (filterEndDate && filterEndDate.value) params.append('end_date', filterEndDate.value);
        if (filterSearch && filterSearch.value.trim()) params.append('search', filterSearch.value.trim());
        if (filterSSHCommandType && filterSSHCommandType.value) params.append('ssh_command_type', filterSSHCommandType.value);
        
        const excludeProtocol = document.getElementById('excludeProtocol');
        const excludeLevel = document.getElementById('excludeLevel');
        const excludeIP = document.getElementById('excludeIP');
        const excludeDescription = document.getElementById('excludeDescription');
        const excludePort = document.getElementById('excludePort');
        const excludeStartDate = document.getElementById('excludeStartDate');
        const excludeEndDate = document.getElementById('excludeEndDate');
        const excludeSSHCommandType = document.getElementById('excludeSSHCommandType');
        
        if (excludeProtocol && excludeProtocol.checked) params.append('exclude_protocol', 'true');
        if (excludeLevel && excludeLevel.checked) params.append('exclude_level', 'true');
        if (excludeIP && excludeIP.checked) params.append('exclude_source_ip', 'true');
        if (excludeDescription && excludeDescription.checked) params.append('exclude_description', 'true');
        if (excludePort && excludePort.checked) params.append('exclude_port', 'true');
        if (excludeStartDate && excludeStartDate.checked) params.append('exclude_start_date', 'true');
        if (excludeEndDate && excludeEndDate.checked) params.append('exclude_end_date', 'true');
        if (excludeSSHCommandType && excludeSSHCommandType.checked) params.append('exclude_ssh_command_type', 'true');
        
        if (currentPage > 1) params.append('page', currentPage);
        
        // Update URL without reloading page
        const newURL = window.location.pathname + (params.toString() ? '?' + params.toString() : '');
        window.history.pushState({}, '', newURL);
    } catch (e) {
        console.warn('Failed to update URL with filters:', e);
    }
}

// Save filters to localStorage
function saveFiltersToStorage() {
    try {
        const filters = {
            protocol: document.getElementById('filterProtocol')?.value || '',
            level: document.getElementById('filterLevel')?.value || '',
            source_ip: document.getElementById('filterIP')?.value || '',
            description: document.getElementById('filterDescription')?.value || '',
            port: document.getElementById('filterPort')?.value || '',
            start_date: document.getElementById('filterStartDate')?.value || '',
            end_date: document.getElementById('filterEndDate')?.value || '',
            search: document.getElementById('filterSearch')?.value || '',
            ssh_command_type: document.getElementById('filterSSHCommandType')?.value || '',
            exclude_protocol: document.getElementById('excludeProtocol')?.checked || false,
            exclude_level: document.getElementById('excludeLevel')?.checked || false,
            exclude_ip: document.getElementById('excludeIP')?.checked || false,
            exclude_description: document.getElementById('excludeDescription')?.checked || false,
            exclude_port: document.getElementById('excludePort')?.checked || false,
            exclude_start_date: document.getElementById('excludeStartDate')?.checked || false,
            exclude_end_date: document.getElementById('excludeEndDate')?.checked || false,
            exclude_ssh_command_type: document.getElementById('excludeSSHCommandType')?.checked || false
        };
        localStorage.setItem('beelzebub_filters', JSON.stringify(filters));
    } catch (e) {
        console.warn('Failed to save filters to localStorage:', e);
    }
}

// Load filters from localStorage
function loadFiltersFromStorage() {
    try {
        const saved = localStorage.getItem('beelzebub_filters');
        if (!saved) return;
        
        const filters = JSON.parse(saved);
        
        const filterProtocol = document.getElementById('filterProtocol');
        const filterLevel = document.getElementById('filterLevel');
        const filterIP = document.getElementById('filterIP');
        const filterDescription = document.getElementById('filterDescription');
        const filterStartDate = document.getElementById('filterStartDate');
        const filterEndDate = document.getElementById('filterEndDate');
        const filterSearch = document.getElementById('filterSearch');
        const filterSSHCommandType = document.getElementById('filterSSHCommandType');
        
        if (filterProtocol && filters.protocol) filterProtocol.value = filters.protocol;
        if (filterLevel && filters.level) filterLevel.value = filters.level;
        if (filterIP && filters.source_ip) filterIP.value = filters.source_ip;
        if (filterDescription && filters.description) filterDescription.value = filters.description;
        if (filterPort && filters.port) filterPort.value = filters.port;
        if (filterStartDate && filters.start_date) filterStartDate.value = filters.start_date;
        if (filterEndDate && filters.end_date) filterEndDate.value = filters.end_date;
        if (filterSearch && filters.search) filterSearch.value = filters.search;
        if (filterSSHCommandType && filters.ssh_command_type) filterSSHCommandType.value = filters.ssh_command_type;
        
        const excludeProtocol = document.getElementById('excludeProtocol');
        const excludeLevel = document.getElementById('excludeLevel');
        const excludeIP = document.getElementById('excludeIP');
        const excludeDescription = document.getElementById('excludeDescription');
        const excludePort = document.getElementById('excludePort');
        const excludeStartDate = document.getElementById('excludeStartDate');
        const excludeEndDate = document.getElementById('excludeEndDate');
        const excludeSSHCommandType = document.getElementById('excludeSSHCommandType');
        
        if (excludeProtocol) excludeProtocol.checked = filters.exclude_protocol || false;
        if (excludeLevel) excludeLevel.checked = filters.exclude_level || false;
        if (excludeIP) excludeIP.checked = filters.exclude_ip || false;
        if (excludeDescription) excludeDescription.checked = filters.exclude_description || false;
        if (excludePort) excludePort.checked = filters.exclude_port || false;
        if (excludeStartDate) excludeStartDate.checked = filters.exclude_start_date || false;
        if (excludeEndDate) excludeEndDate.checked = filters.exclude_end_date || false;
        if (excludeSSHCommandType) excludeSSHCommandType.checked = filters.exclude_ssh_command_type || false;
        
        // Update SSH filter visibility
        toggleSSHCommandTypeFilter();
        
        // Update search clear buttons
        const clearSearchBtn = document.getElementById('clearSearchBtn');
        if (filterSearch && clearSearchBtn) {
            clearSearchBtn.style.display = filterSearch.value.trim() ? 'flex' : 'none';
        }
        
        // Update exclude visual indicators
        const excludeCheckboxes = ['excludeProtocol', 'excludeLevel', 'excludeIP', 'excludeDescription', 'excludePort',
                                   'excludeStartDate', 'excludeEndDate', 'excludeSSHCommandType'];
        excludeCheckboxes.forEach(checkboxId => {
            updateExcludeVisualIndicator(checkboxId);
        });
        
        return true;
    } catch (e) {
        console.warn('Failed to load filters from localStorage:', e);
        return false;
    }
}

// Load logs
async function loadLogs() {
    const tbody = document.getElementById('logsTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = '<tr><td colspan="7" class="loading"><i class="fas fa-spinner fa-spin"></i> Loading logs...</td></tr>';

    try {
        const filterProtocol = document.getElementById('filterProtocol');
        const filterLevel = document.getElementById('filterLevel');
        const filterIP = document.getElementById('filterIP');
        const filterDescription = document.getElementById('filterDescription');
        const filterPort = document.getElementById('filterPort');
        const filterStartDate = document.getElementById('filterStartDate');
        const filterEndDate = document.getElementById('filterEndDate');
        const filterSearch = document.getElementById('filterSearch');
        
        const filterSSHCommandType = document.getElementById('filterSSHCommandType');
        
        const params = new URLSearchParams({
            page: currentPage,
            per_page: perPage,
            protocol: filterProtocol ? filterProtocol.value : '',
            level: filterLevel ? filterLevel.value : '',
            source_ip: filterIP ? filterIP.value : '',
            description: filterDescription ? filterDescription.value : '',
            port: filterPort ? filterPort.value : '',
            start_date: filterStartDate ? filterStartDate.value : '',
            end_date: filterEndDate ? filterEndDate.value : '',
            search: filterSearch ? filterSearch.value : '',
            ssh_command_type: filterSSHCommandType ? filterSSHCommandType.value : ''
        });

        // Add exclude parameters if checkboxes are checked
        const excludeProtocol = document.getElementById('excludeProtocol');
        const excludeLevel = document.getElementById('excludeLevel');
        const excludeIP = document.getElementById('excludeIP');
        const excludeDescription = document.getElementById('excludeDescription');
        const excludePort = document.getElementById('excludePort');
        const excludeStartDate = document.getElementById('excludeStartDate');
        const excludeEndDate = document.getElementById('excludeEndDate');
        const excludeSSHCommandType = document.getElementById('excludeSSHCommandType');

        if (excludeProtocol && excludeProtocol.checked && filterProtocol && filterProtocol.value) {
            params.append('exclude_protocol', filterProtocol.value);
        }
        if (excludeLevel && excludeLevel.checked && filterLevel && filterLevel.value) {
            params.append('exclude_level', filterLevel.value);
        }
        if (excludeIP && excludeIP.checked && filterIP && filterIP.value) {
            params.append('exclude_source_ip', filterIP.value);
        }
        if (excludeDescription && excludeDescription.checked && filterDescription && filterDescription.value) {
            params.append('exclude_description', filterDescription.value);
        }
        if (excludePort && excludePort.checked && filterPort && filterPort.value) {
            params.append('exclude_port', filterPort.value);
        }
        if (excludeStartDate && excludeStartDate.checked && filterStartDate && filterStartDate.value) {
            params.append('exclude_start_date', filterStartDate.value);
        }
        if (excludeEndDate && excludeEndDate.checked && filterEndDate && filterEndDate.value) {
            params.append('exclude_end_date', filterEndDate.value);
        }
        if (excludeSSHCommandType && excludeSSHCommandType.checked && filterSSHCommandType && filterSSHCommandType.value) {
            params.append('exclude_ssh_command_type', filterSSHCommandType.value);
        }
        
        // Update active filter count when filters change
        updateActiveFilterCount();

        const response = await fetch(`/api/logs?${params}`);
        const data = await response.json();

        // Clear loading
        tbody.innerHTML = '';

        if (data.logs.length === 0) {
            const hasFilters = countActiveFilters() > 0;
            let emptyMessage = '<tr><td colspan="7" class="loading">';
            if (hasFilters) {
                emptyMessage += '<div style="padding: 20px;"><i class="fas fa-filter" style="font-size: 2rem; color: var(--text-secondary); margin-bottom: 10px;"></i><br>';
                emptyMessage += '<strong style="color: var(--text-primary);">No logs match your filters</strong><br>';
                emptyMessage += '<span style="color: var(--text-secondary); font-size: 0.9rem;">Try adjusting your filter criteria or clearing filters to see more results.</span></div>';
            } else {
                emptyMessage += '<div style="padding: 20px;"><i class="fas fa-inbox" style="font-size: 2rem; color: var(--text-secondary); margin-bottom: 10px;"></i><br>';
                emptyMessage += '<strong style="color: var(--text-primary);">No logs found</strong><br>';
                emptyMessage += '<span style="color: var(--text-secondary); font-size: 0.9rem;">The log file may be empty or not loaded yet.</span></div>';
            }
            emptyMessage += '</td></tr>';
            tbody.innerHTML = emptyMessage;
            
            // Update active filter count
            updateActiveFilterCount();
            return;
        }
        
        // Update active filter count
        updateActiveFilterCount();

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
        tbody.innerHTML = '<tr><td colspan="7" class="loading">' +
            '<div style="padding: 20px;"><i class="fas fa-exclamation-triangle" style="font-size: 2rem; color: var(--danger-color); margin-bottom: 10px;"></i><br>' +
            '<strong style="color: var(--text-primary);">Error loading logs</strong><br>' +
            '<span style="color: var(--text-secondary); font-size: 0.9rem;">Please refresh the page or check your connection.</span></div>' +
            '</td></tr>';
        updateActiveFilterCount();
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

// Escape HTML entities
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Render event details
function renderEventDetails(event) {
    let html = '<div class="detail-section">';
    html += '<h4>Basic Information</h4>';
    html += `<div class="detail-row"><div class="detail-label">Time:</div><div class="detail-value">${escapeHtml(new Date(event.time).toLocaleString())}</div></div>`;
    html += `<div class="detail-row"><div class="detail-label">Level:</div><div class="detail-value">${escapeHtml(event.level)}</div></div>`;
    html += `<div class="detail-row"><div class="detail-label">Message:</div><div class="detail-value">${escapeHtml(event.msg)}</div></div>`;
    html += `<div class="detail-row"><div class="detail-label">Line Number:</div><div class="detail-value">${escapeHtml(event.line_number)}</div></div>`;
    html += '</div>';

    if (event.event) {
        const evt = event.event;

        html += '<div class="detail-section">';
        html += '<h4>Event Details</h4>';
        if (evt.Protocol) html += `<div class="detail-row"><div class="detail-label">Protocol:</div><div class="detail-value">${escapeHtml(evt.Protocol)}</div></div>`;
        if (evt.SourceIp) html += `<div class="detail-row"><div class="detail-label">Source IP:</div><div class="detail-value">${escapeHtml(evt.SourceIp)}</div></div>`;
        if (evt.SourcePort) html += `<div class="detail-row"><div class="detail-label">Source Port:</div><div class="detail-value">${escapeHtml(evt.SourcePort)}</div></div>`;
        if (evt.RemoteAddr) html += `<div class="detail-row"><div class="detail-label">Remote Address:</div><div class="detail-value">${escapeHtml(evt.RemoteAddr)}</div></div>`;
        if (evt.Description) html += `<div class="detail-row"><div class="detail-label">Description:</div><div class="detail-value">${escapeHtml(evt.Description)}</div></div>`;
        if (evt.Status) html += `<div class="detail-row"><div class="detail-label">Status:</div><div class="detail-value">${escapeHtml(evt.Status)}</div></div>`;
        html += '</div>';

        if (evt.HTTPMethod || evt.RequestURI) {
            html += '<div class="detail-section">';
            html += '<h4>HTTP Details</h4>';
            if (evt.HTTPMethod) html += `<div class="detail-row"><div class="detail-label">Method:</div><div class="detail-value">${escapeHtml(evt.HTTPMethod)}</div></div>`;
            if (evt.RequestURI) html += `<div class="detail-row"><div class="detail-label">Request URI:</div><div class="detail-value">${escapeHtml(evt.RequestURI)}</div></div>`;
            if (evt.HostHTTPRequest) html += `<div class="detail-row"><div class="detail-label">Host:</div><div class="detail-value">${escapeHtml(evt.HostHTTPRequest)}</div></div>`;
            if (evt.UserAgent) html += `<div class="detail-row"><div class="detail-label">User Agent:</div><div class="detail-value">${escapeHtml(evt.UserAgent)}</div></div>`;
            if (evt.Cookies) html += `<div class="detail-row"><div class="detail-label">Cookies:</div><div class="detail-value">${escapeHtml(evt.Cookies)}</div></div>`;
            if (evt.Body) html += `<div class="detail-row"><div class="detail-label">Body:</div><div class="detail-value"><pre class="command-output">${escapeHtml(evt.Body)}</pre></div></div>`;
            html += '</div>';
        }

        if (evt.HeadersMap) {
            html += '<div class="detail-section">';
            html += '<h4>HTTP Headers</h4>';
            for (const [key, values] of Object.entries(evt.HeadersMap)) {
                html += `<div class="detail-row"><div class="detail-label">${escapeHtml(key)}:</div><div class="detail-value">${escapeHtml(Array.isArray(values) ? values.join(', ') : values)}</div></div>`;
            }
            html += '</div>';
        }

        if (evt.User || evt.Password) {
            html += '<div class="detail-section">';
            html += '<h4>Credentials</h4>';
            if (evt.User) html += `<div class="detail-row"><div class="detail-label">User:</div><div class="detail-value">${escapeHtml(evt.User)}</div></div>`;
            if (evt.Password) html += `<div class="detail-row"><div class="detail-label">Password:</div><div class="detail-value">${escapeHtml(evt.Password)}</div></div>`;
            html += '</div>';
        }

        if (evt.Command) {
            html += '<div class="detail-section">';
            html += '<h4>Command</h4>';
            html += `<div class="detail-row"><div class="detail-value"><pre class="command-output">${escapeHtml(evt.Command)}</pre></div></div>`;
            if (evt.CommandOutput) {
                html += '<div class="detail-row detail-row-output">';
                html += '<div class="detail-label">Output:</div>';
                html += `<div class="detail-value"><pre class="command-output">${escapeHtml(evt.CommandOutput)}</pre></div>`;
                html += '</div>';
            }
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

// Render top services (descriptions) chart
function renderDescriptionChart(data) {
    const ctx = document.getElementById('descriptionChart');
    if (!ctx) return;
    if (charts.descriptions) charts.descriptions.destroy();
    charts.descriptions = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: Object.keys(data),
            datasets: [{
                label: 'Top Services',
                data: Object.values(data),
                backgroundColor: 'rgba(118, 75, 162, 0.8)',
                borderColor: 'rgba(118, 75, 162, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: { legend: { display: false }, tooltip: { intersect: false } },
            scales: {
                x: { ticks: { color: '#a8b2d1' }, grid: { color: 'rgba(168, 178, 209, 0.1)' } },
                y: { ticks: { color: '#a8b2d1' }, grid: { color: 'rgba(168, 178, 209, 0.1)' } }
            }
        }
    });
}

// Render top paths chart
function renderPathChart(data) {
    const ctx = document.getElementById('pathChart');
    if (!ctx) return;
    if (charts.paths) charts.paths.destroy();
    charts.paths = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: Object.keys(data),
            datasets: [{
                label: 'Top Paths',
                data: Object.values(data),
                backgroundColor: 'rgba(79, 172, 254, 0.8)',
                borderColor: 'rgba(79, 172, 254, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: { legend: { display: false }, tooltip: { intersect: false } },
            scales: {
                x: { ticks: { color: '#a8b2d1', maxRotation: 45, minRotation: 45 }, grid: { color: 'rgba(168, 178, 209, 0.1)' } },
                y: { ticks: { color: '#a8b2d1' }, grid: { color: 'rgba(168, 178, 209, 0.1)' } }
            }
        }
    });
}

// Render ports chart
function renderPortChart(data) {
    const ctx = document.getElementById('portChart');
    if (!ctx) return;
    if (charts.ports) charts.ports.destroy();
    charts.ports = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: Object.keys(data),
            datasets: [{
                data: Object.values(data),
                backgroundColor: [
                    'rgba(102, 126, 234, 0.8)',
                    'rgba(118, 75, 162, 0.8)',
                    'rgba(79, 172, 254, 0.8)',
                    'rgba(67, 233, 123, 0.8)',
                    'rgba(245, 87, 108, 0.8)',
                    'rgba(255, 165, 2, 0.8)'
                ],
                borderWidth: 2,
                borderColor: '#16213e'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#ffffff' } }
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
        const params = new URLSearchParams({
            page: ipPage,
            per_page: ipPerPage
        });
        
        // Add search parameter if search input exists and has value
        const ipSearchInput = document.getElementById('ipSearchInput');
        if (ipSearchInput && ipSearchInput.value.trim()) {
            params.append('search', ipSearchInput.value.trim());
        }
        
        const response = await fetch(`/api/all-ips?${params}`);
        const data = await response.json();
        
        tbody.innerHTML = '';
        
        if (!data.ips || data.ips.length === 0) {
            const ipSearchInput = document.getElementById('ipSearchInput');
            const hasSearch = ipSearchInput && ipSearchInput.value.trim();
            let emptyMessage = '<tr><td colspan="7" class="loading">';
            if (hasSearch) {
                emptyMessage += '<div style="padding: 20px;"><i class="fas fa-search" style="font-size: 2rem; color: var(--text-secondary); margin-bottom: 10px;"></i><br>';
                emptyMessage += '<strong style="color: var(--text-primary);">No IP addresses match your search</strong><br>';
                emptyMessage += '<span style="color: var(--text-secondary); font-size: 0.9rem;">Try a different search term or clear the search to see all IPs.</span></div>';
            } else {
                emptyMessage += '<div style="padding: 20px;"><i class="fas fa-network-wired" style="font-size: 2rem; color: var(--text-secondary); margin-bottom: 10px;"></i><br>';
                emptyMessage += '<strong style="color: var(--text-primary);">No IP addresses found</strong><br>';
                emptyMessage += '<span style="color: var(--text-secondary); font-size: 0.9rem;">The log file may not contain any IP addresses yet.</span></div>';
            }
            emptyMessage += '</td></tr>';
            tbody.innerHTML = emptyMessage;
            return;
        }
        
        data.ips.forEach(ipData => {
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
        
        // Update pagination controls
        const ipsInfo = document.getElementById('ipsPageInfo');
        const prevBtn = document.getElementById('prevIPsPage');
        const nextBtn = document.getElementById('nextIPsPage');
        if (ipsInfo && prevBtn && nextBtn) {
            ipsInfo.textContent = `Page ${data.page} of ${data.total_pages} (${data.total.toLocaleString()} IPs)`;
            prevBtn.disabled = data.page === 1;
            nextBtn.disabled = data.page === data.total_pages;
        }
        
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
        
        // Add search parameter if search input exists and has value
        const credSearchInput = document.getElementById('credSearchInput');
        if (credSearchInput && credSearchInput.value.trim()) {
            params.append('search', credSearchInput.value.trim());
        }
        
        const response = await fetch(`/api/credentials?${params}`);
        const data = await response.json();
        
        tbody.innerHTML = '';
        
        if (data.credentials.length === 0) {
            const credSearchInput = document.getElementById('credSearchInput');
            const hasSearch = credSearchInput && credSearchInput.value.trim();
            let emptyMessage = '<tr><td colspan="4" class="loading">';
            if (hasSearch) {
                emptyMessage += '<div style="padding: 20px;"><i class="fas fa-search" style="font-size: 2rem; color: var(--text-secondary); margin-bottom: 10px;"></i><br>';
                emptyMessage += '<strong style="color: var(--text-primary);">No credentials match your search</strong><br>';
                emptyMessage += '<span style="color: var(--text-secondary); font-size: 0.9rem;">Try a different search term or clear the search to see all credentials.</span></div>';
            } else {
                emptyMessage += '<div style="padding: 20px;"><i class="fas fa-key" style="font-size: 2rem; color: var(--text-secondary); margin-bottom: 10px;"></i><br>';
                emptyMessage += '<strong style="color: var(--text-primary);">No credentials found</strong><br>';
                emptyMessage += '<span style="color: var(--text-secondary); font-size: 0.9rem;">The honeypot hasn\'t captured any credentials yet.</span></div>';
            }
            emptyMessage += '</td></tr>';
            tbody.innerHTML = emptyMessage;
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

// Export IP addresses (with search filter support)
function exportIPs(format) {
    const ipSearchInput = document.getElementById('ipSearchInput');
    const search = ipSearchInput && ipSearchInput.value.trim() ? ipSearchInput.value.trim() : '';
    const params = new URLSearchParams();
    if (search) {
        params.append('search', search);
    }
    const url = `/api/export/ips/${format}${params.toString() ? '?' + params.toString() : ''}`;
    window.location.href = url;
}

// Export credentials (with search filter support)
function exportCredentials(format) {
    const credSearchInput = document.getElementById('credSearchInput');
    const search = credSearchInput && credSearchInput.value.trim() ? credSearchInput.value.trim() : '';
    const params = new URLSearchParams();
    if (search) {
        params.append('search', search);
    }
    const url = `/api/export/credentials/${format}${params.toString() ? '?' + params.toString() : ''}`;
    window.location.href = url;
}

