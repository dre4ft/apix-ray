// ===== Configuration =====
const API_BASE = 'http://localhost:8080';
let currentScanId = null;
let scanStartTime = null;
let scanInterval = null;
let selectedVulnerabilities = [];
let scanWs = null;

// ===== Initialize =====
document.addEventListener('DOMContentLoaded', () => {
    initializeUI();
    setupEventListeners();
    checkHealth();
});

async function initializeUI() {
    // Load vulnerabilities from playbooks
    await loadVulnerabilitiesFromPlaybooks();

    // Load schemas
    loadSchemas();

    // Load playbooks
    loadPlaybooks();
}

function setupEventListeners() {
    // Tabs
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });

    // Buttons
    document.getElementById('start-scan-btn').addEventListener('click', startScan);
    document.getElementById('stop-scan-btn').addEventListener('click', stopScan);
    document.getElementById('refresh-btn').addEventListener('click', refreshScan);
    document.getElementById('export-report-btn').addEventListener('click', exportReport);
    document.getElementById('clear-logs-btn').addEventListener('click', clearLogs);

    // Schema management
    document.getElementById('refresh-schemas-btn').addEventListener('click', loadSchemas);
    document.getElementById('upload-schema-btn').addEventListener('click', uploadSchema);

    // Reports management
    document.getElementById('refresh-reports-btn').addEventListener('click', loadReports);

    // Playbooks management
    document.getElementById('refresh-playbooks-btn').addEventListener('click', loadPlaybooks);
    document.getElementById('add-playbook-btn').addEventListener('click', showAddPlaybookForm);
    document.getElementById('save-playbook-btn').addEventListener('click', saveNewPlaybook);
    document.getElementById('cancel-playbook-btn').addEventListener('click', hideAddPlaybookForm);

    // History management
    document.getElementById('refresh-history-btn').addEventListener('click', loadScanHistory);

    // Vulnerability checkboxes
    document.querySelectorAll('.checkbox input[type="checkbox"]').forEach(cb => {
        cb.addEventListener('change', (e) => {
            if (e.target.checked) {
                if (!selectedVulnerabilities.includes(e.target.value)) {
                    selectedVulnerabilities.push(e.target.value);
                }
            } else {
                selectedVulnerabilities = selectedVulnerabilities.filter(v => v !== e.target.value);
            }
        });
    });

    // LLM Type change
    document.getElementById('llm-type').addEventListener('change', (e) => {
        loadLLMModels(e.target.value);
    });

    // Advanced configuration toggle
    document.getElementById('advanced-config-toggle').addEventListener('change', (e) => {
        const advancedConfig = document.getElementById('advanced-config');
        if (e.target.checked) {
            advancedConfig.style.display = 'block';
        } else {
            advancedConfig.style.display = 'none';
        }
    });
}

// ===== Health Check =====
async function checkHealth() {
    try {
        const response = await fetch(`${API_BASE}/health`);
        if (response.ok) {
            setHealthStatus(true);
        } else {
            setHealthStatus(false);
        }
    } catch (error) {
        setHealthStatus(false);
    }
}

function setHealthStatus(isHealthy) {
    const indicator = document.getElementById('health-status');
    const text = document.getElementById('health-text');
    
    if (isHealthy) {
        indicator.classList.remove('offline');
        text.textContent = 'Connected';
    } else {
        indicator.classList.add('offline');
        text.textContent = 'Offline';
    }
}

// ===== Vulnerabilities from Playbooks =====
async function loadVulnerabilitiesFromPlaybooks() {
    try {
        const response = await fetch(`${API_BASE}/playbooks/vulnerabilities`);
        const data = await response.json();

        const vulnerabilityList = document.querySelector('.checkbox-group');
        vulnerabilityList.innerHTML = ''; // Clear existing checkboxes

        data.vulnerabilities.forEach(vuln => {
            const label = document.createElement('label');
            label.className = 'checkbox';

            label.innerHTML = `
                <input type="checkbox" value="${vuln}" checked>
                ${vuln}
            `;

            vulnerabilityList.appendChild(label);

            // Add to selected vulnerabilities
            selectedVulnerabilities.push(vuln);
        });

        // Re-attach event listeners for new checkboxes
        document.querySelectorAll('.checkbox input[type="checkbox"]').forEach(cb => {
            cb.addEventListener('change', (e) => {
                if (e.target.checked) {
                    if (!selectedVulnerabilities.includes(e.target.value)) {
                        selectedVulnerabilities.push(e.target.value);
                    }
                } else {
                    selectedVulnerabilities = selectedVulnerabilities.filter(v => v !== e.target.value);
                }
            });
        });

    } catch (error) {
        console.error('Failed to load vulnerabilities from playbooks:', error);
        // Fallback to default vulnerabilities
        showToast('Failed to load vulnerabilities, using defaults', 'warning');
    }
}

// ===== LLM Models =====
async function loadLLMModels(llmType) {
    try {
        const response = await fetch(`${API_BASE}/llm/models`);
        const data = await response.json();
        
        const modelSelect = document.getElementById('llm-model');
        const models = data.models[llmType] || [];
        
        modelSelect.innerHTML = models.map(model => 
            `<option value="${model}">${model}</option>`
        ).join('');
    } catch (error) {
        showToast('Failed to load LLM models', 'error');
    }
}

// ===== Scan Operations =====
async function startScan() {
    const targetUrl = document.getElementById('target-url').value;
    const llmType = document.getElementById('llm-type').value;
    const llmModel = document.getElementById('llm-model').value;
    const oasSchema = document.getElementById('oas-schema').value;

    if (!targetUrl) {
        showToast('Please enter a target URL', 'warning');
        return;
    }

    if (!oasSchema) {
        showToast('Please select an OpenAPI schema', 'warning');
        return;
    }

    if (selectedVulnerabilities.length === 0) {
        showToast('Please select at least one vulnerability to test', 'warning');
        return;
    }

    try {
        // Disable start button, enable stop button
        document.getElementById('start-scan-btn').disabled = true;
        document.getElementById('stop-scan-btn').disabled = false;

        const useMcp = document.getElementById('use-mcp').checked;

        // Build request limits configuration
        const requestLimits = {
            global_max_requests: parseInt(document.getElementById('global-max-requests').value) || 100,
            per_vulnerability_max: parseInt(document.getElementById('per-vuln-max').value) || 25,
            adaptive_enabled: document.getElementById('adaptive-enabled').checked,
            relevance_threshold: parseFloat(document.getElementById('relevance-threshold').value) || 0.7,
            evolution_factor: parseFloat(document.getElementById('evolution-factor').value) || 1.2
        };

        const response = await fetch(`${API_BASE}/start_scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target_url: targetUrl,
                llm_type: llmType,
                model: llmModel,
                schema_id: oasSchema,
                vulnerabilities: selectedVulnerabilities,
                use_mcp: useMcp,
                request_limits: requestLimits
            })
        });

        const data = await response.json();
        currentScanId = data.scan_id;

        connectScanWebSocket(currentScanId);
        
        // Update target info
        document.getElementById('target-info-url').textContent = targetUrl;
        document.getElementById('target-info-llm').textContent = llmType;
        document.getElementById('target-info-model').textContent = llmModel;
        document.getElementById('target-info-scanid').textContent = currentScanId.substring(0, 8) + '...';

        // Start polling for updates (moins fréquent maintenant qu'on a WebSocket)
        scanStartTime = Date.now();
        scanInterval = setInterval(pollScanStatus, 10000); // Toutes les 10 secondes au lieu de 2

        // Switch to dashboard tab
        switchTab('dashboard');
        
        showToast('Scan started successfully', 'success');
        addLog('Scan initialized with ID: ' + currentScanId, 'success');

    } catch (error) {
        showToast('Failed to start scan', 'error');
        document.getElementById('start-scan-btn').disabled = false;
        document.getElementById('stop-scan-btn').disabled = true;
    }
}
async function stopScan() {
    if (!currentScanId) {
        showToast('No active scan to stop', 'warning');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/stop_scan/${currentScanId}`, {
            method: 'POST'
        });

        const data = await response.json();

        if (response.ok) {
            if (scanInterval) {
                clearInterval(scanInterval);
                scanInterval = null;
            }

            disconnectScanWebSocket();
            
            document.getElementById('start-scan-btn').disabled = false;
            document.getElementById('stop-scan-btn').disabled = true;
            document.getElementById('status-value').textContent = '⏹️ Stopped';
            
            showToast('Scan stopped successfully', 'warning');
            addLog('Scan stopped by user', 'warning');
        } else {
            showToast('Failed to stop scan', 'error');
        }
    } catch (error) {
        showToast('Error stopping scan', 'error');
        console.error('Stop scan error:', error);
    }
}

async function pollScanStatus() {
    if (!currentScanId) return;

    try {
        const response = await fetch(`${API_BASE}/scan_overview/${currentScanId}`);
        const data = await response.json();

        if (response.ok) {
            updateDashboard(data);

            if (data.logs && data.logs.length > 0) {
                displayLogs(data.logs);
            }

            if (data.results && data.results.length > 0) {
                displayResults(data.results);
            }

            // Mise à jour des métriques si disponibles
            if (data.metrics) {
                updateMetrics(data.metrics);
            }

            // Check if scan is complete
            if (data.status === 'completed' || data.status === 'failed' || data.status === 'error') {
                clearInterval(scanInterval);
                document.getElementById('start-scan-btn').disabled = false;
                document.getElementById('stop-scan-btn').disabled = true;
                document.getElementById('export-report-btn').disabled = false;
                
                if (data.status === 'completed') {
                    showToast('Scan completed successfully', 'success');
                } else if (data.status === 'error') {
                    const errorMsg = data.error || 'Scan failed with an error';
                    showToast(`Scan error: ${errorMsg}`, 'error');
                } else {
                    showToast('Scan failed', 'error');
                }
            }
        }
    } catch (error) {
        console.error('Polling error:', error);
    }
}

function refreshScan() {
    if (currentScanId) {
        pollScanStatus();
        showToast('Refreshed scan status', 'success');
    }
}

function connectScanWebSocket(scanId) {
    disconnectScanWebSocket();

    try {
        scanWs = new WebSocket(`ws://localhost:8080/ws/scan/${scanId}`);

        scanWs.onopen = () => {
            console.log('WebSocket scan connecté', scanId);
        };

        scanWs.onmessage = (event) => {
            const msg = JSON.parse(event.data);
            if (msg.type === 'scan_update') {
                // Mise à jour complète du dashboard
                updateDashboard({
                    status: msg.status,
                    progress: msg.progress
                });

                // Mise à jour des logs si nouveaux
                if (msg.logs && msg.logs.length > 0) {
                    displayLogs(msg.logs);
                }

                // Mise à jour des résultats si nouveaux
                if (msg.results && msg.results.length > 0) {
                    displayResults(msg.results);
                }

                // Mise à jour des métriques si disponibles
                if (msg.metrics) {
                    updateMetrics(msg.metrics);
                }

                // Vérifier si scan terminé
                if (msg.status === 'completed' || msg.status === 'failed' || msg.status === 'error') {
                    if (scanInterval) {
                        clearInterval(scanInterval);
                        scanInterval = null;
                    }
                    disconnectScanWebSocket();
                    document.getElementById('start-scan-btn').disabled = false;
                    document.getElementById('stop-scan-btn').disabled = true;
                    document.getElementById('export-report-btn').disabled = false;

                    if (msg.status === 'completed') {
                        showToast('Scan completed successfully', 'success');
                    } else if (msg.status === 'error') {
                        const errorMsg = msg.error || 'Scan failed with an error';
                        showToast(`Scan error: ${errorMsg}`, 'error');
                    } else {
                        showToast('Scan failed', 'error');
                    }
                }
            } else if (msg.type === 'init') {
                // État initial
                if (msg.logs) displayLogs(msg.logs);
                if (msg.results) displayResults(msg.results);
                updateDashboard({
                    status: msg.status,
                    progress: msg.progress
                });
            }
        };

        scanWs.onclose = () => {
            console.log('WebSocket scan déconnecté', scanId);
        };

        scanWs.onerror = (err) => {
            console.error('WebSocket scan error', err);
        };
    } catch (error) {
        console.error('Impossible de démarrer WebSocket', error);
    }
}

function disconnectScanWebSocket() {
    if (scanWs) {
        scanWs.close();
        scanWs = null;
    }
}

// ===== Dashboard Updates =====
function updateDashboard(statusData) {
    // Update status
    const statusMap = {
        'running': '🔄 Running',
        'completed': '✅ Completed',
        'failed': '❌ Failed',
        'error': '❌ Error',
        'stopped': '⏹️ Stopped'
    };
    
    document.getElementById('status-value').textContent = statusMap[statusData.status] || statusData.status;
    
    // Update progress
    const progress = statusData.progress || 0;
    document.getElementById('progress-value').textContent = progress + '%';
    document.getElementById('progress-fill').style.width = progress + '%';

    // Update scan time
    if (scanStartTime) {
        const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
        const hours = Math.floor(elapsed / 3600);
        const minutes = Math.floor((elapsed % 3600) / 60);
        const seconds = elapsed % 60;
        
        document.getElementById('scan-time').textContent = 
            `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
    }
}

function updateMetrics(metrics) {
    // Update metrics grid values
    if (metrics.endpoints_discovered !== undefined) {
        document.getElementById('metric-endpoints').textContent = metrics.endpoints_discovered;
    }
    if (metrics.tests_generated !== undefined) {
        document.getElementById('metric-tests').textContent = metrics.tests_generated;
    }
    if (metrics.high_severity !== undefined) {
        document.getElementById('metric-high').textContent = metrics.high_severity;
    }
    if (metrics.medium_severity !== undefined) {
        document.getElementById('metric-medium').textContent = metrics.medium_severity;
    }

    // Update status cards
    if (metrics.vulnerabilities_found !== undefined) {
        document.getElementById('vuln-count').textContent = metrics.vulnerabilities_found;
    }
    if (metrics.requests_executed !== undefined) {
        document.getElementById('requests-count').textContent = metrics.requests_executed;
    }

    // Update additional metrics if elements exist
    if (metrics.low_severity !== undefined && document.getElementById('metric-low')) {
        document.getElementById('metric-low').textContent = metrics.low_severity;
    }
    if (metrics.critical_severity !== undefined && document.getElementById('metric-critical')) {
        document.getElementById('metric-critical').textContent = metrics.critical_severity;
    }
    if (metrics.info_severity !== undefined && document.getElementById('metric-info')) {
        document.getElementById('metric-info').textContent = metrics.info_severity;
    }
    if (metrics.scan_time_seconds !== undefined && document.getElementById('metric-scan-time')) {
        document.getElementById('metric-scan-time').textContent = metrics.scan_time_seconds + 's';
    }
    if (metrics.avg_response_time_ms !== undefined && document.getElementById('metric-avg-response')) {
        document.getElementById('metric-avg-response').textContent = metrics.avg_response_time_ms + 'ms';
    }
    if (metrics.success_rate_percent !== undefined && document.getElementById('metric-success-rate')) {
        document.getElementById('metric-success-rate').textContent = metrics.success_rate_percent + '%';
    }
}

// ===== Logs Management =====
function addLog(message, type = 'info') {
    const logsContainer = document.getElementById('logs-container');
    const entry = document.createElement('p');
    entry.className = `log-entry log-${type}`;
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    logsContainer.appendChild(entry);
    logsContainer.scrollTop = logsContainer.scrollHeight;
}

function displayLogs(logs) {
    const logsContainer = document.getElementById('logs-container');
    logsContainer.innerHTML = '';
    
    logs.forEach(log => {
        const entry = document.createElement('p');
        entry.className = 'log-entry log-info';
        entry.textContent = `[${new Date().toLocaleTimeString()}] ${log}`;
        logsContainer.appendChild(entry);
    });
    
    logsContainer.scrollTop = logsContainer.scrollHeight;
}

function clearLogs() {
    document.getElementById('logs-container').innerHTML = 
        '<p class="log-entry log-info">Logs cleared</p>';
}

// ===== Results Management =====
function displayResults(results) {
    const resultsContainer = document.getElementById('results-container');
    resultsContainer.innerHTML = '';
    
    if (results.length === 0) {
        resultsContainer.innerHTML = '<p class="empty-state">No vulnerabilities found.</p>';
        document.getElementById('vuln-count').textContent = '0';
        return;
    }

    document.getElementById('vuln-count').textContent = results.length;
    
    results.forEach((vuln, index) => {
        const item = document.createElement('div');
        item.className = 'vulnerability-item';
        
        const severity = vuln.severity || 'medium';
        const severityClass = severity === 'high' ? 'high' : severity === 'medium' ? 'medium' : 'low';
        
        item.innerHTML = `
            <div class="vuln-title">${index + 1}. ${vuln.title || 'Unknown Vulnerability'}</div>
            <span class="vuln-severity ${severityClass}">${severity.toUpperCase()}</span>
            <div class="vuln-detail"><strong>Type:</strong> ${vuln.type || 'N/A'}</div>
            <div class="vuln-detail"><strong>Endpoint:</strong> ${vuln.endpoint || 'N/A'}</div>
            <div class="vuln-detail"><strong>Description:</strong> ${vuln.description || 'N/A'}</div>
            ${vuln.payload ? `<div class="vuln-detail"><strong>Payload:</strong> ${vuln.payload}</div>` : ''}
            ${vuln.response ? `<div class="vuln-detail"><strong>Response:</strong> ${vuln.response.substring(0, 100)}...</div>` : ''}
        `;
        
        resultsContainer.appendChild(item);
    });
}

// ===== Export Report =====
async function exportReport() {
    if (!currentScanId) {
        showToast('No scan results to export', 'warning');
        return;
    }

    try {
        // Récupérer le rapport au format Markdown depuis l'API
        const response = await fetch(`${API_BASE}/get_report/${currentScanId}`);

        if (!response.ok) {
            const errorData = await response.json();
            showToast(`Failed to get report: ${errorData.error}`, 'error');
            return;
        }

        // Le rapport est retourné directement au format Markdown
        const reportMarkdown = await response.text();

        // Créer un blob avec le contenu Markdown
        const dataBlob = new Blob([reportMarkdown], { type: 'text/markdown' });
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `apix-ray-report-${currentScanId.substring(0, 8)}.md`;
        link.click();

        // Nettoyer l'URL
        URL.revokeObjectURL(url);

        showToast('Report exported successfully as Markdown', 'success');

    } catch (error) {
        showToast('Failed to export report', 'error');
        console.error('Export report error:', error);
    }
}

// ===== Schema Management =====
async function loadSchemas() {
    try {
        const response = await fetch(`${API_BASE}/schemas`);
        const data = await response.json();

        displaySchemas(data.schemas || []);
    } catch (error) {
        showToast('Failed to load schemas', 'error');
        console.error('Load schemas error:', error);
    }
}

// ===== Reports Management =====
async function loadReports() {
    try {
        const response = await fetch(`${API_BASE}/list_reports`);
        const data = await response.json();

        displayReports(data.reports || []);
    } catch (error) {
        showToast('Failed to load reports', 'error');
        console.error('Load reports error:', error);
        displayReports([]);
    }
}

function displayReports(reports) {
    const container = document.getElementById('reports-container');

    if (reports.length === 0) {
        container.innerHTML = '<p class="empty-state">No reports available. Run a scan to generate reports.</p>';
        return;
    }

    container.innerHTML = '';

    reports.forEach(report => {
        const reportElement = document.createElement('div');
        reportElement.className = 'report-item';

        const createdDate = new Date(report.created_at).toLocaleString();

        reportElement.innerHTML = `
            <div class="report-info">
                <div class="report-title">Scan ${report.scan_id.substring(0, 8)}</div>
                <div class="report-meta"><strong>Target:</strong> ${report.target_url}</div>
                <div class="report-meta"><strong>Status:</strong> ${report.status}</div>
                <div class="report-meta"><strong>Vulnerabilities:</strong> ${report.vulnerabilities_count}</div>
                <div class="report-meta"><strong>Created:</strong> ${createdDate}</div>
            </div>
            <div class="report-actions">
                <button class="btn btn-primary btn-small" onclick="downloadReport('${report.scan_id}')">
                    📥 Download
                </button>
            </div>
        `;

        container.appendChild(reportElement);
    });
}

async function downloadReport(scanId) {
    try {
        const response = await fetch(`${API_BASE}/get_report/${scanId}`);

        if (!response.ok) {
            const errorData = await response.json();
            showToast(`Failed to download report: ${errorData.error}`, 'error');
            return;
        }

        // Créer un blob avec le contenu Markdown
        const reportContent = await response.text();
        const blob = new Blob([reportContent], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);

        // Créer un lien de téléchargement
        const link = document.createElement('a');
        link.href = url;
        link.download = `apix-ray-report-${scanId.substring(0, 8)}.md`;
        link.click();

        // Nettoyer
        URL.revokeObjectURL(url);

        showToast('Report downloaded successfully', 'success');
    } catch (error) {
        showToast('Failed to download report', 'error');
        console.error('Download report error:', error);
    }
}

// ===== Playbooks Management =====
async function loadPlaybooks() {
    try {
        const response = await fetch(`${API_BASE}/playbooks/`);
        const data = await response.json();

        displayPlaybooks(data.playbooks || {});
    } catch (error) {
        showToast('Failed to load playbooks', 'error');
        console.error('Load playbooks error:', error);
        displayPlaybooks({});
    }
}

function displayPlaybooks(playbooks) {
    const container = document.getElementById('playbooks-container');

    if (Object.keys(playbooks).length === 0) {
        container.innerHTML = '<p class="empty-state">No playbooks available.</p>';
        return;
    }

    container.innerHTML = '';

    Object.entries(playbooks).forEach(([vulnType, playbook]) => {
        const playbookElement = document.createElement('div');
        playbookElement.className = 'playbook-item';

        const severityClass = `severity-${playbook.severity.toLowerCase()}`;

        playbookElement.innerHTML = `
            <div class="playbook-header">
                <div>
                    <div class="playbook-title">${vulnType}</div>
                    <div class="playbook-description">${playbook.description}</div>
                </div>
                <div class="playbook-meta">
                    <span class="severity-badge ${severityClass}">${playbook.severity}</span>
                    <span>CVSS: ${playbook.cvss_base_score}</span>
                </div>
            </div>
            <div class="playbook-details">
                <button class="btn btn-small" onclick="showPlaybookDetails('${vulnType}')">
                    📖 View Methodology
                </button>
                <button class="btn btn-small btn-warning" onclick="editPlaybook('${vulnType}')">
                    ✏️ Edit
                </button>
                <button class="btn btn-small btn-danger" onclick="deletePlaybook('${vulnType}')">
                    🗑️ Delete
                </button>
            </div>
        `;

        container.appendChild(playbookElement);
    });
}

async function showPlaybookDetails(vulnType) {
    try {
        const response = await fetch(`${API_BASE}/playbooks/${encodeURIComponent(vulnType)}`);
        const data = await response.json();

        if (!response.ok) {
            showToast(`Failed to load playbook details: ${data.error}`, 'error');
            return;
        }

        const playbook = data.playbook;
        const methodology = playbook.methodology;

        // Create modal or expand details
        const detailsHtml = `
            <div style="background: var(--surface); padding: 20px; border-radius: 8px; margin-top: 10px;">
                <h3>🔬 Testing Methodology for ${vulnType}</h3>

                <div class="methodology-section">
                    <h4 class="methodology-title">📋 Reconnaissance</h4>
                    <ul class="methodology-list">
                        ${methodology.reconnaissance.map(item => `<li>${item}</li>`).join('')}
                    </ul>
                </div>

                <div class="methodology-section">
                    <h4 class="methodology-title">🎯 Testing Phases</h4>
                    ${methodology.testing_phases.map(phase => `
                        <div style="margin-bottom: 15px; padding: 10px; background: var(--surface-light); border-radius: 4px;">
                            <strong>${phase.phase}</strong>: ${phase.description}
                            <br><small style="color: var(--text-secondary);">Payloads: ${phase.payloads.slice(0, 3).join(', ')}${phase.payloads.length > 3 ? '...' : ''}</small>
                        </div>
                    `).join('')}
                </div>

                <div class="methodology-section">
                    <h4 class="methodology-title">✅ Validation Rules</h4>
                    <ul class="methodology-list">
                        ${methodology.validation_rules.map(rule => `<li>${rule}</li>`).join('')}
                    </ul>
                </div>
            </div>
        `;

        // Show in a modal or replace content
        showModal(`Playbook: ${vulnType}`, detailsHtml);

    } catch (error) {
        showToast('Failed to load playbook details', 'error');
        console.error('Load playbook details error:', error);
    }
}

// ===== Playbook Creation =====
function showAddPlaybookForm() {
    document.getElementById('add-playbook-form').style.display = 'block';
    document.getElementById('add-playbook-btn').style.display = 'none';
}

function hideAddPlaybookForm() {
    document.getElementById('add-playbook-form').style.display = 'none';
    document.getElementById('add-playbook-btn').style.display = 'inline-block';
    // Clear form
    document.getElementById('new-playbook-type').value = '';
    document.getElementById('new-playbook-description').value = '';
    document.getElementById('new-playbook-severity').value = 'medium';
    document.getElementById('new-playbook-cvss').value = '5.0';
    document.getElementById('new-playbook-recon').value = '';
    document.getElementById('new-playbook-validation').value = '';
}

async function saveNewPlaybook() {
    const vulnType = document.getElementById('new-playbook-type').value.trim();
    const description = document.getElementById('new-playbook-description').value.trim();
    const severity = document.getElementById('new-playbook-severity').value;
    const cvssScore = parseFloat(document.getElementById('new-playbook-cvss').value) || 5.0;

    // Get reconnaissance steps
    const reconText = document.getElementById('new-playbook-recon').value.trim();
    const reconnaissance = reconText ? reconText.split('\n').filter(line => line.trim()) : [];

    // Get validation rules
    const validationText = document.getElementById('new-playbook-validation').value.trim();
    const validationRules = validationText ? validationText.split('\n').filter(line => line.trim()) : [];

    // Validate required fields
    if (!vulnType || !description) {
        showToast('Vulnerability Type and Description are required', 'error');
        return;
    }

    // Create playbook structure
    const playbook = {
        description: description,
        methodology: {
            reconnaissance: reconnaissance,
            testing_phases: [
                {
                    phase: "Basic Testing",
                    description: `Basic ${vulnType} vulnerability testing`,
                    payloads: ["' OR '1'='1", "test", "<script>alert(1)</script>"],
                    target_parameters: ["id", "name", "query"],
                    http_methods: ["GET", "POST"],
                    success_indicators: ["error", "exception", "vulnerable"]
                }
            ],
            validation_rules: validationRules
        },
        severity: severity,
        cvss_base_score: cvssScore,
        enabled: true
    };

    try {
        const response = await fetch(`${API_BASE}/playbooks/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                vulnerability_type: vulnType,
                playbook: playbook
            })
        });

        const data = await response.json();

        if (response.ok) {
            showToast(`Playbook for ${vulnType} created successfully!`, 'success');
            hideAddPlaybookForm();
            loadPlaybooks(); // Refresh the list
        } else {
            showToast(`Failed to create playbook: ${data.error}`, 'error');
        }
    } catch (error) {
        showToast('Failed to create playbook', 'error');
        console.error('Create playbook error:', error);
    }
}

async function editPlaybook(vulnType) {
    // For now, just show a message that editing is not implemented
    // In a full implementation, this would open the form with existing data
    showToast(`Editing playbook "${vulnType}" - Feature coming soon!`, 'info');
}

async function deletePlaybook(vulnType) {
    if (!confirm(`Are you sure you want to delete the playbook for "${vulnType}"? This action cannot be undone.`)) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/playbooks/${encodeURIComponent(vulnType)}`, {
            method: 'DELETE'
        });

        const data = await response.json();

        if (response.ok) {
            showToast(`Playbook for ${vulnType} deleted successfully!`, 'success');
            loadPlaybooks(); // Refresh the list
        } else {
            showToast(`Failed to delete playbook: ${data.error}`, 'error');
        }
    } catch (error) {
        showToast('Failed to delete playbook', 'error');
        console.error('Delete playbook error:', error);
    }
}

function showModal(title, content) {
    // Create modal overlay
    const modal = document.createElement('div');
    modal.style.cssText = `
        position: fixed; top: 0; left: 0; width: 100%; height: 100%;
        background: rgba(0,0,0,0.8); z-index: 1000; display: flex;
        align-items: center; justify-content: center;
    `;

    modal.innerHTML = `
        <div style="background: var(--background); border-radius: 8px; max-width: 800px; max-height: 80vh; overflow-y: auto; width: 90%; padding: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2 style="margin: 0; color: var(--text-primary);">${title}</h2>
                <button onclick="this.closest('div').parentElement.remove()" style="background: none; border: none; color: var(--text-primary); font-size: 24px; cursor: pointer;">×</button>
            </div>
            ${content}
        </div>
    `;

    document.body.appendChild(modal);
}

async function uploadSchema() {
    const fileInput = document.getElementById('schema-file');
    const file = fileInput.files[0];
    
    if (!file) {
        showToast('Please select a file to upload', 'warning');
        return;
    }

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch(`${API_BASE}/schemas`, {
            method: 'POST',
            body: formData
        });

        const data = await response.json();
        
        if (response.ok) {
            showToast('Schema uploaded successfully', 'success');
            fileInput.value = ''; // Clear file input
            loadSchemas(); // Refresh the list
        } else {
            showToast(data.error || 'Failed to upload schema', 'error');
        }
    } catch (error) {
        showToast('Error uploading schema', 'error');
        console.error('Upload schema error:', error);
    }
}

async function deleteSchema(schemaId) {
    if (!confirm('Are you sure you want to delete this schema?')) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/schemas/${schemaId}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            showToast('Schema deleted successfully', 'success');
            loadSchemas(); // Refresh the list
        } else {
            const data = await response.json();
            showToast(data.error || 'Failed to delete schema', 'error');
        }
    } catch (error) {
        showToast('Error deleting schema', 'error');
        console.error('Delete schema error:', error);
    }
}

async function viewSchema(schemaId) {
    try {
        const response = await fetch(`${API_BASE}/schemas/${schemaId}`);
        const data = await response.json();
        
        if (response.ok) {
            // Display schema in a modal
            const schemaText = JSON.stringify(data.schema, null, 2);
            showSchemaModal(data.schema.info?.title || schemaId, schemaText);
        } else {
            showToast(data.error || 'Failed to load schema', 'error');
        }
    } catch (error) {
        showToast('Error loading schema', 'error');
        console.error('View schema error:', error);
    }
}

function displaySchemas(schemas) {
    const container = document.getElementById('schemas-container');
    const schemaSelect = document.getElementById('oas-schema');
    
    // Update the dropdown
    schemaSelect.innerHTML = '<option value="">Select a schema...</option>';
    schemas.forEach(schema => {
        const option = document.createElement('option');
        option.value = schema.id;
        option.textContent = `${schema.title} (v${schema.version})`;
        schemaSelect.appendChild(option);
    });
    
    if (schemas.length === 0) {
        container.innerHTML = '<p class="empty-state">No schemas found. Upload a schema to get started.</p>';
        return;
    }

    container.innerHTML = '';
    
    schemas.forEach(schema => {
        const item = document.createElement('div');
        item.className = 'schema-item';
        
        item.innerHTML = `
            <div class="schema-info">
                <div class="schema-title">${schema.title}</div>
                <div class="schema-details">
                    <span class="schema-version">v${schema.version}</span>
                    <span class="schema-id">${schema.id.substring(0, 8)}...</span>
                </div>
            </div>
            <div class="schema-actions">
                <button class="btn btn-small btn-secondary" onclick="viewSchema('${schema.id}')">👁️ View</button>
                <button class="btn btn-small btn-danger" onclick="deleteSchema('${schema.id}')">🗑️ Delete</button>
            </div>
        `;
        
        container.appendChild(item);
    });
}

// ===== Schema Modal =====
function showSchemaModal(title, content) {
    // Create modal if it doesn't exist
    let modal = document.getElementById('schema-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'schema-modal';
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h2 id="modal-title"></h2>
                    <button class="modal-close" onclick="closeSchemaModal()">×</button>
                </div>
                <div class="modal-body">
                    <pre id="modal-content"></pre>
                </div>
            </div>
        `;
        // Close modal when clicking outside
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                closeSchemaModal();
            }
        });
        document.body.appendChild(modal);
    }
    
    // Update content
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-content').textContent = content;
    
    // Show modal
    modal.style.display = 'block';
    document.body.style.overflow = 'hidden';
    
    // Add escape key listener
    const escapeHandler = function(e) {
        if (e.key === 'Escape') {
            closeSchemaModal();
            document.removeEventListener('keydown', escapeHandler);
        }
    };
    document.addEventListener('keydown', escapeHandler);
}

function closeSchemaModal() {
    const modal = document.getElementById('schema-modal');
    if (modal) {
        modal.style.display = 'none';
        document.body.style.overflow = 'auto';
    }
}

// ===== History Management =====
async function loadScanHistory() {
    try {
        const response = await fetch(`${API_BASE}/scan_history`);
        const data = await response.json();

        displayScanHistory(data.scans || []);
    } catch (error) {
        showToast('Failed to load scan history', 'error');
        console.error('Load scan history error:', error);
        displayScanHistory([]);
    }
}

function displayScanHistory(scans) {
    const container = document.getElementById('history-container');

    if (scans.length === 0) {
        container.innerHTML = '<p class="empty-state">No scan history available.</p>';
        return;
    }

    container.innerHTML = '';

    scans.forEach(scan => {
        const scanElement = document.createElement('div');
        scanElement.className = 'scan-card';
        scanElement.onclick = () => viewScanDetails(scan.scan_id);

        const statusClass = `scan-status ${scan.status.toLowerCase()}`;
        const createdDate = new Date(scan.created_at).toLocaleString();
        const vulnCount = scan.vulnerabilities_found || 0;

        scanElement.innerHTML = `
            <div class="scan-card-header">
                <div class="scan-id">${scan.scan_id}</div>
                <div class="${statusClass}">${scan.status}</div>
            </div>
            <div class="scan-meta">
                <span>📅 ${createdDate}</span>
                <span>🎯 ${scan.target_url}</span>
                <span>⚠️ ${vulnCount} vulnerabilities</span>
            </div>
            <div class="scan-summary">
                ${scan.summary || 'No summary available'}
            </div>
        `;

        container.appendChild(scanElement);
    });
}

async function viewScanDetails(scanId) {
    try {
        const response = await fetch(`${API_BASE}/get_report/${scanId}`);
        const data = await response.json();

        if (response.ok) {
            // Display scan report in a modal or switch to reports tab
            switchTab('reports');
            // You could also implement a modal here
            showToast('Scan report loaded', 'success');
        } else {
            showToast('Failed to load scan report', 'error');
        }
    } catch (error) {
        showToast('Error loading scan report', 'error');
        console.error('View scan details error:', error);
    }
}

// ===== Tab Switching =====
function switchTab(tabName) {
    // Deactivate all tabs
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));

    // Activate selected tab
    document.getElementById(tabName).classList.add('active');
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

    // Load content for specific tabs
    if (tabName === 'reports') {
        loadReports();
    } else if (tabName === 'history') {
        loadScanHistory();
    }
}

// ===== Toast Notifications =====
function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    toastContainer.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// ===== Utility Functions =====
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Poll health status every 30 seconds
setInterval(checkHealth, 30000);
