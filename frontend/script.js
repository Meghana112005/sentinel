// Configuration
const API_BASE_URL = 'http://localhost:8080/api';

// Global variables
let currentScanId = null;

// DOM Elements
const targetUrlInput = document.getElementById('targetUrl');
const scanBtn = document.getElementById('scanBtn');
const statusSection = document.getElementById('statusSection');
const statusBadge = document.getElementById('statusBadge');
const progressFill = document.getElementById('progressFill');
const statusDetails = document.getElementById('statusDetails');
const resultsSection = document.getElementById('resultsSection');
const summaryCards = document.getElementById('summaryCards');
const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');
const downloadReportBtn = document.getElementById('downloadReportBtn');
const newScanBtn = document.getElementById('newScanBtn');

// Event Listeners
scanBtn.addEventListener('click', startScan);
downloadReportBtn.addEventListener('click', downloadReport);
newScanBtn.addEventListener('click', resetScan);

targetUrlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        startScan();
    }
});

// Smooth scrolling for navigation links
document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const targetId = link.getAttribute('href');
        const targetSection = document.querySelector(targetId);
        if (targetSection) {
            targetSection.scrollIntoView({ behavior: 'smooth' });
        }
        
        // Update active state
        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
        link.classList.add('active');
    });
});

/**
 * Set example URL
 */
function setUrl(url) {
    targetUrlInput.value = url;
    targetUrlInput.focus();
}

/**
 * Start security scan
 */
async function startScan() {
    const targetUrl = targetUrlInput.value.trim();
    
    // Validate input
    if (!targetUrl) {
        showError('Please enter a target URL');
        return;
    }

    // Disable scan button
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<span class="btn-text">Scanning...</span><span class="btn-icon">⏳</span>';

    // Show status section
    statusSection.classList.remove('hidden');
    resultsSection.classList.add('hidden');

    // Update status
    updateStatus('Initializing scan...', 'info', 10);

    try {
        // Call backend API
        const response = await fetch(`${API_BASE_URL}/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ targetUrl })
        });

        if (!response.ok) {
            throw new Error('Scan failed. Please check if the backend is running.');
        }

        const result = await response.json();

        // Check for errors
        if (result.status === 'error') {
            throw new Error(result.message || 'Scan failed');
        }

        // Update progress
        updateStatus('Crawling website...', 'info', 30);
        await delay(500);

        updateStatus('Extracting forms...', 'info', 50);
        await delay(500);

        updateStatus('Testing vulnerabilities...', 'warning', 70);
        await delay(500);

        updateStatus('Analyzing results...', 'info', 90);
        await delay(500);

        updateStatus('Scan completed!', 'success', 100);

        // Store scan ID
        currentScanId = result.scanId;

        // Display results
        await delay(1000);
        displayResults(result);

    } catch (error) {
        console.error('Scan error:', error);
        updateStatus(`Error: ${error.message}`, 'error', 0);
        showError(error.message);
        
        // Re-enable button
        scanBtn.disabled = false;
        scanBtn.innerHTML = '<span class="btn-text">Start Scan</span><span class="btn-icon">🔍</span>';
    }
}

/**
 * Update scan status
 */
function updateStatus(message, type, progress) {
    statusBadge.textContent = message;
    statusBadge.style.background = getStatusColor(type);
    progressFill.style.width = `${progress}%`;
    
    const details = [
        `Status: ${message}`,
        `Progress: ${progress}%`
    ];
    statusDetails.innerHTML = details.join('<br>');
}

/**
 * Get status badge color
 */
function getStatusColor(type) {
    const colors = {
        'info': '#3498db',
        'warning': '#f39c12',
        'success': '#27ae60',
        'error': '#e74c3c'
    };
    return colors[type] || colors.info;
}

/**
 * Display scan results
 */
function displayResults(result) {
    // Hide status, show results
    statusSection.classList.add('hidden');
    resultsSection.classList.remove('hidden');

    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth' });

    // Count vulnerabilities by risk level
    const vulnerabilities = result.vulnerabilities || [];
    const highRisk = vulnerabilities.filter(v => v.riskLevel === 'HIGH').length;
    const mediumRisk = vulnerabilities.filter(v => v.riskLevel === 'MEDIUM').length;
    const lowRisk = vulnerabilities.filter(v => v.riskLevel === 'LOW').length;

    // Display summary cards
    summaryCards.innerHTML = `
        <div class="summary-card">
            <h3>${result.vulnerabilitiesFound || 0}</h3>
            <p>Total Vulnerabilities</p>
        </div>
        <div class="summary-card high">
            <h3>${highRisk}</h3>
            <p>High Risk</p>
        </div>
        <div class="summary-card medium">
            <h3>${mediumRisk}</h3>
            <p>Medium Risk</p>
        </div>
        <div class="summary-card low">
            <h3>${lowRisk}</h3>
            <p>Low Risk</p>
        </div>
        <div class="summary-card">
            <h3>${result.pagesScanned || 0}</h3>
            <p>Pages Scanned</p>
        </div>
        <div class="summary-card">
            <h3>${result.formsFound || 0}</h3>
            <p>Forms Found</p>
        </div>
    `;

    // Display vulnerabilities
    if (vulnerabilities.length === 0) {
        vulnerabilitiesList.innerHTML = `
            <div class="vuln-card" style="text-align: center; padding: 3rem;">
                <h3 style="font-size: 24px; color: #27ae60; margin-bottom: 1rem;">✅ No Vulnerabilities Found</h3>
                <p style="color: #7f8c8d;">The target application appears to be secure against the tested vulnerabilities.</p>
            </div>
        `;
    } else {
        vulnerabilitiesList.innerHTML = vulnerabilities.map(vuln => `
            <div class="vuln-card ${vuln.riskLevel.toLowerCase()}">
                <div class="vuln-header">
                    <div class="vuln-type">${formatVulnType(vuln.vulnerabilityType)}</div>
                    <div class="risk-badge risk-${vuln.riskLevel.toLowerCase()}">
                        ${vuln.riskLevel} RISK
                    </div>
                </div>
                
                <div class="vuln-detail">
                    <div class="detail-label">Affected URL:</div>
                    <div class="detail-value">${escapeHtml(vuln.affectedUrl)}</div>
                </div>
                
                <div class="vuln-detail">
                    <div class="detail-label">Payload Used:</div>
                    <div class="code-block">${escapeHtml(vuln.payload)}</div>
                </div>
                
                <div class="vuln-detail">
                    <div class="detail-label">Evidence:</div>
                    <div class="code-block">${escapeHtml(vuln.evidence)}</div>
                </div>
            </div>
        `).join('');
    }

    // Re-enable scan button
    scanBtn.disabled = false;
    scanBtn.innerHTML = '<span class="btn-text">Start Scan</span><span class="btn-icon">🔍</span>';
}

/**
 * Download HTML report
 */
async function downloadReport() {
    if (!currentScanId) {
        showError('No scan results available');
        return;
    }

    try {
        downloadReportBtn.disabled = true;
        downloadReportBtn.textContent = '⏳ Generating...';

        const response = await fetch(`${API_BASE_URL}/report/${currentScanId}`);
        
        if (!response.ok) {
            throw new Error('Failed to generate report');
        }

        const data = await response.json();
        const reportHtml = data.report;

        // Create and download file
        const blob = new Blob([reportHtml], { type: 'text/html' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `sentinel-report-${currentScanId}.html`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        downloadReportBtn.disabled = false;
        downloadReportBtn.textContent = '📄 Download Report';

        showSuccess('Report downloaded successfully!');

    } catch (error) {
        console.error('Download error:', error);
        showError('Failed to download report');
        downloadReportBtn.disabled = false;
        downloadReportBtn.textContent = '📄 Download Report';
    }
}

/**
 * Reset scan for new test
 */
function resetScan() {
    currentScanId = null;
    targetUrlInput.value = '';
    statusSection.classList.add('hidden');
    resultsSection.classList.add('hidden');
    progressFill.style.width = '0%';
    
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
    
    // Focus input
    targetUrlInput.focus();
}

/**
 * Format vulnerability type
 */
function formatVulnType(type) {
    const types = {
        'SQL_INJECTION': '💉 SQL Injection',
        'XSS': '⚡ Cross-Site Scripting (XSS)',
        'CSRF': '🔒 Cross-Site Request Forgery',
        'XXE': '📄 XML External Entity'
    };
    return types[type] || type.replace('_', ' ');
}

/**
 * Escape HTML to prevent XSS in display
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Show error notification
 */
function showError(message) {
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: #e74c3c;
        color: white;
        padding: 1rem 2rem;
        border-radius: 8px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        z-index: 10000;
        animation: slideIn 0.3s ease-out;
    `;
    notification.textContent = `❌ ${message}`;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 4000);
}

/**
 * Show success notification
 */
function showSuccess(message) {
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: #27ae60;
        color: white;
        padding: 1rem 2rem;
        border-radius: 8px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        z-index: 10000;
        animation: slideIn 0.3s ease-out;
    `;
    notification.textContent = `✅ ${message}`;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

/**
 * Delay utility
 */
function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// Check backend connectivity on page load
window.addEventListener('load', async () => {
    try {
        const response = await fetch(`${API_BASE_URL}/health`);
        if (response.ok) {
            console.log('✅ Backend connected successfully');
        }
    } catch (error) {
        console.error('⚠️ Backend not connected. Please start the Spring Boot application.');
        showError('Backend not connected. Please start the Spring Boot server on port 8080');
    }
});