// ========================================
// HTTP HEADERS ANALYZER
// Category: Purple Team
// ========================================

(function() {
    'use strict';

    const headerChecks = {
        'strict-transport-security': {
            name: 'Strict-Transport-Security (HSTS)',
            severity: 'critical',
            description: 'Forces HTTPS connections and prevents protocol downgrade attacks',
            recommendation: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            checkValue: (value) => {
                const issues = [];
                if (!value.includes('max-age=')) {
                    issues.push('Missing max-age directive');
                } else {
                    const maxAge = parseInt(value.match(/max-age=(\d+)/)?.[1] || 0);
                    if (maxAge < 31536000) issues.push(`max-age too short (${maxAge}s, recommend 31536000)`);
                }
                if (!value.includes('includeSubDomains')) issues.push('Missing includeSubDomains');
                if (!value.includes('preload')) issues.push('Consider adding preload');
                return issues.length === 0 ? { status: 'good', issues: [] } : 
                       { status: 'warning', issues };
            }
        },
        'content-security-policy': {
            name: 'Content-Security-Policy (CSP)',
            severity: 'critical',
            description: 'Prevents XSS, clickjacking, and code injection attacks',
            recommendation: "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
            checkValue: (value) => {
                const issues = [];
                if (value.includes("'unsafe-inline'")) issues.push("⚠️ Contains 'unsafe-inline' - XSS risk");
                if (value.includes("'unsafe-eval'")) issues.push("⚠️ Contains 'unsafe-eval' - code execution risk");
                if (value.match(/script-src[^;]*\*/)) issues.push("⚠️ Wildcard in script-src - major security risk");
                if (value.match(/default-src[^;]*\*/)) issues.push("⚠️ Wildcard in default-src");
                if (!value.includes('object-src')) issues.push("Missing object-src directive");
                if (!value.includes('base-uri')) issues.push("Missing base-uri directive");
                return issues.length === 0 ? { status: 'good', issues: [] } : 
                       { status: issues.some(i => i.includes('⚠️')) ? 'danger' : 'warning', issues };
            }
        },
        'x-frame-options': {
            name: 'X-Frame-Options',
            severity: 'high',
            description: 'Prevents clickjacking by controlling iframe embedding',
            recommendation: 'X-Frame-Options: DENY or SAMEORIGIN',
            checkValue: (value) => {
                const upper = value.toUpperCase();
                if (upper.includes('DENY') || upper.includes('SAMEORIGIN')) {
                    return { status: 'good', issues: [] };
                }
                return { status: 'warning', issues: ['Should be DENY or SAMEORIGIN'] };
            }
        },
        'x-content-type-options': {
            name: 'X-Content-Type-Options',
            severity: 'medium',
            description: 'Prevents MIME-sniffing attacks',
            recommendation: 'X-Content-Type-Options: nosniff',
            checkValue: (value) => {
                return value.toLowerCase() === 'nosniff' ? 
                       { status: 'good', issues: [] } : 
                       { status: 'warning', issues: ['Must be "nosniff"'] };
            }
        },
        'referrer-policy': {
            name: 'Referrer-Policy',
            severity: 'medium',
            description: 'Controls referrer information sent with requests',
            recommendation: 'Referrer-Policy: strict-origin-when-cross-origin or no-referrer',
            checkValue: (value) => {
                const secure = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin', 'same-origin'];
                const insecure = ['unsafe-url', 'no-referrer-when-downgrade'];
                if (insecure.some(v => value.toLowerCase().includes(v))) {
                    return { status: 'warning', issues: ['Policy may leak sensitive information'] };
                }
                return secure.some(v => value.toLowerCase().includes(v)) ? 
                       { status: 'good', issues: [] } : 
                       { status: 'info', issues: ['Consider more restrictive policy'] };
            }
        },
        'permissions-policy': {
            name: 'Permissions-Policy',
            severity: 'low',
            description: 'Controls browser features and APIs',
            recommendation: 'Permissions-Policy: geolocation=(), microphone=(), camera=()',
            checkValue: (value) => {
                return { status: 'good', issues: [] };
            }
        },
        'x-xss-protection': {
            name: 'X-XSS-Protection',
            severity: 'low',
            description: 'Legacy XSS filter (deprecated, use CSP instead)',
            recommendation: 'Remove header and use Content-Security-Policy',
            checkValue: (value) => {
                if (value === '0') return { status: 'info', issues: ['Disabled - ensure CSP is strong'] };
                return { status: 'info', issues: ['Legacy header, use CSP for modern protection'] };
            }
        }
    };

    const informationDisclosureHeaders = {
        'server': {
            name: 'Server',
            risk: 'medium',
            description: 'Reveals web server software and version'
        },
        'x-powered-by': {
            name: 'X-Powered-By',
            risk: 'medium',
            description: 'Reveals backend technology stack'
        },
        'x-aspnet-version': {
            name: 'X-AspNet-Version',
            risk: 'medium',
            description: 'Reveals ASP.NET version'
        },
        'x-aspnetmvc-version': {
            name: 'X-AspNetMvc-Version',
            risk: 'medium',
            description: 'Reveals ASP.NET MVC version'
        },
        'x-generator': {
            name: 'X-Generator',
            risk: 'low',
            description: 'Reveals CMS or framework used'
        },
        'x-drupal-cache': {
            name: 'X-Drupal-Cache',
            risk: 'low',
            description: 'Reveals Drupal CMS usage'
        }
    };

    function render() {
        return `
            <style>
                .security-section {
                    margin-bottom: 1.5rem;
                }
                .header-item {
                    padding: 0.75rem;
                    border-left: 3px solid;
                    margin-bottom: 0.5rem;
                    background: #161b22;
                    border-radius: 4px;
                }
                .header-item.status-good {
                    border-color: #28a745;
                }
                .header-item.status-warning {
                    border-color: #ffc107;
                }
                .header-item.status-danger {
                    border-color: #dc3545;
                }
                .header-item.status-missing {
                    border-color: #6c757d;
                    opacity: 0.8;
                }
                .header-item.status-info {
                    border-color: #17a2b8;
                }
                .header-name {
                    font-weight: 600;
                    font-size: 0.9rem;
                }
                .header-desc {
                    font-size: 0.8rem;
                    color: #8b949e;
                    margin: 0.25rem 0;
                }
                .header-value {
                    font-family: 'Courier New', monospace;
                    font-size: 0.75rem;
                    background: #0d1117;
                    padding: 0.4rem;
                    border-radius: 3px;
                    margin: 0.4rem 0;
                    word-break: break-all;
                }
                .issue-badge {
                    display: inline-block;
                    font-size: 0.7rem;
                    padding: 0.2rem 0.5rem;
                    border-radius: 3px;
                    margin-right: 0.3rem;
                    margin-top: 0.2rem;
                }
                .recommendation {
                    font-size: 0.75rem;
                    color: #58a6ff;
                    margin-top: 0.4rem;
                }
                .collapsible-content {
                    margin-top: 0.5rem;
                    padding-top: 0.5rem;
                    border-top: 1px solid #30363d;
                }
                .toggle-details {
                    cursor: pointer;
                    font-size: 0.75rem;
                    color: #58a6ff;
                    user-select: none;
                }
                .toggle-details:hover {
                    text-decoration: underline;
                }
            </style>
            
            <div class="mb-3">
                <h4><i class="bi bi-shield-lock"></i> HTTP Security Headers Checker</h4>
                <p class="text-secondary mb-0">Advanced security analysis with misconfiguration detection</p>
            </div>
            
            <div class="mb-3">
                <label for="headerUrl" class="form-label">Target URL</label>
                <input type="url" class="form-control" id="headerUrl" placeholder="https://example.com">
                <small class="text-secondary">CORS may prevent direct checking. Manual input available if needed.</small>
            </div>
            
            <button class="btn btn-primary" onclick="checkHeaders()">
                <i class="bi bi-search"></i> Analyze Headers
            </button>
            
            <div id="headerResults" class="mt-3"></div>
        `;
    }

    function init() {
        window.checkHeaders = async function() {
            const url = document.getElementById('headerUrl').value.trim();
            const resultsDiv = document.getElementById('headerResults');
            
            if (!url) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter a URL</div>';
                return;
            }
            
            try {
                new URL(url);
            } catch (e) {
                resultsDiv.innerHTML = '<div class="alert alert-danger">Invalid URL format</div>';
                return;
            }

            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <span class="spinner-border spinner-border-sm me-2"></span>
                    Analyzing security headers...
                </div>
            `;

            try {
                const response = await fetch(url, { 
                    method: 'HEAD', 
                    mode: 'cors',
                    cache: 'no-cache'
                });
                
                const headers = {};
                response.headers.forEach((value, key) => {
                    headers[key.toLowerCase()] = value;
                });
                
                displayHeaderResults(headers, resultsDiv);
                
            } catch (error) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-warning">
                        <h6 class="alert-heading"><i class="bi bi-exclamation-triangle"></i> CORS Restriction</h6>
                        <p class="mb-2">Unable to fetch headers automatically due to CORS policy.</p>
                        <button class="btn btn-sm btn-primary" onclick="showManualInput()">
                            <i class="bi bi-input-cursor-text"></i> Enter Headers Manually
                        </button>
                    </div>
                `;
            }
        };

        window.showManualInput = function() {
            const resultsDiv = document.getElementById('headerResults');
            resultsDiv.innerHTML = `
                <div class="card bg-dark">
                    <div class="card-body">
                        <h6><i class="bi bi-input-cursor-text"></i> Manual Header Input</h6>
                        <label for="manualHeaders" class="form-label small">Paste Response Headers</label>
                        <textarea class="form-control font-monospace" id="manualHeaders" rows="12" 
                                  placeholder="Header-Name: value
Header-Name-2: value2
..."></textarea>
                        <button class="btn btn-primary btn-sm mt-2" onclick="analyzeManualHeaders()">
                            <i class="bi bi-search"></i> Analyze
                        </button>
                    </div>
                </div>
                
                <div class="alert alert-info mt-3 small">
                    <strong>How to get headers:</strong>
                    <ol class="mb-0">
                        <li>Open DevTools (F12) → Network tab</li>
                        <li>Visit the target URL</li>
                        <li>Click on the main request</li>
                        <li>Copy all Response Headers and paste above</li>
                    </ol>
                </div>
            `;
        };

        window.analyzeManualHeaders = function() {
            const headerText = document.getElementById('manualHeaders').value;
            const resultsDiv = document.getElementById('headerResults');
            
            if (!headerText.trim()) {
                alert('Please paste headers');
                return;
            }
            
            const headers = {};
            headerText.split('\n').forEach(line => {
                const colonIndex = line.indexOf(':');
                if (colonIndex > 0) {
                    const key = line.substring(0, colonIndex).trim().toLowerCase();
                    const value = line.substring(colonIndex + 1).trim();
                    headers[key] = value;
                }
            });
            
            if (Object.keys(headers).length === 0) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">No valid headers found</div>';
                return;
            }
            
            displayHeaderResults(headers, resultsDiv);
        };

        window.toggleDetails = function(id) {
            const element = document.getElementById(id);
            const icon = document.getElementById(id + '-icon');
            if (element.style.display === 'none') {
                element.style.display = 'block';
                icon.className = 'bi bi-chevron-up';
            } else {
                element.style.display = 'none';
                icon.className = 'bi bi-chevron-down';
            }
        };

        function displayHeaderResults(headers, container) {
            // Check for CORS misconfigurations
            const corsIssues = checkCORS(headers);
            
            // Check for Cookie security issues
            const cookieIssues = checkCookies(headers);
            
            // Calculate security score
            let score = 0;
            let maxScore = 0;
            let criticalCount = 0;
            let highCount = 0;
            let mediumCount = 0;
            
            const securityHeaders = [];
            const missingHeaders = [];
            const infoDisclosure = [];
            
            // Check security headers
            Object.entries(headerChecks).forEach(([key, check]) => {
                const scoreWeight = check.severity === 'critical' ? 20 : 
                                   check.severity === 'high' ? 15 : 
                                   check.severity === 'medium' ? 10 : 5;
                maxScore += scoreWeight;
                
                const headerValue = headers[key];
                
                if (headerValue) {
                    const analysis = check.checkValue(headerValue);
                    const statusClass = analysis.status === 'good' ? 'status-good' : 
                                       analysis.status === 'danger' ? 'status-danger' : 
                                       analysis.status === 'warning' ? 'status-warning' : 'status-info';
                    
                    if (analysis.status === 'good') score += scoreWeight;
                    else if (analysis.status === 'warning') score += scoreWeight * 0.5;
                    else if (analysis.status === 'info') score += scoreWeight * 0.3;
                    
                    securityHeaders.push({
                        check,
                        value: headerValue,
                        analysis,
                        statusClass,
                        key
                    });
                } else {
                    if (check.severity === 'critical') criticalCount++;
                    else if (check.severity === 'high') highCount++;
                    else if (check.severity === 'medium') mediumCount++;
                    
                    missingHeaders.push({ check, key });
                }
            });
            
            // Check for information disclosure
            Object.entries(informationDisclosureHeaders).forEach(([key, info]) => {
                if (headers[key]) {
                    infoDisclosure.push({
                        ...info,
                        value: headers[key]
                    });
                }
            });
            
            const scorePercentage = Math.round((score / maxScore) * 100);
            let scoreClass = 'danger';
            let scoreLabel = 'Poor';
            
            if (scorePercentage >= 90) { scoreClass = 'success'; scoreLabel = 'Excellent'; }
            else if (scorePercentage >= 75) { scoreClass = 'primary'; scoreLabel = 'Good'; }
            else if (scorePercentage >= 50) { scoreClass = 'warning'; scoreLabel = 'Fair'; }
            
            // Build output
            let html = `
                <!-- Security Score Summary -->
                <div class="card bg-dark border-${scoreClass} mb-3">
                    <div class="card-header bg-${scoreClass} ${scoreClass === 'warning' ? 'text-dark' : 'text-white'}">
                        <div class="d-flex justify-content-between align-items-center">
                            <h5 class="mb-0">
                                <i class="bi bi-shield-check"></i> Security Score: ${scorePercentage}%
                            </h5>
                            <span class="badge bg-${scoreClass === 'warning' ? 'dark' : 'light'} text-${scoreClass === 'warning' ? 'white' : 'dark'}">${scoreLabel}</span>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="progress mb-3" style="height: 25px;">
                            <div class="progress-bar bg-${scoreClass}" style="width: ${scorePercentage}%">
                                ${scorePercentage}%
                            </div>
                        </div>
                        <div class="row text-center small">
                            <div class="col-3">
                                <div class="text-danger h4 mb-0">${criticalCount}</div>
                                <div class="text-secondary">Critical Missing</div>
                            </div>
                            <div class="col-3">
                                <div class="text-warning h4 mb-0">${highCount}</div>
                                <div class="text-secondary">High Missing</div>
                            </div>
                            <div class="col-3">
                                <div class="text-info h4 mb-0">${mediumCount}</div>
                                <div class="text-secondary">Medium Missing</div>
                            </div>
                            <div class="col-3">
                                <div class="text-success h4 mb-0">${securityHeaders.length}</div>
                                <div class="text-secondary">Present</div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Navigation Tabs -->
                <ul class="nav nav-tabs mb-3" role="tablist">
                    <li class="nav-item">
                        <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#tab-misconfig" type="button">
                            <i class="bi bi-exclamation-triangle-fill text-danger"></i> 
                            Misconfigurations <span class="badge bg-danger">${corsIssues.length + cookieIssues.length}</span>
                        </button>
                    </li>
                    <li class="nav-item">
                        <button class="nav-link" data-bs-toggle="tab" data-bs-target="#tab-disclosure" type="button">
                            <i class="bi bi-info-circle-fill text-warning"></i> 
                            Info Disclosure <span class="badge bg-warning text-dark">${infoDisclosure.length}</span>
                        </button>
                    </li>
                    <li class="nav-item">
                        <button class="nav-link" data-bs-toggle="tab" data-bs-target="#tab-configured" type="button">
                            <i class="bi bi-check-circle-fill text-success"></i> 
                            Configured <span class="badge bg-success">${securityHeaders.filter(h => h.analysis.status === 'good').length}</span>
                        </button>
                    </li>
                    <li class="nav-item">
                        <button class="nav-link" data-bs-toggle="tab" data-bs-target="#tab-partial" type="button">
                            <i class="bi bi-exclamation-circle-fill text-warning"></i> 
                            Needs Fix <span class="badge bg-warning text-dark">${securityHeaders.filter(h => h.analysis.status !== 'good').length}</span>
                        </button>
                    </li>
                    <li class="nav-item">
                        <button class="nav-link" data-bs-toggle="tab" data-bs-target="#tab-missing" type="button">
                            <i class="bi bi-dash-circle-fill text-secondary"></i> 
                            Missing <span class="badge bg-secondary">${missingHeaders.length}</span>
                        </button>
                    </li>
                </ul>
                
                <div class="tab-content">
                    <!-- Misconfigurations Tab -->
                    <div class="tab-pane fade show active" id="tab-misconfig">
            `;
            
            if (corsIssues.length > 0 || cookieIssues.length > 0) {
                html += `<div class="security-section">`;
                
                if (corsIssues.length === 0 && cookieIssues.length === 0) {
                    html += `
                        <div class="alert alert-success">
                            <i class="bi bi-check-circle-fill"></i> No critical misconfigurations detected!
                        </div>
                    `;
                }
                
                corsIssues.forEach(issue => {
                    html += `
                        <div class="header-item status-danger">
                            <div class="header-name text-danger">
                                <i class="bi bi-x-octagon-fill"></i> ${issue.name}
                            </div>
                            <div class="header-desc">${issue.description}</div>
                            ${issue.value ? `<div class="header-value text-danger">${window.escapeHtml(issue.value)}</div>` : ''}
                            <div class="mt-2">
                                ${issue.issues.map(i => `<span class="issue-badge bg-danger"><i class="bi bi-bug-fill"></i> ${i}</span>`).join('')}
                            </div>
                            <div class="recommendation">
                                <i class="bi bi-shield-fill-check"></i> <strong>Fix:</strong> ${issue.recommendation}
                            </div>
                        </div>
                    `;
                });
                
                cookieIssues.forEach(issue => {
                    html += `
                        <div class="header-item status-danger">
                            <div class="header-name text-danger">
                                <i class="bi bi-x-octagon-fill"></i> ${issue.name}
                            </div>
                            <div class="header-desc">${issue.description}</div>
                            <div class="header-value text-danger">${window.escapeHtml(issue.value)}</div>
                            <div class="mt-2">
                                ${issue.issues.map(i => `<span class="issue-badge bg-danger"><i class="bi bi-bug-fill"></i> ${i}</span>`).join('')}
                            </div>
                            <div class="recommendation">
                                <i class="bi bi-shield-fill-check"></i> <strong>Fix:</strong> ${issue.recommendation}
                            </div>
                        </div>
                    `;
                });
                
                html += `</div>`;
            } else {
                html += `
                    <div class="alert alert-success">
                        <i class="bi bi-check-circle-fill"></i> No critical misconfigurations detected! Your CORS and Cookie configurations appear secure.
                    </div>
                `;
            }
            
            html += `
                    </div>
                    
                    <!-- Information Disclosure Tab -->
                    <div class="tab-pane fade" id="tab-disclosure">
            `;
            
            if (infoDisclosure.length > 0) {
                html += `<div class="security-section">`;
                
                infoDisclosure.forEach(info => {
                    html += `
                        <div class="header-item status-warning">
                            <div class="header-name text-warning">
                                <i class="bi bi-eye-fill"></i> ${info.name}
                            </div>
                            <div class="header-desc">${info.description}</div>
                            <div class="header-value text-warning">${window.escapeHtml(info.value)}</div>
                            <div class="mt-2">
                                <span class="issue-badge bg-warning text-dark"><i class="bi bi-info-circle-fill"></i> Leaks ${info.risk} risk information</span>
                            </div>
                            <div class="recommendation">
                                <i class="bi bi-shield-fill-check"></i> <strong>Fix:</strong> Remove this header to prevent information leakage about your infrastructure
                            </div>
                        </div>
                    `;
                });
                
                html += `</div>`;
            } else {
                html += `
                    <div class="alert alert-success">
                        <i class="bi bi-check-circle-fill"></i> No information disclosure headers detected! Your server is not leaking sensitive information.
                    </div>
                `;
            }
            
            html += `
                    </div>
                    
                    <!-- Properly Configured Tab -->
                    <div class="tab-pane fade" id="tab-configured">
            `;
            
            const properlyConfigured = securityHeaders.filter(h => h.analysis.status === 'good');
            
            if (properlyConfigured.length > 0) {
                html += `<div class="security-section">`;
                
                properlyConfigured.forEach((item, idx) => {
                    const detailId = `detail-good-${idx}`;
                    
                    html += `
                        <div class="header-item status-good">
                            <div class="d-flex justify-content-between align-items-start">
                                <div class="flex-grow-1">
                                    <div class="header-name text-success">
                                        <i class="bi bi-check-circle-fill"></i>
                                        ${item.check.name}
                                    </div>
                                    <div class="header-desc">${item.check.description}</div>
                                </div>
                                <span class="toggle-details" onclick="toggleDetails('${detailId}')">
                                    <i class="bi bi-chevron-down" id="${detailId}-icon"></i> Details
                                </span>
                            </div>
                            
                            <div id="${detailId}" class="collapsible-content" style="display: none;">
                                <div class="header-value text-success">${window.escapeHtml(item.value)}</div>
                                <div class="text-success small mt-2">
                                    <i class="bi bi-patch-check-fill"></i> This header is properly configured and secure
                                </div>
                            </div>
                        </div>
                    `;
                });
                
                html += `</div>`;
            } else {
                html += `
                    <div class="alert alert-warning">
                        <i class="bi bi-exclamation-triangle-fill"></i> No security headers are properly configured yet. Check the other tabs to fix issues.
                    </div>
                `;
            }
            
            html += `
                    </div>
                    
                    <!-- Needs Improvement Tab -->
                    <div class="tab-pane fade" id="tab-partial">
            `;
            
            const needsImprovement = securityHeaders.filter(h => h.analysis.status !== 'good');
            
            if (needsImprovement.length > 0) {
                html += `<div class="security-section">`;
                
                needsImprovement.forEach((item, idx) => {
                    const detailId = `detail-partial-${idx}`;
                    
                    html += `
                        <div class="header-item status-warning">
                            <div class="d-flex justify-content-between align-items-start">
                                <div class="flex-grow-1">
                                    <div class="header-name text-warning">
                                        <i class="bi bi-exclamation-triangle-fill"></i>
                                        ${item.check.name}
                                    </div>
                                    <div class="header-desc">${item.check.description}</div>
                                </div>
                                <span class="toggle-details" onclick="toggleDetails('${detailId}')">
                                    <i class="bi bi-chevron-down" id="${detailId}-icon"></i> Details
                                </span>
                            </div>
                            
                            <div id="${detailId}" class="collapsible-content" style="display: none;">
                                <div class="header-value text-warning">${window.escapeHtml(item.value)}</div>
                                <div class="mt-2">
                                    ${item.analysis.issues.map(issue => 
                                        `<span class="issue-badge bg-warning text-dark"><i class="bi bi-exclamation-circle-fill"></i> ${issue}</span>`
                                    ).join('')}
                                </div>
                                <div class="recommendation">
                                    <i class="bi bi-shield-fill-check"></i> <strong>Recommendation:</strong> ${item.check.recommendation}
                                </div>
                            </div>
                        </div>
                    `;
                });
                
                html += `</div>`;
            } else {
                html += `
                    <div class="alert alert-success">
                        <i class="bi bi-check-circle-fill"></i> All configured headers are properly set! No improvements needed.
                    </div>
                `;
            }
            
            html += `
                    </div>
                    
                    <!-- Missing Headers Tab -->
                    <div class="tab-pane fade" id="tab-missing">
            `;
            
            if (missingHeaders.length > 0) {
                html += `<div class="security-section">`;
                
                missingHeaders.forEach((item, idx) => {
                    const detailId = `missing-${idx}`;
                    const severityColor = item.check.severity === 'critical' ? 'danger' : 
                                         item.check.severity === 'high' ? 'warning' : 
                                         item.check.severity === 'medium' ? 'info' : 'secondary';
                    const severityIcon = item.check.severity === 'critical' ? 'exclamation-octagon-fill' : 
                                        item.check.severity === 'high' ? 'exclamation-triangle-fill' : 
                                        item.check.severity === 'medium' ? 'exclamation-circle-fill' : 'info-circle-fill';
                    
                    html += `
                        <div class="header-item status-missing">
                            <div class="d-flex justify-content-between align-items-start">
                                <div class="flex-grow-1">
                                    <div class="header-name">
                                        <i class="bi bi-${severityIcon} text-${severityColor}"></i>
                                        ${item.check.name}
                                        <span class="badge bg-${severityColor} ms-2">${item.check.severity.toUpperCase()}</span>
                                    </div>
                                    <div class="header-desc">${item.check.description}</div>
                                </div>
                                <span class="toggle-details" onclick="toggleDetails('${detailId}')">
                                    <i class="bi bi-chevron-down" id="${detailId}-icon"></i> Details
                                </span>
                            </div>
                            
                            <div id="${detailId}" class="collapsible-content" style="display: none;">
                                <div class="recommendation">
                                    <i class="bi bi-plus-circle-fill"></i> <strong>Add this header:</strong><br>
                                    <code class="text-info">${item.check.recommendation}</code>
                                </div>
                            </div>
                        </div>
                    `;
                });
                
                html += `</div>`;
            } else {
                html += `
                    <div class="alert alert-success">
                        <i class="bi bi-check-circle-fill"></i> All important security headers are present!
                    </div>
                `;
            }
            
            html += `
                    </div>
                </div>
            `;
            
            container.innerHTML = html;
        }

        function checkCORS(headers) {
            const issues = [];
            const acao = headers['access-control-allow-origin'];
            const acac = headers['access-control-allow-credentials'];
            
            if (acao) {
                if (acao === '*') {
                    issues.push({
                        name: 'CORS Misconfiguration',
                        description: 'Access-Control-Allow-Origin set to wildcard (*)',
                        value: acao,
                        issues: ['Allows any origin to access resources', 'Major security risk for sensitive data'],
                        recommendation: 'Specify exact allowed origins instead of using wildcard'
                    });
                }
                
                if (acao === '*' && acac === 'true') {
                    issues.push({
                        name: 'Critical CORS Misconfiguration',
                        description: 'Wildcard origin with credentials enabled',
                        value: `Access-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac}`,
                        issues: ['EXTREMELY DANGEROUS: Allows any site to make authenticated requests', 'Critical security vulnerability'],
                        recommendation: 'Never use wildcard with credentials. Specify exact origins.'
                    });
                }
            }
            
            return issues;
        }

        function checkCookies(headers) {
            const issues = [];
            const setCookie = headers['set-cookie'];
            
            if (setCookie) {
                const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
                
                cookies.forEach(cookie => {
                    const problems = [];
                    
                    if (!cookie.toLowerCase().includes('secure')) {
                        problems.push('Missing Secure flag');
                    }
                    if (!cookie.toLowerCase().includes('httponly')) {
                        problems.push('Missing HttpOnly flag');
                    }
                    if (!cookie.toLowerCase().includes('samesite')) {
                        problems.push('Missing SameSite attribute');
                    } else if (cookie.toLowerCase().includes('samesite=none')) {
                        problems.push('SameSite=None without proper justification');
                    }
                    
                    if (problems.length > 0) {
                        issues.push({
                            name: 'Insecure Cookie Configuration',
                            description: 'Cookie lacks security attributes',
                            value: cookie,
                            issues: problems,
                            recommendation: 'Add: Secure; HttpOnly; SameSite=Strict (or Lax) attributes'
                        });
                    }
                });
            }
            
            return issues;
        }
    }

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'security-headers',
        name: 'HTTP Security Headers',
        description: 'Advanced security headers analysis with misconfiguration detection',
        icon: 'bi-shield-lock',
        category: 'purple',
        render: render,
        init: init
    });
})();