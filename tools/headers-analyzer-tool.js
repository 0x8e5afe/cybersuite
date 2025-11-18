// ========================================
// SECURITY HEADERS ANALYZER
// Category: Blue Team
// ========================================

(function() {
    'use strict';

    // Header definitions with security best practices
    const securityHeaders = {
        // Missing Headers (Should be present)
        missing: {
            'strict-transport-security': {
                name: 'Strict-Transport-Security (HSTS)',
                severity: 'high',
                description: 'Forces browsers to use HTTPS connections only, preventing protocol downgrade attacks and cookie hijacking.',
                solution: 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
                check: (headers) => !headers['strict-transport-security']
            },
            'content-security-policy': {
                name: 'Content-Security-Policy (CSP)',
                severity: 'critical',
                description: 'Prevents XSS attacks by controlling which resources can be loaded and executed on your page.',
                solution: "Add header: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'],
                check: (headers) => !headers['content-security-policy']
            },
            'x-frame-options': {
                name: 'X-Frame-Options',
                severity: 'high',
                description: 'Protects against clickjacking attacks by preventing your site from being embedded in iframes.',
                solution: 'Add header: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'],
                check: (headers) => !headers['x-frame-options']
            },
            'x-content-type-options': {
                name: 'X-Content-Type-Options',
                severity: 'medium',
                description: 'Prevents MIME-type sniffing attacks by forcing browsers to respect the declared Content-Type.',
                solution: 'Add header: X-Content-Type-Options: nosniff',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'],
                check: (headers) => !headers['x-content-type-options']
            },
            'referrer-policy': {
                name: 'Referrer-Policy',
                severity: 'medium',
                description: 'Controls how much referrer information is included with requests, preventing information leakage.',
                solution: 'Add header: Referrer-Policy: strict-origin-when-cross-origin or no-referrer',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'],
                check: (headers) => !headers['referrer-policy']
            },
            'permissions-policy': {
                name: 'Permissions-Policy',
                severity: 'low',
                description: 'Controls which browser features and APIs can be used, reducing attack surface.',
                solution: 'Add header: Permissions-Policy: geolocation=(), microphone=(), camera=()',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy'],
                check: (headers) => !headers['permissions-policy']
            }
        },
        
        // Misconfigured Headers
        misconfigured: {
            'strict-transport-security': {
                name: 'Strict-Transport-Security (HSTS)',
                severity: 'medium',
                description: 'HSTS header is present but may be misconfigured (max-age too short or missing directives).',
                solution: 'Ensure max-age is at least 31536000 (1 year) and consider adding includeSubDomains and preload',
                references: ['https://hstspreload.org/'],
                check: (headers) => {
                    const hsts = headers['strict-transport-security'];
                    if (!hsts) return false;
                    const maxAge = hsts.match(/max-age=(\d+)/);
                    return maxAge && parseInt(maxAge[1]) < 31536000;
                }
            },
            'content-security-policy': {
                name: 'Content-Security-Policy (CSP)',
                severity: 'high',
                description: "CSP header contains 'unsafe-inline' or 'unsafe-eval' directives which weaken security.",
                solution: "Remove 'unsafe-inline' and 'unsafe-eval'. Use nonces or hashes for inline scripts instead.",
                references: ['https://content-security-policy.com/'],
                check: (headers) => {
                    const csp = headers['content-security-policy'];
                    return csp && (csp.includes('unsafe-inline') || csp.includes('unsafe-eval'));
                }
            },
            'x-frame-options': {
                name: 'X-Frame-Options',
                severity: 'low',
                description: 'X-Frame-Options is set to ALLOW-FROM which is deprecated and not supported by modern browsers.',
                solution: 'Use Content-Security-Policy with frame-ancestors directive instead',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors'],
                check: (headers) => {
                    const xfo = headers['x-frame-options'];
                    return xfo && xfo.toLowerCase().startsWith('allow-from');
                }
            },
            'referrer-policy': {
                name: 'Referrer-Policy',
                severity: 'low',
                description: 'Referrer-Policy is set to an insecure value that may leak sensitive information.',
                solution: 'Use strict-origin-when-cross-origin, no-referrer, or same-origin',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'],
                check: (headers) => {
                    const rp = headers['referrer-policy'];
                    const insecureValues = ['unsafe-url', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin'];
                    return rp && insecureValues.some(v => rp.toLowerCase().includes(v));
                }
            },
            'x-xss-protection': {
                name: 'X-XSS-Protection',
                severity: 'low',
                description: 'X-XSS-Protection header is deprecated and can introduce vulnerabilities in older browsers.',
                solution: 'Remove this header and rely on Content-Security-Policy instead',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection'],
                check: (headers) => !!headers['x-xss-protection']
            }
        },
        
        // Information Disclosure Headers
        infoDisclosure: {
            'server': {
                name: 'Server',
                severity: 'info',
                description: 'Server header discloses web server software and version, aiding attackers in reconnaissance.',
                solution: 'Remove or obfuscate the Server header to hide server information',
                references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server'],
                check: (headers) => !!headers['server']
            },
            'x-powered-by': {
                name: 'X-Powered-By',
                severity: 'info',
                description: 'X-Powered-By header reveals technology stack information useful for attackers.',
                solution: 'Remove the X-Powered-By header from server configuration',
                references: ['https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'],
                check: (headers) => !!headers['x-powered-by']
            },
            'x-aspnet-version': {
                name: 'X-AspNet-Version',
                severity: 'info',
                description: 'X-AspNet-Version header exposes ASP.NET framework version.',
                solution: 'Disable in web.config: <httpRuntime enableVersionHeader="false" />',
                references: ['https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpruntimesection.enableversionheader'],
                check: (headers) => !!headers['x-aspnet-version']
            },
            'x-aspnetmvc-version': {
                name: 'X-AspNetMvc-Version',
                severity: 'info',
                description: 'X-AspNetMvc-Version header reveals ASP.NET MVC version.',
                solution: 'Add to Global.asax.cs: MvcHandler.DisableMvcResponseHeader = true;',
                references: ['https://docs.microsoft.com/en-us/aspnet/mvc/overview/security/'],
                check: (headers) => !!headers['x-aspnetmvc-version']
            },
            'x-generator': {
                name: 'X-Generator',
                severity: 'info',
                description: 'X-Generator header discloses CMS or framework information.',
                solution: 'Remove or disable the X-Generator header in your CMS/framework configuration',
                references: [],
                check: (headers) => !!headers['x-generator']
            }
        }
    };

    const severityOrder = {
        'critical': 5,
        'high': 4,
        'medium': 3,
        'low': 2,
        'info': 1
    };

     const severityConfig = {
        'critical': { class: 'dark-danger', color: '#8b0000', icon: 'bi-exclamation-octagon-fill', score: -20 },
        'high':     { class: 'danger',      color: '#ff0000', icon: 'bi-exclamation-triangle-fill', score: -15 },
        'medium':   { class: 'warning',     color: '#ffcc00', icon: 'bi-exclamation-diamond-fill', score: -10 },
        'low':      { class: 'success',     color: '#00ff88', icon: 'bi-info-circle-fill',         score: -5 },
        'info':     { class: 'info',        color: '#0dcaf0', icon: 'bi-info-circle',              score: -1 }
    };

    function parseHeaders(input) {
        const headers = {};
        const lines = input.trim().split('\n');
        
        for (const line of lines) {
            const colonIndex = line.indexOf(':');
            if (colonIndex > 0) {
                const key = line.substring(0, colonIndex).trim().toLowerCase();
                const value = line.substring(colonIndex + 1).trim();
                if (key && value) {
                    headers[key] = value;
                }
            }
        }
        
        return headers;
    }

    function analyzeHeaders(headers) {
        const issues = {
            missing: [],
            misconfigured: [],
            infoDisclosure: []
        };

        // Check for missing headers
        Object.entries(securityHeaders.missing).forEach(([key, config]) => {
            if (config.check(headers)) {
                issues.missing.push({ ...config, header: key });
            }
        });

        // Check for misconfigured headers
        Object.entries(securityHeaders.misconfigured).forEach(([key, config]) => {
            if (config.check(headers)) {
                issues.misconfigured.push({ ...config, header: key, value: headers[key] });
            }
        });

        // Check for information disclosure
        Object.entries(securityHeaders.infoDisclosure).forEach(([key, config]) => {
            if (config.check(headers)) {
                issues.infoDisclosure.push({ ...config, header: key, value: headers[key] });
            }
        });

        // Sort by severity
        const sortBySeverity = (a, b) => severityOrder[b.severity] - severityOrder[a.severity];
        issues.missing.sort(sortBySeverity);
        issues.misconfigured.sort(sortBySeverity);
        issues.infoDisclosure.sort(sortBySeverity);

        return issues;
    }

function calculateScore(issues) {
    let score = 100;

    const applyIssue = (issue) => {
        const s = severityConfig[issue.severity];
        if (!s) return; // ignore unknown severities
        score += s.score;
    };

    issues.missing.forEach(applyIssue);
    issues.misconfigured.forEach(applyIssue);
    issues.infoDisclosure.forEach(applyIssue);

    return Math.max(0, Math.min(100, score));
}

function renderIssueCard(issue, index, category) {
    const severityInfo = severityConfig[issue.severity] || severityConfig['low'];
    const cardId = `issue-${category}-${index}`;
        
        return `
            <div class="accordion-item bg-dark border-${severityInfo.class}">
                <h2 class="accordion-header">
                    <button class="accordion-button collapsed severity-header-${severityInfo.class}" 
                            type="button" 
                            data-bs-toggle="collapse" 
                            data-bs-target="#${cardId}">
                        <div class="d-flex align-items-center gap-2 w-100">
                            <i class="${severityInfo.icon} text-${severityInfo.class}"></i>
                            <span class="flex-grow-1">${issue.name}</span>
                        
                        </div>
                    </button>
                </h2>
                <div id="${cardId}" class="accordion-collapse collapse">
                    <div class="accordion-body">
                        ${issue.value ? `
                            <div class="mb-3">
                                <strong class="text-${severityInfo.class}">Current Value:</strong>
                                <code class="d-block mt-1">${window.escapeHtml(issue.value)}</code>
                            </div>
                        ` : ''}
                        
                        <div class="mb-3">
                            <strong><i class="bi bi-exclamation-circle"></i> Issue:</strong>
                            <p class="mb-0 mt-1">${issue.description}</p>
                        </div>
                        
                        <div class="mb-3">
                            <strong><i class="bi bi-tools"></i> Solution:</strong>
                            <p class="mb-0 mt-1">${issue.solution}</p>
                        </div>
                        
                        ${issue.references && issue.references.length > 0 ? `
                            <div>
                                <strong><i class="bi bi-book"></i> References:</strong>
                                <ul class="mb-0 mt-1 small">
                                    ${issue.references.map(ref => 
                                        `<li><a href="${ref}" target="_blank" class="text-primary">${ref}</a></li>`
                                    ).join('')}
                                </ul>
                            </div>
                        ` : ''}
                    </div>
                </div>
            </div>
        `;
    }

    function render() {
        return `
            <div class="section-header">
                <h3 class="mb-1 d-flex align-items-center gap-2">
                    <i class="bi bi-shield-check"></i>
                    <span>Security Headers Analyzer</span>
                </h3>
                <p class="text-secondary mb-0">
                    Analyze HTTP response headers for security misconfigurations and missing protections
                </p>
            </div>

            <div class="row g-3 mb-4">
                <div class="col-12">
                    <ul class="nav nav-tabs" role="tablist">
                        <li class="nav-item">
                            <button class="nav-link active" id="url-tab" data-bs-toggle="tab" 
                                    data-bs-target="#url-panel" type="button">
                                <i class="bi bi-link-45deg"></i> URL Scanner
                            </button>
                        </li>
                        <li class="nav-item">
                            <button class="nav-link" id="manual-tab" data-bs-toggle="tab" 
                                    data-bs-target="#manual-panel" type="button">
                                <i class="bi bi-code-square"></i> Manual Input
                            </button>
                        </li>
                    </ul>
                    
                    <div class="tab-content mt-3">
                        <div class="tab-pane fade show active" id="url-panel">
                            <div class="card bg-dark">
                                <div class="card-body">
                                    <label for="targetUrl" class="form-label">Target URL</label>
                                    <div class="input-group mb-3">
                                        <input type="url" class="form-control" id="targetUrl" 
                                               placeholder="https://example.com">
                                        <button class="btn btn-primary" onclick="fetchHeaders()">
                                            <i class="bi bi-search"></i> Scan
                                        </button>
                                    </div>
                                    <div class="alert alert-warning mb-0">
                                        <i class="bi bi-exclamation-triangle"></i>
                                        <strong>Note:</strong> Due to CORS restrictions, you may need to use a browser extension 
                                        or the manual input method for cross-origin requests.
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="tab-pane fade" id="manual-panel">
                            <div class="card bg-dark">
                                <div class="card-body">
                                    <label for="headersInput" class="form-label">
                                        HTTP Response Headers
                                        <small class="text-secondary">(one per line, format: Header-Name: value)</small>
                                    </label>
                                    <textarea class="form-control font-monospace" id="headersInput" 
                                              rows="12" placeholder="Content-Type: text/html
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
..."></textarea>
                                    <div class="mt-3 d-flex gap-2">
                                        <button class="btn btn-primary" onclick="analyzeManualHeaders()">
                                            <i class="bi bi-search"></i> Analyze Headers
                                        </button>
                                        <button class="btn btn-outline-secondary" onclick="clearManualInput()">
                                            <i class="bi bi-x-circle"></i> Clear
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div id="analysisResults"></div>
        `;
    }

    function init() {
        window.fetchHeaders = async function() {
            const url = document.getElementById('targetUrl').value.trim();
            const resultsDiv = document.getElementById('analysisResults');
            
            if (!url) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter a URL</div>';
                return;
            }

            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <div class="spinner-border spinner-border-sm me-2"></div>
                    Fetching headers from ${window.escapeHtml(url)}...
                </div>
            `;

            try {
                const response = await fetch(url, { method: 'HEAD' });
                const headers = {};
                
                for (const [key, value] of response.headers.entries()) {
                    headers[key.toLowerCase()] = value;
                }

                displayResults(headers);
            } catch (error) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-danger">
                        <strong><i class="bi bi-x-circle-fill"></i> Error:</strong> 
                        ${window.escapeHtml(error.message)}
                        <hr>
                        <small>This is likely due to CORS restrictions. Please use the Manual Input tab instead.</small>
                    </div>
                `;
            }
        };

        window.analyzeManualHeaders = function() {
            const input = document.getElementById('headersInput').value.trim();
            const resultsDiv = document.getElementById('analysisResults');
            
            if (!input) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter some headers</div>';
                return;
            }

            try {
                const headers = parseHeaders(input);
                if (Object.keys(headers).length === 0) {
                    resultsDiv.innerHTML = '<div class="alert alert-warning">No valid headers found. Use format: Header-Name: value</div>';
                    return;
                }
                displayResults(headers);
            } catch (error) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-danger">
                        <strong><i class="bi bi-x-circle-fill"></i> Error:</strong> 
                        ${window.escapeHtml(error.message)}
                    </div>
                `;
            }
        };

        window.clearManualInput = function() {
            document.getElementById('headersInput').value = '';
            document.getElementById('analysisResults').innerHTML = '';
        };

            function getScoreGrade(score) {
        if (score >= 90) return { grade: 'A', class: 'success',      text: 'Excellent' };
        if (score >= 80) return { grade: 'B', class: 'info',         text: 'Good' };
        if (score >= 70) return { grade: 'C', class: 'warning',      text: 'Fair' };
        if (score >= 60) return { grade: 'D', class: 'danger',       text: 'Poor' };
        return               { grade: 'F', class: 'dark-danger',     text: 'Critical' };
    }


        function displayResults(headers) {
            const issues = analyzeHeaders(headers);
            const score = calculateScore(issues);
            const grade = getScoreGrade(score);
            const totalIssues = issues.missing.length + issues.misconfigured.length + issues.infoDisclosure.length;

            const resultsDiv = document.getElementById('analysisResults');
            
            resultsDiv.innerHTML = `
                <!-- Score Card -->
                <div class="card bg-dark border-${grade.class} mb-4">
                    <div class="card-header bg-${grade.class}">
                        <h5 class="mb-0">
                            <i class="bi bi-award-fill"></i> Security Score
                        </h5>
                    </div>
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col-md-4 text-center">
                                <div class="display-1 fw-bold text-${grade.class}">${grade.grade}</div>
                                <div class="fs-5 text-${grade.class}">${grade.text}</div>
                            </div>
                            <div class="col-md-8">
                                <div class="mb-3">
                                    <div class="d-flex justify-content-between mb-1">
                                        <span>Overall Score</span>
                                        <span class="fw-bold">${score}/100</span>
                                    </div>
                                    <div class="progress" style="height: 30px;">
                                        <div class="progress-bar bg-${grade.class}" style="width: ${score}%">
                                            ${score}%
                                        </div>
                                    </div>
                                </div>
                                <div class="row g-2 small">
                                    <div class="col-6">
                                        <i class="bi bi-x-circle text-danger"></i>
                                        <strong>Missing:</strong> ${issues.missing.length}
                                    </div>
                                    <div class="col-6">
                                        <i class="bi bi-exclamation-triangle text-warning"></i>
                                        <strong>Misconfigured:</strong> ${issues.misconfigured.length}
                                    </div>
                                    <div class="col-6">
                                        <i class="bi bi-info-circle text-blue"></i>
                                        <strong>Info Disclosure:</strong> ${issues.infoDisclosure.length}
                                    </div>
                                    <div class="col-6">
                                        <i class="bi bi-bug text-danger"></i>
                                        <strong>Total Issues:</strong> ${totalIssues}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Issues Tabs -->
                ${totalIssues > 0 ? `
                    <div class="card bg-dark">
                        <div class="card-body p-0">
                            <ul class="nav nav-tabs border-bottom-0 px-3 pt-3" role="tablist">
                                <li class="nav-item">
                                    <button class="nav-link nav-link-missing ${issues.missing.length > 0 ? 'active' : ''}" 
                                            data-bs-toggle="tab" data-bs-target="#missing-panel" type="button">
                                        <i class="bi bi-x-circle"></i> Missing 
                                        <span class="badge bg-danger ms-1">${issues.missing.length}</span>
                                    </button>
                                </li>
                                <li class="nav-item">
                                    <button class="nav-link nav-link-misconfigured ${issues.missing.length === 0 && issues.misconfigured.length > 0 ? 'active' : ''}" 
                                            data-bs-toggle="tab" data-bs-target="#misconfigured-panel" type="button">
                                        <i class="bi bi-exclamation-triangle"></i> Misconfigured 
                                        <span class="badge bg-warning text-dark ms-1">${issues.misconfigured.length}</span>
                                    </button>
                                </li>
                                <li class="nav-item">
                                    <button class="nav-link nav-link-info-disclosure ${issues.missing.length === 0 && issues.misconfigured.length === 0 ? 'active' : ''}" 
                                            data-bs-toggle="tab" data-bs-target="#info-panel" type="button">
                                        <i class="bi bi-info-circle"></i> Info Disclosure 
                                        <span class="badge bg-info ms-1">${issues.infoDisclosure.length}</span>
                                    </button>
                                </li>
                            </ul>
                            
                            <div class="tab-content p-3">
                                <!-- Missing Headers -->
                                <div class="tab-pane fade ${issues.missing.length > 0 ? 'show active' : ''}" id="missing-panel">
                                    ${issues.missing.length > 0 ? `
                                        <div class="accordion" id="missingAccordion">
                                            ${issues.missing.map((issue, idx) => renderIssueCard(issue, idx, 'missing')).join('')}
                                        </div>
                                    ` : '<div class="alert alert-success mb-0"><i class="bi bi-check-circle-fill"></i> All recommended security headers are present!</div>'}
                                </div>
                                
                                <!-- Misconfigured Headers -->
                                <div class="tab-pane fade ${issues.missing.length === 0 && issues.misconfigured.length > 0 ? 'show active' : ''}" id="misconfigured-panel">
                                    ${issues.misconfigured.length > 0 ? `
                                        <div class="accordion" id="misconfiguredAccordion">
                                            ${issues.misconfigured.map((issue, idx) => renderIssueCard(issue, idx, 'misconfigured')).join('')}
                                        </div>
                                    ` : '<div class="alert alert-success mb-0"><i class="bi bi-check-circle-fill"></i> No misconfigured headers detected!</div>'}
                                </div>
                                
                                <!-- Information Disclosure -->
                                <div class="tab-pane fade ${issues.missing.length === 0 && issues.misconfigured.length === 0 ? 'show active' : ''}" id="info-panel">
                                    ${issues.infoDisclosure.length > 0 ? `
                                        <div class="accordion" id="infoAccordion">
                                            ${issues.infoDisclosure.map((issue, idx) => renderIssueCard(issue, idx, 'info')).join('')}
                                        </div>
                                    ` : '<div class="alert alert-success mb-0"><i class="bi bi-check-circle-fill"></i> No information disclosure headers found!</div>'}
                                </div>
                            </div>
                        </div>
                    </div>
                ` : `
                    <div class="alert alert-success">
                        <h5 class="alert-heading"><i class="bi bi-check-circle-fill"></i> Perfect Security Headers!</h5>
                        <p class="mb-0">All recommended security headers are properly configured with no information disclosure.</p>
                    </div>
                `}
            `;
        }
    }

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'security-headers',
        name: 'Security Headers Analyzer',
        description: 'Analyze HTTP response headers for missing, misconfigured, or information disclosure issues',
        icon: 'bi-shield-check',
        category: 'purple',
        render: render,
        init: init
    });
})();