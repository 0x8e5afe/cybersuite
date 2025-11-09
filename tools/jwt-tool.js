// ========================================
// JWT TOOL
// Category: Purple Team
// ========================================

(function() {
    'use strict';

    function render() {
        return `
            <div class="mb-4">
                <h4><i class="bi bi-key-fill"></i> JWT Tool</h4>
                <p class="text-secondary">Decode, analyze, and generate JSON Web Tokens</p>
            </div>
            
            <ul class="nav nav-tabs mb-3" id="jwtTabs" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" id="decode-tab" data-bs-toggle="tab" data-bs-target="#decode" type="button">
                        <i class="bi bi-unlock-fill"></i> Decode JWT
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="generate-tab" data-bs-toggle="tab" data-bs-target="#generate" type="button">
                        <i class="bi bi-hammer"></i> Generate JWT
                    </button>
                </li>
            </ul>
            
            <div class="tab-content" id="jwtTabContent">
                <!-- Decode Tab -->
                <div class="tab-pane fade show active" id="decode" role="tabpanel">
                    <div class="mb-3">
                        <label for="jwtInput" class="form-label">JWT Token</label>
                        <textarea class="form-control font-monospace" id="jwtInput" rows="4" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."></textarea>
                    </div>
                    <button class="btn btn-primary" onclick="decodeJwt()">
                        <i class="bi bi-play-fill"></i> Decode & Analyze
                    </button>
                    <div id="jwtDecodeResults" class="mt-3"></div>
                </div>
                
                <!-- Generate Tab -->
                <div class="tab-pane fade" id="generate" role="tabpanel">
                    <div class="mb-3">
                        <label for="jwtAlgorithm" class="form-label">Algorithm</label>
                        <select class="form-select" id="jwtAlgorithm">
                            <option value="HS256">HS256 (HMAC + SHA256)</option>
                            <option value="HS384">HS384 (HMAC + SHA384)</option>
                            <option value="HS512">HS512 (HMAC + SHA512)</option>
                            <option value="none">none (No signature - UNSAFE!)</option>
                        </select>
                    </div>
                    
                    <div class="mb-3">
                        <label for="jwtPayload" class="form-label">Payload (JSON)</label>
                        <textarea class="form-control font-monospace" id="jwtPayload" rows="6" placeholder='{"sub": "1234567890", "name": "John Doe", "iat": 1516239022}'></textarea>
                    </div>
                    
                    <div class="mb-3">
                        <label for="jwtSecret" class="form-label">Secret Key (for HMAC algorithms)</label>
                        <input type="text" class="form-control font-monospace" id="jwtSecret" placeholder="your-256-bit-secret">
                    </div>
                    
                    <button class="btn btn-primary" onclick="generateJwt()">
                        <i class="bi bi-hammer"></i> Generate JWT
                    </button>
                    <div id="jwtGenerateResults" class="mt-3"></div>
                </div>
            </div>
        `;
    }

    function init() {
        window.generateJwt = async function() {
            const algorithm = document.getElementById('jwtAlgorithm').value;
            const payloadText = document.getElementById('jwtPayload').value.trim();
            const secret = document.getElementById('jwtSecret').value;
            const resultsDiv = document.getElementById('jwtGenerateResults');
            
            if (!payloadText) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter a payload</div>';
                return;
            }
            
            try {
                const payload = JSON.parse(payloadText);
                const header = { alg: algorithm, typ: 'JWT' };
                
                const base64UrlEncode = (str) => {
                    return btoa(unescape(encodeURIComponent(str)))
                        .replace(/\+/g, '-')
                        .replace(/\//g, '_')
                        .replace(/=+$/, '');
                };
                
                const headerB64 = base64UrlEncode(JSON.stringify(header));
                const payloadB64 = base64UrlEncode(JSON.stringify(payload));
                
                let signature = '';
                if (algorithm !== 'none') {
                    if (!secret) {
                        resultsDiv.innerHTML = '<div class="alert alert-danger">Secret key required for HMAC algorithms</div>';
                        return;
                    }
                    
                    const encoder = new TextEncoder();
                    const key = await crypto.subtle.importKey(
                        'raw',
                        encoder.encode(secret),
                        { name: 'HMAC', hash: algorithm.replace('HS', 'SHA-') },
                        false,
                        ['sign']
                    );
                    
                    const data = encoder.encode(`${headerB64}.${payloadB64}`);
                    const sig = await crypto.subtle.sign('HMAC', key, data);
                    signature = base64UrlEncode(String.fromCharCode(...new Uint8Array(sig)));
                }
                
                const jwt = `${headerB64}.${payloadB64}.${signature}`;
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-success">
                        <h6 class="alert-heading"><i class="bi bi-check-circle-fill"></i> JWT Generated Successfully</h6>
                        <div class="code-block mt-2 mb-2">${window.escapeHtml(jwt)}</div>
                        <button class="btn btn-sm btn-outline-primary" onclick="copyToClipboard('${jwt.replace(/'/g, "\\'")}', this)">
                            <i class="bi bi-clipboard"></i> Copy to Clipboard
                        </button>
                    </div>
                `;
            } catch (error) {
                resultsDiv.innerHTML = `<div class="alert alert-danger"><strong>Error:</strong> ${window.escapeHtml(error.message)}</div>`;
            }
        };

        window.decodeJwt = function() {
            const jwt = document.getElementById('jwtInput').value.trim();
            const resultsDiv = document.getElementById('jwtDecodeResults');
            
            if (!jwt) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter a JWT token</div>';
                return;
            }

            try {
                const parts = jwt.split('.');
                if (parts.length !== 3) {
                    throw new Error('Invalid JWT format. Expected 3 parts separated by dots.');
                }

                const base64UrlDecode = (str) => {
                    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
                    while (base64.length % 4 !== 0) base64 += '=';
                    return decodeURIComponent(
                        atob(base64)
                            .split('')
                            .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
                            .join('')
                    );
                };

                const header = JSON.parse(base64UrlDecode(parts[0]));
                const payload = JSON.parse(base64UrlDecode(parts[1]));
                const signature = parts[2];

                let html = '<div class="row g-3">';
                
                // Header
                html += `
                    <div class="col-12">
                        <div class="card bg-dark">
                            <div class="card-header bg-info text-dark">
                                <i class="bi bi-file-earmark-text"></i> Header
                            </div>
                            <div class="card-body">
                                <pre class="mb-0"><code>${JSON.stringify(header, null, 2)}</code></pre>
                            </div>
                        </div>
                    </div>
                `;

                // Payload
                html += `
                    <div class="col-12">
                        <div class="card bg-dark">
                            <div class="card-header bg-info text-dark">
                                <i class="bi bi-box"></i> Payload
                            </div>
                            <div class="card-body">
                                <pre class="mb-0"><code>${JSON.stringify(payload, null, 2)}</code></pre>
                            </div>
                        </div>
                    </div>
                `;

                // Signature
                html += `
                    <div class="col-12">
                        <div class="card bg-dark">
                            <div class="card-header bg-info text-dark">
                                <i class="bi bi-pen"></i> Signature
                            </div>
                            <div class="card-body">
                                <code class="text-break">${signature || '(empty)'}</code>
                            </div>
                        </div>
                    </div>
                `;

                // Security Analysis
                const securityIssues = [];
                
                if (header.alg && header.alg.toLowerCase() === 'none') {
                    securityIssues.push({
                        severity: 'danger',
                        icon: 'exclamation-triangle-fill',
                        title: 'CRITICAL: Unsigned Token',
                        desc: 'Algorithm is "none" - token has no signature and can be forged by anyone!'
                    });
                }

                if (payload.exp) {
                    const expDate = new Date(payload.exp * 1000);
                    const isExpired = expDate < new Date();
                    if (isExpired) {
                        securityIssues.push({
                            severity: 'danger',
                            icon: 'clock-fill',
                            title: 'Token Expired',
                            desc: `Expired on: ${expDate.toLocaleString()}`
                        });
                    } else {
                        securityIssues.push({
                            severity: 'success',
                            icon: 'check-circle-fill',
                            title: 'Valid Expiration',
                            desc: `Expires on: ${expDate.toLocaleString()}`
                        });
                    }
                } else {
                    securityIssues.push({
                        severity: 'warning',
                        icon: 'exclamation-circle-fill',
                        title: 'No Expiration',
                        desc: 'Token does not expire - potential security risk for long-lived tokens'
                    });
                }

                if (payload.iat) {
                    const iatDate = new Date(payload.iat * 1000);
                    securityIssues.push({
                        severity: 'info',
                        icon: 'info-circle-fill',
                        title: 'Issued At',
                        desc: `${iatDate.toLocaleString()}`
                    });
                }

                html += '<div class="col-12"><h6 class="mt-2">Security Analysis</h6></div>';
                securityIssues.forEach(issue => {
                    html += `
                        <div class="col-12">
                            <div class="alert alert-${issue.severity} mb-2">
                                <strong><i class="bi bi-${issue.icon}"></i> ${issue.title}</strong>
                                <p class="mb-0 small">${issue.desc}</p>
                            </div>
                        </div>
                    `;
                });

                html += '</div>';
                resultsDiv.innerHTML = html;
            } catch (error) {
                resultsDiv.innerHTML = `<div class="alert alert-danger"><strong>Decoding Error:</strong> ${window.escapeHtml(error.message)}</div>`;
            }
        };
    }

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'jwt-tool',
        name: 'JWT Tool',
        description: 'Decode, analyze, and generate JSON Web Tokens with security analysis',
        icon: 'bi-key-fill',
        category: 'purple',
        render: render,
        init: init
    });
})();