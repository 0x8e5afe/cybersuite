// ========================================
// JWT TOOL
// Category: Purple Team
// ========================================

(function() {
    'use strict';

        function base64UrlEncode(str) {
        return btoa(unescape(encodeURIComponent(str)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }

    function base64UrlDecode(str) {
        let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4 !== 0) base64 += '=';
        return decodeURIComponent(
            atob(base64)
                .split('')
                .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
                .join('')
        );
    }

    function normalizeJsonInput(text) {
        if (!text) return '';
        text = text.replace(/^\uFEFF/, ''); // BOM

        // Smart quotes → straight quotes
        text = text
            .replace(/[\u2018\u2019\u201B]/g, "'")
            .replace(/[\u201C\u201D\u201F]/g, '"');

        text = text.replace(/\r\n?/g, '\n');
        return text;
    }

    function buildJsonErrorHelpHtml(rawText, error) {
        const hints = [];

        if (/[“”‘’]/.test(rawText)) {
            hints.push('It looks like you used “smart quotes”. JSON only accepts straight quotes, for example: {"test": "test"}.');
        }
        if (/['‘’]\s*:/.test(rawText) || /:\s*['‘’]/.test(rawText)) {
            hints.push('JSON requires double quotes for keys and strings. Use "test" instead of \'test\'.');
        }
        if (/,(\s*[}\]])/.test(rawText)) {
            hints.push('Remove any trailing comma before } or ]. JSON does not allow trailing commas.');
        }
        if (/\/\/|\/\*/.test(rawText)) {
            hints.push('JSON does not allow comments (// or /* */). Remove all comments before parsing.');
        }
        if (!/^\s*[{[\"]/.test(rawText)) {
            hints.push('The payload should start with { for an object or [ for an array. Example: {"test": "test"}.');
        }

        let html = `<strong>Error parsing JSON:</strong> ${window.escapeHtml(error.message)}`;
        if (hints.length) {
            html += '<ul class="mt-2 mb-0">';
            hints.forEach(h => { html += `<li>${window.escapeHtml(h)}</li>`; });
            html += '</ul>';
        }
        return html;
    }

    function parseJsonWithHelpfulErrors(rawText) {
        const normalized = normalizeJsonInput(rawText.trim());
        try {
            const value = JSON.parse(normalized);
            let warning = null;

            if (value === null || typeof value !== 'object' || Array.isArray(value)) {
                warning = 'The payload is valid JSON, but it is not a JSON object. JWT payloads are typically objects like {"sub": "123", "name": "Alice"}.';
            }

            return { ok: true, value, normalized, warning };
        } catch (err) {
            return { ok: false, error: err, normalized };
        }
    }

    async function verifyHmacSignature(alg, secret, headerB64, payloadB64, signatureB64) {
        if (!secret) {
            return { status: 'no-secret', message: 'No secret provided' };
        }

        if (!/^HS(256|384|512)$/i.test(alg || '')) {
            return { status: 'unsupported', message: `Verification only implemented for HS256/384/512 (got "${alg || 'none'}").` };
        }

        const hashName = alg.replace('HS', 'SHA-');
        const encoder = new TextEncoder();
        const key = await crypto.subtle.importKey(
            'raw',
            encoder.encode(secret),
            { name: 'HMAC', hash: hashName },
            false,
            ['sign']
        );

        const data = encoder.encode(`${headerB64}.${payloadB64}`);
        const sig = await crypto.subtle.sign('HMAC', key, data);
        const sigStr = String.fromCharCode(...new Uint8Array(sig));
        const recomputed = base64UrlEncode(sigStr);

        const matches = recomputed === signatureB64;
        return {
            status: matches ? 'ok' : 'mismatch',
            message: matches ? 'Signature is VALID for this secret.' : 'Signature does NOT match for this secret.'
        };
    }

    function estimateSecretStrength(secret) {
        if (!secret) {
            return { score: 0, label: 'No secret', detail: 'Provide a secret for HMAC algorithms.' };
        }

        const length = secret.length;
        let classes = 0;
        if (/[a-z]/.test(secret)) classes++;
        if (/[A-Z]/.test(secret)) classes++;
        if (/[0-9]/.test(secret)) classes++;
        if (/[^A-Za-z0-9]/.test(secret)) classes++;

        let score = 0;
        let label = 'Very weak';
        let detail = 'Short length and low character variety. Easily guessable.';

        if (length >= 8 && classes >= 2) {
            score = 1;
            label = 'Weak';
            detail = 'Better than nothing, but still too short for a JWT HMAC secret.';
        }
        if (length >= 16 && classes >= 2) {
            score = 2;
            label = 'Moderate';
            detail = 'Acceptable for low-risk scenarios; still consider a longer random secret.';
        }
        if (length >= 32 && classes >= 3) {
            score = 3;
            label = 'Strong';
            detail = 'Good entropy for an HMAC secret.';
        }
        if (length >= 48 && classes >= 3) {
            score = 4;
            label = 'Very strong';
            detail = 'High-entropy secret, suitable for production use.';
        }

        return { score, label, detail };
    }

    function analyzeSensitiveClaims(payload) {
        const hints = [];

        if (!payload || typeof payload !== 'object') return hints;

        if (payload.admin === true || payload.is_admin === true) {
            hints.push('Claim "admin": true present. High-privilege token – ensure server-side authorization.');
        }
        if (typeof payload.role === 'string' && /admin|root|superuser/i.test(payload.role)) {
            hints.push(`Role "${payload.role}" present. Treat this as a high-privilege token.`);
        }
        if (typeof payload.scope === 'string' && /\*/.test(payload.scope)) {
            hints.push('Wildcard scope detected in "scope". Verify the API correctly enforces scopes.');
        }
        if (payload.impersonated_user || payload.on_behalf_of) {
            hints.push('Impersonation-related claims present. Confirm that impersonation is strictly controlled.');
        }

        return hints;
    }

    function render() {
        return `

            <div class="section-header">
                <h3 class="mb-1 d-flex align-items-center gap-2">
                    <i class="bi bi-key-fill"></i>
                    <span>JWT Tool</span>
                </h3>
                <p class="text-secondary mb-0">
                   Decode, analyze, and generate JSON Web Tokens
                </p>
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
                        <div class="form-check mt-1">
                            <input class="form-check-input" type="checkbox" id="jwtStripBearer" checked>
                            <label class="form-check-label small" for="jwtStripBearer">
                                Automatically strip "Bearer " prefix
                            </label>
                        </div>
                    </div>

                    <div class="card mb-3">
                        <div class="card-header">
                            <i class="bi bi-shield-check"></i> Signature Verification (HMAC)
                        </div>
                        <div class="card-body">
                            <p class="small text-secondary mb-2">
                                Optional: verify HS256 / HS384 / HS512 signatures with a shared secret.
                            </p>
                            <div class="row g-2 align-items-center">
                                <div class="col-md-6">
                                    <label for="jwtVerifySecret" class="form-label mb-1">Verification Secret</label>
                                    <input type="password" class="form-control font-monospace" id="jwtVerifySecret" placeholder="shared-secret">
                                </div>
                                <div class="col-md-3">
                                    <label class="form-label mb-1">Result</label>
                                    <div id="jwtVerifyResult" class="small text-muted">
                                        Not checked yet
                                    </div>
                                </div>
                            </div>
                            <p class="small text-muted mt-2 mb-0">
                                Secret is used only locally in your browser to recompute the HMAC and compare signatures.
                            </p>
                        </div>
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
                        <div class="mt-2 d-flex flex-wrap gap-2">
                            <button type="button" class="btn btn-sm btn-outline-secondary" onclick="jwtApplyLifetimePreset('short')">
                                <i class="bi bi-clock-fill"></i> iat=now, exp=+1h
                            </button>
                            <button type="button" class="btn btn-sm btn-outline-secondary" onclick="jwtApplyLifetimePreset('day')">
                                <i class="bi bi-calendar-day"></i> iat=now, exp=+1d
                            </button>
                            <button type="button" class="btn btn-sm btn-outline-secondary" onclick="jwtApplyLifetimePreset('long')">
                                <i class="bi bi-calendar-range"></i> iat=now, exp=+30d
                            </button>
                        </div>
                    </div>
                    
                    <div class="mb-1">
                        <label for="jwtSecret" class="form-label">Secret Key (for HMAC algorithms)</label>
                        <input type="password" class="form-control font-monospace" id="jwtSecret" placeholder="your-256-bit-secret">
                    </div>
                    <div id="jwtSecretStrength" class="small text-muted mb-3">
                        Secret strength: not evaluated
                    </div>
                    
                    <button class="btn btn-primary" onclick="generateJwt()">
                        <i class="bi bi-hammer"></i> Generate JWT
                    </button>
                    <div id="jwtGenerateResults" class="mt-3"></div>
                </div>
            </div>
        `;
    }

        function normalizeJsonInput(text) {
        if (!text) return '';

        // Remove leading BOM if present
        text = text.replace(/^\uFEFF/, '');

        // Replace smart quotes with normal quotes
        // “ ” => "
        // ‘ ’ => '
        text = text
            .replace(/[\u2018\u2019\u201B]/g, "'")
            .replace(/[\u201C\u201D\u201F]/g, '"');

        // Normalize line endings
        text = text.replace(/\r\n?/g, '\n');

        return text;
    }

    function buildJsonErrorHelpHtml(rawText, error) {
        const hints = [];

        // Smart quotes
        if (/[“”‘’]/.test(rawText)) {
            hints.push('It looks like you used “smart quotes”. JSON only accepts straight quotes, for example: {"test": "test"}.');
        }

        // Single-quoted keys/strings (JS object style)
        if (/['‘’]\s*:/.test(rawText) || /:\s*['‘’]/.test(rawText)) {
            hints.push('JSON requires double quotes for keys and strings. Use "test" instead of \'test\'.');
        }

        // Trailing commas
        if (/,(\s*[}\]])/.test(rawText)) {
            hints.push('Remove any trailing comma before } or ]. JSON does not allow trailing commas.');
        }

        // Comments
        if (/\/\/|\/\*/.test(rawText)) {
            hints.push('JSON does not allow comments (// or /* */). Remove all comments before parsing.');
        }

        // Not starting like JSON at all
        if (!/^\s*[{[\"]/ .test(rawText)) {
            hints.push('The payload should start with { for an object or [ for an array. Example: {"test": "test"}.');
        }

        let html = `<strong>Error parsing JSON:</strong> ${window.escapeHtml(error.message)}`;

        if (hints.length) {
            html += '<ul class="mt-2 mb-0">';
            hints.forEach(h => {
                html += `<li>${window.escapeHtml(h)}</li>`;
            });
            html += '</ul>';
        }

        return html;
    }

    function parseJsonWithHelpfulErrors(rawText) {
        const normalized = normalizeJsonInput(rawText.trim());

        try {
            const value = JSON.parse(normalized);

            let warning = null;
            // JWT payloads are typically JSON objects; warn if not
            if (value === null || typeof value !== 'object' || Array.isArray(value)) {
                warning = 'The payload is valid JSON, but it is not a JSON object. JWT payloads are typically objects like {"sub": "123", "name": "Alice"}.';
            }

            return {
                ok: true,
                value,
                normalized,
                warning
            };
        } catch (err) {
            return {
                ok: false,
                error: err,
                normalized
            };
        }
    }

        function init() {
        // lifetime presets for iat/exp
        window.jwtApplyLifetimePreset = function(preset) {
            const payloadEl = document.getElementById('jwtPayload');
            const resultsDiv = document.getElementById('jwtGenerateResults');
            const raw = payloadEl.value;

            const parsed = parseJsonWithHelpfulErrors(raw || '{}');
            if (!parsed.ok) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-danger">
                        ${buildJsonErrorHelpHtml(raw || '{}', parsed.error)}
                    </div>
                `;
                return;
            }

            const payload = parsed.value && typeof parsed.value === 'object' ? parsed.value : {};

            const now = Math.floor(Date.now() / 1000);
            let delta = 3600; // 1h default

            if (preset === 'short') delta = 3600;        // 1h
            else if (preset === 'day') delta = 86400;    // 1 day
            else if (preset === 'long') delta = 30 * 86400; // 30 days

            payload.iat = now;
            payload.exp = now + delta;

            payloadEl.value = JSON.stringify(payload, null, 2);
            resultsDiv.innerHTML = `
                <div class="alert alert-info mb-2">
                    <strong>Lifetime preset applied.</strong>
                    <div class="small">iat set to now, exp set to now + ${Math.round(delta / 3600)}h.</div>
                </div>
            `;
        };

        // secret strength live update
        const secretInput = document.getElementById('jwtSecret');
        if (secretInput) {
            secretInput.addEventListener('input', () => {
                const infoEl = document.getElementById('jwtSecretStrength');
                if (!infoEl) return;
                const { score, label, detail } = estimateSecretStrength(secretInput.value || '');
                infoEl.innerHTML = `Secret strength: <strong>${window.escapeHtml(label)}</strong><br><span class="small">${window.escapeHtml(detail)}</span>`;
            });
        }

        window.generateJwt = async function() {
            const algorithm = document.getElementById('jwtAlgorithm').value;
            const payloadText = document.getElementById('jwtPayload').value.trim();
            const secret = document.getElementById('jwtSecret').value;
            const resultsDiv = document.getElementById('jwtGenerateResults');
            
            if (!payloadText) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter a payload</div>';
                return;
            }

            const parsed = parseJsonWithHelpfulErrors(payloadText);
            if (!parsed.ok) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-danger">
                        ${buildJsonErrorHelpHtml(payloadText, parsed.error)}
                    </div>
                `;
                return;
            }

            const payload = parsed.value;

            try {
                const header = { alg: algorithm, typ: 'JWT' };
                
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

                const warningHtml = parsed.warning
                    ? `<p class="mb-0 mt-2 small text-warning">${window.escapeHtml(parsed.warning)}</p>`
                    : '';

                resultsDiv.innerHTML = `
                    <div class="alert alert-success">
                        <h6 class="alert-heading"><i class="bi bi-check-circle-fill"></i> JWT Generated Successfully</h6>
                        <div class="code-block mt-2 mb-2">${window.escapeHtml(jwt)}</div>
                        <button class="btn btn-sm btn-outline-primary" onclick="copyToClipboard('${jwt.replace(/'/g, "\\'")}', this)">
                            <i class="bi bi-clipboard"></i> Copy to Clipboard
                        </button>
                        ${warningHtml}
                    </div>
                `;
            } catch (error) {
                resultsDiv.innerHTML = `<div class="alert alert-danger"><strong>Error:</strong> ${window.escapeHtml(error.message)}</div>`;
            }
        };

        window.decodeJwt = async function() {
            let jwt = document.getElementById('jwtInput').value.trim();
            const resultsDiv = document.getElementById('jwtDecodeResults');
            const verifyResultEl = document.getElementById('jwtVerifyResult');
            const stripBearer = document.getElementById('jwtStripBearer')?.checked;

            if (!jwt) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter a JWT token</div>';
                if (verifyResultEl) verifyResultEl.textContent = 'Not checked yet';
                return;
            }

            if (stripBearer && /^Bearer\s+/i.test(jwt)) {
                jwt = jwt.replace(/^Bearer\s+/i, '').trim();
            }

            try {
                const parts = jwt.split('.');
                if (parts.length !== 3) {
                    throw new Error('Invalid JWT format. Expected 3 parts separated by dots.');
                }

                const [headerB64, payloadB64, signature] = parts;
                const header = JSON.parse(base64UrlDecode(headerB64));
                const payload = JSON.parse(base64UrlDecode(payloadB64));

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
                const now = new Date();

                if (header.alg && header.alg.toLowerCase() === 'none') {
                    securityIssues.push({
                        severity: 'danger',
                        icon: 'exclamation-triangle-fill',
                        title: 'CRITICAL: Unsigned Token',
                        desc: 'Algorithm is "none" - token has no signature and can be forged by anyone.'
                    });
                }

                if (payload.exp) {
                    const expDate = new Date(payload.exp * 1000);
                    const isExpired = expDate < now;
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
                        desc: 'Token does not expire - potential security risk for long-lived tokens.'
                    });
                }

                if (payload.nbf) {
                    const nbfDate = new Date(payload.nbf * 1000);
                    const notYet = nbfDate > now;
                    securityIssues.push({
                        severity: notYet ? 'warning' : 'info',
                        icon: 'hourglass-split',
                        title: 'Not Before (nbf)',
                        desc: `${notYet ? 'Not valid until: ' : 'Became valid at: '}${nbfDate.toLocaleString()}`
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

                const sensitiveHints = analyzeSensitiveClaims(payload);
                sensitiveHints.forEach(msg => {
                    securityIssues.push({
                        severity: 'warning',
                        icon: 'shield-exclamation',
                        title: 'High-Privilege Claim Detected',
                        desc: msg
                    });
                });

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

                // Validity summary
                let validitySummary = 'No explicit exp/nbf claims – treat carefully for long-lived sessions.';
                if (payload.exp) {
                    const expDate = new Date(payload.exp * 1000);
                    if (expDate < now) {
                        validitySummary = 'Token is currently expired.';
                    } else if (payload.nbf && new Date(payload.nbf * 1000) > now) {
                        validitySummary = 'Token is not yet valid (nbf in the future).';
                    } else {
                        validitySummary = 'Token is currently within its valid time window based on nbf/exp.';
                    }
                }

                html += `
                    <div class="col-12">
                        <div class="alert alert-secondary mb-2">
                            <strong><i class="bi bi-calendar-check"></i> Time Validity Summary</strong>
                            <p class="mb-0 small">${window.escapeHtml(validitySummary)}</p>
                        </div>
                    </div>
                `;

                html += '</div>';
                resultsDiv.innerHTML = html;

                // Signature verification (optional)
                if (verifyResultEl) {
                    const secret = document.getElementById('jwtVerifySecret')?.value;
                    if (secret) {
                        try {
                            const verifyResult = await verifyHmacSignature(header.alg, secret, headerB64, payloadB64, signature);
                            if (verifyResult.status === 'ok') {
                                verifyResultEl.innerHTML = '<span class="text-success"><i class="bi bi-check-circle-fill"></i> Signature is VALID for this secret.</span>';
                            } else if (verifyResult.status === 'mismatch') {
                                verifyResultEl.innerHTML = '<span class="text-danger"><i class="bi bi-x-circle-fill"></i> Signature does NOT match this secret.</span>';
                            } else if (verifyResult.status === 'unsupported') {
                                verifyResultEl.innerHTML = `<span class="text-muted"><i class="bi bi-info-circle"></i> ${window.escapeHtml(verifyResult.message)}</span>`;
                            } else {
                                verifyResultEl.innerHTML = '<span class="text-muted">No secret provided.</span>';
                            }
                        } catch (e) {
                            verifyResultEl.innerHTML = `<span class="text-danger"><i class="bi bi-exclamation-triangle-fill"></i> Error verifying signature: ${window.escapeHtml(e.message)}</span>`;
                        }
                    } else {
                        verifyResultEl.textContent = 'No secret provided.';
                    }
                }
            } catch (error) {
                resultsDiv.innerHTML = `<div class="alert alert-danger"><strong>Decoding Error:</strong> ${window.escapeHtml(error.message)}</div>`;
                if (verifyResultEl) verifyResultEl.textContent = 'Verification skipped due to decode error.';
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