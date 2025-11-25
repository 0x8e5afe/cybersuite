// ========================================
// PASSWORD CRACKING COMPLEXITY ANALYZER
// Category: Purple Team
// ========================================

(function() {
    'use strict';

    function render() {
        return `

             <div class="section-header">
                <h3 class="mb-1 d-flex align-items-center gap-2">
                    <i class="bi bi-speedometer2"></i>
                    <span>Password Cracking Complexity Analyzer</span>
                </h3>
                <p class="text-secondary mb-0">
                  Calculate the time required to crack passwords based on character set and length.
                </p>
            </div>
            
            <div class="row g-3">
                <div class="col-md-6">
                    <label for="crackPasswordLength" class="form-label">Password Length</label>
                    <input type="number" class="form-control" id="crackPasswordLength" value="8" min="1" max="128">
                </div>
                
                <div class="col-md-6">
                    <label for="crackAttemptsPerSec" class="form-label">Hashes per Second</label>
                    <select class="form-select" id="crackAttemptsPerSec">
                        <option value="1000000">1 Million (Basic GPU)</option>
                        <option value="10000000">10 Million (Good GPU)</option>
                        <option value="100000000" selected>100 Million (High-end GPU)</option>
                        <option value="1000000000">1 Billion (GPU Cluster)</option>
                        <option value="10000000000">10 Billion (Advanced Cluster)</option>
                        <option value="custom">Custom...</option>
                    </select>
                    <input type="number" class="form-control mt-2 d-none" id="crackAttemptsCustom" placeholder="Enter custom value">
                </div>
            </div>
            
            <div class="row g-3 mt-2">
                <div class="col-12">
                    <label class="form-label">Character Set</label>
                </div>
                <div class="col-md-6 col-lg-3">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="crackLower" checked>
                        <label class="form-check-label" for="crackLower">
                            Lowercase (26 chars)
                        </label>
                    </div>
                </div>
                
                <div class="col-md-6 col-lg-3">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="crackUpper" checked>
                        <label class="form-check-label" for="crackUpper">
                            Uppercase (26 chars)
                        </label>
                    </div>
                </div>
                
                <div class="col-md-6 col-lg-3">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="crackDigits" checked>
                        <label class="form-check-label" for="crackDigits">
                            Digits (10 chars)
                        </label>
                    </div>
                </div>
                
                <div class="col-md-6 col-lg-3">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="crackSpecial">
                        <label class="form-check-label" for="crackSpecial">
                            Special (32 chars)
                        </label>
                    </div>
                </div>
            </div>
            
            <div class="row g-3 mt-2">
                <div class="col-md-6">
                    <label for="crackCustomCharset" class="form-label">Or Enter Custom Character Set Size</label>
                    <input type="number" class="form-control" id="crackCustomCharset" placeholder="e.g., 95 for full ASCII">
                </div>
            </div>

            <div class="row g-3 mt-4">
                <div class="col-12">
                    <label for="crackPasswordList" class="form-label">Password List (one per line, optional)</label>
                    <textarea class="form-control font-monospace" id="crackPasswordList" rows="4" placeholder="correcthorsebatterystaple&#10;Tr0ub4dor&3"></textarea>
                    <small class="text-secondary">
                        When this tool starts a pipeline, the values from this box are used as input.
                    </small>
                </div>
            </div>
            
            <div class="mt-3">
                <button class="btn btn-primary" id="crackCalcBtn" onclick="calculateCrackTime()">
                    <i class="bi bi-calculator"></i> Calculate Complexity
                </button>
            </div>
            
            <div id="crackResults" class="mt-3"></div>
        `;
    }

function init() {
    // Show/hide custom attempts input
    document.getElementById('crackAttemptsPerSec').addEventListener('change', function() {
        const customInput = document.getElementById('crackAttemptsCustom');
        if (this.value === 'custom') {
            customInput.classList.remove('d-none');
        } else {
            customInput.classList.add('d-none');
        }
    });

    // --- Auto-recalculation support ---
    let autoRecalculateEnabled = false;

    function attachAutoRecalc() {
        const ids = [
            'crackPasswordLength',
            'crackAttemptsPerSec',
            'crackAttemptsCustom',
            'crackLower',
            'crackUpper',
            'crackDigits',
            'crackSpecial',
            'crackCustomCharset'
        ];

        ids.forEach(id => {
            const el = document.getElementById(id);
            if (!el) return;

            const eventName =
                el.tagName === 'INPUT' && (el.type === 'number' || el.type === 'text')
                    ? 'input'
                    : 'change';

            el.addEventListener(eventName, () => {
                if (autoRecalculateEnabled) {
                    window.calculateCrackTime();
                }
            });
        });
    }

    attachAutoRecalc();

    // --- Main calculation function (styled + tooltip + GPU table + auto-recalc) ---
    window.calculateCrackTime = function() {
        const length = parseInt(document.getElementById('crackPasswordLength').value);
        const attemptsSelect = document.getElementById('crackAttemptsPerSec').value;
        let attemptsPerSec;

        if (attemptsSelect === 'custom') {
            attemptsPerSec = parseInt(document.getElementById('crackAttemptsCustom').value);
            if (!attemptsPerSec || attemptsPerSec <= 0) {
                document.getElementById('crackResults').innerHTML =
                    '<div class="alert alert-warning">Please enter a valid custom value for hashes per second</div>';
                return;
            }
        } else {
            attemptsPerSec = parseInt(attemptsSelect);
        }

        const resultsDiv = document.getElementById('crackResults');

        if (!length || length <= 0) {
            resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter a valid password length</div>';
            return;
        }

        // Calculate character set size
        let charsetSize = 0;
        const customCharset = document.getElementById('crackCustomCharset').value;

        if (customCharset) {
            charsetSize = parseInt(customCharset);
        } else {
            if (document.getElementById('crackLower').checked) charsetSize += 26;
            if (document.getElementById('crackUpper').checked) charsetSize += 26;
            if (document.getElementById('crackDigits').checked) charsetSize += 10;
            if (document.getElementById('crackSpecial').checked) charsetSize += 32;
        }

        if (!charsetSize || charsetSize <= 0) {
            resultsDiv.innerHTML =
                '<div class="alert alert-warning">Please select at least one character set or enter a custom size</div>';
            return;
        }

        // Calculate total combinations
        const totalCombinations = Math.pow(charsetSize, length);

        // Calculate time for exhaustive search
        const secondsToExhaust = totalCombinations / attemptsPerSec;
        const secondsToAverage = secondsToExhaust / 2; // Average case

        // Format time
        const formatTime = (seconds) => {
            if (seconds < 60) {
                return `${seconds.toFixed(2)} seconds`;
            } else if (seconds < 3600) {
                return `${(seconds / 60).toFixed(2)} minutes`;
            } else if (seconds < 86400) {
                return `${(seconds / 3600).toFixed(2)} hours`;
            } else if (seconds < 31536000) {
                return `${(seconds / 86400).toFixed(2)} days`;
            } else if (seconds < 31536000000) {
                return `${(seconds / 31536000).toFixed(2)} years`;
            } else if (seconds < 31536000000000) {
                return `${(seconds / 31536000000).toFixed(2)} thousand years`;
            } else if (seconds < 31536000000000000) {
                return `${(seconds / 31536000000000).toFixed(2)} million years`;
            } else {
                return `${(seconds / 31536000000000000).toFixed(2)} billion years`;
            }
        };

        // Determine strength and map to global severity colors
        let strength, headerClass, borderClass, strengthBadgeText;

        if (secondsToAverage < 60) {
            strength = 'Very Weak';
            headerClass = 'bg-danger';
            borderClass = 'border-danger';
            strengthBadgeText = 'DANGER';
        } else if (secondsToAverage < 3600) {
            strength = 'Weak';
            headerClass = 'bg-warning';
            borderClass = 'border-warning';
            strengthBadgeText = 'WARNING';
        } else if (secondsToAverage < 86400) {
            strength = 'Fair';
            headerClass = 'bg-info';
            borderClass = 'border-info';
            strengthBadgeText = 'INFO';
        } else if (secondsToAverage < 31536000) {
            strength = 'Good';
            headerClass = 'bg-success';
            borderClass = 'border-success';
            strengthBadgeText = 'GOOD';
        } else {
            strength = 'Strong';
            headerClass = 'bg-success';
            borderClass = 'border-success';
            strengthBadgeText = 'STRONG';
        }

        // Calculate entropy
        const entropy = Math.log2(totalCombinations);

        // Helper to rescale times for different hardware:
        // time_new = time_base * (speed_base / speed_new)
        const scaleTime = (baseSeconds, baseSpeed, newSpeed) => {
            return baseSeconds * (baseSpeed / newSpeed);
        };

        // Approximate NTLM/fast-hash cracking speeds from public benchmarks
        const cpuSpeed       = 1e9;      // ~1    GH/s  (high-end CPU)
        const gtx1070Speed   = 3e10;     // ~30   GH/s  (GTX 1070)
        const rtx4070tiSpeed = 1.4e11;   // ~140  GH/s  (RTX 4070 Ti)
        const rig8x4090Speed = 2e12;     // ~2    TH/s  (8× RTX 4090)

        resultsDiv.innerHTML = `
            <div class="card ${borderClass}">
                <div class="card-header ${headerClass} d-flex justify-content-between align-items-center">
                    <div>
                        <i class="bi bi-shield-lock"></i>
                        Password Strength: ${strength}
                        <span class="badge ${headerClass.replace('bg', 'bg')} ms-2">${strengthBadgeText}</span>
                    </div>
                    <div>
                        <i class="bi bi-info-circle hint-icon"
                           data-bs-toggle="tooltip"
                           data-bs-placement="left"
                           title="Average: ~50% of keyspace searched. Worst: full keyspace. Entropy: randomness in bits (80+ is strong). Assumes pure brute-force only."></i>
                    </div>
                </div>
                <div class="card-body">
                    <div class="row g-3">
  <div class="row g-3">
    <div class="col-md-6">
        <div class="d-flex align-items-center mb-2">
            <span class="badge bg-secondary">
                <i class="bi bi-sliders me-1"></i> Configuration
            </span>
        </div>
        <ul class="list-unstyled mb-0">
            <li><strong>Password Length:</strong> ${length} characters</li>
            <li><strong>Character Set Size:</strong> ${charsetSize}</li>
            <li><strong>Hashing Speed:</strong> ${attemptsPerSec.toLocaleString()} hashes/sec</li>
            <li><strong>Entropy:</strong> ${entropy.toFixed(2)} bits</li>
        </ul>
    </div>

    <div class="col-md-6">
        <div class="d-flex align-items-center mb-2">
            <span class="badge bg-secondary">
                <i class="bi bi-speedometer2 me-1"></i> Cracking Time Estimates
            </span>
        </div>
        <ul class="list-unstyled mb-0">
            <li><strong>Total Combinations:</strong> ${totalCombinations.toExponential(2)}</li>
            <li><strong>Average Case:</strong> <span class="text-info">${formatTime(secondsToAverage)}</span></li>
            <li><strong>Worst Case:</strong> ${formatTime(secondsToExhaust)}</li>
        </ul>
    </div>
</div>
                    </div>
                </div>
            </div>

            <div class="mt-3">
                <h6>Comparison with Realistic Attack Speeds</h6>
                <div class="table-responsive">
                    <table class="table table-dark table-striped table-sm">
                        <thead>
                            <tr>
                                <th>Example Hardware</th>
                                <th>Approx. Hashes/Second</th>
                                <th>Average Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>High-end CPU only (Intel i7 / Ryzen 7)</td>
                                <td>${cpuSpeed.toLocaleString()} (~1 GH/s)</td>
                                <td>${formatTime(scaleTime(secondsToAverage, attemptsPerSec, cpuSpeed))}</td>
                            </tr>
                            <tr>
                                <td>Single older GPU (NVIDIA GTX 1070)</td>
                                <td>${gtx1070Speed.toLocaleString()} (~30 GH/s)</td>
                                <td>${formatTime(scaleTime(secondsToAverage, attemptsPerSec, gtx1070Speed))}</td>
                            </tr>
                            <tr>
                                <td>Modern GPU (NVIDIA RTX 4070 Ti)</td>
                                <td>${rtx4070tiSpeed.toLocaleString()} (~140 GH/s)</td>
                                <td>${formatTime(scaleTime(secondsToAverage, attemptsPerSec, rtx4070tiSpeed))}</td>
                            </tr>
                            <tr>
                                <td>GPU Cluster (8× NVIDIA RTX 4090)</td>
                                <td>${rig8x4090Speed.toLocaleString()} (~2 TH/s)</td>
                                <td>${formatTime(scaleTime(secondsToAverage, attemptsPerSec, rig8x4090Speed))}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                <p class="text-muted small mt-2 mb-0">
                    Speeds are approximate NTLM benchmarks; real-world performance varies by hash type, configuration and workload.
                </p>
            </div>
        `;

        // Enable auto-recalculate from now on
        autoRecalculateEnabled = true;

        // Re-initialize Bootstrap tooltips for dynamically injected content
        if (window.bootstrap && bootstrap.Tooltip) {
            const tooltipTriggerList = [].slice.call(
                resultsDiv.querySelectorAll('[data-bs-toggle="tooltip"]')
            );
            tooltipTriggerList.forEach(el => new bootstrap.Tooltip(el));
        }
    };
}

function initPipeline(context) {
    init();
    // Hide manual trigger/output when embedded in pipeline
    const btn = document.getElementById('crackCalcBtn');
    if (btn) btn.style.display = 'none';
    const resultsDiv = document.getElementById('crackResults');
    if (resultsDiv) resultsDiv.style.display = 'none';
}

    // Build HTML representation for pipeline results (per-password metrics)
    function buildPasswordCrackerResultsHtml(results, attemptsPerSec) {
        if (!Array.isArray(results) || results.length === 0) {
            return `
                <div class="alert alert-warning mb-0">
                    No passwords to analyze.
                </div>
            `;
        }

        // If there is only one password, show a compact summary instead of a table
        if (results.length === 1) {
            const row = results[0];
            const strengthBadge = row.strength || 'n/a';
            const badgeClass =
                strengthBadge === 'Very Weak' ? 'danger' :
                strengthBadge === 'Weak' ? 'warning' :
                strengthBadge === 'Fair' ? 'info' :
                'success';

            return `
                <div class="alert alert-${badgeClass} mb-3">
                    <div class="d-flex align-items-center gap-2">
                        <i class="bi bi-shield-lock"></i>
                        <strong>${window.escapeHtml(row.password)}</strong>
                        <span class="badge bg-${badgeClass}">${strengthBadge}</span>
                        <span class="badge bg-secondary">${attemptsPerSec.toLocaleString()} hashes/sec</span>
                    </div>
                    <div class="small mt-2">
                        <div><strong>Length:</strong> ${row.length}</div>
                        <div><strong>Charset size:</strong> ${row.charsetSize}</div>
                        <div><strong>Entropy:</strong> ${row.entropyBits.toFixed ? row.entropyBits.toFixed(2) : row.entropyBits} bits</div>
                        <div><strong>Average time:</strong> ${row.formattedAverage}</div>
                        <div><strong>Worst case:</strong> ${row.formattedWorst}</div>
                    </div>
                </div>
            `;
        }

        let html = `
            <div class="card bg-dark border-secondary">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span>
                        <i class="bi bi-speedometer2"></i>
                        Password Cracking Complexity (Pipeline)
                    </span>
                    <span class="badge bg-secondary">
                        ${attemptsPerSec.toLocaleString()} hashes/sec
                    </span>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-dark table-striped table-sm mb-0">
                            <thead>
                                <tr>
                                    <th>Password</th>
                                    <th>Length</th>
                                    <th>Charset Size</th>
                                    <th>Entropy (bits)</th>
                                    <th>Average Time</th>
                                    <th>Worst Time</th>
                                    <th>Strength</th>
                                </tr>
                            </thead>
                            <tbody>
        `;

        results.forEach(row => {
            const pwd = typeof row.password === 'string' ? row.password : String(row.password);
            const length = row.length != null ? row.length : pwd.length;
            const charsetSize = row.charsetSize != null ? row.charsetSize : 0;
            const entropyBits = row.entropyBits != null ? row.entropyBits : 0;
            const avg = row.formattedAverage || '';
            const worst = row.formattedWorst || '';
            const strength = row.strength || 'n/a';

            html += `
                                <tr>
                                    <td class="font-monospace">${window.escapeHtml(pwd)}</td>
                                    <td>${length}</td>
                                    <td>${charsetSize}</td>
                                    <td>${entropyBits.toFixed ? entropyBits.toFixed(2) : entropyBits}</td>
                                    <td>${avg}</td>
                                    <td>${worst}</td>
                                    <td>${window.escapeHtml(strength)}</td>
                                </tr>
            `;
        });

        html += `
                            </tbody>
                        </table>
                    </div>
                    <p class="text-muted small mt-2 mb-0">
                        Estimates assume pure brute-force search at the indicated rate and do not account for smarter attacks or slower hash functions.
                    </p>
                </div>
            </div>
        `;

        return html;
    }

    // ========================================
    // PIPELINE INTEGRATION
    // ========================================
    async function passwordCrackerPipelineProcess(input, context = {}) {
        try {
            let passwords = [];
            let workingInput = input;

            const isEmptyValue = (val) => {
                if (val === null || val === undefined) return true;
                if (typeof val === 'string') return val.trim().length === 0;
                return false;
            };

            const getScopedElement = (id) => {
                if (context && typeof context.stepIndex === 'number') {
                    const root = document.getElementById(`pipelineToolBody-${context.stepIndex}`);
                    if (root) {
                        const scoped = root.querySelector(`#${id}`);
                        if (scoped) return scoped;
                    }
                }
                return document.getElementById(id);
            };

            const textarea = getScopedElement('crackPasswordList');
            const textareaValue = textarea ? textarea.value.trim() : '';

            if (context && context.isFirst && textareaValue) {
                workingInput = textareaValue;
            } else if (isEmptyValue(workingInput) && textareaValue) {
                workingInput = textareaValue;
            }

            const getNumberValue = (id, fallback) => {
                const el = getScopedElement(id);
                const val = el ? parseInt(el.value, 10) : NaN;
                return Number.isFinite(val) && val > 0 ? val : fallback;
            };

            const isChecked = (id, fallback = false) => {
                const el = getScopedElement(id);
                return el ? !!el.checked : fallback;
            };

            const buildSamplePasswords = () => {
                const length = getNumberValue('crackPasswordLength', 8);
                const includeLower = isChecked('crackLower', true);
                const includeUpper = isChecked('crackUpper', true);
                const includeDigits = isChecked('crackDigits', true);
                const includeSpecial = isChecked('crackSpecial', false);

                let pool = '';
                if (includeLower) pool += 'abcdefghijklmnopqrstuvwxyz';
                if (includeUpper) pool += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
                if (includeDigits) pool += '0123456789';
                if (includeSpecial) pool += '!@#$%^&*';
                if (!pool) {
                    pool = 'abc123';
                }

                const sample = [];
                for (let i = 0; i < length; i++) {
                    sample.push(pool.charAt(i % pool.length));
                }

                return [sample.join('')];
            };

            // Helper: normalize input into an array of strings
            const normalize = (val) => {
                if (!val) return [];

                if (Array.isArray(val)) {
                    return val.map(v => String(v));
                }

                if (typeof val === 'string') {
                    // Try to parse as JSON array first
                    try {
                        const parsed = JSON.parse(val);
                        if (Array.isArray(parsed)) {
                            return parsed.map(v => String(v));
                        }
                    } catch (e) {
                        // Not JSON; treat as newline-separated list
                    }
                    return val
                        .split(/\r?\n/)
                        .map(s => s.trim())
                        .filter(Boolean);
                }

                if (typeof val === 'object') {
                    if (Array.isArray(val.passwords)) {
                        return val.passwords.map(v => String(v));
                    }
                }

                return [];
            };

            passwords = normalize(workingInput);

            if (!passwords.length) {
                passwords = buildSamplePasswords();
            }

            // Put a hard limit to avoid huge computations
            if (passwords.length > 1000) {
                return {
                    success: false,
                    error: 'Too many passwords for pipeline mode (max 1000)'
                };
            }

            // Default cracking speed for pipeline mode (100M hashes/sec, same as UI default)
            const attemptsPerSec = 100000000;

            // Helper: format time using the same logic as the UI
            const formatTime = (seconds) => {
                if (seconds < 60) {
                    return `${seconds.toFixed(2)} seconds`;
                } else if (seconds < 3600) {
                    return `${(seconds / 60).toFixed(2)} minutes`;
                } else if (seconds < 86400) {
                    return `${(seconds / 3600).toFixed(2)} hours`;
                } else if (seconds < 31536000) {
                    return `${(seconds / 86400).toFixed(2)} days`;
                } else if (seconds < 31536000000) {
                    return `${(seconds / 31536000).toFixed(2)} years`;
                } else if (seconds < 31536000000000) {
                    return `${(seconds / 31536000000).toFixed(2)} thousand years`;
                } else if (seconds < 31536000000000000) {
                    return `${(seconds / 31536000000000).toFixed(2)} million years`;
                } else {
                    return `${(seconds / 31536000000000000).toFixed(2)} billion years`;
                }
            };

            const results = passwords.map(pw => {
                const password = String(pw);
                const length = password.length;

                if (length === 0) {
                    return {
                        password,
                        length: 0,
                        charsetSize: 0,
                        entropyBits: 0,
                        totalCombinations: 0,
                        averageSeconds: 0,
                        worstSeconds: 0,
                        formattedAverage: 'n/a',
                        formattedWorst: 'n/a',
                        strength: 'Invalid'
                    };
                }

                // Detect character classes used by this password
                const hasLower = /[a-z]/.test(password);
                const hasUpper = /[A-Z]/.test(password);
                const hasDigits = /[0-9]/.test(password);
                const hasSpecial = /[^A-Za-z0-9]/.test(password);

                let charsetSize = 0;
                if (hasLower) charsetSize += 26;
                if (hasUpper) charsetSize += 26;
                if (hasDigits) charsetSize += 10;
                if (hasSpecial) charsetSize += 32;

                if (!charsetSize) {
                    // Fallback, should not really happen because any character
                    // will match one of the above categories
                    charsetSize = 1;
                }

                // Use length * log2(charsetSize) for entropy to avoid overflow
                const entropyBits = length * Math.log2(charsetSize);

                // Combinations and cracking time (may be very large; JS can still represent up to 1e308)
                const totalCombinations = Math.pow(charsetSize, length);
                const secondsToExhaust = totalCombinations / attemptsPerSec;
                const secondsToAverage = secondsToExhaust / 2;

                // Determine strength as in the UI (based on average time)
                let strength;
                if (secondsToAverage < 60) {
                    strength = 'Very Weak';
                } else if (secondsToAverage < 3600) {
                    strength = 'Weak';
                } else if (secondsToAverage < 86400) {
                    strength = 'Fair';
                } else if (secondsToAverage < 31536000) {
                    strength = 'Good';
                } else {
                    strength = 'Strong';
                }

                return {
                    password,
                    length,
                    charsetSize,
                    entropyBits,
                    totalCombinations,
                    attemptsPerSec,
                    averageSeconds: secondsToAverage,
                    worstSeconds: secondsToExhaust,
                    formattedAverage: formatTime(secondsToAverage),
                    formattedWorst: formatTime(secondsToExhaust),
                    strength
                };
            });

            const html = buildPasswordCrackerResultsHtml(results, attemptsPerSec);
            return {
                success: true,
                output: results,
                metadata: {
                    source: 'password-cracker',
                    count: results.length,
                    attemptsPerSec,
                    html
                }
            };
        } catch (e) {
            return {
                success: false,
                error: 'Password cracker pipeline error: ' + e.message
            };
        }
    }

    function buildPolicyPipelineHtml(result) {
        const badgeClass =
            result.strength === 'Very Weak' ? 'danger' :
            result.strength === 'Weak' ? 'warning' :
            result.strength === 'Fair' ? 'info' :
            'success';

        return `
            <div class="card bg-dark border-${badgeClass}">
                <div class="card-header bg-${badgeClass} d-flex justify-content-between align-items-center">
                    <span><i class="bi bi-file-earmark-lock"></i> Policy Complexity</span>
                    <span class="badge bg-dark text-light">${window.escapeHtml(result.strength)}</span>
                </div>
                <div class="card-body">
                    <div class="row g-3">
                        <div class="col-md-6">
                            <h6 class="text-secondary text-uppercase small mb-2">Lengths</h6>
                            <ul class="list-unstyled mb-0 small">
                                <li><strong>Min length:</strong> ${result.minLength}</li>
                                <li><strong>Max length:</strong> ${result.maxLength}</li>
                                <li><strong>Charset size:</strong> ${result.charsetSize}</li>
                            </ul>
                        </div>
                        <div class="col-md-6">
                            <h6 class="text-secondary text-uppercase small mb-2">Entropy</h6>
                            <ul class="list-unstyled mb-0 small">
                                <li><strong>Min entropy:</strong> ${result.entropyMin.toFixed(2)} bits</li>
                                <li><strong>Max entropy:</strong> ${result.entropyMax.toFixed(2)} bits</li>
                                <li><strong>Hashes/sec:</strong> ${result.attemptsPerSec.toLocaleString()}</li>
                            </ul>
                        </div>
                    </div>
                    <hr class="text-secondary" />
                    <div class="row g-3 small">
                        <div class="col-md-6">
                            <div class="alert alert-info mb-0">
                                <strong>Average time @ min length:</strong><br>${result.formattedAverageMin}<br>
                                <small class="text-secondary">Worst case: ${result.formattedWorstMin}</small>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="alert alert-info mb-0">
                                <strong>Average time @ max length:</strong><br>${result.formattedAverageMax}<br>
                                <small class="text-secondary">Worst case: ${result.formattedWorstMax}</small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    function renderPolicyPipelineForm({ stepIndex }) {
        const suffix = typeof stepIndex === 'number' ? stepIndex : 'policy';
        const textareaId = `policyPipelineInput-${suffix}`;
        const sampleBtnId = `policyPipelineLoadSample-${suffix}`;

        const samplePolicy = {
            minLength: 12,
            maxLength: 16,
            requireLower: true,
            requireUpper: true,
            requireDigits: true,
            requireSpecial: true,
            specialCharacters: "!@#$%^&*",
            hashesPerSecond: 100000000
        };

        return `
            <div class="card bg-dark pipeline-input-card">
                <div class="card-header d-flex align-items-center gap-2">
                    <i class="bi bi-clipboard-data"></i>
                    <span>Password policy JSON</span>
                </div>
                <div class="card-body">
                    <textarea class="form-control font-monospace" id="${textareaId}" rows="6" placeholder='${window.escapeHtml(JSON.stringify(samplePolicy, null, 2))}'></textarea>
                    <div class="d-flex justify-content-between align-items-center mt-2">
                        <small class="text-secondary">Fields: minLength, maxLength, requireLower/Upper/Digits/Special, specialCharacters, hashesPerSecond.</small>
                        <button class="btn btn-sm btn-outline-info" type="button" id="${sampleBtnId}">
                            <i class="bi bi-magic"></i> Sample
                        </button>
                    </div>
                </div>
            </div>
        `;
    }

    function initPolicyPipelineForm(context = {}) {
        const suffix = typeof context.index === 'number' ? context.index : 'policy';
        const sampleBtn = document.getElementById(`policyPipelineLoadSample-${suffix}`);
        const textarea = document.getElementById(`policyPipelineInput-${suffix}`);
        if (sampleBtn && textarea) {
            sampleBtn.addEventListener('click', () => {
                const samplePolicy = {
                    minLength: 12,
                    maxLength: 16,
                    requireLower: true,
                    requireUpper: true,
                    requireDigits: true,
                    requireSpecial: true,
                    specialCharacters: "!@#$%^&*",
                    hashesPerSecond: 100000000
                };
                textarea.value = JSON.stringify(samplePolicy, null, 2);
            });
        }
    }

    function renderSmartComplexityPipelineForm({ stepIndex }) {
        const suffix = typeof stepIndex === 'number' ? stepIndex : 'smart';
        const pwdId = `smartPasswordList-${suffix}`;
        const pwdSampleId = `smartPasswordSample-${suffix}`;
        const policyId = `smartPolicyInput-${suffix}`;
        const policySampleId = `smartPolicySample-${suffix}`;

        return `
            <div class="card bg-dark pipeline-input-card mb-3">
                <div class="card-header d-flex align-items-center gap-2">
                    <i class="bi bi-key"></i>
                    <span>Password list (optional)</span>
                    <button class="btn btn-sm btn-warning ms-auto" type="button" id="${pwdSampleId}">
                        <i class="bi bi-magic"></i> Sample
                    </button>
                </div>
                <div class="card-body">
                    <textarea class="form-control font-monospace" id="${pwdId}" rows="4" placeholder="hunter2&#10;Tr0ub4dor&3"></textarea>
                    <small class="text-secondary d-block mt-2">Provide newline-separated passwords to analyze.</small>
                </div>
            </div>
            <div class="card bg-dark pipeline-input-card">
                <div class="card-header d-flex align-items-center gap-2">
                    <i class="bi bi-clipboard-data"></i>
                    <span>Password policy or {"passwords":[...]}</span>
                    <button class="btn btn-sm btn-warning ms-auto" type="button" id="${policySampleId}">
                        <i class="bi bi-magic"></i> Sample
                    </button>
                </div>
                <div class="card-body">
                    <div class="row g-2">
                        <div class="col-6">
                            <label class="form-label small">Min length</label>
                            <input type="number" class="form-control" id="smartPolicyMin-${suffix}" min="1" placeholder="12">
                        </div>
                        <div class="col-6">
                            <label class="form-label small">Max length</label>
                            <input type="number" class="form-control" id="smartPolicyMax-${suffix}" min="1" placeholder="16">
                        </div>
                        <div class="col-6">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="smartPolicyLower-${suffix}" checked>
                                <label class="form-check-label small" for="smartPolicyLower-${suffix}">Require lowercase</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="smartPolicyUpper-${suffix}" checked>
                                <label class="form-check-label small" for="smartPolicyUpper-${suffix}">Require uppercase</label>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="smartPolicyDigits-${suffix}" checked>
                                <label class="form-check-label small" for="smartPolicyDigits-${suffix}">Require digits</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="smartPolicySpecial-${suffix}" checked>
                                <label class="form-check-label small" for="smartPolicySpecial-${suffix}">Require special</label>
                            </div>
                        </div>
                        <div class="col-12">
                            <label class="form-label small">Special characters</label>
                            <input type="text" class="form-control" id="smartPolicySpecialChars-${suffix}" placeholder="!@#$%^&*">
                        </div>
                        <div class="col-12">
                            <label class="form-label small">Hashes per second (approx)</label>
                            <input type="number" class="form-control" id="smartPolicyHps-${suffix}" placeholder="100000000">
                        </div>
                    </div>
                    <small class="text-secondary d-block mt-2">Fill fields for a policy or provide passwords above; JSON {"passwords":[...]} from upstream is also accepted.</small>
                </div>
            </div>
        `;
    }

    function initSmartComplexityPipelineForm({ index }) {
        const suffix = typeof index === 'number' ? index : 'smart';
        const pwdId = `smartPasswordList-${suffix}`;
        const pwdSampleId = `smartPasswordSample-${suffix}`;
        const policySampleId = `smartPolicySample-${suffix}`;

        const pwdTextarea = document.getElementById(pwdId);
        const pwdSampleBtn = document.getElementById(pwdSampleId);
        const policySampleBtn = document.getElementById(policySampleId);

        if (pwdSampleBtn && pwdTextarea) {
            pwdSampleBtn.addEventListener('click', () => {
                pwdTextarea.value = 'hunter2\nTr0ub4dor&3\nCorrectHorseBatteryStaple!';
                pwdTextarea.focus();
            });
        }

        if (policySampleBtn) {
            policySampleBtn.addEventListener('click', () => {
                const setVal = (id, val) => {
                    const el = document.getElementById(id);
                    if (el) {
                        if (el.type === 'checkbox') {
                            el.checked = !!val;
                        } else {
                            el.value = val;
                        }
                    }
                };
                setVal(`smartPolicyMin-${suffix}`, 12);
                setVal(`smartPolicyMax-${suffix}`, 16);
                setVal(`smartPolicyLower-${suffix}`, true);
                setVal(`smartPolicyUpper-${suffix}`, true);
                setVal(`smartPolicyDigits-${suffix}`, true);
                setVal(`smartPolicySpecial-${suffix}`, true);
                setVal(`smartPolicySpecialChars-${suffix}`, '!@#$%^&*');
                setVal(`smartPolicyHps-${suffix}`, 100000000);
            });
        }
    }

    function passwordPolicyPipelineProcess(rawInput, context = {}) {
        const normalizePolicy = (input) => {
            if (typeof input === 'string' && input.trim() !== '') {
                return JSON.parse(input);
            }
            if (input && typeof input === 'object') {
                return input;
            }
            throw new Error('Password policy must be provided as JSON object or string');
        };

        try {
            const scopedTextarea = context && typeof context.stepIndex === 'number'
                ? document.querySelector(`#pipelineToolBody-${context.stepIndex} #policyPipelineInput-${context.stepIndex}`)
                : null;
            const hasScopedValue = scopedTextarea && scopedTextarea.value.trim();
            const workingInput = hasScopedValue ? scopedTextarea.value : rawInput;
            const policy = normalizePolicy(workingInput);

            const attemptsPerSec = Number(policy.hashesPerSecond) > 0 ? Number(policy.hashesPerSecond) : 100000000;
            const minLength = Number(policy.minLength || policy.length || 0);
            const maxLength = Number(policy.maxLength || policy.minLength || policy.length || 0) || minLength;

            if (!Number.isFinite(minLength) || minLength <= 0) {
                return { success: false, error: 'Policy requires a positive minLength' };
            }
            if (!Number.isFinite(maxLength) || maxLength < minLength) {
                return { success: false, error: 'Policy maxLength must be >= minLength' };
            }

            const requireLower = !!policy.requireLower;
            const requireUpper = !!policy.requireUpper;
            const requireDigits = !!policy.requireDigits;
            const requireSpecial = !!policy.requireSpecial;
            const customCharset = typeof policy.customCharset === 'string' ? policy.customCharset : '';
            const specialCharacters = typeof policy.specialCharacters === 'string' ? policy.specialCharacters : '';

            let charsetSize = 0;
            if (requireLower) charsetSize += 26;
            if (requireUpper) charsetSize += 26;
            if (requireDigits) charsetSize += 10;
            if (requireSpecial) charsetSize += Math.max(1, specialCharacters.length || 10);
            charsetSize += customCharset.length;

            if (!charsetSize) {
                return { success: false, error: 'Policy produced an empty charset; enable at least one requirement' };
            }

            const formatTime = (seconds) => {
                if (seconds < 60) {
                    return `${seconds.toFixed(2)} seconds`;
                } else if (seconds < 3600) {
                    return `${(seconds / 60).toFixed(2)} minutes`;
                } else if (seconds < 86400) {
                    return `${(seconds / 3600).toFixed(2)} hours`;
                } else if (seconds < 31536000) {
                    return `${(seconds / 86400).toFixed(2)} days`;
                } else if (seconds < 31536000000) {
                    return `${(seconds / 31536000).toFixed(2)} years`;
                } else if (seconds < 31536000000000) {
                    return `${(seconds / 31536000000).toFixed(2)} thousand years`;
                } else if (seconds < 31536000000000000) {
                    return `${(seconds / 31536000000000).toFixed(2)} million years`;
                } else {
                    return `${(seconds / 31536000000000000).toFixed(2)} billion years`;
                }
            };

            const entropyMin = minLength * Math.log2(charsetSize);
            const entropyMax = maxLength * Math.log2(charsetSize);

            const combinationsMin = Math.pow(charsetSize, minLength);
            const combinationsMax = Math.pow(charsetSize, maxLength);

            const worstMin = combinationsMin / attemptsPerSec;
            const avgMin = worstMin / 2;
            const worstMax = combinationsMax / attemptsPerSec;
            const avgMax = worstMax / 2;

            const classify = (secondsToAverage) => {
                if (secondsToAverage < 60) return 'Very Weak';
                if (secondsToAverage < 3600) return 'Weak';
                if (secondsToAverage < 86400) return 'Fair';
                if (secondsToAverage < 31536000) return 'Good';
                return 'Strong';
            };

            const result = {
                minLength,
                maxLength,
                charsetSize,
                attemptsPerSec,
                entropyMin,
                entropyMax,
                formattedAverageMin: formatTime(avgMin),
                formattedWorstMin: formatTime(worstMin),
                formattedAverageMax: formatTime(avgMax),
                formattedWorstMax: formatTime(worstMax),
                strength: classify(avgMin)
            };

            return {
                success: true,
                output: result,
                metadata: {
                    source: 'password-policy',
                    html: buildPolicyPipelineHtml(result)
                }
            };
        } catch (e) {
            return {
                success: false,
                error: 'Password policy pipeline error: ' + e.message
            };
        }
    }

    async function smartPasswordComplexityPipelineProcess(rawInput, context = {}) {
        const suffix = typeof context.stepIndex === 'number' ? context.stepIndex : 'smart';
        const getScoped = (id) => {
            if (context && typeof context.stepIndex === 'number') {
                const root = document.getElementById(`pipelineToolBody-${context.stepIndex}`);
                if (root) {
                    const scoped = root.querySelector(`#${id}`);
                    if (scoped) return scoped;
                }
            }
            return document.getElementById(id);
        };

        const pwdTextarea = getScoped(`smartPasswordList-${suffix}`);
        const pwdText = pwdTextarea ? pwdTextarea.value.trim() : '';

        const readPolicyForm = () => {
            const readNumber = (id) => {
                const el = getScoped(id);
                if (!el) return NaN;
                const v = parseInt(el.value, 10);
                return Number.isFinite(v) ? v : NaN;
            };
            const readBool = (id, def = false) => {
                const el = getScoped(id);
                return el ? !!el.checked : def;
            };
            const minLength = readNumber(`smartPolicyMin-${suffix}`);
            const maxLength = readNumber(`smartPolicyMax-${suffix}`);
            const specialCharsVal = getScoped(`smartPolicySpecialChars-${suffix}`)?.value?.trim();
            const hpsVal = getScoped(`smartPolicyHps-${suffix}`)?.value?.trim();
            const hasAnyField = !isNaN(minLength) || !isNaN(maxLength) || (specialCharsVal && specialCharsVal.length) || (hpsVal && hpsVal.length);

            if (!hasAnyField) return null;

            const policy = {};
            if (!isNaN(minLength)) policy.minLength = minLength;
            if (!isNaN(maxLength)) policy.maxLength = maxLength;
            policy.requireLower = readBool(`smartPolicyLower-${suffix}`, true);
            policy.requireUpper = readBool(`smartPolicyUpper-${suffix}`, true);
            policy.requireDigits = readBool(`smartPolicyDigits-${suffix}`, true);
            policy.requireSpecial = readBool(`smartPolicySpecial-${suffix}`, true);
            if (specialCharsVal) policy.specialCharacters = specialCharsVal;
            const hps = readNumber(`smartPolicyHps-${suffix}`);
            if (!isNaN(hps)) policy.hashesPerSecond = hps;

            return policy;
        };
        const policyFromForm = readPolicyForm();

        let workingInput = rawInput;

        if (context && context.isFirst) {
            if (policyFromForm) {
                workingInput = policyFromForm;
            } else if (pwdText) {
                workingInput = pwdText;
            }
        } else if (workingInput == null || (typeof workingInput === 'string' && workingInput.trim() === '')) {
            if (policyFromForm) {
                workingInput = policyFromForm;
            } else if (pwdText) {
                workingInput = pwdText;
            }
        }

        const tryParse = (val) => {
            if (typeof val !== 'string') return { ok: false };
            try {
                return { ok: true, value: JSON.parse(val) };
            } catch (e) {
                return { ok: false };
            }
        };

        // If string and JSON parseable, decide based on shape
        if (typeof workingInput === 'string') {
            const parsed = tryParse(workingInput);
            if (parsed.ok) {
                workingInput = parsed.value;
            }
        }

        // If we have an object or array, decide the path
        if (Array.isArray(workingInput)) {
            return passwordCrackerPipelineProcess(workingInput, context);
        }

        if (workingInput && typeof workingInput === 'object') {
            if (Array.isArray(workingInput.passwords)) {
                return passwordCrackerPipelineProcess(workingInput.passwords, context);
            }
            // Treat as policy-like object
            return passwordPolicyPipelineProcess(workingInput, context);
        }

        // Fallback: treat as text password list
        return passwordCrackerPipelineProcess(workingInput, context);
    }

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'password-cracker',
        name: 'Password Cracking Complexity',
        description: 'Calculate time required to crack passwords based on keyspace and attack speed',
        icon: 'bi-speedometer2',
        category: 'purple',
        render: render,
        init: init,
        initPipeline: initPipeline,
        // Unified smart pipeline block
        pipelineBlocks: [
            {
                id: 'smart',
                name: 'Password complexity',
                description: 'Analyze passwords or policies automatically',
                inputTypes: ['text', 'json'],
                outputType: 'json',
                processPipeline: smartPasswordComplexityPipelineProcess,
                renderPipelineOutput: function({ output, metadata }) {
                    if (metadata && typeof metadata.html === 'string') {
                        return metadata.html;
                    }
                    if (Array.isArray(output)) {
                        return buildPasswordCrackerResultsHtml(output || [], metadata && metadata.attemptsPerSec ? metadata.attemptsPerSec : 100000000);
                    }
                    if (output && typeof output === 'object' && output.passwords && Array.isArray(output.passwords)) {
                        return buildPasswordCrackerResultsHtml(output.passwords, metadata && metadata.attemptsPerSec ? metadata.attemptsPerSec : 100000000);
                    }
                    return '<pre class="mb-0"><code>' + window.escapeHtml(JSON.stringify(output, null, 2)) + '</code></pre>';
                },
                renderPipelineForm: renderSmartComplexityPipelineForm,
                initPipeline: initSmartComplexityPipelineForm,
                hint: 'Input: text -> passwords; JSON -> policy or {"passwords":[...]}. Outputs cracking complexity for passwords or policy.'
            }
        ]
    });
})();
