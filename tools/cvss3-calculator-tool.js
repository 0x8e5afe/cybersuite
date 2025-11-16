// ========================================
// CVSS v3.1 CALCULATOR - ENHANCED
// Category: Purple Team
// ========================================

(function() {
    'use strict';

    const cvssMetrics = {
        // Base Metrics
        AV: { 
            name: 'Attack Vector', 
            hint: 'How the vulnerability is exploited. Network means remotely exploitable, Adjacent requires local network access, Local requires local access, Physical requires physical access to the device.',
            values: {
                N: { label: 'Network', value: 0.85 },
                A: { label: 'Adjacent', value: 0.62 },
                L: { label: 'Local', value: 0.55 },
                P: { label: 'Physical', value: 0.2 }
            }
        },
        AC: { 
            name: 'Attack Complexity', 
            hint: 'How difficult is it to exploit the vulnerability. Low means no special conditions are required. High means special conditions must exist (e.g., race condition, complex configuration).',
            values: {
                L: { label: 'Low', value: 0.77 },
                H: { label: 'High', value: 0.44 }
            }
        },
        PR: { 
            name: 'Privileges Required', 
            hint: 'What level of privileges an attacker must have before exploiting the vulnerability. None means no authentication needed, Low means basic user privileges, High means admin/root privileges.',
            values: {
                N: { label: 'None', value: 0.85, scopeChanged: 0.85 },
                L: { label: 'Low', value: 0.62, scopeChanged: 0.68 },
                H: { label: 'High', value: 0.27, scopeChanged: 0.50 }
            }
        },
        UI: { 
            name: 'User Interaction', 
            hint: 'Does the vulnerability require a user to perform an action? None means no user interaction needed. Required means a user must take some action (e.g., click a link, open a file).',
            values: {
                N: { label: 'None', value: 0.85 },
                R: { label: 'Required', value: 0.62 }
            }
        },
        S: { 
            name: 'Scope', 
            hint: 'Can the vulnerability affect components beyond its security scope? Unchanged means impact is limited to the vulnerable component. Changed means impact can affect other components.',
            values: {
                U: { label: 'Unchanged', value: false },
                C: { label: 'Changed', value: true }
            }
        },
        C: { 
            name: 'Confidentiality Impact', 
            hint: 'How much information can be disclosed? None means no impact. Low means some information disclosure. High means total information disclosure.',
            values: {
                N: { label: 'None', value: 0 },
                L: { label: 'Low', value: 0.22 },
                H: { label: 'High', value: 0.56 }
            }
        },
        I: { 
            name: 'Integrity Impact', 
            hint: 'How much can the attacker modify data? None means no impact. Low means limited modification. High means complete modification of data.',
            values: {
                N: { label: 'None', value: 0 },
                L: { label: 'Low', value: 0.22 },
                H: { label: 'High', value: 0.56 }
            }
        },
        A: { 
            name: 'Availability Impact', 
            hint: 'How much is availability affected? None means no impact. Low means reduced performance. High means complete denial of service.',
            values: {
                N: { label: 'None', value: 0 },
                L: { label: 'Low', value: 0.22 },
                H: { label: 'High', value: 0.56 }
            }
        }
    };

    // Helper function to determine severity class based on score
    function getSeverityClass(score) {
        if (score === 0) {
            return { class: 'info', textClass: 'text-white' };
        } else if (score < 4.0) {
            return { class: 'success', textClass: 'text-white' };
        } else if (score < 7.0) {
            return { class: 'warning', textClass: 'text-white' };
        } else if (score < 9.0) {
            return { class: 'danger', textClass: 'text-white' };
        } else {
            return { class: 'dark-danger', textClass: 'text-white' };
        }
    }

    // Parse CVSS vector string
    function parseVector(vectorString) {
        const cleanVector = vectorString.trim();
        
        // Try full format first: CVSS:3.1/AV:N/AC:L/...
        let regex = /CVSS:3\.[01]\/AV:([NALP])\/AC:([LH])\/PR:([NLH])\/UI:([NR])\/S:([UC])\/C:([NLH])\/I:([NLH])\/A:([NLH])/;
        let match = cleanVector.match(regex);
        
        if (match) {
            return {
                AV: match[1],
                AC: match[2],
                PR: match[3],
                UI: match[4],
                S: match[5],
                C: match[6],
                I: match[7],
                A: match[8]
            };
        }
        
        // Try short format: AV:N/AC:L/...
        regex = /^AV:([NALP])\/AC:([LH])\/PR:([NLH])\/UI:([NR])\/S:([UC])\/C:([NLH])\/I:([NLH])\/A:([NLH])$/;
        match = cleanVector.match(regex);
        
        if (match) {
            return {
                AV: match[1],
                AC: match[2],
                PR: match[3],
                UI: match[4],
                S: match[5],
                C: match[6],
                I: match[7],
                A: match[8]
            };
        }
        
        return null;
    }

    // Apply parsed values to form
    function applyVectorToForm(values) {
        Object.entries(values).forEach(([key, value]) => {
            const radio = document.querySelector(`input[name="cvss_${key}"][value="${value}"]`);
            if (radio) {
                radio.checked = true;
            }
        });
    }

function render() {
    let html = `

        <div class="section-header">
                <h3 class="mb-1 d-flex align-items-center gap-2">
                    <i class="bi bi-exclamation-triangle-fill"></i>
                    <span>CVSS v3.1 Calculator</span>
                </h3>
                <p class="text-secondary mb-0">
                    Calculate Common Vulnerability Scoring System (CVSS) scores.
                </p>
            </div>
        
        <div class="row">
            <!-- Left Column: Metrics -->
            <div class="col-md-5">
                <!-- Vector String Input -->
                <div class="card bg-dark mb-3">
                    <div class="card-body">
                        <label class="form-label small mb-2">
                            <i class="bi bi-code-slash"></i> Import CVSS Vector String
                        </label>
                        <div class="input-group input-group-sm mb-2">
                            <input type="text" class="form-control font-monospace" id="vectorInput" 
                                   placeholder="CVSS:3.1/AV:N/AC:L/... or AV:N/AC:L/...">
                        </div>
                        <div id="vectorError" class="small text-danger"></div>
                    </div>
                </div>
                
                <!-- Manual Selection -->
                <div class="card bg-dark mb-3">
                    <div class="card-header d-flex align-items-center justify-content-between">
                        <small class="fw-bold">Manual Selection</small>
                    </div>
                    <div class="card-body">
    `;

        // Generate form for each metric
        Object.entries(cvssMetrics).forEach(([key, metric]) => {
            html += `
                <div class="mb-2">
                    <label class="form-label fw-bold small">
                        ${metric.name}
                        <i class="bi bi-question-circle hint-icon" 
                           data-bs-toggle="tooltip" 
                           data-bs-placement="right" 
                           title="${metric.hint}"></i>
                    </label>
                    <div class="btn-group btn-group-sm w-100" role="group">
            `;
            
            Object.entries(metric.values).forEach(([valueKey, value]) => {
                html += `
                    <input type="radio" class="btn-check cvss-btn-check" name="cvss_${key}" id="cvss_${key}_${valueKey}" value="${valueKey}" autocomplete="off">
                    <label class="btn btn-outline-secondary btn-sm" for="cvss_${key}_${valueKey}" style="cursor: pointer;">
                        ${value.label}
                    </label>
                `;
            });
            
            html += `
                    </div>
                </div>
            `;
        });

        html += `
                            <div class="mt-3 d-flex gap-2">
                                <button class="btn btn-primary btn-sm flex-fill" onclick="calculateCVSS()">
                                    <i class="bi bi-calculator"></i> Calculate
                                </button>
                                <button class="btn btn-outline-secondary btn-sm" onclick="resetCVSS()">
                                    <i class="bi bi-arrow-counterclockwise"></i> Reset
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Right Column: Results & Graphs -->
                <div class="col-md-7">
                    <div id="cvssResults"></div>
                </div>
            </div>
        `;

        return html;
    }

    function init() {
        // Initialize Bootstrap tooltips
        setTimeout(() => {
            const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
            [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
            
            // Add event listeners to all radio buttons for auto-calculation
            document.querySelectorAll('input[type="radio"][name^="cvss_"]').forEach(radio => {
                radio.addEventListener('change', () => {
                    // Check if all metrics are selected
                    const selected = {};
                    let allSelected = true;
                    
                    Object.keys(cvssMetrics).forEach(key => {
                        const selectedRadio = document.querySelector(`input[name="cvss_${key}"]:checked`);
                        if (selectedRadio) {
                            selected[key] = selectedRadio.value;
                        } else {
                            allSelected = false;
                        }
                    });
                    
                    // Auto-calculate if all metrics are selected
                    if (allSelected) {
                        calculateCVSS();
                    }
                });
            });

            // Real-time vector parsing
            const vectorInput = document.getElementById('vectorInput');
            if (vectorInput) {
                vectorInput.addEventListener('input', () => {
                    parseVectorString();
                });
            }
        }, 100);
        
        window.parseVectorString = function() {
            const input = document.getElementById('vectorInput');
            const errorDiv = document.getElementById('vectorError');
            const vectorString = input.value.trim();
            
            if (!vectorString) {
                errorDiv.textContent = '';
                return;
            }
            
            const parsed = parseVector(vectorString);
            
            if (!parsed) {
                errorDiv.textContent = 'Invalid format';
                input.classList.remove('is-valid');
                return;
            }
            
            // Valid vector - clear error and apply to form
            errorDiv.textContent = '';
            input.classList.add('is-valid');
            applyVectorToForm(parsed);
            
            // Auto-calculate
            calculateCVSS();
        };
        
        window.calculateCVSS = function() {
            const resultsDiv = document.getElementById('cvssResults');
            
            // Get selected values
            const selected = {};
            let allSelected = true;
            
            Object.keys(cvssMetrics).forEach(key => {
                const radio = document.querySelector(`input[name="cvss_${key}"]:checked`);
                if (radio) {
                    selected[key] = radio.value;
                } else {
                    allSelected = false;
                }
            });
            
            if (!allSelected) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please select a value for all metrics or load a CVSS vector string</div>';
                return;
            }
            
            // Calculate CVSS score
            const scopeChanged = selected.S === 'C';
            
            // Get metric values
            const AV = cvssMetrics.AV.values[selected.AV].value;
            const AC = cvssMetrics.AC.values[selected.AC].value;
            const PR = scopeChanged ? 
                cvssMetrics.PR.values[selected.PR].scopeChanged : 
                cvssMetrics.PR.values[selected.PR].value;
            const UI = cvssMetrics.UI.values[selected.UI].value;
            const C = cvssMetrics.C.values[selected.C].value;
            const I = cvssMetrics.I.values[selected.I].value;
            const A = cvssMetrics.A.values[selected.A].value;
            
            // Calculate Impact Sub Score (ISS)
            const ISS = 1 - ((1 - C) * (1 - I) * (1 - A));
            
            // Calculate Impact
            let impact;
            if (scopeChanged) {
                impact = 7.52 * (ISS - 0.029) - 3.25 * Math.pow(ISS - 0.02, 15);
            } else {
                impact = 6.42 * ISS;
            }
            
            // Calculate Exploitability
            const exploitability = 8.22 * AV * AC * PR * UI;
            
            // Calculate Base Score
            let baseScore;
            if (impact <= 0) {
                baseScore = 0;
            } else {
                if (scopeChanged) {
                    baseScore = Math.min(1.08 * (impact + exploitability), 10);
                } else {
                    baseScore = Math.min(impact + exploitability, 10);
                }
            }
            
            // Round to one decimal
            baseScore = Math.ceil(baseScore * 10) / 10;
            
            // Determine severity for each component
            const baseSeverity = getSeverityClass(baseScore);
            const impactSeverity = getSeverityClass(impact);
            const exploitSeverity = getSeverityClass(exploitability);
            
            // Overall severity for the header
            let overallSeverity, overallSeverityClass;
            if (baseScore === 0) {
                overallSeverity = 'None';
                overallSeverityClass = 'info';
            } else if (baseScore < 4.0) {
                overallSeverity = 'Low';
                overallSeverityClass = 'success';
            } else if (baseScore < 7.0) {
                overallSeverity = 'Medium';
                overallSeverityClass = 'warning';
            } else if (baseScore < 9.0) {
                overallSeverity = 'High';
                overallSeverityClass = 'danger';
            } else {
                overallSeverity = 'Critical';
                overallSeverityClass = 'dark-danger';
            }
            
            // Generate vector string
            const vector = `CVSS:3.1/AV:${selected.AV}/AC:${selected.AC}/PR:${selected.PR}/UI:${selected.UI}/S:${selected.S}/C:${selected.C}/I:${selected.I}/A:${selected.A}`;
            
            // Display results
            resultsDiv.innerHTML = `
                <div class="card bg-dark border-${overallSeverityClass}">
    <div class="card-header bg-${overallSeverityClass}">
        <h5 class="mb-0">
            <i class="bi bi-shield-exclamation"></i> 
            Score: ${baseScore} - ${overallSeverity}
        </h5>
    </div>
                    <div class="card-body p-3">
                        <!-- Visualizations -->
                        <div class="mb-3">
                            <h6 class="small mb-2">Base Scores</h6>
                            <div class="d-flex gap-2 align-items-end">
                                <div class="flex-fill text-center d-flex flex-column justify-content-end">
                                    <div class="bg-${baseSeverity.class} rounded p-2" style="height: ${baseScore * 10}%; min-height: 30px;">
                                        <small class="${baseSeverity.textClass} fw-bold">${baseScore}</small>
                                    </div>
                                    <small class="d-block mt-1">Base</small>
                                </div>
                                <div class="flex-fill text-center d-flex flex-column justify-content-end">
                                    <div class="bg-${impactSeverity.class} rounded p-2" style="height: ${(impact/10) * 100}%; min-height: 30px;">
                                        <small class="${impactSeverity.textClass} fw-bold">${impact.toFixed(1)}</small>
                                    </div>
                                    <small class="d-block mt-1">Impact</small>
                                </div>
                                <div class="flex-fill text-center d-flex flex-column justify-content-end">
                                    <div class="bg-${exploitSeverity.class} rounded p-2" style="height: ${(exploitability/10) * 100}%; min-height: 30px;">
                                        <small class="${exploitSeverity.textClass} fw-bold">${exploitability.toFixed(1)}</small>
                                    </div>
                                    <small class="d-block mt-1">Exploit</small>
                                </div>
                            </div>
                        </div>
                        
                        <hr>
                        
                        <!-- Overall Score Bar -->
                        <div class="mb-3">
                            <h6 class="small mb-2">Overall Score</h6>
                            <div class="progress" style="height: 30px;">
                                <div class="progress-bar bg-${overallSeverityClass}" role="progressbar" 
                                     style="width: ${baseScore * 10}%"
                                     aria-valuenow="${baseScore}" aria-valuemin="0" aria-valuemax="10">
                                    ${baseScore} / 10
                                </div>
                            </div>
                        </div>
                        
                        <hr>
                        
                        <!-- Score Details -->
                        <div class="row g-2 small">
                            <div class="col-6">
                                <strong>Base Score:</strong> ${baseScore}
                            </div>
                            <div class="col-6">
                                <strong>Severity:</strong> <span class="badge bg-${overallSeverityClass}">${overallSeverity}</span>
                            </div>
                            <div class="col-6">
                                <strong>Impact:</strong> ${impact.toFixed(2)}
                            </div>
                            <div class="col-6">
                                <strong>Exploitability:</strong> ${exploitability.toFixed(2)}
                            </div>
                        </div>
                        
                        <hr>
                        
                        <!-- Selected Metrics -->
                        <div class="mb-3">
                            <h6 class="small mb-2">Selected Metrics</h6>
                            <div class="small">
                                ${Object.entries(selected).map(([key, val]) => 
                                    `<div class="mb-1"><strong>${cvssMetrics[key].name}:</strong> ${cvssMetrics[key].values[val].label}</div>`
                                ).join('')}
                            </div>
                        </div>
                        
                        <!-- Vector String -->
                        <div class="mb-3">
                            <label class="form-label small mb-1">CVSS Vector String</label>
                            <div class="input-group input-group-sm">
                                <input type="text" class="form-control font-monospace" id="cvssVector" value="${vector}" readonly>
                                <button class="btn btn-outline-primary" onclick="copyToClipboard('${vector}', this)">
                                    <i class="bi bi-clipboard"></i>
                                </button>
                            </div>
                        </div>
                        
                        <!-- Severity Reference -->
                        <div class="alert alert-dark mb-0 p-2">
                            <div class="small">
                                <strong class="d-block mb-1">Severity Ratings:</strong>
                                <div class="d-flex flex-wrap gap-2">
                                    <span class="badge bg-info">None: 0.0</span>
                                    <span class="badge bg-success">Low: 0.1-3.9</span>
                                    <span class="badge bg-warning text-dark">Medium: 4.0-6.9</span>
                                    <span class="badge bg-danger">High: 7.0-8.9</span>
                                    <span class="badge bg-dark-danger">Critical: 9.0-10.0</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        };
        
        window.resetCVSS = function() {
            document.querySelectorAll('input[type="radio"][name^="cvss_"]').forEach(radio => {
                radio.checked = false;
            });
            document.getElementById('cvssResults').innerHTML = '';
            document.getElementById('vectorInput').value = '';
            document.getElementById('vectorError').textContent = '';
        };
    }

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'cvss3-calculator',
        name: 'CVSS v3.1 Calculator',
        description: 'Calculate Common Vulnerability Scoring System scores for security vulnerabilities',
        icon: 'bi-exclamation-triangle-fill',
        category: 'purple',
        render: render,
        init: init
    });
})();