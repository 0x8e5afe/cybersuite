
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

    // Temporal Metrics
    const cvssTemporalMetrics = {
        E: {
            name: 'Exploit Code Maturity',
            hint: 'Current state of exploit techniques or code. Not Defined has no effect.',
            values: {
                X: { label: 'Not Defined', value: 1.0 },
                U: { label: 'Unproven', value: 0.91 },
                P: { label: 'Proof-of-Concept', value: 0.94 },
                F: { label: 'Functional', value: 0.97 },
                H: { label: 'High', value: 1.0 }
            }
        },
        RL: {
            name: 'Remediation Level',
            hint: 'Level of remediation available. Not Defined has no effect.',
            values: {
                X: { label: 'Not Defined', value: 1.0 },
                O: { label: 'Official Fix', value: 0.95 },
                T: { label: 'Temporary Fix', value: 0.96 },
                W: { label: 'Workaround', value: 0.97 },
                U: { label: 'Unavailable', value: 1.0 }
            }
        },
        RC: {
            name: 'Report Confidence',
            hint: 'Level of confidence in the existence of the vulnerability.',
            values: {
                X: { label: 'Not Defined', value: 1.0 },
                U: { label: 'Unknown', value: 0.92 },
                R: { label: 'Reasonable', value: 0.96 },
                C: { label: 'Confirmed', value: 1.0 }
            }
        }
    };

    // Environmental Metrics
    const cvssEnvironmentalMetrics = {
        CR: {
            name: 'Confidentiality Requirement',
            hint: 'Relative importance of confidentiality in the environment.',
            values: {
                X: { label: 'Not Defined', value: 1.0 },
                L: { label: 'Low', value: 0.5 },
                M: { label: 'Medium', value: 1.0 },
                H: { label: 'High', value: 1.5 }
            }
        },
        IR: {
            name: 'Integrity Requirement',
            hint: 'Relative importance of integrity in the environment.',
            values: {
                X: { label: 'Not Defined', value: 1.0 },
                L: { label: 'Low', value: 0.5 },
                M: { label: 'Medium', value: 1.0 },
                H: { label: 'High', value: 1.5 }
            }
        },
        AR: {
            name: 'Availability Requirement',
            hint: 'Relative importance of availability in the environment.',
            values: {
                X: { label: 'Not Defined', value: 1.0 },
                L: { label: 'Low', value: 0.5 },
                M: { label: 'Medium', value: 1.0 },
                H: { label: 'High', value: 1.5 }
            }
        },
        MAV: {
            name: 'Modified Attack Vector',
            hint: 'Customised Attack Vector for the specific environment.',
            values: {
                X: { label: 'Not Defined', value: null },
                N: { label: 'Network', value: 0.85 },
                A: { label: 'Adjacent', value: 0.62 },
                L: { label: 'Local', value: 0.55 },
                P: { label: 'Physical', value: 0.2 }
            }
        },
        MAC: {
            name: 'Modified Attack Complexity',
            hint: 'Customised Attack Complexity for the environment.',
            values: {
                X: { label: 'Not Defined', value: null },
                L: { label: 'Low', value: 0.77 },
                H: { label: 'High', value: 0.44 }
            }
        },
        MPR: {
            name: 'Modified Privileges Required',
            hint: 'Customised Privileges Required in this environment.',
            values: {
                X: { label: 'Not Defined', value: null },
                N: { label: 'None', value: 0.85, scopeChanged: 0.85 },
                L: { label: 'Low', value: 0.62, scopeChanged: 0.68 },
                H: { label: 'High', value: 0.27, scopeChanged: 0.50 }
            }
        },
        MUI: {
            name: 'Modified User Interaction',
            hint: 'Customised User Interaction in this environment.',
            values: {
                X: { label: 'Not Defined', value: null },
                N: { label: 'None', value: 0.85 },
                R: { label: 'Required', value: 0.62 }
            }
        },
        MS: {
            name: 'Modified Scope',
            hint: 'Scope considering the specific environment. Not Defined inherits Base Scope.',
            values: {
                X: { label: 'Not Defined', value: null },
                U: { label: 'Unchanged', value: false },
                C: { label: 'Changed', value: true }
            }
        },
        MC: {
            name: 'Modified Confidentiality',
            hint: 'Adjusted Confidentiality impact for the environment.',
            values: {
                X: { label: 'Not Defined', value: null },
                N: { label: 'None', value: 0 },
                L: { label: 'Low', value: 0.22 },
                H: { label: 'High', value: 0.56 }
            }
        },
        MI: {
            name: 'Modified Integrity',
            hint: 'Adjusted Integrity impact for the environment.',
            values: {
                X: { label: 'Not Defined', value: null },
                N: { label: 'None', value: 0 },
                L: { label: 'Low', value: 0.22 },
                H: { label: 'High', value: 0.56 }
            }
        },
        MA: {
            name: 'Modified Availability',
            hint: 'Adjusted Availability impact for the environment.',
            values: {
                X: { label: 'Not Defined', value: null },
                N: { label: 'None', value: 0 },
                L: { label: 'Low', value: 0.22 },
                H: { label: 'High', value: 0.56 }
            }
        }
    };

function getSeverityClass(score) {
    if (score === 0)                return { class: 'info',        textClass: 'text-white' }; // NONE (blue)
    else if (score < 4.0)           return { class: 'success',     textClass: 'text-white' }; // LOW (green)
    else if (score < 7.0)           return { class: 'warning',     textClass: 'text-white' }; // MEDIUM (yellow/orange)
    else if (score < 9.0)           return { class: 'danger',      textClass: 'text-white' }; // HIGH (red)
    else                            return { class: 'dark-danger', textClass: 'text-white' }; // CRITICAL (dark red)
}

function getSeverityName(score) {
    if (score === 0) return 'None';
    if (score < 4.0) return 'Low';
    if (score < 7.0) return 'Medium';
    if (score < 9.0) return 'High';
    return 'Critical';
}

    function roundUp1(num) {
        return Math.ceil(num * 10) / 10;
    }

    // Generic CVSS v3.1 vector parser
    function parseVector(vectorString) {
        const cleanVector = vectorString.trim();
        if (!cleanVector) return null;

        const baseKeys = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
        const allKeys = baseKeys.concat([
            'E', 'RL', 'RC',
            'CR', 'IR', 'AR',
            'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA'
        ]);

        const result = {};

        const parts = cleanVector.split('/');
        parts.forEach(part => {
            if (!part) return;
            if (part.startsWith('CVSS:')) return;

            const idx = part.indexOf(':');
            if (idx === -1) return;
            const key = part.slice(0, idx).trim().toUpperCase();
            const val = part.slice(idx + 1).trim().toUpperCase();
            if (!key || !val) return;

            if (allKeys.includes(key)) {
                result[key] = val;
            }
        });

        const hasAllBase = baseKeys.every(k => result[k]);
        if (!hasAllBase) return null;

        return result;
    }

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
        <div class="section-header purple-team">
            <h3 class="mb-1 d-flex align-items-center gap-2">
                <i class="bi bi-exclamation-triangle-fill"></i>
                <span>CVSS v3.1 Calculator</span>
            </h3>
            <p class="text-secondary mb-0">
                Calculate Common Vulnerability Scoring System (CVSS) scores.
            </p>
        </div>
        
        <div class="row g-3">
            <!-- Left Column: Metrics -->
            <div class="col-12 col-lg-5">
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
                
                <!-- BASE METRICS CARD -->
                <div class="card bg-dark mb-3 cvss-section-card">
                    <div class="card-header d-flex align-items-center justify-content-between">
                        <span class="fw-bold">
                            <i class="bi bi-shield-fill text-success me-2"></i>
                            Base Metrics
                        </span>
                        <span class="badge bg-success">Required</span>
                    </div>
                    <div class="card-body">
        `;

        // Base metrics
        Object.entries(cvssMetrics).forEach(([key, metric]) => {
            html += `
            <div class="mb-3">
                <label class="form-label fw-bold small d-flex align-items-center justify-content-between">
                    <span>${metric.name}</span>
                    <i class="bi bi-question-circle hint-icon" 
                       data-bs-toggle="tooltip" 
                       data-bs-placement="right" 
                       title="${metric.hint}"></i>
                </label>
                <div class="btn-group w-100 cvss-metric-group cvss-base-group" role="group" aria-label="${metric.name}">
            `;
            
            Object.entries(metric.values).forEach(([valueKey, value]) => {
                html += `
                <input type="radio" class="btn-check cvss-btn-check" name="cvss_${key}" id="cvss_${key}_${valueKey}" value="${valueKey}" autocomplete="off">
                <label class="btn btn-outline-secondary cvss-option-btn" for="cvss_${key}_${valueKey}">
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
                    </div>
                </div>
        `;

        // ADVANCED METRICS ACCORDION (Temporal + Environmental)
html += `
    <div class="accordion mb-3 cvss-accordion" id="cvssAdvancedAccordion">

        <!-- Temporal -->
        <div class="accordion-item">
            <h2 class="accordion-header">
                <button class="accordion-button collapsed"
                        type="button"
                        data-bs-toggle="collapse"
                        data-bs-target="#cvssTemporalCollapse"
                        aria-expanded="false"
                        aria-controls="cvssTemporalCollapse">
                    <i class="bi bi-clock-history me-2 text-success"></i>
                    Temporal Metrics
                </button>
            </h2>

            <div id="cvssTemporalCollapse"
                 class="accordion-collapse collapse"
                 data-bs-parent="#cvssAdvancedAccordion">
                <div class="accordion-body">
                    <p class="small text-muted mb-3">
                        Temporal metrics measure characteristics that change over time.
                    </p>
`;

        // Temporal metrics content (unchanged)
        Object.entries(cvssTemporalMetrics).forEach(([key, metric]) => {
            html += `
                <div class="mb-3">
                    <label class="form-label fw-bold small d-flex align-items-center justify-content-between">
                        <span>${metric.name}</span>
                        <i class="bi bi-question-circle hint-icon"
                           data-bs-toggle="tooltip"
                           data-bs-placement="right"
                           title="${metric.hint}"></i>
                    </label>
                    <div class="btn-group w-100 cvss-metric-group cvss-temporal-group" role="group" aria-label="${metric.name}">
            `;
            Object.entries(metric.values).forEach(([valueKey, value]) => {
                const isDefault = valueKey === 'X';
                html += `
                        <input type="radio"
                               class="btn-check cvss-btn-check"
                               name="cvss_${key}"
                               id="cvss_${key}_${valueKey}"
                               value="${valueKey}"
                               autocomplete="off"
                               ${isDefault ? 'checked' : ''}>
                        <label class="btn btn-outline-secondary cvss-option-btn ${isDefault ? 'cvss-default-option' : ''}"
                               for="cvss_${key}_${valueKey}">
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
                            </div>
                        </div>
                    </div>

                    <!-- Environmental metrics -->
<div class="accordion-item">
            <h2 class="accordion-header">
                <button class="accordion-button collapsed"
                        type="button"
                        data-bs-toggle="collapse"
                        data-bs-target="#cvssEnvironmentalCollapse"
                        aria-expanded="false"
                        aria-controls="cvssEnvironmentalCollapse">
                    <i class="bi bi-globe2 me-2 text-success"></i>
                    Environmental Metrics
                </button>
            </h2>
            <div id="cvssEnvironmentalCollapse"
                 class="accordion-collapse collapse"
                 data-bs-parent="#cvssAdvancedAccordion">
                <div class="accordion-body">
                    <p class="small text-muted mb-3">
                        Environmental metrics customize the score for your specific environment.
                    </p>
        `;

        // Environmental metrics content (unchanged)
        Object.entries(cvssEnvironmentalMetrics).forEach(([key, metric]) => {
            html += `
                <div class="mb-3">
                    <label class="form-label fw-bold small d-flex align-items-center justify-content-between">
                        <span>${metric.name}</span>
                        <i class="bi bi-question-circle hint-icon"
                           data-bs-toggle="tooltip"
                           data-bs-placement="right"
                           title="${metric.hint}"></i>
                    </label>
                    <div class="btn-group w-100 cvss-metric-group cvss-env-group" role="group" aria-label="${metric.name}">
            `;
            Object.entries(metric.values).forEach(([valueKey, value]) => {
                const isDefault = valueKey === 'X';
                html += `
                        <input type="radio"
                               class="btn-check cvss-btn-check"
                               name="cvss_${key}"
                               id="cvss_${key}_${valueKey}"
                               value="${valueKey}"
                               autocomplete="off"
                               ${isDefault ? 'checked' : ''}>
                        <label class="btn btn-outline-secondary cvss-option-btn ${isDefault ? 'cvss-default-option' : ''}"
                               for="cvss_${key}_${valueKey}">
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
                            </div>
                        </div>
                    </div>
                </div>
        `;

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
            
            <!-- Right Column: Results & Graphs -->
            <div class="col-12 col-lg-7">
                <div id="cvssResults"></div>
            </div>
        </div>
        `;

        return html;
    }

    function init() {
        // Inject enhanced CSS

        setTimeout(() => {
            const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
            [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
            
            document.querySelectorAll('input[type="radio"][name^="cvss_"]').forEach(radio => {
                radio.addEventListener('change', () => {
                    const baseSelected = {};
                    let allBaseSelected = true;
                    
                    Object.keys(cvssMetrics).forEach(key => {
                        const selectedRadio = document.querySelector(`input[name="cvss_${key}"]:checked`);
                        if (selectedRadio) {
                            baseSelected[key] = selectedRadio.value;
                        } else {
                            allBaseSelected = false;
                        }
                    });
                    
                    if (allBaseSelected) {
                        calculateCVSS();
                    }
                });
            });

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
                input.classList.remove('is-valid');
                return;
            }
            
            const parsed = parseVector(vectorString);
            
            if (!parsed) {
                errorDiv.textContent = 'Invalid format';
                input.classList.remove('is-valid');
                return;
            }
            
            errorDiv.textContent = '';
            input.classList.add('is-valid');
            applyVectorToForm(parsed);
            calculateCVSS();
        };
        
        window.calculateCVSS = function() {
            const resultsDiv = document.getElementById('cvssResults');
            
            const baseSelected = {};
            let allBaseSelected = true;
            
            Object.keys(cvssMetrics).forEach(key => {
                const radio = document.querySelector(`input[name="cvss_${key}"]:checked`);
                if (radio) {
                    baseSelected[key] = radio.value;
                } else {
                    allBaseSelected = false;
                }
            });
            
            if (!allBaseSelected) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please select a value for all Base metrics or load a CVSS vector string</div>';
                return;
            }

            // Temporal selections
            const temporalSelected = {};
            Object.keys(cvssTemporalMetrics).forEach(key => {
                const radio = document.querySelector(`input[name="cvss_${key}"]:checked`);
                temporalSelected[key] = radio ? radio.value : 'X';
            });

            // Environmental selections
            const envSelected = {};
            Object.keys(cvssEnvironmentalMetrics).forEach(key => {
                const radio = document.querySelector(`input[name="cvss_${key}"]:checked`);
                envSelected[key] = radio ? radio.value : 'X';
            });
            
            // Check if temporal or environmental metrics are actually defined
            const hasTemporalDefined = Object.entries(temporalSelected).some(([_, v]) => v !== 'X');
            const hasEnvDefined = Object.entries(envSelected).some(([_, v]) => v !== 'X');
            
            // Base calculation
            const baseScopeChanged = baseSelected.S === 'C';
            
            const AV = cvssMetrics.AV.values[baseSelected.AV].value;
            const AC = cvssMetrics.AC.values[baseSelected.AC].value;
            const PRbaseObj = cvssMetrics.PR.values[baseSelected.PR];
            const PR = baseScopeChanged && PRbaseObj.scopeChanged != null ? PRbaseObj.scopeChanged : PRbaseObj.value;
            const UI = cvssMetrics.UI.values[baseSelected.UI].value;
            const C = cvssMetrics.C.values[baseSelected.C].value;
            const I = cvssMetrics.I.values[baseSelected.I].value;
            const A = cvssMetrics.A.values[baseSelected.A].value;
            
            const ISS = 1 - ((1 - C) * (1 - I) * (1 - A));
            
            let impact;
            if (baseScopeChanged) {
                impact = 7.52 * (ISS - 0.029) - 3.25 * Math.pow(ISS - 0.02, 15);
            } else {
                impact = 6.42 * ISS;
            }
            
            const exploitability = 8.22 * AV * AC * PR * UI;
            
            let baseScore;
            if (impact <= 0) {
                baseScore = 0;
            } else {
                if (baseScopeChanged) {
                    baseScore = Math.min(1.08 * (impact + exploitability), 10);
                } else {
                    baseScore = Math.min(impact + exploitability, 10);
                }
            }
            
            baseScore = roundUp1(baseScore);

            // Temporal factors
            const E = cvssTemporalMetrics.E.values[temporalSelected.E].value;
            const RL = cvssTemporalMetrics.RL.values[temporalSelected.RL].value;
            const RC = cvssTemporalMetrics.RC.values[temporalSelected.RC].value;

            const temporalScore = roundUp1(baseScore * E * RL * RC);

            // Environmental calculation
            const envScopeCode = envSelected.MS !== 'X' ? envSelected.MS : baseSelected.S;
            const envScopeChanged = envScopeCode === 'C';

            const AVenv = (envSelected.MAV !== 'X')
                ? cvssEnvironmentalMetrics.MAV.values[envSelected.MAV].value
                : AV;
            const ACenv = (envSelected.MAC !== 'X')
                ? cvssEnvironmentalMetrics.MAC.values[envSelected.MAC].value
                : AC;

            const PRenvCode = envSelected.MPR !== 'X' ? envSelected.MPR : baseSelected.PR;
            const PRenvObj = cvssMetrics.PR.values[PRenvCode];
            const PRenv = envScopeChanged && PRenvObj.scopeChanged != null ? PRenvObj.scopeChanged : PRenvObj.value;

            const UIenv = (envSelected.MUI !== 'X')
                ? cvssEnvironmentalMetrics.MUI.values[envSelected.MUI].value
                : UI;

            const CR = cvssEnvironmentalMetrics.CR.values[envSelected.CR].value;
            const IR = cvssEnvironmentalMetrics.IR.values[envSelected.IR].value;
            const AR = cvssEnvironmentalMetrics.AR.values[envSelected.AR].value;

            const Cbase = C;
            const Ibase = I;
            const Abase = A;

            const MC = envSelected.MC !== 'X'
                ? cvssEnvironmentalMetrics.MC.values[envSelected.MC].value
                : Cbase;
            const MI = envSelected.MI !== 'X'
                ? cvssEnvironmentalMetrics.MI.values[envSelected.MI].value
                : Ibase;
            const MA = envSelected.MA !== 'X'
                ? cvssEnvironmentalMetrics.MA.values[envSelected.MA].value
                : Abase;

            const Cenv = MC * CR;
            const Ienv = MI * IR;
            const Aenv = MA * AR;

            const ISSenv = Math.min(1 - ((1 - Cenv) * (1 - Ienv) * (1 - Aenv)), 1);

            let impactEnv;
            if (envScopeChanged) {
                impactEnv = 7.52 * (ISSenv - 0.029) - 3.25 * Math.pow(ISSenv - 0.02, 15);
            } else {
                impactEnv = 6.42 * ISSenv;
            }

            const exploitEnv = 8.22 * AVenv * ACenv * PRenv * UIenv;

            let envBaseScore;
            if (impactEnv <= 0) {
                envBaseScore = 0;
            } else {
                if (envScopeChanged) {
                    envBaseScore = Math.min(1.08 * (impactEnv + exploitEnv), 10);
                } else {
                    envBaseScore = Math.min(impactEnv + exploitEnv, 10);
                }
            }

            const environmentalScore = roundUp1(envBaseScore * E * RL * RC);

            const baseSeverity = getSeverityClass(baseScore);
            const impactSeverity = getSeverityClass(impact);
            const exploitSeverity = getSeverityClass(exploitability);
            const temporalSeverity = getSeverityClass(temporalScore);
            const environmentalSeverity = getSeverityClass(environmentalScore);

            const baseMetricsBorderClass =
    baseSeverity.class === 'danger' || baseSeverity.class === 'dark-danger'
        ? 'border-danger'
        : baseSeverity.class === 'warning'
            ? 'border-warning'
            : 'border-success';

const baseMetricsTextClass =
    baseSeverity.class === 'danger' || baseSeverity.class === 'dark-danger'
        ? 'text-danger'
        : baseSeverity.class === 'warning'
            ? 'text-warning'
            : 'text-success';

const temporalMetricsBorderClass =
    temporalSeverity.class === 'danger' || temporalSeverity.class === 'dark-danger'
        ? 'border-danger'
        : temporalSeverity.class === 'warning'
            ? 'border-warning'
            : 'border-success';

const temporalMetricsTextClass =
    temporalSeverity.class === 'danger' || temporalSeverity.class === 'dark-danger'
        ? 'text-danger'
        : temporalSeverity.class === 'warning'
            ? 'text-warning'
            : 'text-success';

const environmentalMetricsBorderClass =
    environmentalSeverity.class === 'danger' || environmentalSeverity.class === 'dark-danger'
        ? 'border-danger'
        : environmentalSeverity.class === 'warning'
            ? 'border-warning'
            : 'border-success';

const environmentalMetricsTextClass =
    environmentalSeverity.class === 'danger' || environmentalSeverity.class === 'dark-danger'
        ? 'text-danger'
        : environmentalSeverity.class === 'warning'
            ? 'text-warning'
            : 'text-success';
            
            let overallScore;
let overallSeverityClass;
let overallSeverityName;

if (hasEnvDefined) {
    overallScore = environmentalScore;
    overallSeverityClass = environmentalSeverity.class;
    overallSeverityName = getSeverityName(environmentalScore);
} else if (hasTemporalDefined) {
    overallScore = temporalScore;
    overallSeverityClass = temporalSeverity.class;
    overallSeverityName = getSeverityName(temporalScore);
} else {
    overallScore = baseScore;
    overallSeverityClass = baseSeverity.class;
    overallSeverityName = getSeverityName(baseScore);
}

            // Build vector string with only defined metrics
            let vectorParts = [
                `CVSS:3.1`,
                `AV:${baseSelected.AV}`,
                `AC:${baseSelected.AC}`,
                `PR:${baseSelected.PR}`,
                `UI:${baseSelected.UI}`,
                `S:${baseSelected.S}`,
                `C:${baseSelected.C}`,
                `I:${baseSelected.I}`,
                `A:${baseSelected.A}`
            ];

            // Add temporal only if defined
            if (hasTemporalDefined) {
                ['E', 'RL', 'RC'].forEach(key => {
                    const val = temporalSelected[key];
                    if (val && val !== 'X') {
                        vectorParts.push(`${key}:${val}`);
                    }
                });
            }

            // Add environmental only if defined
            if (hasEnvDefined) {
                Object.keys(cvssEnvironmentalMetrics).forEach(key => {
                    const val = envSelected[key];
                    if (val && val !== 'X') {
                        vectorParts.push(`${key}:${val}`);
                    }
                });
            }

            const vector = vectorParts.join('/');

            // Selected metrics HTML (only defined ones)
            const baseMetricsHtml = Object.entries(baseSelected).map(([key, val]) =>
    `<div class="mb-1">
        <span class="text-muted small">${cvssMetrics[key].name}:</span>
        <span class="${baseMetricsTextClass} fw-semibold ms-1">${cvssMetrics[key].values[val].label}</span>
    </div>`
).join('');

let temporalMetricsHtml = '';
if (hasTemporalDefined) {
    temporalMetricsHtml = Object.entries(temporalSelected)
        .filter(([_, val]) => val !== 'X')
        .map(([key, val]) =>
            `<div class="mb-1">
                <span class="text-muted small">${cvssTemporalMetrics[key].name}:</span>
                <span class="${temporalMetricsTextClass} fw-semibold ms-1">${cvssTemporalMetrics[key].values[val].label}</span>
            </div>`
        ).join('');
}

let envMetricsHtml = '';
if (hasEnvDefined) {
    envMetricsHtml = Object.entries(envSelected)
        .filter(([_, val]) => val !== 'X')
        .map(([key, val]) =>
            `<div class="mb-1">
                <span class="text-muted small">${cvssEnvironmentalMetrics[key].name}:</span>
                <span class="${environmentalMetricsTextClass} fw-semibold ms-1">${cvssEnvironmentalMetrics[key].values[val].label}</span>
            </div>`
        ).join('');
}

            let scoresBarsHtml = `
    <div class="mb-2">
        <div class="d-flex justify-content-between small">
            <span class="fw-semibold">Base Score</span>
            <span class="fw-bold">
                ${baseScore} / 10
                <span class="badge bg-${baseSeverity.class} ms-1">
                    ${getSeverityName(baseScore)}
                </span>
            </span>
        </div>
        <div class="progress" style="height: 24px;">
            <div class="progress-bar bg-${baseSeverity.class}" role="progressbar"
                 style="width: ${baseScore * 10}%"
                 aria-valuenow="${baseScore}" aria-valuemin="0" aria-valuemax="10">
                <strong>${baseScore}</strong>
            </div>
        </div>
    </div>
`;

if (hasTemporalDefined) {
    scoresBarsHtml += `
        <div class="mb-2">
            <div class="d-flex justify-content-between small">
                <span class="fw-semibold">Temporal Score</span>
                <span class="fw-bold">
                    ${temporalScore} / 10
                    <span class="badge bg-${temporalSeverity.class} ms-1">
                        ${getSeverityName(temporalScore)}
                    </span>
                </span>
            </div>
            <div class="progress" style="height: 24px;">
                <div class="progress-bar bg-${temporalSeverity.class}" role="progressbar"
                     style="width: ${temporalScore * 10}%"
                     aria-valuenow="${temporalScore}" aria-valuemin="0" aria-valuemax="10">
                    <strong>${temporalScore}</strong>
                </div>
            </div>
        </div>
    `;
}

if (hasEnvDefined) {
    scoresBarsHtml += `
        <div>
            <div class="d-flex justify-content-between small">
                <span class="fw-semibold">Environmental Score</span>
                <span class="fw-bold">
                    ${environmentalScore} / 10
                    <span class="badge bg-${environmentalSeverity.class} ms-1">
                        ${getSeverityName(environmentalScore)}
                    </span>
                </span>
            </div>
            <div class="progress" style="height: 24px;">
                <div class="progress-bar bg-${environmentalSeverity.class}" role="progressbar"
                     style="width: ${environmentalScore * 10}%"
                     aria-valuenow="${environmentalScore}" aria-valuemin="0" aria-valuemax="10">
                    <strong>${environmentalScore}</strong>
                </div>
            </div>
        </div>
    `;
}

            // Score detail lines – hide temporal/env when unused
            let scoreDetailsHtml = `
                <div class="col-md-6">
                    <strong class="text-muted">Base Score:</strong> <span class="text-white">${baseScore}</span> <span class="badge bg-${baseSeverity.class}">${getSeverityName(baseScore)}</span>
                </div>
                <div class="col-md-3">
                    <strong class="text-muted">Impact:</strong> <span class="text-white">${impact.toFixed(2)}</span>
                </div>
                <div class="col-md-3">
                    <strong class="text-muted">Exploitability:</strong> <span class="text-white">${exploitability.toFixed(2)}</span>
                </div>
            `;

            if (hasTemporalDefined) {
                scoreDetailsHtml += `
                    <div class="col-md-6">
                        <strong class="text-muted">Temporal Score:</strong> <span class="text-white">${temporalScore}</span> <span class="badge bg-${temporalSeverity.class}">${getSeverityName(temporalScore)}</span>
                    </div>
                `;
            }

            if (hasEnvDefined) {
                scoreDetailsHtml += `
                    <div class="col-md-6">
                        <strong class="text-muted">Environmental Score:</strong> <span class="text-white">${environmentalScore}</span> <span class="badge bg-${environmentalSeverity.class}">${getSeverityName(environmentalScore)}</span>
                    </div>
                `;
            }

            // Selected Metrics columns – show only groups with defined values
            let selectedMetricsColumns = `
    <div class="${hasTemporalDefined || hasEnvDefined ? 'col-md-4' : 'col-12'}">
        <div class="rounded p-3 h-100">
            <div class="fw-bold ${baseMetricsTextClass} mb-2 d-flex align-items-center">
                <i class="bi bi-shield-fill me-2"></i> Base Metrics
            </div>
            ${baseMetricsHtml}
        </div>
    </div>
`;

if (hasTemporalDefined) {
    selectedMetricsColumns += `
        <div class="col-md-4">
            <div class="rounded p-3 h-100">
                <div class="fw-bold ${temporalMetricsTextClass} mb-2 d-flex align-items-center">
                    <i class="bi bi-clock-history me-2"></i> Temporal Metrics
                </div>
                ${temporalMetricsHtml}
            </div>
        </div>
    `;
}

if (hasEnvDefined) {
    selectedMetricsColumns += `
        <div class="col-md-4">
            <div class="rounded p-3 h-100">
                <div class="fw-bold ${environmentalMetricsTextClass} mb-2 d-flex align-items-center">
                    <i class="bi bi-globe2 me-2"></i> Environmental Metrics
                </div>
                ${envMetricsHtml}
            </div>
        </div>
    `;
}

            const vectorHint = hasTemporalDefined || hasEnvDefined
                ? 'Vector includes only the defined metrics (excludes "Not Defined" values).'
                : 'Base-only CVSS v3.1 vector (no Temporal/Environmental overrides).';

            resultsDiv.innerHTML = `
                <div class="card bg-dark border-${overallSeverityClass} shadow-lg">
                    <div class="card-header bg-${overallSeverityClass}">
                        <h5 class="mb-0 d-flex justify-content-between align-items-center">
                            <span>
                                <i class="bi bi-shield-exclamation"></i> 
                                CVSS v3.1 Score: ${overallScore}
                            </span>
                            <span class="badge bg-light text-dark">${overallSeverityName}</span>
                        </h5>
                    </div>
                    <div class="card-body p-3">
                        <div class="mb-4">
                            <h6 class="small text-uppercase text-muted mb-3 fw-bold">
                                <i class="bi bi-bar-chart-fill me-1"></i> Score Breakdown
                            </h6>
                            ${scoresBarsHtml}
                        </div>
                        
                        <hr class="border-secondary">
                        
                        <div class="mb-4">
                            <h6 class="small text-uppercase text-muted mb-3 fw-bold">
                                <i class="bi bi-diagram-3-fill me-1"></i> Base Components
                            </h6>
                            <div class="d-flex gap-2 align-items-end justify-content-around">
                                <div class="text-center d-flex flex-column justify-content-end" style="flex: 1;">
                                    <div class="bg-${baseSeverity.class} rounded p-2 d-flex align-items-center justify-content-center" style="height: ${Math.max(baseScore * 8, 40)}px;">
                                        <small class="${baseSeverity.textClass} fw-bold">${baseScore}</small>
                                    </div>
                                    <small class="d-block mt-2 text-muted">Base</small>
                                </div>
                                <div class="text-center d-flex flex-column justify-content-end" style="flex: 1;">
                                    <div class="bg-${impactSeverity.class} rounded p-2 d-flex align-items-center justify-content-center" style="height: ${Math.max((impact/10) * 80, 40)}px;">
                                        <small class="${impactSeverity.textClass} fw-bold">${impact.toFixed(1)}</small>
                                    </div>
                                    <small class="d-block mt-2 text-muted">Impact</small>
                                </div>
                                <div class="text-center d-flex flex-column justify-content-end" style="flex: 1;">
                                    <div class="bg-${exploitSeverity.class} rounded p-2 d-flex align-items-center justify-content-center" style="height: ${Math.max((exploitability/10) * 80, 40)}px;">
                                        <small class="${exploitSeverity.textClass} fw-bold">${exploitability.toFixed(1)}</small>
                                    </div>
                                    <small class="d-block mt-2 text-muted">Exploit</small>
                                </div>
                            </div>
                        </div>
                        
                        <hr class="border-secondary">
                        
                        <div class="row g-2 small mb-4">
                            ${scoreDetailsHtml}
                        </div>
                        
                        <hr class="border-secondary">
                        
                        <div class="mb-4">
                            <h6 class="small text-uppercase text-muted mb-3 fw-bold">
                                <i class="bi bi-list-check me-1"></i> Selected Metrics
                            </h6>
                            <div class="row g-3">
                                ${selectedMetricsColumns}
                            </div>
                        </div>
                        
                        <hr class="border-secondary">
                        
                        <div class="mb-3">
                            <label class="form-label small mb-2 fw-bold text-muted">
                                <i class="bi bi-code-slash me-1"></i> CVSS Vector String
                            </label>
                            <div class="input-group input-group-sm">
                                <input type="text" class="form-control font-monospace bg-dark text-success" 
                                       id="cvssVector" value="${vector}" readonly>
                                <button class="btn btn-outline-success" onclick="copyToClipboard('${vector}', this)" title="Copy to clipboard">
                                    <i class="bi bi-clipboard"></i>
                                </button>
                            </div>
                            <small class="text-muted d-block mt-2">
                                <i class="bi bi-info-circle me-1"></i> ${vectorHint}
                            </small>
                        </div>
                        
                        <div class="alert alert-dark border border-secondary mb-0 p-3">
                            <div class="small">
                                <strong class="d-block mb-2 text-uppercase">
                                    <i class="bi bi-speedometer2 me-1"></i> Severity Ratings Reference
                                </strong>
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
            // Reset all base metrics
            document.querySelectorAll('input[type="radio"][name^="cvss_"]').forEach(radio => {
                // For temporal and environmental, set back to "Not Defined" (X)
                if (radio.value === 'X' && (radio.name.startsWith('cvss_E') || 
                    radio.name.startsWith('cvss_RL') || radio.name.startsWith('cvss_RC') ||
                    radio.name.startsWith('cvss_CR') || radio.name.startsWith('cvss_IR') || 
                    radio.name.startsWith('cvss_AR') || radio.name.startsWith('cvss_M'))) {
                    radio.checked = true;
                } else if (!radio.name.includes('_E') && !radio.name.includes('_RL') && 
                           !radio.name.includes('_RC') && !radio.name.includes('_CR') && 
                           !radio.name.includes('_IR') && !radio.name.includes('_AR') && 
                           !radio.name.includes('_M')) {
                    radio.checked = false;
                }
            });
            
            // Collapse temporal and environmental sections
            const temporalCollapse = document.getElementById('cvssTemporalCollapse');
            const envCollapse = document.getElementById('cvssEnvironmentalCollapse');
            if (temporalCollapse) {
                const bsCollapse = bootstrap.Collapse.getInstance(temporalCollapse);
                if (bsCollapse) bsCollapse.hide();
            }
            if (envCollapse) {
                const bsCollapse = bootstrap.Collapse.getInstance(envCollapse);
                if (bsCollapse) bsCollapse.hide();
            }
            
            document.getElementById('cvssResults').innerHTML = '';
            document.getElementById('vectorInput').value = '';
            document.getElementById('vectorError').textContent = '';
            document.getElementById('vectorInput').classList.remove('is-valid');
        };
    }

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
            