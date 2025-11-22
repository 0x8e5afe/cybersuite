// ========================================
// PASSWORD GENERATOR
// Category: Purple Team
// ========================================

(function() {
    'use strict';

    function render() {
        return `

                         <div class="section-header">
                <h3 class="mb-1 d-flex align-items-center gap-2">
                    <i class="bi bi-shield-lock-fill"></i>
                    <span>Password Generator</span>
                </h3>
                <p class="text-secondary mb-0">
                  Generate strong, random passwords with custom character sets.
                </p>
            </div>
            
            <div class="row g-3">
                <div class="col-md-6">
                    <label for="pwdLength" class="form-label">Password Length: <span id="pwdLengthValue">16</span></label>
                    <input type="range" class="form-range" id="pwdLength" min="4" max="128" value="16" oninput="updateLengthLabel()">
                </div>
                
                <div class="col-md-6">
                    <label for="pwdCount" class="form-label">Number of Passwords: <span id="pwdCountValue">1</span></label>
                    <input type="range" class="form-range" id="pwdCount" min="1" max="20" value="1" oninput="updateCountLabel()">
                </div>
            </div>
            
            <div class="row g-3 mt-2">
                <div class="col-md-6 col-lg-3">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="includeLower" checked>
                        <label class="form-check-label" for="includeLower">
                            Lowercase (a-z)
                        </label>
                    </div>
                </div>
                
                <div class="col-md-6 col-lg-3">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="includeUpper" checked>
                        <label class="form-check-label" for="includeUpper">
                            Uppercase (A-Z)
                        </label>
                    </div>
                </div>
                
                <div class="col-md-6 col-lg-3">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="includeDigits" checked>
                        <label class="form-check-label" for="includeDigits">
                            Digits (0-9)
                        </label>
                    </div>
                </div>
                
                <div class="col-md-6 col-lg-3">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="includeSpecial" checked>
                        <label class="form-check-label" for="includeSpecial">
                            Special (!@#$%...)
                        </label>
                    </div>
                </div>
            </div>
            
            <div class="row g-3 mt-2">
                <div class="col-12">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="avoidAmbiguous">
                        <label class="form-check-label" for="avoidAmbiguous">
                            Avoid ambiguous characters (0, O, l, 1, I)
                        </label>
                    </div>
                </div>
                
                <div class="col-12">
                    <label for="customChars" class="form-label">Custom Characters (optional)</label>
                    <input type="text" class="form-control font-monospace" id="customChars" placeholder="Add custom characters to include">
                    <small class="text-secondary">These will be added to the selected character sets</small>
                </div>
            </div>
            
            <div class="mt-3">
                <button class="btn btn-primary" id="pwdGenerateBtn" onclick="generatePasswords()">
                    <i class="bi bi-arrow-repeat"></i> Generate Passwords
                </button>
            </div>
            
            <div id="passwordResults" class="mt-3"></div>
        `;
    }

    function buildPasswordResultsHtml(passwords, charset, length) {
        // Calculate entropy
        const entropy = Math.log2(Math.pow(charset.length, length));

        // Build results card
        let html = `
                <div class="card bg-dark mb-3">
                    <div class="card-header bg-success text-dark">
                        <i class="bi bi-shield-check"></i> Generated Passwords
                    </div>
                    <div class="card-body">
                        <div class="alert alert-info mb-3">
                            <strong>Entropy:</strong> ${entropy.toFixed(2)} bits<br>
                            <strong>Character Set Size:</strong> ${charset.length} characters<br>
                            <strong>Possible Combinations:</strong> ${charset.length}^${length} ≈ ${Math.pow(charset.length, length).toExponential(2)}
                        </div>
            `;

        passwords.forEach((pwd, idx) => {
            const pwdId = `pwd_${idx}`;
            html += `
                    <div class="mb-2">
                        <div class="input-group">
                            <input type="text" class="form-control font-monospace" id="${pwdId}" value="${window.escapeHtml(pwd)}" readonly>
                            <button class="btn btn-outline-primary" onclick="copyPasswordToClipboard('${pwdId}', this)">
                                <i class="bi bi-clipboard"></i>
                            </button>
                        </div>
                    </div>
                `;
        });

        html += `
                        <button class="btn btn-sm btn-outline-secondary mt-2" onclick="copyAllPasswords()">
                            <i class="bi bi-files"></i> Copy All
                        </button>
                    </div>
                </div>
            `;

        // Strength indicator
        let strength = 'Weak';
        let strengthClass = 'danger';
        if (entropy > 100) {
            strength = 'Very Strong';
            strengthClass = 'success';
        } else if (entropy > 80) {
            strength = 'Strong';
            strengthClass = 'success';
        } else if (entropy > 60) {
            strength = 'Good';
            strengthClass = 'primary';
        } else if (entropy > 40) {
            strength = 'Fair';
            strengthClass = 'warning';
        }

        html += `
                <div class="alert alert-${strengthClass}">
                    <strong>Password Strength:</strong> ${strength}
                </div>
            `;

        return {
            html,
            entropy
        };
    }

    function init() {
        window.updateLengthLabel = function() {
            const value = document.getElementById('pwdLength').value;
            document.getElementById('pwdLengthValue').textContent = value;
        };
        
        window.updateCountLabel = function() {
            const value = document.getElementById('pwdCount').value;
            document.getElementById('pwdCountValue').textContent = value;
        };

        window.generatePasswords = function() {
            const length = parseInt(document.getElementById('pwdLength').value);
            const count = parseInt(document.getElementById('pwdCount').value);
            const includeLower = document.getElementById('includeLower').checked;
            const includeUpper = document.getElementById('includeUpper').checked;
            const includeDigits = document.getElementById('includeDigits').checked;
            const includeSpecial = document.getElementById('includeSpecial').checked;
            const avoidAmbiguous = document.getElementById('avoidAmbiguous').checked;
            const customChars = document.getElementById('customChars').value;
            const resultsDiv = document.getElementById('passwordResults');
            
            // Build character set
            let charset = '';
            
            if (includeLower) {
                charset += avoidAmbiguous ? 'abcdefghijkmnopqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
            }
            if (includeUpper) {
                charset += avoidAmbiguous ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            }
            if (includeDigits) {
                charset += avoidAmbiguous ? '23456789' : '0123456789';
            }
            if (includeSpecial) {
                charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
            }
            if (customChars) {
                charset += customChars;
            }
            
            if (charset.length === 0) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please select at least one character type</div>';
                return;
            }
            
            // Generate passwords
            const passwords = [];
            for (let i = 0; i < count; i++) {
                let password = '';
                const array = new Uint32Array(length);
                crypto.getRandomValues(array);

                for (let j = 0; j < length; j++) {
                    password += charset[array[j] % charset.length];
                }
                passwords.push(password);
            }

            const { html } = buildPasswordResultsHtml(passwords, charset, length);
            resultsDiv.innerHTML = html;

            // Store passwords for copy all function
            window.generatedPasswords = passwords;
        };
        
        window.copyPasswordToClipboard = function(inputId, button) {
            const input = document.getElementById(inputId);
            copyToClipboard(input.value, button);
        };
        
        window.copyAllPasswords = function() {
            if (window.generatedPasswords && window.generatedPasswords.length > 0) {
                const allPasswords = window.generatedPasswords.join('\n');
                navigator.clipboard.writeText(allPasswords).then(() => {
                    const resultsDiv = document.getElementById('passwordResults');
                    const alert = document.createElement('div');
                    alert.className = 'alert alert-success mt-2';
                    alert.innerHTML = '<i class="bi bi-check-circle-fill"></i> All passwords copied to clipboard!';
                    resultsDiv.insertBefore(alert, resultsDiv.firstChild);
                    setTimeout(() => alert.remove(), 2000);
                });
            }
        };
    }

function initPipeline(context) {
    // Reuse normal init logic to wire up sliders and handlers
    init();
    
    // In pipeline mode, the pipeline engine will invoke generation,
    // so the manual "Generate Passwords" button should be hidden.
    const btn = document.getElementById('pwdGenerateBtn');
    if (btn) {
        btn.style.display = 'none';
    }
    
    // In pipeline mode, we also don't show the normal output panel;
    // results are meant to flow through the pipeline, not be displayed here.
    const resultsDiv = document.getElementById('passwordResults');
    if (resultsDiv) {
        resultsDiv.style.display = 'none';
    }
}

    // ========================================
    // PIPELINE INTEGRATION
    // ========================================
    async function passwordGeneratorPipelineProcess(input) {
        try {
            // Try to read options from the UI if present (pipeline tool box)
            const lengthEl = document.getElementById('pwdLength');
            const countEl = document.getElementById('pwdCount');
            const includeLowerEl = document.getElementById('includeLower');
            const includeUpperEl = document.getElementById('includeUpper');
            const includeDigitsEl = document.getElementById('includeDigits');
            const includeSpecialEl = document.getElementById('includeSpecial');
            const avoidAmbiguousEl = document.getElementById('avoidAmbiguous');
            const customCharsEl = document.getElementById('customChars');
            const hasUI = !!(lengthEl && countEl && includeLowerEl && includeUpperEl && includeDigitsEl && includeSpecialEl && avoidAmbiguousEl && customCharsEl);
    
            // Determine desired count from pipeline input (optional override)
            let countFromInput = 0;
            if (typeof input === 'number') {
                countFromInput = input;
            } else if (typeof input === 'string') {
                const parsed = parseInt(input.trim(), 10);
                countFromInput = isNaN(parsed) ? 0 : parsed;
            } else if (input && typeof input === 'object') {
                if (typeof input.count === 'number') {
                    countFromInput = input.count;
                } else if (typeof input.passwords === 'number') {
                    countFromInput = input.passwords;
                } else if (typeof input.n === 'number') {
                    countFromInput = input.n;
                }
            }
    
            // Resolve generation parameters
            let length;
            let count;
            let includeLower;
            let includeUpper;
            let includeDigits;
            let includeSpecial;
            let avoidAmbiguous;
            let customChars;
    
            if (hasUI) {
                // Read from UI controls
                length = parseInt(lengthEl.value, 10) || 16;
    
                let uiCount = parseInt(countEl.value, 10) || 1;
                if (Number.isFinite(countFromInput) && countFromInput > 0) {
                    const max = parseInt(countEl.max || '20', 10) || 20;
                    uiCount = Math.min(countFromInput, max);
                }
                count = uiCount;
    
                includeLower = includeLowerEl.checked;
                includeUpper = includeUpperEl.checked;
                includeDigits = includeDigitsEl.checked;
                includeSpecial = includeSpecialEl.checked;
                avoidAmbiguous = avoidAmbiguousEl.checked;
                customChars = customCharsEl.value || '';
            } else {
                // Headless mode (no UI available), use defaults
                if (Number.isFinite(countFromInput) && countFromInput > 0) {
                    count = countFromInput;
                } else {
                    count = 1;
                }
    
                length = 16;
                includeLower = true;
                includeUpper = true;
                includeDigits = true;
                includeSpecial = true;
                avoidAmbiguous = false;
                customChars = '';
            }
    
            if (!Number.isFinite(count) || count <= 0) {
                return {
                    success: false,
                    error: 'Password generator pipeline expected a positive number of passwords as input'
                };
            }
    
            // Enforce an upper bound to avoid heavy computations
            if (count > 1000) {
                return {
                    success: false,
                    error: 'Requested password count is too large for pipeline mode (max 1000)'
                };
            }
    
            // Build character set (same rules as in generatePasswords)
            let charset = '';
            if (includeLower) {
                charset += avoidAmbiguous ? 'abcdefghijkmnopqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
            }
            if (includeUpper) {
                charset += avoidAmbiguous ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            }
            if (includeDigits) {
                charset += avoidAmbiguous ? '23456789' : '0123456789';
            }
            if (includeSpecial) {
                charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
            }
            if (customChars) {
                charset += customChars;
            }
    
            if (!charset || charset.length === 0) {
                return {
                    success: false,
                    error: hasUI
                        ? 'Character set is empty in password generator pipeline (check UI settings)'
                        : 'Internal error: character set is empty in password generator pipeline'
                };
            }
    
            // Generate passwords using crypto.getRandomValues, without touching the visible output
            const passwords = [];
            for (let i = 0; i < count; i++) {
                let password = '';
                const array = new Uint32Array(length);
                crypto.getRandomValues(array);
    
                for (let j = 0; j < length; j++) {
                    password += charset[array[j] % charset.length];
                }
                passwords.push(password);
            }
    
            const { html, entropy } = buildPasswordResultsHtml(passwords, charset, length);
    
            return {
                success: true,
                output: passwords,
                metadata: {
                    source: 'password-generator',
                    count,
                    length,
                    charsetLength: charset.length,
                    entropyPerPassword: entropy,
                    html
                }
            };
        } catch (e) {
            return {
                success: false,
                error: 'Password generator pipeline error: ' + e.message
            };
        }
    }

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'password-generator',
        name: 'Password Generator',
        description: 'Generate strong, cryptographically secure random passwords',
        icon: 'bi-shield-lock-fill',
        category: 'purple',
        render: render,
        init: init,
        initPipeline: initPipeline,
        // Pipeline Integration: receives a number (or numeric string/object)
        // and/or uses its own UI, and returns an array of generated passwords for downstream tools.
        inputTypes: 'number',
        outputType: 'json',
        processPipeline: passwordGeneratorPipelineProcess
    });
})();