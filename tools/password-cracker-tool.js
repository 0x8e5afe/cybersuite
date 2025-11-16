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
            
            <div class="mt-3">
                <button class="btn btn-primary" onclick="calculateCrackTime()">
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

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'password-cracker',
        name: 'Password Cracking Complexity',
        description: 'Calculate time required to crack passwords based on keyspace and attack speed',
        icon: 'bi-speedometer2',
        category: 'purple',
        render: render,
        init: init
    });
})();