// ========================================
// PASSWORD CRACKING COMPLEXITY ANALYZER
// Category: Purple Team
// ========================================

(function() {
    'use strict';

    function render() {
        return `
            <div class="mb-4">
                <h4><i class="bi bi-speedometer2"></i> Password Cracking Complexity Analyzer</h4>
                <p class="text-secondary">Calculate the time required to crack passwords based on character set and length</p>
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
            
            if (charsetSize === 0) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please select at least one character set or enter a custom size</div>';
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
            
            // Determine strength
            let strength, strengthClass, strengthIcon;
            if (secondsToAverage < 60) {
                strength = 'Very Weak';
                strengthClass = 'danger';
                strengthIcon = 'x-circle-fill';
            } else if (secondsToAverage < 3600) {
                strength = 'Weak';
                strengthClass = 'warning';
                strengthIcon = 'exclamation-circle-fill';
            } else if (secondsToAverage < 86400) {
                strength = 'Fair';
                strengthClass = 'info';
                strengthIcon = 'info-circle-fill';
            } else if (secondsToAverage < 31536000) {
                strength = 'Good';
                strengthClass = 'primary';
                strengthIcon = 'check-circle-fill';
            } else {
                strength = 'Strong';
                strengthClass = 'success';
                strengthIcon = 'shield-check';
            }
            
            // Calculate entropy
            const entropy = Math.log2(totalCombinations);
            
            resultsDiv.innerHTML = `
                <div class="card bg-dark">
                    <div class="card-header bg-${strengthClass} text-dark">
                        <i class="bi bi-${strengthIcon}"></i> Password Strength: ${strength}
                    </div>
                    <div class="card-body">
                        <div class="row g-3">
                            <div class="col-md-6">
                                <h6>Configuration</h6>
                                <ul class="list-unstyled">
                                    <li><strong>Password Length:</strong> ${length} characters</li>
                                    <li><strong>Character Set Size:</strong> ${charsetSize}</li>
                                    <li><strong>Hashing Speed:</strong> ${attemptsPerSec.toLocaleString()} hashes/sec</li>
                                    <li><strong>Entropy:</strong> ${entropy.toFixed(2)} bits</li>
                                </ul>
                            </div>
                            
                            <div class="col-md-6">
                                <h6>Cracking Time Estimates</h6>
                                <ul class="list-unstyled">
                                    <li><strong>Total Combinations:</strong> ${totalCombinations.toExponential(2)}</li>
                                    <li><strong>Average Case:</strong> <span class="text-${strengthClass}">${formatTime(secondsToAverage)}</span></li>
                                    <li><strong>Worst Case:</strong> ${formatTime(secondsToExhaust)}</li>
                                </ul>
                            </div>
                        </div>
                        
                        <hr>
                        
                        <div class="alert alert-info mb-0">
                            <h6 class="alert-heading">Understanding the Results</h6>
                            <ul class="mb-0 small">
                                <li><strong>Average Case:</strong> Time to find password on average (50% of search space)</li>
                                <li><strong>Worst Case:</strong> Time for exhaustive search of entire keyspace</li>
                                <li><strong>Entropy:</strong> Measure of randomness; higher is better (>80 bits recommended)</li>
                                <li><strong>Note:</strong> These calculations assume pure brute force without dictionary attacks or rainbow tables</li>
                            </ul>
                        </div>
                    </div>
                </div>
                
                <div class="mt-3">
                    <h6>Comparison with Different Attack Speeds</h6>
                    <div class="table-responsive">
                        <table class="table table-dark table-striped table-sm">
                            <thead>
                                <tr>
                                    <th>Attack Method</th>
                                    <th>Hashes/Second</th>
                                    <th>Average Time</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>CPU Only</td>
                                    <td>100,000</td>
                                    <td>${formatTime(secondsToAverage / attemptsPerSec * 100000)}</td>
                                </tr>
                                <tr>
                                    <td>Single GPU</td>
                                    <td>10 Million</td>
                                    <td>${formatTime(secondsToAverage / attemptsPerSec * 10000000)}</td>
                                </tr>
                                <tr>
                                    <td>High-end GPU</td>
                                    <td>100 Million</td>
                                    <td>${formatTime(secondsToAverage / attemptsPerSec * 100000000)}</td>
                                </tr>
                                <tr>
                                    <td>GPU Cluster</td>
                                    <td>1 Billion</td>
                                    <td>${formatTime(secondsToAverage / attemptsPerSec * 1000000000)}</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
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