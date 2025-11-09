// ========================================
// LISTS GENERATOR FOR FUZZING/ATTACKS
// Category: Red Team
// ========================================

(function() {
    'use strict';

    function render() {
        return `
            <div class="mb-4">
                <h4><i class="bi bi-list-ul"></i> Attack Lists Generator</h4>
                <p class="text-secondary">Generate custom wordlists for Burp Intruder, fuzzing, and brute force attacks</p>
            </div>
            
            <ul class="nav nav-tabs mb-3" id="listsTabs" role="tablist">
                <li class="nav-item">
                    <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#numeric-tab">
                        <i class="bi bi-123"></i> Numeric
                    </button>
                </li>
                <li class="nav-item">
                    <button class="nav-link" data-bs-toggle="tab" data-bs-target="#alpha-tab">
                        <i class="bi bi-alphabet"></i> Alphabetic
                    </button>
                </li>
                <li class="nav-item">
                    <button class="nav-link" data-bs-toggle="tab" data-bs-target="#dates-tab">
                        <i class="bi bi-calendar"></i> Dates
                    </button>
                </li>
                <li class="nav-item">
                    <button class="nav-link" data-bs-toggle="tab" data-bs-target="#custom-tab">
                        <i class="bi bi-gear"></i> Custom
                    </button>
                </li>
            </ul>
            
            <div class="tab-content">
                <!-- Numeric Tab -->
                <div class="tab-pane fade show active" id="numeric-tab">
                    <div class="row g-3">
                        <div class="col-md-6">
                            <label for="numStart" class="form-label">Start Number</label>
                            <input type="number" class="form-control" id="numStart" value="0">
                        </div>
                        <div class="col-md-6">
                            <label for="numEnd" class="form-label">End Number</label>
                            <input type="number" class="form-control" id="numEnd" value="9999">
                        </div>
                        <div class="col-md-6">
                            <label for="numPadding" class="form-label">Zero Padding (digits)</label>
                            <input type="number" class="form-control" id="numPadding" value="4" min="0">
                        </div>
                        <div class="col-md-6">
                            <label for="numPrefix" class="form-label">Prefix (optional)</label>
                            <input type="text" class="form-control" id="numPrefix" placeholder="e.g., ID-">
                        </div>
                        <div class="col-12">
                            <button class="btn btn-primary" onclick="generateNumericList()">
                                <i class="bi bi-play-fill"></i> Generate
                            </button>
                        </div>
                    </div>
                </div>
                
                <!-- Alphabetic Tab -->
                <div class="tab-pane fade" id="alpha-tab">
                    <div class="row g-3">
                        <div class="col-md-6">
                            <label for="alphaLength" class="form-label">String Length</label>
                            <input type="number" class="form-control" id="alphaLength" value="2" min="1" max="4">
                            <small class="text-warning">Warning: Length > 3 generates large lists</small>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Character Set</label>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="alphaLower" checked>
                                <label class="form-check-label" for="alphaLower">Lowercase</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="alphaUpper">
                                <label class="form-check-label" for="alphaUpper">Uppercase</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="alphaDigits">
                                <label class="form-check-label" for="alphaDigits">Digits</label>
                            </div>
                        </div>
                        <div class="col-12">
                            <button class="btn btn-primary" onclick="generateAlphaList()">
                                <i class="bi bi-play-fill"></i> Generate
                            </button>
                        </div>
                    </div>
                </div>
                
                <!-- Dates Tab -->
                <div class="tab-pane fade" id="dates-tab">
                    <div class="row g-3">
                        <div class="col-md-6">
                            <label for="dateStart" class="form-label">Start Date</label>
                            <input type="date" class="form-control" id="dateStart">
                        </div>
                        <div class="col-md-6">
                            <label for="dateEnd" class="form-label">End Date</label>
                            <input type="date" class="form-control" id="dateEnd">
                        </div>
                        <div class="col-12">
                            <label for="dateFormat" class="form-label">Date Format</label>
                            <select class="form-select" id="dateFormat">
                                <option value="YYYY-MM-DD">YYYY-MM-DD (2024-01-15)</option>
                                <option value="DD/MM/YYYY">DD/MM/YYYY (15/01/2024)</option>
                                <option value="MM/DD/YYYY">MM/DD/YYYY (01/15/2024)</option>
                                <option value="YYYYMMDD">YYYYMMDD (20240115)</option>
                                <option value="DDMMYYYY">DDMMYYYY (15012024)</option>
                            </select>
                        </div>
                        <div class="col-12">
                            <button class="btn btn-primary" onclick="generateDatesList()">
                                <i class="bi bi-play-fill"></i> Generate
                            </button>
                        </div>
                    </div>
                </div>
                
                <!-- Custom Tab -->
                <div class="tab-pane fade" id="custom-tab">
                    <div class="row g-3">
                        <div class="col-12">
                            <label for="customBase" class="form-label">Base Words (one per line)</label>
                            <textarea class="form-control" id="customBase" rows="6" placeholder="admin\nuser\ntest"></textarea>
                        </div>
                        <div class="col-md-6">
                            <label for="customSuffix" class="form-label">Suffixes (comma separated)</label>
                            <input type="text" class="form-control" id="customSuffix" placeholder="123, 2024, !">
                        </div>
                        <div class="col-md-6">
                            <label for="customPrefix" class="form-label">Prefixes (comma separated)</label>
                            <input type="text" class="form-control" id="customPrefix" placeholder="test_, dev_, prod_">
                        </div>
                        <div class="col-12">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="customCasing">
                                <label class="form-check-label" for="customCasing">
                                    Include case variations (lowercase, UPPERCASE, Capitalize)
                                </label>
                            </div>
                        </div>
                        <div class="col-12">
                            <button class="btn btn-primary" onclick="generateCustomList()">
                                <i class="bi bi-play-fill"></i> Generate
                            </button>
                        </div>
                    </div>
                </div>
            </div>
            
            <div id="listsResults" class="mt-3"></div>
        `;
    }

    function init() {
        // Set default dates
        const today = new Date();
        const startDate = new Date(today.getFullYear(), 0, 1);
        document.getElementById('dateStart').valueAsDate = startDate;
        document.getElementById('dateEnd').valueAsDate = today;

        window.generateNumericList = function() {
            const start = parseInt(document.getElementById('numStart').value);
            const end = parseInt(document.getElementById('numEnd').value);
            const padding = parseInt(document.getElementById('numPadding').value);
            const prefix = document.getElementById('numPrefix').value;
            
            if (start > end) {
                displayList('listsResults', [], 'Start number must be less than or equal to end number', 'warning');
                return;
            }
            
            const count = end - start + 1;
            if (count > 100000) {
                if (!confirm(`This will generate ${count} entries. Continue?`)) return;
            }
            
            const list = [];
            for (let i = start; i <= end; i++) {
                const padded = String(i).padStart(padding, '0');
                list.push(prefix + padded);
            }
            
            displayList('listsResults', list, 'Numeric List Generated');
        };

        window.generateAlphaList = function() {
            const length = parseInt(document.getElementById('alphaLength').value);
            const includeLower = document.getElementById('alphaLower').checked;
            const includeUpper = document.getElementById('alphaUpper').checked;
            const includeDigits = document.getElementById('alphaDigits').checked;
            
            let charset = '';
            if (includeLower) charset += 'abcdefghijklmnopqrstuvwxyz';
            if (includeUpper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            if (includeDigits) charset += '0123456789';
            
            if (charset.length === 0) {
                displayList('listsResults', [], 'Please select at least one character set', 'warning');
                return;
            }
            
            const totalCombinations = Math.pow(charset.length, length);
            if (totalCombinations > 100000) {
                if (!confirm(`This will generate ${totalCombinations} entries. This may take a while. Continue?`)) return;
            }
            
            const list = [];
            const generate = (current) => {
                if (current.length === length) {
                    list.push(current);
                    return;
                }
                for (let char of charset) {
                    generate(current + char);
                }
            };
            
            generate('');
            displayList('listsResults', list, 'Alphabetic List Generated');
        };

        window.generateDatesList = function() {
            const start = new Date(document.getElementById('dateStart').value);
            const end = new Date(document.getElementById('dateEnd').value);
            const format = document.getElementById('dateFormat').value;
            
            if (start > end) {
                displayList('listsResults', [], 'Start date must be before end date', 'warning');
                return;
            }
            
            const list = [];
            const current = new Date(start);
            
            while (current <= end) {
                let formatted;
                const y = current.getFullYear();
                const m = String(current.getMonth() + 1).padStart(2, '0');
                const d = String(current.getDate()).padStart(2, '0');
                
                switch(format) {
                    case 'YYYY-MM-DD':
                        formatted = `${y}-${m}-${d}`;
                        break;
                    case 'DD/MM/YYYY':
                        formatted = `${d}/${m}/${y}`;
                        break;
                    case 'MM/DD/YYYY':
                        formatted = `${m}/${d}/${y}`;
                        break;
                    case 'YYYYMMDD':
                        formatted = `${y}${m}${d}`;
                        break;
                    case 'DDMMYYYY':
                        formatted = `${d}${m}${y}`;
                        break;
                }
                
                list.push(formatted);
                current.setDate(current.getDate() + 1);
            }
            
            displayList('listsResults', list, 'Date List Generated');
        };

        window.generateCustomList = function() {
            const baseWords = document.getElementById('customBase').value.split('\n').filter(w => w.trim());
            const suffixes = document.getElementById('customSuffix').value.split(',').map(s => s.trim()).filter(s => s);
            const prefixes = document.getElementById('customPrefix').value.split(',').map(p => p.trim()).filter(p => p);
            const includeCasing = document.getElementById('customCasing').checked;
            
            if (baseWords.length === 0) {
                displayList('listsResults', [], 'Please enter at least one base word', 'warning');
                return;
            }
            
            const list = new Set();
            
            baseWords.forEach(word => {
                word = word.trim();
                if (!word) return;
                
                const variants = [word];
                if (includeCasing) {
                    variants.push(word.toLowerCase());
                    variants.push(word.toUpperCase());
                    variants.push(word.charAt(0).toUpperCase() + word.slice(1).toLowerCase());
                }
                
                variants.forEach(variant => {
                    list.add(variant);
                    
                    prefixes.forEach(prefix => {
                        list.add(prefix + variant);
                    });
                    
                    suffixes.forEach(suffix => {
                        list.add(variant + suffix);
                    });
                    
                    prefixes.forEach(prefix => {
                        suffixes.forEach(suffix => {
                            list.add(prefix + variant + suffix);
                        });
                    });
                });
            });
            
            displayList('listsResults', Array.from(list), 'Custom List Generated');
        };

        function displayList(containerId, list, title, type = 'success') {
            const container = document.getElementById(containerId);
            
            if (list.length === 0) {
                container.innerHTML = `<div class="alert alert-${type}">${title}</div>`;
                return;
            }
            
            const preview = list.slice(0, 50).join('\n');
            const hasMore = list.length > 50;
            
            container.innerHTML = `
                <div class="card bg-dark">
                    <div class="card-header bg-success text-dark">
                        <i class="bi bi-check-circle-fill"></i> ${title}
                    </div>
                    <div class="card-body">
                        <div class="alert alert-info">
                            <strong>Total Entries:</strong> ${list.length.toLocaleString()}
                            ${hasMore ? '<br><small>Showing first 50 entries in preview</small>' : ''}
                        </div>
                        
                        <label class="form-label">Preview</label>
                        <textarea class="form-control font-monospace" rows="10" readonly>${window.escapeHtml(preview)}</textarea>
                        
                        <div class="mt-3">
                            <button class="btn btn-primary" onclick="downloadList(${JSON.stringify(list)})">
                                <i class="bi bi-download"></i> Download List
                            </button>
                            <button class="btn btn-outline-primary" onclick="copyListToClipboard(${JSON.stringify(list)}, this)">
                                <i class="bi bi-clipboard"></i> Copy All
                            </button>
                        </div>
                    </div>
                </div>
            `;
        }
        
        window.downloadList = function(list) {
            const content = list.join('\n');
            const filename = `wordlist_${Date.now()}.txt`;
            window.downloadFile(filename, content, 'text/plain');
        };
        
        window.copyListToClipboard = function(list, button) {
            const content = list.join('\n');
            copyToClipboard(content, button);
        };
    }

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'lists-generator',
        name: 'Wordlists Generator',
        description: 'Generate custom wordlists for fuzzing, brute force, and penetration testing',
        icon: 'bi-list-ul',
        category: 'red',
        render: render,
        init: init
    });
})();