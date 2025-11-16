// ========================================
// HASHCAT RULE GENERATOR
// Category: Red Team
// ========================================

(function() {
    'use strict';

    const ruleCategories = {
        basic: {
            name: 'Basic Mutations',
            icon: 'bi-pencil',
            color: 'success',
            rules: [
                { rule: ':', description: 'Do nothing (pass through)', example: 'password → password' },
                { rule: 'l', description: 'Lowercase all', example: 'PassWord → password' },
                { rule: 'u', description: 'Uppercase all', example: 'password → PASSWORD' },
                { rule: 'c', description: 'Capitalize first, lowercase rest', example: 'password → Password' },
                { rule: 'C', description: 'Lowercase first, uppercase rest', example: 'password → pASSWORD' },
                { rule: 't', description: 'Toggle case', example: 'password → PASSWORD' },
                { rule: 'r', description: 'Reverse', example: 'password → drowssap' },
                { rule: 'd', description: 'Duplicate', example: 'password → passwordpassword' },
                { rule: 'f', description: 'Duplicate reversed', example: 'password → passworddrowssap' },
                { rule: '{', description: 'Rotate left', example: 'password → asswordp' },
                { rule: '}', description: 'Rotate right', example: 'password → dpasswor' }
            ]
        },
        
        append: {
            name: 'Append Operations',
            icon: 'bi-arrow-right-circle',
            color: 'success',
            rules: [
                { rule: '$1', description: 'Append "1"', example: 'password → password1' },
                { rule: '$2', description: 'Append "2"', example: 'password → password2' },
                { rule: '$3', description: 'Append "3"', example: 'password → password3' },
                { rule: '$!', description: 'Append "!"', example: 'password → password!' },
                { rule: '$@', description: 'Append "@"', example: 'password → password@' },
                { rule: '$#', description: 'Append "#"', example: 'password → password#' },
                { rule: '$$', description: 'Append "$"', example: 'password → password$' }
            ]
        },
        
        prepend: {
            name: 'Prepend Operations',
            icon: 'bi-arrow-left-circle',
            color: 'success',
            rules: [
                { rule: '^1', description: 'Prepend "1"', example: 'password → 1password' },
                { rule: '^!', description: 'Prepend "!"', example: 'password → !password' },
                { rule: '^@', description: 'Prepend "@"', example: 'password → @password' },
                { rule: '^#', description: 'Prepend "#"', example: 'password → #password' }
            ]
        },
        
        substitute: {
            name: 'Character Substitution',
            icon: 'bi-arrow-left-right',
            color: 'success',
            rules: [
                { rule: 'sa@', description: 'Replace "a" with "@"', example: 'password → p@ssword' },
                { rule: 'se3', description: 'Replace "e" with "3"', example: 'hello → h3llo' },
                { rule: 'si!', description: 'Replace "i" with "!"', example: 'admin → adm!n' },
                { rule: 'so0', description: 'Replace "o" with "0"', example: 'password → passwrd' },
                { rule: 'ss$', description: 'Replace "s" with "$"', example: 'password → pa$$word' },
                { rule: 'sl1', description: 'Replace "l" with "1"', example: 'hello → he11o' },
                { rule: 'st+', description: 'Replace "t" with "+"', example: 'test → +es+' }
            ]
        },
        
        delete: {
            name: 'Delete Operations',
            icon: 'bi-trash',
            color: 'success',
            rules: [
                { rule: '[', description: 'Delete first character', example: 'password → assword' },
                { rule: ']', description: 'Delete last character', example: 'password → passwor' },
                { rule: 'D0', description: 'Delete at position 0', example: 'password → assword' },
                { rule: 'D3', description: 'Delete at position 3', example: 'password → pasword' }
            ]
        },
        
        years: {
            name: 'Year Patterns',
            icon: 'bi-calendar',
            color: 'success',
            rules: [
                { rule: '$2 $0 $2 $0', description: 'Append "2020"', example: 'password → password2020' },
                { rule: '$2 $0 $2 $1', description: 'Append "2021"', example: 'password → password2021' },
                { rule: '$2 $0 $2 $2', description: 'Append "2022"', example: 'password → password2022' },
                { rule: '$2 $0 $2 $3', description: 'Append "2023"', example: 'password → password2023' },
                { rule: '$2 $0 $2 $4', description: 'Append "2024"', example: 'password → password2024' },
                { rule: '$2 $0 $2 $5', description: 'Append "2025"', example: 'password → password2025' }
            ]
        }
    };

    function render() {
        return `
            <style>
                .rule-card {
                    background: #161b22;
                    border: 1px solid #30363d;
                    border-radius: 4px;
                    padding: 0.75rem;
                    margin-bottom: 0.5rem;
                    transition: all 0.2s;
                    cursor: pointer;
                }
                .rule-card:hover {
                    border-color: #00ff88;
                    background: #1c2128;
                }
                .rule-syntax {
                    font-family: 'Courier New', monospace;
                    background: #0d1117;
                    padding: 0.3rem 0.6rem;
                    border-radius: 3px;
                    font-size: 0.9rem;
                    color: #00ff88;
                }
                .rule-example {
                    font-family: 'Courier New', monospace;
                    font-size: 0.75rem;
                    color: #8b949e;
                }
                .category-section {
                    margin-bottom: 1.5rem;
                }
                .new-rule-area {
                    background: #0d1117;
                    border: 2px dashed #30363d;
                    border-radius: 6px;
                    padding: 1.5rem;
                    min-height: 120px;
                    transition: all 0.2s;
                }
                .new-rule-area.drag-over {
                    border-color: #00ff88;
                    background: #1c2128;
                }
                .rule-item {
                    display: inline-block;
                    background: #1c2128;
                    border: 1px solid #30363d;
                    padding: 0.4rem 0.7rem;
                    border-radius: 4px;
                    margin: 0.25rem;
                    font-family: 'Courier New', monospace;
                    font-size: 0.85rem;
                    cursor: move;
                    user-select: none;
                }
                .rule-item:hover {
                    border-color: #00ff88;
                }
                .rule-item.dragging {
                    opacity: 0.5;
                }
                .rule-item .remove-btn {
                    cursor: pointer;
                    margin-left: 0.5rem;
                    color: #dc3545;
                    font-weight: bold;
                }
                .rule-set {
                    background: #0d1117;
                    border: 1px solid #30363d;
                    border-radius: 6px;
                    padding: 1rem;
                    margin-bottom: 0.75rem;
                }
                .rule-set-header {
                    border-bottom: 1px solid #30363d;
                    padding-bottom: 0.5rem;
                    margin-bottom: 0.75rem;
                }
                .saved-rules-area {
                    max-height: 300px;
                    overflow-y: auto;
                }
            </style>
            
            <div class="mb-3">
                <h4><i class="bi bi-gear-fill"></i> Hashcat Rule Generator</h4>
                <p class="text-secondary small mb-0">Build password mutation rules by combining operations</p>
            </div>
            
            <!-- New Rule Builder -->
            <div class="card bg-dark mb-3">
                <div class="card-header">
                    <h6 class="mb-0"><i class="bi bi-tools"></i> Rule Builder</h6>
                </div>
                <div class="card-body">
                    <label class="form-label small">Click + to add rules, drag to reorder:</label>
                    <div class="new-rule-area" id="newRuleArea" ondrop="dropInNewArea(event)" ondragover="allowDrop(event)" ondragleave="dragLeave(event)">
                        <div class="text-center text-secondary" id="emptyState">
                            <i class="bi bi-plus-circle"></i> Click + buttons below to add rules here
                        </div>
                        <div id="newRuleItems"></div>
                    </div>
                    
                    <div class="d-flex gap-2 mt-3 flex-wrap">
                        <button class="btn btn-success btn-sm" onclick="saveRule()">
                            <i class="bi bi-check-lg"></i> Save Rule
                        </button>
                        <button class="btn btn-outline-secondary btn-sm" onclick="clearNewRule()">
                            <i class="bi bi-trash"></i> Clear
                        </button>
                        <span class="text-secondary small align-self-center" id="rulePreview"></span>
                    </div>
                </div>
            </div>
            
            <!-- Saved Rules -->
            <div class="card bg-dark mb-3">
                <div class="card-header">
                    <div class="d-flex justify-content-between align-items-center flex-wrap gap-2">
                        <h6 class="mb-0"><i class="bi bi-collection"></i> Saved Rules</h6>
                        <div class="d-flex gap-2 flex-wrap">
                            <button class="btn btn-sm btn-success" onclick="downloadRules()">
                                <i class="bi bi-download"></i> Download
                            </button>
                            <button class="btn btn-sm btn-info" onclick="copyAllRules()">
                                <i class="bi bi-clipboard"></i> Copy
                            </button>
                            <button class="btn btn-sm btn-outline-danger" onclick="clearAllRules()">
                                <i class="bi bi-trash"></i> Clear All
                            </button>
                        </div>
                    </div>
                </div>
                <div class="card-body">
                    <div class="saved-rules-area" id="savedRulesArea">
                        <div class="text-center text-secondary py-3">
                            <i class="bi bi-inbox"></i> No saved rules yet
                        </div>
                    </div>
                    <div class="mt-2 text-secondary small" id="ruleCount">0 rules saved</div>
                </div>
            </div>
            
            <!-- Test Rules -->
            <div class="card bg-dark mb-3">
                <div class="card-header">
                    <h6 class="mb-0"><i class="bi bi-play-circle"></i> Test Rules</h6>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-12 col-md-6 mb-2">
                            <label class="form-label small">Test Password:</label>
                            <input type="text" class="form-control" id="testPassword" value="password" placeholder="password">
                        </div>
                        <div class="col-12 col-md-6 mb-2">
                            <label class="form-label small d-none d-md-block">&nbsp;</label>
                            <button class="btn btn-primary w-100" onclick="testRules()">
                                <i class="bi bi-play-fill"></i> Test Rules
                            </button>
                        </div>
                    </div>
                    <div id="testResults" class="mt-2"></div>
                </div>
            </div>
            
            <!-- Search -->
            <div class="mb-3">
                <input type="text" class="form-control" id="ruleSearch" placeholder="Search available rules...">
            </div>
            
            <!-- Available Rules -->
            <h5 class="mb-3"><i class="bi bi-list-check"></i> Available Rules</h5>
            <div id="ruleCategories"></div>
        `;
    }

    function init() {
        let newRuleItems = [];
        let savedRules = [];
        let draggedIndex = null;
        
        // Render new rule area
        function renderNewRuleArea() {
            const container = document.getElementById('newRuleItems');
            const emptyState = document.getElementById('emptyState');
            const preview = document.getElementById('rulePreview');
            
            if (newRuleItems.length === 0) {
                container.innerHTML = '';
                emptyState.style.display = 'block';
                preview.textContent = '';
                return;
            }
            
            emptyState.style.display = 'none';
            
            let html = '';
            newRuleItems.forEach((rule, idx) => {
                html += `
                    <span class="rule-item" draggable="true" ondragstart="dragStart(event, ${idx})" ondragover="dragOver(event, ${idx})" ondrop="drop(event, ${idx})">
                        ${window.escapeHtml(rule)}
                        <span class="remove-btn" onclick="removeFromNew(${idx})">×</span>
                    </span>
                `;
            });
            
            container.innerHTML = html;
            preview.textContent = `Preview: ${newRuleItems.join(' ')}`;
        }
        
        // Render saved rules
        function renderSavedRules() {
            const container = document.getElementById('savedRulesArea');
            const countDiv = document.getElementById('ruleCount');
            
            if (savedRules.length === 0) {
                container.innerHTML = `
                    <div class="text-center text-secondary py-3">
                        <i class="bi bi-inbox"></i> No saved rules yet
                    </div>
                `;
                countDiv.textContent = '0 rules saved';
                return;
            }
            
            let html = '';
            savedRules.forEach((rule, idx) => {
                html += `
                    <div class="rule-set">
                        <div class="rule-set-header d-flex justify-content-between align-items-center">
                            <small class="text-secondary"><i class="bi bi-hash"></i> Rule ${idx + 1}</small>
                            <button class="btn btn-sm btn-outline-danger" onclick="removeSavedRule(${idx})">
                                <i class="bi bi-trash"></i>
                            </button>
                        </div>
                        <code class="text-info">${window.escapeHtml(rule)}</code>
                    </div>
                `;
            });
            
            container.innerHTML = html;
            countDiv.textContent = `${savedRules.length} rule${savedRules.length !== 1 ? 's' : ''} saved`;
        }
        
        // Render available rules
        function renderCategories(searchQuery = '') {
            const container = document.getElementById('ruleCategories');
            let html = '';
            const query = searchQuery.toLowerCase();
            
            Object.entries(ruleCategories).forEach(([key, category]) => {
                let categoryHtml = '';
                let visibleCount = 0;
                
                category.rules.forEach((ruleItem) => {
                    const matches = !query || 
                                   ruleItem.description.toLowerCase().includes(query) ||
                                   ruleItem.example.toLowerCase().includes(query) ||
                                   ruleItem.rule.toLowerCase().includes(query);
                    
                    if (matches) {
                        visibleCount++;
                        categoryHtml += `
                            <div class="rule-card">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div class="flex-grow-1">
                                        <div class="mb-1">
                                            <span class="rule-syntax">${window.escapeHtml(ruleItem.rule)}</span>
                                        </div>
                                        <div class="small mb-1">${ruleItem.description}</div>
                                        <div class="rule-example">${window.escapeHtml(ruleItem.example)}</div>
                                    </div>
                                    <button class="btn btn-sm btn-outline-success" onclick="addToNew('${ruleItem.rule.replace(/'/g, "\\'")}')">
                                        <i class="bi bi-plus-lg"></i>
                                    </button>
                                </div>
                            </div>
                        `;
                    }
                });
                
                if (visibleCount > 0) {
                    html += `
                        <div class="category-section">
                            <h5 class="mb-2">
                                <i class="bi ${category.icon} text-${category.color}"></i>
                                ${category.name}
                                <span class="badge bg-${category.color}">${visibleCount}</span>
                            </h5>
                            ${categoryHtml}
                        </div>
                    `;
                }
            });
            
            container.innerHTML = html || '<div class="alert alert-warning">No rules found.</div>';
        }
        
        // Add rule to new area
        window.addToNew = function(rule) {
            newRuleItems.push(rule);
            renderNewRuleArea();
        };
        
        // Remove from new area
        window.removeFromNew = function(index) {
            newRuleItems.splice(index, 1);
            renderNewRuleArea();
        };
        
        // Drag and drop handlers
        window.dragStart = function(event, index) {
            draggedIndex = index;
            event.target.classList.add('dragging');
            event.dataTransfer.effectAllowed = 'move';
        };
        
        window.dragOver = function(event, index) {
            event.preventDefault();
            
            if (draggedIndex === null || draggedIndex === index) return;
            
            const draggedItem = newRuleItems[draggedIndex];
            newRuleItems.splice(draggedIndex, 1);
            newRuleItems.splice(index, 0, draggedItem);
            draggedIndex = index;
            
            renderNewRuleArea();
        };
        
        window.drop = function(event, index) {
            event.preventDefault();
            draggedIndex = null;
            document.querySelectorAll('.dragging').forEach(el => el.classList.remove('dragging'));
        };
        
        window.allowDrop = function(event) {
            event.preventDefault();
            event.currentTarget.classList.add('drag-over');
        };
        
        window.dragLeave = function(event) {
            if (event.currentTarget.contains(event.relatedTarget)) return;
            event.currentTarget.classList.remove('drag-over');
        };
        
        window.dropInNewArea = function(event) {
            event.preventDefault();
            event.currentTarget.classList.remove('drag-over');
        };
        
        // Save rule
        window.saveRule = function() {
            if (newRuleItems.length === 0) {
                alert('Add some rules first!');
                return;
            }
            
            const rule = newRuleItems.join(' ');
            savedRules.push(rule);
            newRuleItems = [];
            
            renderNewRuleArea();
            renderSavedRules();
        };
        
        // Clear new rule
        window.clearNewRule = function() {
            if (newRuleItems.length > 0) {
                newRuleItems = [];
                renderNewRuleArea();
            }
        };
        
        // Remove saved rule
        window.removeSavedRule = function(index) {
            savedRules.splice(index, 1);
            renderSavedRules();
        };
        
        // Clear all rules
        window.clearAllRules = function() {
            if (savedRules.length > 0) {
                if (confirm('Clear all saved rules?')) {
                    savedRules = [];
                    renderSavedRules();
                }
            }
        };
        
        // Copy all rules
        window.copyAllRules = async function() {
            if (savedRules.length === 0) {
                alert('No rules to copy');
                return;
            }
            
            try {
                await navigator.clipboard.writeText(savedRules.join('\n'));
                alert(`Copied ${savedRules.length} rules!`);
            } catch (err) {
                console.error('Failed to copy:', err);
            }
        };
        
        // Download rules
        window.downloadRules = function() {
            if (savedRules.length === 0) {
                alert('No rules to download');
                return;
            }
            
            const content = savedRules.join('\n');
            const filename = `hashcat-rules-${Date.now()}.rule`;
            window.downloadFile(filename, content, 'text/plain');
        };
        
        // Test rules
        window.testRules = function() {
            const testPassword = document.getElementById('testPassword').value;
            const resultsDiv = document.getElementById('testResults');
            
            if (!testPassword) {
                resultsDiv.innerHTML = '<div class="alert alert-warning small">Please enter a test password</div>';
                return;
            }
            
            if (savedRules.length === 0) {
                resultsDiv.innerHTML = '<div class="alert alert-warning small">No saved rules to test</div>';
                return;
            }
            
            const mutations = savedRules.slice(0, 50).map((rule, idx) => {
                const result = simulateRule(testPassword, rule);
                return `Rule ${idx + 1}: ${window.escapeHtml(rule).padEnd(35)} → ${window.escapeHtml(result)}`;
            });
            
            resultsDiv.innerHTML = `
                <div class="alert alert-info small mb-2">
                    <strong><i class="bi bi-info-circle"></i> Note:</strong> Simplified simulation. Actual Hashcat may differ.
                </div>
                <div class="card bg-dark">
                    <div class="card-body">
                        <h6 class="mb-2">Output (showing ${Math.min(savedRules.length, 50)} rules):</h6>
                        <pre class="bg-black p-2 rounded small mb-0" style="max-height: 400px; overflow-y: auto;">${mutations.join('\n')}</pre>
                    </div>
                </div>
            `;
        };
        
        // Simulate rule
        function simulateRule(password, rule) {
            try {
                let result = password;
                const operations = rule.split(' ');
                
                operations.forEach(op => {
                    op = op.trim();
                    if (!op) return;
                    
                    if (op === ':') return;
                    else if (op === 'l') result = result.toLowerCase();
                    else if (op === 'u') result = result.toUpperCase();
                    else if (op === 'c') result = result.charAt(0).toUpperCase() + result.slice(1).toLowerCase();
                    else if (op === 'C') result = result.charAt(0).toLowerCase() + result.slice(1).toUpperCase();
                    else if (op === 't') result = result.split('').map(c => c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase()).join('');
                    else if (op === 'r') result = result.split('').reverse().join('');
                    else if (op === 'd') result = result + result;
                    else if (op === 'f') result = result + result.split('').reverse().join('');
                    else if (op === '{') result = result.slice(1) + result.charAt(0);
                    else if (op === '}') result = result.slice(-1) + result.slice(0, -1);
                    else if (op === '[') result = result.slice(1);
                    else if (op === ']') result = result.slice(0, -1);
                    else if (op.startsWith('$')) result += op.slice(1);
                    else if (op.startsWith('^')) result = op.slice(1) + result;
                    else if (op.startsWith('s') && op.length === 3) result = result.replace(new RegExp(op[1], 'g'), op[2]);
                    else if (op.startsWith('D')) {
                        const pos = parseInt(op.slice(1));
                        if (!isNaN(pos)) result = result.slice(0, pos) + result.slice(pos + 1);
                    }
                });
                
                return result;
            } catch (e) {
                return '[error]';
            }
        }
        
        // Search
        document.getElementById('ruleSearch').addEventListener('input', function() {
            renderCategories(this.value);
        });
        
        // Cleanup dragging class
        document.addEventListener('dragend', function(e) {
            document.querySelectorAll('.dragging').forEach(el => el.classList.remove('dragging'));
            draggedIndex = null;
        });
        
        // Initialize
        renderNewRuleArea();
        renderSavedRules();
        renderCategories();
    }

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'hashcat-rule-generator',
        name: 'Hashcat Rule Generator',
        description: 'Build password mutation rules by combining operations - drag to reorder',
        icon: 'bi-gear-fill',
        category: 'red',
        render: render,
        init: init
    });
})();