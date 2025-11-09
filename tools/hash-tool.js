// ========================================
// HASH GENERATOR (ENHANCED)
// Category: Purple Team
// ========================================

(function() {
    'use strict';

    function render() {
        return `
            <div class="mb-4">
                <h4><i class="bi bi-hash"></i> Hash Generator</h4>
                <p class="text-secondary">Generate cryptographic hashes for security testing and verification</p>
            </div>
            
            <div class="mb-3">
                <label for="hashInput" class="form-label">Input Text</label>
                <textarea class="form-control font-monospace" id="hashInput" rows="6" placeholder="Enter text to hash..."></textarea>
            </div>
            
            <div class="row g-2 mb-3">
                <div class="col-auto">
                    <button class="btn btn-primary" onclick="generateHashes()">
                        <i class="bi bi-play-fill"></i> Generate Hashes
                    </button>
                </div>
                <div class="col-auto">
                    <button class="btn btn-outline-secondary" onclick="clearHashInput()">
                        <i class="bi bi-x-circle"></i> Clear
                    </button>
                </div>
                <div class="col-auto">
                    <div class="form-check mt-2">
                        <input class="form-check-input" type="checkbox" id="autoGenerate">
                        <label class="form-check-label" for="autoGenerate">
                            Auto-generate on input
                        </label>
                    </div>
                </div>
            </div>
            
            <div id="hashResults"></div>
            
            <div class="card bg-dark mt-3">
                <div class="card-header">
                    <i class="bi bi-info-circle"></i> Hash Algorithm Information
                </div>
                <div class="card-body">
                    <div class="row small">
                        <div class="col-md-6">
                            <h6>SHA-1 (160 bits)</h6>
                            <p class="mb-2">Legacy algorithm, considered weak. Still used in Git and some legacy systems.</p>
                            
                            <h6>SHA-256 (256 bits)</h6>
                            <p class="mb-2">Part of SHA-2 family. Widely used, recommended for most applications.</p>
                        </div>
                        <div class="col-md-6">
                            <h6>SHA-384 (384 bits)</h6>
                            <p class="mb-2">Truncated SHA-512. More secure than SHA-256, used in TLS/SSL.</p>
                            
                            <h6>SHA-512 (512 bits)</h6>
                            <p class="mb-2">Most secure SHA-2 variant. Recommended for high-security applications.</p>
                        </div>
                    </div>
                    <div class="alert alert-info mb-0 mt-2">
                        <strong>Security Note:</strong> These are cryptographic hash functions, not encryption. 
                        Hashes are one-way and cannot be reversed. Use for data integrity verification, 
                        password hashing (with salt), and digital signatures.
                    </div>
                </div>
            </div>
        `;
    }

    function init() {
        // Auto-generate on input if checkbox is checked
        document.addEventListener('input', function(e) {
            if (e.target.id === 'hashInput' && document.getElementById('autoGenerate')?.checked) {
                window.generateHashes();
            }
        });

        window.generateHashes = async function() {
            const input = document.getElementById('hashInput').value;
            const resultsDiv = document.getElementById('hashResults');
            
            if (!input) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter text to hash</div>';
                return;
            }

            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <span class="spinner-border spinner-border-sm me-2"></span>
                    Generating hashes...
                </div>
            `;

            const encoder = new TextEncoder();
            const data = encoder.encode(input);
            
            const algorithms = [
                { name: 'SHA-1', id: 'SHA-1', bits: 160, color: 'warning' },
                { name: 'SHA-256', id: 'SHA-256', bits: 256, color: 'success' },
                { name: 'SHA-384', id: 'SHA-384', bits: 384, color: 'primary' },
                { name: 'SHA-512', id: 'SHA-512', bits: 512, color: 'info' }
            ];
            
            let html = '<div class="row g-3">';
            
            for (const algo of algorithms) {
                try {
                    const hashBuffer = await crypto.subtle.digest(algo.id, data);
                    const hashArray = Array.from(new Uint8Array(hashBuffer));
                    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                    
                    html += `
                        <div class="col-12">
                            <div class="card bg-dark border-${algo.color}">
                                <div class="card-header bg-${algo.color} text-dark d-flex justify-content-between align-items-center">
                                    <strong>${algo.name}</strong>
                                    <span class="badge bg-dark">${algo.bits} bits</span>
                                </div>
                                <div class="card-body">
                                    <div class="input-group">
                                        <input type="text" class="form-control font-monospace small" 
                                               id="hash_${algo.id}" value="${hashHex}" readonly>
                                        <button class="btn btn-outline-primary" 
                                                onclick="copyHash('hash_${algo.id}', this)">
                                            <i class="bi bi-clipboard"></i>
                                        </button>
                                    </div>
                                    <div class="mt-2 small text-secondary">
                                        Length: ${hashHex.length} characters (${hashArray.length} bytes)
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                } catch (error) {
                    html += `
                        <div class="col-12">
                            <div class="alert alert-danger">
                                <strong>${algo.name} Error:</strong> ${window.escapeHtml(error.message)}
                            </div>
                        </div>
                    `;
                }
            }
            
            html += '</div>';
            
            // Add summary card
            html += `
                <div class="card bg-dark mt-3">
                    <div class="card-body">
                        <h6>Input Information</h6>
                        <ul class="list-unstyled small mb-0">
                            <li><strong>Input Length:</strong> ${input.length} characters</li>
                            <li><strong>Byte Size:</strong> ${data.length} bytes</li>
                            <li><strong>Input Preview:</strong> ${window.escapeHtml(input.substring(0, 100))}${input.length > 100 ? '...' : ''}</li>
                        </ul>
                    </div>
                </div>
            `;
            
            resultsDiv.innerHTML = html;
        };
        
        window.copyHash = function(inputId, button) {
            const input = document.getElementById(inputId);
            copyToClipboard(input.value, button);
        };
        
        window.clearHashInput = function() {
            document.getElementById('hashInput').value = '';
            document.getElementById('hashResults').innerHTML = '';
        };
    }

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'hash-generator',
        name: 'Hash Generator',
        description: 'Generate cryptographic hashes: SHA-1, SHA-256, SHA-384, SHA-512',
        icon: 'bi-hash',
        category: 'purple',
        render: render,
        init: init
    });
})();