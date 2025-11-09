// ========================================
// ENCRYPTION TOOL (ENHANCED)
// Category: Purple Team
// ========================================

(function() {
    'use strict';

    function render() {
        return `
            <div class="mb-4">
                <h4><i class="bi bi-lock-fill"></i> Encryption Tool</h4>
                <p class="text-secondary">Encrypt and decrypt text using AES-256-GCM with PBKDF2 key derivation</p>
            </div>
            
            <ul class="nav nav-tabs mb-3" role="tablist">
                <li class="nav-item">
                    <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#encrypt-tab">
                        <i class="bi bi-lock"></i> Encrypt
                    </button>
                </li>
                <li class="nav-item">
                    <button class="nav-link" data-bs-toggle="tab" data-bs-target="#decrypt-tab">
                        <i class="bi bi-unlock"></i> Decrypt
                    </button>
                </li>
            </ul>
            
            <div class="tab-content">
                <!-- Encrypt Tab -->
                <div class="tab-pane fade show active" id="encrypt-tab">
                    <div class="mb-3">
                        <label for="encryptInput" class="form-label">Text to Encrypt</label>
                        <textarea class="form-control font-monospace" id="encryptInput" rows="6" 
                                  placeholder="Enter sensitive text..."></textarea>
                    </div>
                    
                    <div class="mb-3">
                        <label for="encryptPassword" class="form-label">Password</label>
                        <div class="input-group">
                            <input type="password" class="form-control" id="encryptPassword" 
                                   placeholder="Enter a strong password">
                            <button class="btn btn-outline-secondary" type="button" 
                                    onclick="togglePassword('encryptPassword')">
                                <i class="bi bi-eye" id="encryptPassword-icon"></i>
                            </button>
                        </div>
                        <div class="form-text">
                            Use a strong password. Minimum 12 characters recommended.
                        </div>
                    </div>
                    
                    <button class="btn btn-primary" onclick="encryptText()">
                        <i class="bi bi-lock-fill"></i> Encrypt
                    </button>
                </div>
                
                <!-- Decrypt Tab -->
                <div class="tab-pane fade" id="decrypt-tab">
                    <div class="mb-3">
                        <label for="decryptInput" class="form-label">Encrypted Text (Base64)</label>
                        <textarea class="form-control font-monospace" id="decryptInput" rows="6" 
                                  placeholder="Paste encrypted text here..."></textarea>
                    </div>
                    
                    <div class="mb-3">
                        <label for="decryptPassword" class="form-label">Password</label>
                        <div class="input-group">
                            <input type="password" class="form-control" id="decryptPassword" 
                                   placeholder="Enter the password">
                            <button class="btn btn-outline-secondary" type="button" 
                                    onclick="togglePassword('decryptPassword')">
                                <i class="bi bi-eye" id="decryptPassword-icon"></i>
                            </button>
                        </div>
                    </div>
                    
                    <button class="btn btn-warning" onclick="decryptText()">
                        <i class="bi bi-unlock-fill"></i> Decrypt
                    </button>
                </div>
            </div>
            
            <div id="encryptResults" class="mt-3"></div>
            
            <div class="card bg-dark mt-3">
                <div class="card-header">
                    <i class="bi bi-shield-check"></i> Security Information
                </div>
                <div class="card-body">
                    <div class="row small">
                        <div class="col-md-6">
                            <h6>Encryption Details</h6>
                            <ul>
                                <li><strong>Algorithm:</strong> AES-256-GCM</li>
                                <li><strong>Key Derivation:</strong> PBKDF2</li>
                                <li><strong>Iterations:</strong> 100,000</li>
                                <li><strong>Salt:</strong> 16 bytes (random)</li>
                                <li><strong>IV:</strong> 12 bytes (random)</li>
                            </ul>
                        </div>
                        <div class="col-md-6">
                            <h6>Best Practices</h6>
                            <ul>
                                <li>Use long, random passwords</li>
                                <li>Don't reuse passwords</li>
                                <li>Store encrypted data safely</li>
                                <li>Keep password separate from data</li>
                                <li>Consider additional layers of security</li>
                            </ul>
                        </div>
                    </div>
                    <div class="alert alert-warning mb-0 mt-2">
                        <strong>Warning:</strong> Client-side encryption is convenient but less secure than 
                        server-side encryption. Use for testing and non-critical data only.
                    </div>
                </div>
            </div>
        `;
    }

    function init() {
        window.togglePassword = function(fieldId) {
            const field = document.getElementById(fieldId);
            const icon = document.getElementById(fieldId + '-icon');
            
            if (field.type === 'password') {
                field.type = 'text';
                icon.classList.remove('bi-eye');
                icon.classList.add('bi-eye-slash');
            } else {
                field.type = 'password';
                icon.classList.remove('bi-eye-slash');
                icon.classList.add('bi-eye');
            }
        };

        window.encryptText = async function() {
            const text = document.getElementById('encryptInput').value;
            const password = document.getElementById('encryptPassword').value;
            const resultsDiv = document.getElementById('encryptResults');
            
            if (!text) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter text to encrypt</div>';
                return;
            }
            
            if (!password) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter a password</div>';
                return;
            }
            
            if (password.length < 8) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Password should be at least 8 characters long</div>';
                return;
            }

            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <span class="spinner-border spinner-border-sm me-2"></span>
                    Encrypting...
                </div>
            `;

            try {
                const encoder = new TextEncoder();
                const salt = crypto.getRandomValues(new Uint8Array(16));
                const iv = crypto.getRandomValues(new Uint8Array(12));
                
                // Derive key from password
                const keyMaterial = await crypto.subtle.importKey(
                    'raw',
                    encoder.encode(password),
                    'PBKDF2',
                    false,
                    ['deriveBits', 'deriveKey']
                );
                
                const key = await crypto.subtle.deriveKey(
                    {
                        name: 'PBKDF2',
                        salt: salt,
                        iterations: 100000,
                        hash: 'SHA-256'
                    },
                    keyMaterial,
                    { name: 'AES-GCM', length: 256 },
                    false,
                    ['encrypt']
                );
                
                // Encrypt the text
                const encrypted = await crypto.subtle.encrypt(
                    { name: 'AES-GCM', iv: iv },
                    key,
                    encoder.encode(text)
                );
                
                // Combine salt + iv + encrypted data
                const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
                combined.set(salt, 0);
                combined.set(iv, salt.length);
                combined.set(new Uint8Array(encrypted), salt.length + iv.length);
                
                // Convert to base64
                const base64 = btoa(String.fromCharCode(...combined));
                
                resultsDiv.innerHTML = `
                    <div class="card bg-dark border-success">
                        <div class="card-header bg-success text-dark">
                            <i class="bi bi-check-circle-fill"></i> Encryption Successful
                        </div>
                        <div class="card-body">
                            <label class="form-label">Encrypted Data (Base64)</label>
                            <div class="input-group mb-2">
                                <textarea class="form-control font-monospace small" id="encryptedOutput" 
                                          rows="4" readonly>${base64}</textarea>
                            </div>
                            <div class="d-flex gap-2">
                                <button class="btn btn-outline-primary" onclick="copyEncrypted()">
                                    <i class="bi bi-clipboard"></i> Copy
                                </button>
                                <button class="btn btn-outline-secondary" onclick="downloadEncrypted()">
                                    <i class="bi bi-download"></i> Download
                                </button>
                            </div>
                            <div class="mt-3 small">
                                <div class="row">
                                    <div class="col-md-4">
                                        <strong>Original Size:</strong> ${text.length} chars
                                    </div>
                                    <div class="col-md-4">
                                        <strong>Encrypted Size:</strong> ${base64.length} chars
                                    </div>
                                    <div class="col-md-4">
                                        <strong>Overhead:</strong> ${((base64.length / text.length - 1) * 100).toFixed(1)}%
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
                
                // Store for download
                window.currentEncrypted = base64;
            } catch (error) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-danger">
                        <strong><i class="bi bi-exclamation-triangle-fill"></i> Encryption Error:</strong> 
                        ${window.escapeHtml(error.message)}
                    </div>
                `;
            }
        };

        window.decryptText = async function() {
            const encryptedBase64 = document.getElementById('decryptInput').value.trim();
            const password = document.getElementById('decryptPassword').value;
            const resultsDiv = document.getElementById('encryptResults');
            
            if (!encryptedBase64) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter encrypted text</div>';
                return;
            }
            
            if (!password) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter the password</div>';
                return;
            }

            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <span class="spinner-border spinner-border-sm me-2"></span>
                    Decrypting...
                </div>
            `;

            try {
                const encoder = new TextEncoder();
                
                // Decode base64
                const combined = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
                
                // Extract salt, iv, and encrypted data
                const salt = combined.slice(0, 16);
                const iv = combined.slice(16, 28);
                const encrypted = combined.slice(28);
                
                // Derive key from password
                const keyMaterial = await crypto.subtle.importKey(
                    'raw',
                    encoder.encode(password),
                    'PBKDF2',
                    false,
                    ['deriveBits', 'deriveKey']
                );
                
                const key = await crypto.subtle.deriveKey(
                    {
                        name: 'PBKDF2',
                        salt: salt,
                        iterations: 100000,
                        hash: 'SHA-256'
                    },
                    keyMaterial,
                    { name: 'AES-GCM', length: 256 },
                    false,
                    ['decrypt']
                );
                
                // Decrypt
                const decrypted = await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: iv },
                    key,
                    encrypted
                );
                
                const text = new TextDecoder().decode(decrypted);
                
                resultsDiv.innerHTML = `
                    <div class="card bg-dark border-success">
                        <div class="card-header bg-success text-dark">
                            <i class="bi bi-check-circle-fill"></i> Decryption Successful
                        </div>
                        <div class="card-body">
                            <label class="form-label">Decrypted Text</label>
                            <textarea class="form-control" rows="6" readonly>${window.escapeHtml(text)}</textarea>
                            <button class="btn btn-outline-primary mt-2" onclick="copyDecrypted('${text.replace(/'/g, "\\'")}')">
                                <i class="bi bi-clipboard"></i> Copy
                            </button>
                            <div class="mt-3 small">
                                <strong>Decrypted Length:</strong> ${text.length} characters
                            </div>
                        </div>
                    </div>
                `;
            } catch (error) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-danger">
                        <strong><i class="bi bi-exclamation-triangle-fill"></i> Decryption Failed</strong>
                        <p class="mb-0">Possible reasons:</p>
                        <ul class="mb-0">
                            <li>Incorrect password</li>
                            <li>Corrupted or invalid encrypted data</li>
                            <li>Data was not encrypted with this tool</li>
                        </ul>
                    </div>
                `;
            }
        };
        
        window.copyEncrypted = function() {
            const text = document.getElementById('encryptedOutput').value;
            navigator.clipboard.writeText(text).then(() => {
                const btn = event.target.closest('button');
                const originalHTML = btn.innerHTML;
                btn.innerHTML = '<i class="bi bi-check"></i> Copied!';
                setTimeout(() => btn.innerHTML = originalHTML, 2000);
            });
        };
        
        window.downloadEncrypted = function() {
            if (window.currentEncrypted) {
                downloadFile('encrypted.txt', window.currentEncrypted, 'text/plain');
            }
        };
        
        window.copyDecrypted = function(text) {
            navigator.clipboard.writeText(text).then(() => {
                const btn = event.target;
                const originalHTML = btn.innerHTML;
                btn.innerHTML = '<i class="bi bi-check"></i> Copied!';
                setTimeout(() => btn.innerHTML = originalHTML, 2000);
            });
        };
    }

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'encryption-tool',
        name: 'Encryption Tool',
        description: 'Encrypt/decrypt text using AES-256-GCM with password-based key derivation',
        icon: 'bi-lock-fill',
        category: 'purple',
        render: render,
        init: init
    });
})();