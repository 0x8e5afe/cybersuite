// ========================================
// ENCRYPTION TOOL (ENHANCED)
// Category: Purple Team
// ========================================

(function() {
    'use strict';

    function render() {
        return `

            <div class="section-header">
                <h3 class="mb-1 d-flex align-items-center gap-2">
                    <i class="bi bi-lock-fill"></i>
                    <span>Encryption Tool</span>
                </h3>
                <p class="text-secondary mb-0">
                    Encrypt and decrypt text and files using multiple algorithms
                </p>
            </div>
            
            <ul class="nav nav-tabs mb-3" role="tablist">
                <li class="nav-item">
                    <button class="nav-link active" id="encrypt-nav-tab" data-bs-toggle="tab" data-bs-target="#encrypt-tab">
                        <i class="bi bi-lock"></i> Encrypt
                    </button>
                </li>
                <li class="nav-item">
                    <button class="nav-link" id="decrypt-nav-tab" data-bs-toggle="tab" data-bs-target="#decrypt-tab">
                        <i class="bi bi-unlock"></i> Decrypt
                    </button>
                </li>
                <li class="nav-item">
                    <button class="nav-link" id="file-nav-tab" data-bs-toggle="tab" data-bs-target="#file-tab">
                        <i class="bi bi-file-earmark-lock"></i> File Encryption
                    </button>
                </li>
                <li class="nav-item">
                    <button class="nav-link" id="hmac-nav-tab" data-bs-toggle="tab" data-bs-target="#hmac-tab">
                        <i class="bi bi-key"></i> HMAC
                    </button>
                </li>
            </ul>
            
            <div class="tab-content">
                <!-- Encrypt Tab -->
                <div class="tab-pane fade show active" id="encrypt-tab">
                    <div class="mb-3">
                        <label for="encryptAlgorithm" class="form-label">Encryption Algorithm</label>
                        <select class="form-select" id="encryptAlgorithm">
                            <option value="AES-GCM" selected>AES-256-GCM (Recommended)</option>
                            <option value="AES-CBC">AES-256-CBC</option>
                            <option value="AES-CTR">AES-256-CTR</option>
                        </select>
                        <div class="form-text">
                            <strong>GCM:</strong> Authenticated encryption (best security) | 
                            <strong>CBC:</strong> Traditional block cipher | 
                            <strong>CTR:</strong> Counter mode (streaming)
                        </div>
                    </div>
                    
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
                            <button class="btn btn-outline-secondary" type="button" id="toggleEncryptPassword">
                                <i class="bi bi-eye"></i>
                            </button>
                        </div>
                        <div class="form-text">
                            Use a strong password. Minimum 12 characters recommended.
                        </div>
                    </div>
                    
                    <button class="btn btn-primary" id="encryptBtn">
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
                            <button class="btn btn-outline-secondary" type="button" id="toggleDecryptPassword">
                                <i class="bi bi-eye"></i>
                            </button>
                        </div>
                    </div>
                    
                    <button class="btn btn-warning" id="decryptBtn">
                        <i class="bi bi-unlock-fill"></i> Decrypt
                    </button>
                </div>
                
                <!-- File Encryption Tab -->
                <div class="tab-pane fade" id="file-tab">
                    <div class="mb-3">
                        <label for="fileAlgorithm" class="form-label">Encryption Algorithm</label>
                        <select class="form-select" id="fileAlgorithm">
                            <option value="AES-GCM" selected>AES-256-GCM (Recommended)</option>
                            <option value="AES-CBC">AES-256-CBC</option>
                            <option value="AES-CTR">AES-256-CTR</option>
                        </select>
                    </div>
                    
                    <div class="mb-3">
                        <label for="fileInput" class="form-label">Select File</label>
                        <input type="file" class="form-control" id="fileInput">
                        <div class="form-text">Maximum file size: 50 MB</div>
                    </div>
                    
                    <div class="mb-3">
                        <label for="filePassword" class="form-label">Password</label>
                        <div class="input-group">
                            <input type="password" class="form-control" id="filePassword" 
                                   placeholder="Enter a strong password">
                            <button class="btn btn-outline-secondary" type="button" id="toggleFilePassword">
                                <i class="bi bi-eye"></i>
                            </button>
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <label class="form-label">Action</label>
                        <div class="form-check">
                            <input class="form-check-input" type="radio" name="fileAction" id="fileEncrypt" value="encrypt" checked>
                            <label class="form-check-label" for="fileEncrypt">
                                Encrypt File
                            </label>
                        </div>
                        <div class="form-check">
                            <input class="form-check-input" type="radio" name="fileAction" id="fileDecrypt" value="decrypt">
                            <label class="form-check-label" for="fileDecrypt">
                                Decrypt File
                            </label>
                        </div>
                    </div>
                    
                    <button class="btn btn-primary" id="fileProcessBtn">
                        <i class="bi bi-play-fill"></i> Process File
                    </button>
                </div>
                
                <!-- HMAC Tab -->
                <div class="tab-pane fade" id="hmac-tab">
                    <div class="mb-3">
                        <label for="hmacAlgorithm" class="form-label">HMAC Algorithm</label>
                        <select class="form-select" id="hmacAlgorithm">
                            <option value="SHA-256" selected>HMAC-SHA-256</option>
                            <option value="SHA-384">HMAC-SHA-384</option>
                            <option value="SHA-512">HMAC-SHA-512</option>
                            <option value="SHA-1">HMAC-SHA-1 (Legacy)</option>
                        </select>
                    </div>
                    
                    <div class="mb-3">
                        <label for="hmacInput" class="form-label">Message</label>
                        <textarea class="form-control font-monospace" id="hmacInput" rows="4" 
                                  placeholder="Enter message to authenticate..."></textarea>
                    </div>
                    
                    <div class="mb-3">
                        <label for="hmacKey" class="form-label">Secret Key</label>
                        <input type="text" class="form-control font-monospace" id="hmacKey" 
                               placeholder="Enter secret key">
                    </div>
                    
                    <button class="btn btn-info" id="hmacBtn">
                        <i class="bi bi-key"></i> Generate HMAC
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
                            <h6>Encryption Algorithms</h6>
                            <ul>
                                <li><strong>AES-GCM:</strong> Authenticated encryption with associated data</li>
                                <li><strong>AES-CBC:</strong> Cipher Block Chaining mode</li>
                                <li><strong>AES-CTR:</strong> Counter mode for streaming</li>
                                <li><strong>Key Size:</strong> 256 bits</li>
                                <li><strong>Key Derivation:</strong> PBKDF2 (100,000 iterations)</li>
                            </ul>
                        </div>
                        <div class="col-md-6">
                            <h6>Best Practices</h6>
                            <ul>
                                <li>Use AES-GCM for maximum security</li>
                                <li>Use long, random passwords (16+ chars)</li>
                                <li>Don't reuse passwords across systems</li>
                                <li>Keep encrypted data and keys separate</li>
                                <li>Test decryption before deleting originals</li>
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
        // Password toggle handlers
        const passwordToggles = [
            { field: 'encryptPassword', button: 'toggleEncryptPassword' },
            { field: 'decryptPassword', button: 'toggleDecryptPassword' },
            { field: 'filePassword', button: 'toggleFilePassword' }
        ];

        passwordToggles.forEach(({ field, button }) => {
            document.getElementById(button).addEventListener('click', function() {
                const fieldEl = document.getElementById(field);
                const icon = this.querySelector('i');
                
                if (fieldEl.type === 'password') {
                    fieldEl.type = 'text';
                    icon.classList.remove('bi-eye');
                    icon.classList.add('bi-eye-slash');
                } else {
                    fieldEl.type = 'password';
                    icon.classList.remove('bi-eye-slash');
                    icon.classList.add('bi-eye');
                }
            });
        });

        // Helper function to derive key
        async function deriveKey(password, salt, algorithm) {
            const encoder = new TextEncoder();
            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                encoder.encode(password),
                'PBKDF2',
                false,
                ['deriveBits', 'deriveKey']
            );
            
            return await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: 100000,
                    hash: 'SHA-256'
                },
                keyMaterial,
                { name: algorithm, length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
        }

        // Encrypt function
        document.getElementById('encryptBtn').addEventListener('click', async function() {
            const text = document.getElementById('encryptInput').value;
            const password = document.getElementById('encryptPassword').value;
            const algorithm = document.getElementById('encryptAlgorithm').value;
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
                    Encrypting with ${algorithm}...
                </div>
            `;

            try {
                const encoder = new TextEncoder();
                const salt = crypto.getRandomValues(new Uint8Array(16));
                const dataToEncrypt = encoder.encode(text);
                
                const key = await deriveKey(password, salt, algorithm);
                
                let encrypted, iv;
                
                if (algorithm === 'AES-GCM') {
                    iv = crypto.getRandomValues(new Uint8Array(12));
                    encrypted = await crypto.subtle.encrypt(
                        { name: 'AES-GCM', iv: iv },
                        key,
                        dataToEncrypt
                    );
                } else if (algorithm === 'AES-CBC') {
                    iv = crypto.getRandomValues(new Uint8Array(16));
                    encrypted = await crypto.subtle.encrypt(
                        { name: 'AES-CBC', iv: iv },
                        key,
                        dataToEncrypt
                    );
                } else if (algorithm === 'AES-CTR') {
                    iv = crypto.getRandomValues(new Uint8Array(16));
                    encrypted = await crypto.subtle.encrypt(
                        { name: 'AES-CTR', counter: iv, length: 64 },
                        key,
                        dataToEncrypt
                    );
                }
                
                const metadata = new Uint8Array([
                    algorithm === 'AES-GCM' ? 1 : algorithm === 'AES-CBC' ? 2 : 3
                ]);
                
                const combined = new Uint8Array(metadata.length + salt.length + iv.length + encrypted.byteLength);
                combined.set(metadata, 0);
                combined.set(salt, metadata.length);
                combined.set(iv, metadata.length + salt.length);
                combined.set(new Uint8Array(encrypted), metadata.length + salt.length + iv.length);
                
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
                                <button class="btn btn-outline-primary copy-encrypted-btn">
                                    <i class="bi bi-clipboard"></i> Copy
                                </button>
                                <button class="btn btn-outline-secondary download-encrypted-btn">
                                    <i class="bi bi-download"></i> Download
                                </button>
                            </div>
                            <div class="mt-3 small">
                                <div class="row">
                                    <div class="col-md-4">
                                        <strong>Algorithm:</strong> ${algorithm}
                                    </div>
                                    <div class="col-md-4">
                                        <strong>Original:</strong> ${text.length} chars
                                    </div>
                                    <div class="col-md-4">
                                        <strong>Encrypted:</strong> ${base64.length} chars
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
                
                document.querySelector('.copy-encrypted-btn').addEventListener('click', function() {
                    const text = document.getElementById('encryptedOutput').value;
                    navigator.clipboard.writeText(text).then(() => {
                        const originalHTML = this.innerHTML;
                        this.innerHTML = '<i class="bi bi-check"></i> Copied!';
                        this.classList.add('btn-success');
                        this.classList.remove('btn-outline-primary');
                        setTimeout(() => {
                            this.innerHTML = originalHTML;
                            this.classList.remove('btn-success');
                            this.classList.add('btn-outline-primary');
                        }, 2000);
                    });
                });
                
                document.querySelector('.download-encrypted-btn').addEventListener('click', function() {
                    const text = document.getElementById('encryptedOutput').value;
                    const blob = new Blob([text], { type: 'text/plain' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'encrypted.txt';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                });
                
            } catch (error) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-danger">
                        <strong><i class="bi bi-exclamation-triangle-fill"></i> Encryption Error:</strong> 
                        ${window.escapeHtml(error.message)}
                    </div>
                `;
            }
        });

        // Decrypt function
        document.getElementById('decryptBtn').addEventListener('click', async function() {
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
                const combined = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
                
                const algorithmCode = combined[0];
                const algorithm = algorithmCode === 1 ? 'AES-GCM' : 
                                 algorithmCode === 2 ? 'AES-CBC' : 'AES-CTR';
                
                const ivLength = algorithm === 'AES-GCM' ? 12 : 16;
                const salt = combined.slice(1, 17);
                const iv = combined.slice(17, 17 + ivLength);
                const encrypted = combined.slice(17 + ivLength);
                
                const key = await deriveKey(password, salt, algorithm);
                
                let decrypted;
                
                if (algorithm === 'AES-GCM') {
                    decrypted = await crypto.subtle.decrypt(
                        { name: 'AES-GCM', iv: iv },
                        key,
                        encrypted
                    );
                } else if (algorithm === 'AES-CBC') {
                    decrypted = await crypto.subtle.decrypt(
                        { name: 'AES-CBC', iv: iv },
                        key,
                        encrypted
                    );
                } else if (algorithm === 'AES-CTR') {
                    decrypted = await crypto.subtle.decrypt(
                        { name: 'AES-CTR', counter: iv, length: 64 },
                        key,
                        encrypted
                    );
                }
                
                const text = new TextDecoder().decode(decrypted);
                
                resultsDiv.innerHTML = `
                    <div class="card bg-dark border-success">
                        <div class="card-header bg-success text-dark">
                            <i class="bi bi-check-circle-fill"></i> Decryption Successful
                        </div>
                        <div class="card-body">
                            <label class="form-label">Decrypted Text</label>
                            <textarea class="form-control" id="decryptedOutput" rows="6" readonly>${window.escapeHtml(text)}</textarea>
                            <button class="btn btn-outline-primary mt-2 copy-decrypted-btn">
                                <i class="bi bi-clipboard"></i> Copy
                            </button>
                            <div class="mt-3 small">
                                <strong>Algorithm:</strong> ${algorithm} | 
                                <strong>Length:</strong> ${text.length} characters
                            </div>
                        </div>
                    </div>
                `;
                
                document.querySelector('.copy-decrypted-btn').addEventListener('click', function() {
                    const text = document.getElementById('decryptedOutput').value;
                    navigator.clipboard.writeText(text).then(() => {
                        const originalHTML = this.innerHTML;
                        this.innerHTML = '<i class="bi bi-check"></i> Copied!';
                        this.classList.add('btn-success');
                        this.classList.remove('btn-outline-primary');
                        setTimeout(() => {
                            this.innerHTML = originalHTML;
                            this.classList.remove('btn-success');
                            this.classList.add('btn-outline-primary');
                        }, 2000);
                    });
                });
                
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
                        <small class="text-muted">Error: ${window.escapeHtml(error.message)}</small>
                    </div>
                `;
            }
        });

        // File processing function
        document.getElementById('fileProcessBtn').addEventListener('click', async function() {
            const fileInput = document.getElementById('fileInput');
            const password = document.getElementById('filePassword').value;
            const algorithm = document.getElementById('fileAlgorithm').value;
            const action = document.querySelector('input[name="fileAction"]:checked').value;
            const resultsDiv = document.getElementById('encryptResults');
            
            if (!fileInput.files || fileInput.files.length === 0) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please select a file</div>';
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

            const file = fileInput.files[0];
            
            if (file.size > 50 * 1024 * 1024) {
                resultsDiv.innerHTML = '<div class="alert alert-danger">File size exceeds 50 MB limit</div>';
                return;
            }

            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <span class="spinner-border spinner-border-sm me-2"></span>
                    ${action === 'encrypt' ? 'Encrypting' : 'Decrypting'} file...
                </div>
            `;

            try {
                const fileData = await file.arrayBuffer();
                
                if (action === 'encrypt') {
                    const salt = crypto.getRandomValues(new Uint8Array(16));
                    const key = await deriveKey(password, salt, algorithm);
                    
                    let encrypted, iv;
                    
                    if (algorithm === 'AES-GCM') {
                        iv = crypto.getRandomValues(new Uint8Array(12));
                        encrypted = await crypto.subtle.encrypt(
                            { name: 'AES-GCM', iv: iv },
                            key,
                            fileData
                        );
                    } else if (algorithm === 'AES-CBC') {
                        iv = crypto.getRandomValues(new Uint8Array(16));
                        encrypted = await crypto.subtle.encrypt(
                            { name: 'AES-CBC', iv: iv },
                            key,
                            fileData
                        );
                    } else if (algorithm === 'AES-CTR') {
                        iv = crypto.getRandomValues(new Uint8Array(16));
                        encrypted = await crypto.subtle.encrypt(
                            { name: 'AES-CTR', counter: iv, length: 64 },
                            key,
                            fileData
                        );
                    }
                    
                    const metadata = new Uint8Array([
                        algorithm === 'AES-GCM' ? 1 : algorithm === 'AES-CBC' ? 2 : 3
                    ]);
                    
                    const combined = new Uint8Array(metadata.length + salt.length + iv.length + encrypted.byteLength);
                    combined.set(metadata, 0);
                    combined.set(salt, metadata.length);
                    combined.set(iv, metadata.length + salt.length);
                    combined.set(new Uint8Array(encrypted), metadata.length + salt.length + iv.length);
                    
                    const blob = new Blob([combined], { type: 'application/octet-stream' });
                    const url = URL.createObjectURL(blob);
                    
                    resultsDiv.innerHTML = `
                        <div class="card bg-dark border-success">
                            <div class="card-header bg-success text-dark">
                                <i class="bi bi-check-circle-fill"></i> File Encrypted Successfully
                            </div>
                            <div class="card-body">
                                <p><strong>Original File:</strong> ${file.name}</p>
                                <p><strong>Algorithm:</strong> ${algorithm}</p>
                                <p><strong>Original Size:</strong> ${(file.size / 1024).toFixed(2)} KB</p>
                                <p><strong>Encrypted Size:</strong> ${(combined.length / 1024).toFixed(2)} KB</p>
                                <button class="btn btn-primary download-encrypted-file-btn" data-url="${url}" data-filename="${file.name}.encrypted">
                                    <i class="bi bi-download"></i> Download Encrypted File
                                </button>
                            </div>
                        </div>
                    `;
                    
                    document.querySelector('.download-encrypted-file-btn').addEventListener('click', function() {
                        const a = document.createElement('a');
                        a.href = this.getAttribute('data-url');
                        a.download = this.getAttribute('data-filename');
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                    });
                    
                } else {
                    // Decrypt
                    const combined = new Uint8Array(fileData);
                    
                    const algorithmCode = combined[0];
                    const detectedAlgorithm = algorithmCode === 1 ? 'AES-GCM' : 
                                     algorithmCode === 2 ? 'AES-CBC' : 'AES-CTR';
                    
                    const ivLength = detectedAlgorithm === 'AES-GCM' ? 12 : 16;
                    const salt = combined.slice(1, 17);
                    const iv = combined.slice(17, 17 + ivLength);
                    const encrypted = combined.slice(17 + ivLength);
                    
                    const key = await deriveKey(password, salt, detectedAlgorithm);
                    
                    let decrypted;
                    
                    if (detectedAlgorithm === 'AES-GCM') {
                        decrypted = await crypto.subtle.decrypt(
                            { name: 'AES-GCM', iv: iv },
                            key,
                            encrypted
                        );
                    } else if (detectedAlgorithm === 'AES-CBC') {
                        decrypted = await crypto.subtle.decrypt(
                            { name: 'AES-CBC', iv: iv },
                            key,
                            encrypted
                        );
                    } else if (detectedAlgorithm === 'AES-CTR') {
                        decrypted = await crypto.subtle.decrypt(
                            { name: 'AES-CTR', counter: iv, length: 64 },
                            key,
                            encrypted
                        );
                    }
                    
                    const blob = new Blob([decrypted], { type: 'application/octet-stream' });
                    const url = URL.createObjectURL(blob);
                    
                    const originalName = file.name.replace('.encrypted', '');
                    
                    resultsDiv.innerHTML = `
                        <div class="card bg-dark border-success">
                            <div class="card-header bg-success text-dark">
                                <i class="bi bi-check-circle-fill"></i> File Decrypted Successfully
                            </div>
                            <div class="card-body">
                                <p><strong>Algorithm Used:</strong> ${detectedAlgorithm}</p>
                                <p><strong>Decrypted Size:</strong> ${(decrypted.byteLength / 1024).toFixed(2)} KB</p>
                                <button class="btn btn-primary download-decrypted-file-btn" data-url="${url}" data-filename="${originalName}">
                                    <i class="bi bi-download"></i> Download Decrypted File
                                </button>
                            </div>
                        </div>
                    `;
                    
                    document.querySelector('.download-decrypted-file-btn').addEventListener('click', function() {
                        const a = document.createElement('a');
                        a.href = this.getAttribute('data-url');
                        a.download = this.getAttribute('data-filename');
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                    });
                }
                
            } catch (error) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-danger">
                        <strong><i class="bi bi-exclamation-triangle-fill"></i> ${action === 'encrypt' ? 'Encryption' : 'Decryption'} Failed</strong>
                        <p class="mb-0">${action === 'decrypt' ? 'Possible reasons:' : 'Error:'}</p>
                        ${action === 'decrypt' ? `
                        <ul class="mb-0">
                            <li>Incorrect password</li>
                            <li>File was not encrypted with this tool</li>
                            <li>File is corrupted</li>
                        </ul>
                        ` : ''}
                        <small class="text-muted">Error: ${window.escapeHtml(error.message)}</small>
                    </div>
                `;
            }
        });

        // HMAC function
        document.getElementById('hmacBtn').addEventListener('click', async function() {
            const text = document.getElementById('hmacInput').value;
            const key = document.getElementById('hmacKey').value;
            const algorithm = document.getElementById('hmacAlgorithm').value;
            const resultsDiv = document.getElementById('encryptResults');
            
            if (!text) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter message</div>';
                return;
            }
            
            if (!key) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter secret key</div>';
                return;
            }

            try {
                const encoder = new TextEncoder();
                
                const cryptoKey = await crypto.subtle.importKey(
                    'raw',
                    encoder.encode(key),
                    { name: 'HMAC', hash: algorithm },
                    false,
                    ['sign']
                );
                
                const signature = await crypto.subtle.sign(
                    'HMAC',
                    cryptoKey,
                    encoder.encode(text)
                );
                
                const hashArray = Array.from(new Uint8Array(signature));
                const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                const hashBase64 = btoa(String.fromCharCode(...hashArray));
                
                resultsDiv.innerHTML = `
                    <div class="card bg-dark border-info">
                        <div class="card-header bg-info text-dark">
                            <i class="bi bi-check-circle-fill"></i> HMAC Generated
                        </div>
                        <div class="card-body">
                            <div class="mb-3">
                                <label class="form-label">HMAC-${algorithm} (Hexadecimal)</label>
                                <div class="input-group mb-2">
                                    <input type="text" class="form-control font-monospace small" id="hmacOutputHex" 
                                           value="${hashHex}" readonly>
                                </div>
                                <button class="btn btn-sm btn-outline-primary copy-hmac-hex-btn">
                                    <i class="bi bi-clipboard"></i> Copy Hex
                                </button>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">HMAC-${algorithm} (Base64)</label>
                                <div class="input-group mb-2">
                                    <input type="text" class="form-control font-monospace small" id="hmacOutputBase64" 
                                           value="${hashBase64}" readonly>
                                </div>
                                <button class="btn btn-sm btn-outline-primary copy-hmac-base64-btn">
                                    <i class="bi bi-clipboard"></i> Copy Base64
                                </button>
                            </div>
                            
                            <div class="mt-3 small">
                                <strong>Algorithm:</strong> HMAC-${algorithm} | 
                                <strong>Length:</strong> ${hashArray.length} bytes
                            </div>
                        </div>
                    </div>
                `;
                
                document.querySelector('.copy-hmac-hex-btn').addEventListener('click', function() {
                    const text = document.getElementById('hmacOutputHex').value;
                    navigator.clipboard.writeText(text).then(() => {
                        const originalHTML = this.innerHTML;
                        this.innerHTML = '<i class="bi bi-check"></i> Copied!';
                        this.classList.add('btn-success');
                        this.classList.remove('btn-outline-primary');
                        setTimeout(() => {
                            this.innerHTML = originalHTML;
                            this.classList.remove('btn-success');
                            this.classList.add('btn-outline-primary');
                        }, 2000);
                    });
                });
                
                document.querySelector('.copy-hmac-base64-btn').addEventListener('click', function() {
                    const text = document.getElementById('hmacOutputBase64').value;
                    navigator.clipboard.writeText(text).then(() => {
                        const originalHTML = this.innerHTML;
                        this.innerHTML = '<i class="bi bi-check"></i> Copied!';
                        this.classList.add('btn-success');
                        this.classList.remove('btn-outline-primary');
                        setTimeout(() => {
                            this.innerHTML = originalHTML;
                            this.classList.remove('btn-success');
                            this.classList.add('btn-outline-primary');
                        }, 2000);
                    });
                });
                
            } catch (error) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-danger">
                        <strong>Error:</strong> ${window.escapeHtml(error.message)}
                    </div>
                `;
            }
        });
    }

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'encryption-tool',
        name: 'Encryption Tool',
        description: 'Encrypt/decrypt text and files with multiple algorithms, plus HMAC generation',
        icon: 'bi-lock-fill',
        category: 'purple',
        render: render,
        init: init
    });
})();