// ========================================
// STEGANOGRAPHY TOOL
// Category: Red Team
// ========================================

(function() {
    'use strict';

    function render() {
        return `

            <div class="section-header">
                <h3 class="mb-1 d-flex align-items-center gap-2">
                    <i class="bi bi-file-image"></i>
                    <span>LSB Steganography Tool</span>
                </h3>
                <p class="text-secondary mb-0">
                  Hide and extract text in images using Least Significant Bit technique.
                </p>
            </div>
            
            <ul class="nav nav-tabs mb-3" role="tablist">
                <li class="nav-item">
                    <button class="nav-link active" id="encode-nav-tab" data-bs-toggle="tab" data-bs-target="#encode-tab">
                        <i class="bi bi-box-arrow-in-down"></i> Encode (Hide Message)
                    </button>
                </li>
                <li class="nav-item">
                    <button class="nav-link" id="decode-nav-tab" data-bs-toggle="tab" data-bs-target="#decode-tab">
                        <i class="bi bi-box-arrow-up"></i> Decode (Extract Message)
                    </button>
                </li>
            </ul>
            
            <div class="tab-content">
                <!-- ENCODE TAB -->
                <div class="tab-pane fade show active" id="encode-tab">
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="baseFile" class="form-label">
                                    <i class="bi bi-image"></i> Select Base Image (PNG recommended)
                                </label>
                                <input type="file" class="form-control" id="baseFile" accept="image/*">
                                <div class="form-text">PNG format preserves hidden data. JPEG will destroy it.</div>
                            </div>

                            <div class="mb-3">
                                <label for="messageText" class="form-label">
                                    <i class="bi bi-chat-left-text"></i> Message to Hide
                                </label>
                                <textarea class="form-control font-monospace" id="messageText" rows="6" 
                                          placeholder="Enter your secret message here..."></textarea>
                                <div class="form-text">
                                    <span id="messageLength">0</span> characters = 
                                    <span id="messageBits">0</span> bits needed
                                </div>
                            </div>

                            <button class="btn btn-primary" id="encodeBtn" disabled>
                                <i class="bi bi-lock-fill"></i> Encode Message into Image
                            </button>
                        </div>

                        <div class="col-md-6">
                            <h5>Image Preview</h5>
                            <div class="canvas-container" id="originalContainer" style="background: #1a1d20; border: 2px dashed #495057; border-radius: 8px; padding: 20px; text-align: center; min-height: 200px; display: flex; align-items: center; justify-content: center;">
                                <p class="text-muted">Upload an image to begin</p>
                            </div>
                            <div id="capacityInfo" class="mt-2"></div>
                        </div>
                    </div>

                    <div id="encodeResults" class="mt-4"></div>
                </div>

                <!-- DECODE TAB -->
                <div class="tab-pane fade" id="decode-tab">
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="decodeFile" class="form-label">
                                    <i class="bi bi-file-image"></i> Select Encoded Image
                                </label>
                                <input type="file" class="form-control" id="decodeFile" accept="image/*">
                                <div class="form-text">Upload an image that contains a hidden message</div>
                            </div>

                            <button class="btn btn-warning" id="decodeBtn" disabled>
                                <i class="bi bi-unlock-fill"></i> Extract Hidden Message
                            </button>
                        </div>

                        <div class="col-md-6">
                            <h5>Image Preview</h5>
                            <div class="canvas-container" id="decodeContainer" style="background: #1a1d20; border: 2px dashed #495057; border-radius: 8px; padding: 20px; text-align: center; min-height: 200px; display: flex; align-items: center; justify-content: center;">
                                <p class="text-muted">Upload an encoded image</p>
                            </div>
                        </div>
                    </div>

                    <div id="decodeResults" class="mt-4"></div>
                </div>
            </div>

            <!-- Info Section -->
            <div class="card bg-dark mt-4">
                <div class="card-header">
                    <i class="bi bi-info-circle"></i> How LSB Steganography Works
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6">
                            <h6>Encoding Process:</h6>
                            <ol class="small">
                                <li><strong>Normalize:</strong> Set all RGB values to even numbers (LSB = 0)</li>
                                <li><strong>Convert:</strong> Transform message to binary (8 bits per character)</li>
                                <li><strong>Embed:</strong> Add binary bits to RGB channels (3 bits per pixel)</li>
                                <li><strong>Save:</strong> Download as PNG to preserve data</li>
                            </ol>
                        </div>
                        <div class="col-md-6">
                            <h6>Example:</h6>
                            <div class="small" style="font-family: 'Courier New', monospace; background: #1a1d20; padding: 10px; border-radius: 4px;">
                                Original: RGB(200, 151, 100)<br>
                                Normalized: RGB(200, 150, 100)<br>
                                Message bits: 0, 1, 0<br>
                                Encoded: RGB(200, 151, 100)<br>
                                <span class="text-success">Difference: invisible to human eye!</span>
                            </div>
                        </div>
                    </div>
                    <div class="alert alert-warning mt-3 mb-0">
                        <strong>Important:</strong> Always use PNG format. JPEG compression will destroy hidden messages.
                    </div>
                </div>
            </div>
        `;
    }

    function init() {
        // Helper functions
        function textToBinary(text) {
            let binary = '';
            for (let i = 0; i < text.length; i++) {
                let charCode = text.charCodeAt(i);
                let binaryChar = charCode.toString(2).padStart(8, '0');
                binary += binaryChar;
            }
            return binary;
        }

        function binaryToText(binary) {
            let text = '';
            for (let i = 0; i < binary.length; i += 8) {
                const byte = binary.substr(i, 8);
                const charCode = parseInt(byte, 2);
                if (charCode === 0) break; // Stop at null terminator
                text += String.fromCharCode(charCode);
            }
            return text;
        }

        function previewImage(file, containerId, canvasId, callback) {
            const reader = new FileReader();
            const container = document.getElementById(containerId);

            reader.onload = function(e) {
                const img = new Image();
                img.onload = function() {
                    const canvas = document.createElement('canvas');
                    canvas.id = canvasId;
                    canvas.width = img.width;
                    canvas.height = img.height;
                    canvas.style.maxWidth = '100%';
                    canvas.style.height = 'auto';
                    canvas.style.border = '1px solid #dee2e6';
                    canvas.style.borderRadius = '4px';
                    
                    const ctx = canvas.getContext('2d');
                    ctx.drawImage(img, 0, 0);
                    
                    container.innerHTML = '';
                    container.appendChild(canvas);
                    
                    if (callback) callback(img.width, img.height);
                };
                img.src = e.target.result;
            };

            reader.readAsDataURL(file);
        }

        // Update message statistics
        document.getElementById('messageText').addEventListener('input', function() {
            const text = this.value;
            const bits = text.length * 8;
            document.getElementById('messageLength').textContent = text.length;
            document.getElementById('messageBits').textContent = bits;
        });

        // Base file upload
        document.getElementById('baseFile').addEventListener('change', function() {
            const file = this.files[0];
            if (!file) return;

            previewImage(file, 'originalContainer', 'originalCanvas', function(width, height) {
                const capacity = Math.floor((width * height * 3) / 8);
                document.getElementById('capacityInfo').innerHTML = `
                    <div class="alert alert-info">
                        <strong>Image Capacity:</strong> ${width}×${height} pixels = 
                        ${capacity.toLocaleString()} characters maximum
                    </div>
                `;
                document.getElementById('encodeBtn').disabled = false;
            });
        });

        // Decode file upload
        document.getElementById('decodeFile').addEventListener('change', function() {
            const file = this.files[0];
            if (!file) return;

            previewImage(file, 'decodeContainer', 'decodeCanvas');
            document.getElementById('decodeBtn').disabled = false;
        });

        // ENCODE FUNCTION
        document.getElementById('encodeBtn').addEventListener('click', function() {
            const message = document.getElementById('messageText').value;
            const resultsDiv = document.getElementById('encodeResults');

            if (!message) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter a message to hide</div>';
                return;
            }

            const canvas = document.getElementById('originalCanvas');
            const ctx = canvas.getContext('2d');
            const width = canvas.width;
            const height = canvas.height;

            // Check capacity
            const binaryMessage = textToBinary(message);
            const requiredBits = binaryMessage.length;
            const availableBits = width * height * 3;

            if (requiredBits > availableBits) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-danger">
                        <strong>Error:</strong> Message too long for this image!<br>
                        Required: ${requiredBits} bits | Available: ${availableBits} bits
                    </div>
                `;
                return;
            }

            resultsDiv.innerHTML = '<div class="alert alert-info"><span class="spinner-border spinner-border-sm me-2"></span>Encoding message...</div>';

            try {
                // Get image data
                const imageData = ctx.getImageData(0, 0, width, height);
                const pixels = imageData.data;

                // Step 1: Normalize (set LSB to 0)
                for (let i = 0; i < pixels.length; i += 4) {
                    pixels[i] = pixels[i] % 2 === 0 ? pixels[i] : pixels[i] - 1;     // R
                    pixels[i + 1] = pixels[i + 1] % 2 === 0 ? pixels[i + 1] : pixels[i + 1] - 1; // G
                    pixels[i + 2] = pixels[i + 2] % 2 === 0 ? pixels[i + 2] : pixels[i + 2] - 1; // B
                }

                // Step 2: Embed binary message
                let bitIndex = 0;
                for (let i = 0; i < pixels.length && bitIndex < binaryMessage.length; i += 4) {
                    // Embed in R, G, B channels (skip Alpha)
                    if (bitIndex < binaryMessage.length) {
                        pixels[i] += parseInt(binaryMessage[bitIndex++]);
                    }
                    if (bitIndex < binaryMessage.length) {
                        pixels[i + 1] += parseInt(binaryMessage[bitIndex++]);
                    }
                    if (bitIndex < binaryMessage.length) {
                        pixels[i + 2] += parseInt(binaryMessage[bitIndex++]);
                    }
                }

                // Put modified data back
                ctx.putImageData(imageData, 0, 0);

                // Create download link
                canvas.toBlob(function(blob) {
                    const url = URL.createObjectURL(blob);
                    
                    resultsDiv.innerHTML = `
                        <div class="card border-success bg-dark">
                            <div class="card-header bg-success text-dark">
                                <i class="bi bi-check-circle-fill"></i> Message Encoded Successfully!
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6">
                                        <h6>Statistics:</h6>
                                        <ul class="small mb-3">
                                            <li><strong>Message Length:</strong> ${message.length} characters</li>
                                            <li><strong>Binary Size:</strong> ${binaryMessage.length} bits</li>
                                            <li><strong>Pixels Modified:</strong> ${Math.ceil(binaryMessage.length / 3)}</li>
                                            <li><strong>Capacity Used:</strong> ${((binaryMessage.length / availableBits) * 100).toFixed(2)}%</li>
                                        </ul>
                                    </div>
                                    <div class="col-md-6">
                                        <h6>Binary Preview:</h6>
                                        <div class="small" style="font-family: 'Courier New', monospace; background: #1a1d20; padding: 10px; border-radius: 4px; max-height: 150px; overflow-y: auto;">
                                            ${binaryMessage.match(/.{1,8}/g).slice(0, 10).join(' ')}<br>
                                            ${binaryMessage.length > 80 ? '...' : ''}
                                        </div>
                                    </div>
                                </div>
                                <a href="${url}" download="encoded_image.png" class="btn btn-primary">
                                    <i class="bi bi-download"></i> Download Encoded Image (PNG)
                                </a>
                                <button class="btn btn-outline-secondary reset-encode-btn">
                                    <i class="bi bi-arrow-clockwise"></i> Reset
                                </button>
                            </div>
                        </div>
                    `;
                    
                    document.querySelector('.reset-encode-btn').addEventListener('click', function() {
                        document.getElementById('messageText').value = '';
                        document.getElementById('encodeResults').innerHTML = '';
                        document.getElementById('messageLength').textContent = '0';
                        document.getElementById('messageBits').textContent = '0';
                    });
                }, 'image/png');

            } catch (error) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-danger">
                        <strong>Error:</strong> ${window.escapeHtml(error.message)}
                    </div>
                `;
            }
        });

        // DECODE FUNCTION
        document.getElementById('decodeBtn').addEventListener('click', function() {
            const resultsDiv = document.getElementById('decodeResults');
            resultsDiv.innerHTML = '<div class="alert alert-info"><span class="spinner-border spinner-border-sm me-2"></span>Extracting hidden message...</div>';

            try {
                const canvas = document.getElementById('decodeCanvas');
                const ctx = canvas.getContext('2d');
                const width = canvas.width;
                const height = canvas.height;

                // Get image data
                const imageData = ctx.getImageData(0, 0, width, height);
                const pixels = imageData.data;

                // Extract LSBs
                let binaryMessage = '';
                for (let i = 0; i < pixels.length; i += 4) {
                    binaryMessage += (pixels[i] % 2).toString();         // R
                    binaryMessage += (pixels[i + 1] % 2).toString();     // G
                    binaryMessage += (pixels[i + 2] % 2).toString();     // B
                }

                // Convert binary to text
                const message = binaryToText(binaryMessage);

                if (!message || message.trim().length === 0) {
                    resultsDiv.innerHTML = `
                        <div class="alert alert-warning">
                            <strong>No message found!</strong><br>
                            This image may not contain a hidden message, or it was saved in a lossy format (like JPEG).
                        </div>
                    `;
                    return;
                }

                resultsDiv.innerHTML = `
                    <div class="card border-success bg-dark">
                        <div class="card-header bg-success text-dark">
                            <i class="bi bi-unlock-fill"></i> Hidden Message Extracted!
                        </div>
                        <div class="card-body">
                            <label class="form-label"><strong>Extracted Message:</strong></label>
                            <textarea class="form-control font-monospace" rows="8" readonly id="extractedMessage">${window.escapeHtml(message)}</textarea>
                            <button class="btn btn-outline-primary mt-2 copy-extracted-btn">
                                <i class="bi bi-clipboard"></i> Copy Message
                            </button>
                            <div class="mt-3 small">
                                <strong>Message Length:</strong> ${message.length} characters |
                                <strong>Binary Size:</strong> ${message.length * 8} bits
                            </div>
                        </div>
                    </div>
                `;
                
                document.querySelector('.copy-extracted-btn').addEventListener('click', function() {
                    const text = document.getElementById('extractedMessage').value;
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
        id: 'steganography-tool',
        name: 'Steganography Tool',
        description: 'Hide and extract messages in images using LSB technique',
        icon: 'bi-file-image',
        category: 'red',
        render: render,
        init: init
    });
})();