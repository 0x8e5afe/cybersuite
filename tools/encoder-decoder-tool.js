// ========================================
// ENCODER/DECODER TOOL
// Category: Purple Team
// ========================================

(function() {
    'use strict';

    let currentMode = 'encode'; // 'encode' or 'decode'
    let conversionHistory = [];

    const encodingMethods = {
        base64: {
            name: 'Base64',
            description: 'Standard Base64 encoding',
            encode: (str) => btoa(unescape(encodeURIComponent(str))),
            decode: (str) => decodeURIComponent(escape(atob(str)))
        },
        base64url: {
            name: 'Base64 URL-Safe',
            description: 'URL-safe Base64 encoding',
            encode: (str) => btoa(unescape(encodeURIComponent(str))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
            decode: (str) => {
                let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
                while (base64.length % 4 !== 0) base64 += '=';
                return decodeURIComponent(escape(atob(base64)));
            }
        },
        url: {
            name: 'URL Encoding',
            description: 'Percent-encoding for URLs',
            encode: (str) => encodeURIComponent(str),
            decode: (str) => decodeURIComponent(str)
        },
        urlDouble: {
            name: 'Double URL Encoding',
            description: 'URL encoding applied twice',
            encode: (str) => encodeURIComponent(encodeURIComponent(str)),
            decode: (str) => decodeURIComponent(decodeURIComponent(str))
        },
        hex: {
            name: 'Hexadecimal',
            description: 'Convert to hex representation',
            encode: (str) => Array.from(str).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(''),
            decode: (str) => {
                if (!str || str.length % 2 !== 0) {
                    throw new Error('Invalid hex input length');
                }
                const pairs = str.match(/.{2}/g);
                if (!pairs) {
                    throw new Error('Invalid hex input');
                }
                return pairs.map(h => String.fromCharCode(parseInt(h, 16))).join('');
            }
        },
        hexWithPrefix: {
            name: 'Hex (\\x format)',
            description: 'Hex with \\x prefix',
            encode: (str) => Array.from(str).map(c => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')).join(''),
            decode: (str) => {
                if (!str.includes('\\x')) {
                    throw new Error('Expected \\x-prefixed hex');
                }
                return str
                    .split('\\x')
                    .slice(1)
                    .map(h => {
                        const part = h.slice(0, 2);
                        if (!/^[0-9a-fA-F]{2}$/.test(part)) {
                            throw new Error('Invalid \\x sequence');
                        }
                        return String.fromCharCode(parseInt(part, 16));
                    })
                    .join('');
            }
        },
        html: {
            name: 'HTML Entities',
            description: 'Convert to HTML entities',
            encode: (str) => str.replace(/[&<>"']/g, m => ({
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#39;'
            })[m]),
            decode: (str) => {
                const txt = document.createElement('textarea');
                txt.innerHTML = str;
                return txt.value;
            }
        },
        htmlDecimal: {
            name: 'HTML Decimal Entities',
            description: 'Numeric HTML entities',
            encode: (str) => Array.from(str).map(c => '&#' + c.charCodeAt(0) + ';').join(''),
            decode: (str) => str.replace(/&#(\d+);/g, (m, p) => String.fromCharCode(parseInt(p)))
        },
        unicode: {
            name: 'Unicode Escape',
            description: 'JavaScript unicode escape',
            encode: (str) => Array.from(str).map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join(''),
            decode: (str) => {
                if (!/\\u[0-9a-fA-F]{4}/.test(str)) {
                    throw new Error('No valid \\uXXXX sequences found');
                }
                return str.replace(/\\u([0-9a-fA-F]{4})/g, (m, p) => String.fromCharCode(parseInt(p, 16)));
            }
        },
        rot13: {
            name: 'ROT13',
            description: 'Simple letter substitution',
            encode: (str) => str.replace(/[a-zA-Z]/g, c => {
                const code = c.charCodeAt(0);
                const base = code >= 97 ? 97 : 65;
                return String.fromCharCode(((code - base + 13) % 26) + base);
            }),
            decode: (str) => str.replace(/[a-zA-Z]/g, c => {
                const code = c.charCodeAt(0);
                const base = code >= 97 ? 97 : 65;
                return String.fromCharCode(((code - base + 13) % 26) + base);
            })
        },
        binary: {
            name: 'Binary',
            description: 'Convert to binary representation',
            encode: (str) => Array.from(str).map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join(' '),
            decode: (str) => {
                if (!str.trim()) return '';
                const chunks = str.trim().split(/\s+/);
                chunks.forEach(b => {
                    if (!/^[01]{8}$/.test(b)) {
                        throw new Error('Invalid binary byte: ' + b);
                    }
                });
                return chunks.map(b => String.fromCharCode(parseInt(b, 2))).join('');
            }
        },
        morse: {
            name: 'Morse Code',
            description: 'International Morse code',
            encode: (str) => {
                const morse = {
                    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
                    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
                    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
                    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
                    'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
                    '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
                    '8': '---..', '9': '----.', ' ': '/'
                };
                return str.toUpperCase().split('').map(c => morse[c] || c).join(' ');
            },
            decode: (str) => {
                const morse = {
                    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
                    '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
                    '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
                    '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
                    '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
                    '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
                    '---..': '8', '----.': '9', '/': ' '
                };
                if (!str.trim()) return '';
                return str.trim().split(/\s+/).map(c => morse[c] || '?').join('');
            }
        }
    };

    function render() {
        const methodOptions = Object.entries(encodingMethods).map(([key, method]) => 
            `<option value="${key}">${method.name}</option>`
        ).join('');

        return `
            <div class="section-header">
                <h3 class="mb-1 d-flex align-items-center gap-2">
                    <i class="bi bi-arrow-left-right"></i>
                    <span>Encoder/Decoder</span>
                </h3>
                <p class="text-secondary mb-0">
                    Encode and decode payloads in multiple formats for security testing
                </p>
            </div>

            <div class="row g-3 mt-2">
                <div class="col-lg-8">
                    <div class="card bg-dark">
                        <div class="card-header">
                            <i class="bi bi-gear-fill"></i> Configuration
                        </div>
                        <div class="card-body">
                            <div class="mb-3">
                                <label for="encodingType" class="form-label">Encoding Type</label>
                                <select class="form-select" id="encodingType" onchange="updateEncodingInfo()">
                                    ${methodOptions}
                                </select>
                                <div class="d-flex justify-content-between align-items-center mt-1" >
                                    <small id="encodingInfo" class="text-secondary"></small>
                                    <span id="encoderModeBadge" class="badge bg-success" style="margin-top:10px">Mode: Encode</span>
                                </div>
                            </div>

                            <div class="mb-3">
                                <label for="encoderInput" class="form-label">Input Text</label>
                                <textarea 
                                    class="form-control font-monospace" 
                                    id="encoderInput" 
                                    rows="8" 
                                    placeholder="Enter text to encode/decode..."
                                ></textarea>
                            </div>

                            <div class="d-flex gap-2">
                                <button class="btn btn-outline-secondary" onclick="swapInputOutput()">
                                    <i class="bi bi-arrow-left-right"></i> Swap & Toggle Mode
                                </button>
                                <button class="btn btn-outline-secondary" onclick="clearInput()">
                                    <i class="bi bi-x-circle"></i> Clear
                                </button>
                                <button class="btn btn-outline-info" onclick="loadSample()">
                                    <i class="bi bi-file-earmark-text"></i> Load Sample
                                </button>
                            </div>
                        </div>
                    </div>

                    <div id="encoderResults" class="mt-3"></div>
                </div>

                <div class="col-lg-4">
                    <div class="card bg-dark">
                        <div class="card-header">
                            <i class="bi bi-clock-history"></i> Conversion History
                        </div>
                        <div class="card-body">
                            <div id="historyList" class="hash-history-list">
                                <p class="text-secondary text-center small mb-0">
                                    No conversions yet
                                </p>
                            </div>
                            <button class="btn btn-sm btn-outline-danger w-100 mt-2" onclick="clearHistory()">
                                <i class="bi bi-trash"></i> Clear History
                            </button>
                        </div>
                    </div>

                    <div class="card bg-dark mt-3">
                        <div class="card-header">
                            <i class="bi bi-info-circle"></i> Supported Formats
                        </div>
                        <div class="card-body small">
                            <p class="mb-2">
                                <strong>Text Encodings:</strong><br>
                                Base64, URL, Double URL, HTML
                            </p>
                            <p class="mb-2">
                                <strong>Numeric:</strong><br>
                                Hex, Hex (\\x), Binary, Unicode
                            </p>
                            <p class="mb-2">
                                <strong>Cipher:</strong><br>
                                ROT13, Morse Code
                            </p>
                            <p class="text-info mb-0">
                                <i class="bi bi-lightbulb"></i>
                                Auto-processing on input enabled
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card bg-dark mt-3">
                <div class="card-header">
                    <i class="bi bi-lightbulb"></i> Usage Tips
                </div>
                <div class="card-body">
                    <div class="row small">
                        <div class="col-md-6">
                            <h6>Common Use Cases:</h6>
                            <ul class="mb-0">
                                <li><strong>Base64:</strong> Binary data in text format</li>
                                <li><strong>URL Encoding:</strong> Safe URL parameters</li>
                                <li><strong>HTML Entities:</strong> XSS prevention/bypass</li>
                                <li><strong>Unicode:</strong> JavaScript injection</li>
                            </ul>
                        </div>
                        <div class="col-md-6">
                            <h6>Testing Tips:</h6>
                            <ul class="mb-0">
                                <li>Try double encoding for WAF bypass</li>
                                <li>Mix encoding types for obfuscation</li>
                                <li>Test different encodings in same parameter</li>
                                <li>Use swap to quickly reverse operations</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    function init() {
        // Load history from memory (not localStorage to avoid storage API)
        updateHistoryDisplay();

        window.updateEncodingInfo = function() {
            const type = document.getElementById('encodingType').value;
            const method = encodingMethods[type];
            document.getElementById('encodingInfo').textContent = method.description;
        };

        window.updateModeUI = function() {
            const badge = document.getElementById('encoderModeBadge');
            if (!badge) return;

            if (currentMode === 'encode') {
                badge.textContent = 'Mode: Encode';
                badge.classList.remove('bg-danger');
                badge.classList.add('bg-success');
            } else {
                badge.textContent = 'Mode: Decode';
                badge.classList.remove('bg-success');
                badge.classList.add('bg-danger');
            }
        };

        window.processTextWithoutHistory = function() {
            const inputField = document.getElementById('encoderInput');
            const resultsDiv = document.getElementById('encoderResults');
            const typeSelect = document.getElementById('encodingType');

            if (!inputField || !resultsDiv || !typeSelect) return;

            const input = inputField.value.trim();
            const type = typeSelect.value;

            if (!input) {
                resultsDiv.innerHTML = '';
                return;
            }

            try {
                const method = encodingMethods[type];
                const fn = currentMode === 'encode' ? method.encode : method.decode;
                const output = fn(input);
                const actionTitle = currentMode === 'encode' ? 'Encoded' : 'Decoded';

                displayResult(true, method, input, output, actionTitle);
            } catch (error) {
                const actionTitle = currentMode === 'encode' ? 'Encoding' : 'Decoding';
                displayResult(false, encodingMethods[type], input, null, actionTitle, error.message);
            }
        };

        window.processText = function() {
            processTextWithoutHistory();
            
            const inputField = document.getElementById('encoderInput');
            const resultsDiv = document.getElementById('encoderResults');
            const typeSelect = document.getElementById('encodingType');
            const output = resultsDiv.querySelector('.alert-success strong.user-select-all')?.textContent;
            
            if (output) {
                const type = typeSelect.value;
                const method = encodingMethods[type];
                addToHistory({
                    mode: currentMode,
                    method: method.name,
                    methodKey: type,
                    input: inputField.value.trim(),
                    output: output,
                    timestamp: new Date().toISOString()
                });
            }
        };

        const inputField = document.getElementById('encoderInput');
        if (inputField) {
            inputField.addEventListener('input', () => {
                // Process without saving to history
                processTextWithoutHistory();
            });
            inputField.addEventListener('blur', () => {
                // Save to history when leaving input field
                const output = document.getElementById('encoderResults').querySelector('.alert-success strong.user-select-all')?.textContent;
                if (output) {
                    const type = document.getElementById('encodingType').value;
                    const method = encodingMethods[type];
                    addToHistory({
                        mode: currentMode,
                        method: method.name,
                        methodKey: type,
                        input: inputField.value.trim(),
                        output: output,
                        timestamp: new Date().toISOString()
                    });
                }
            });
        }

        window.clearInput = function() {
            document.getElementById('encoderInput').value = '';
            document.getElementById('encoderResults').innerHTML = '';
        };

        window.loadSample = function() {
            const samples = {
                'base64': 'Hello, World!',
                'url': 'param=value&special=test@example.com',
                'hex': 'Secret Message',
                'html': '<script>alert("XSS")</script>',
                'unicode': 'Testing Unicode',
                'binary': 'ABC',
                'morse': 'SOS'
            };
            
            const currentType = document.getElementById('encodingType').value;
            document.getElementById('encoderInput').value = samples[currentType] || 'Sample Text';
        };

        window.swapInputOutput = function() {
            const input = document.getElementById('encoderInput');
            const resultsDiv = document.getElementById('encoderResults');
            
            // Check if there's output to swap
            const outputElement = resultsDiv.querySelector('.alert-success');
            if (!outputElement) {
                // Just toggle mode without saving to history
                currentMode = (currentMode === 'encode') ? 'decode' : 'encode';
                window.updateModeUI();
                
                // If there's input, process it with new mode
                if (input.value.trim()) {
                    processTextWithoutHistory();
                }
                return;
            }

            const outputText = outputElement.querySelector('strong.user-select-all')?.textContent;
            
            if (outputText) {
                input.value = outputText;
                
                // Toggle mode
                currentMode = (currentMode === 'encode') ? 'decode' : 'encode';
                window.updateModeUI();
                
                // Automatically process the swapped content
                processTextWithoutHistory();
                
                // Save to history after swap
                const newOutput = document.getElementById('encoderResults').querySelector('.alert-success strong.user-select-all')?.textContent;
                if (newOutput) {
                    const type = document.getElementById('encodingType').value;
                    const method = encodingMethods[type];
                    addToHistory({
                        mode: currentMode,
                        method: method.name,
                        methodKey: type,
                        input: outputText,
                        output: newOutput,
                        timestamp: new Date().toISOString()
                    });
                }
            }
        };

        window.clearHistory = function() {
            conversionHistory = [];
            updateHistoryDisplay();
        };

        // Initialize
        window.updateEncodingInfo();
        window.updateModeUI();
    }

    function displayResult(success, method, input, output, action, error = null) {
        const resultsDiv = document.getElementById('encoderResults');
        
        if (success) {
            resultsDiv.innerHTML = `
                <div class="card border-success">
                    <div class="card-header bg-success">
                        <i class="bi bi-check-circle-fill"></i> ${action} Successfully
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <div class="d-flex justify-content-between align-items-start mb-2">
                                <div class="flex-grow-1">
                                    <div class="d-flex align-items-center gap-2 mb-1">
                                        <i class="bi bi-check-circle-fill text-success"></i>
                                        <span class="badge bg-success">${method.name}</span>
                                        <span class="badge bg-secondary">${currentMode === 'encode' ? 'Encode' : 'Decode'}</span>
                                    </div>
                                    <div class="small text-secondary mb-1">
                                        <strong>Input (${input.length} chars):</strong>
                                    </div>
                                    <code class="d-block mb-2 text-break">${window.escapeHtml(input.substring(0, 100))}${input.length > 100 ? '...' : ''}</code>
                                    <div class="small text-success mb-1">
                                        <strong><i class="bi bi-arrow-right"></i> Output (${output.length} chars):</strong>
                                    </div>
                                    <div class="alert alert-success mb-0 py-2">
                                        <strong class="user-select-all">${window.escapeHtml(output)}</strong>
                                    </div>
                                </div>
                                <button class="btn btn-sm btn-outline-success ms-2" onclick="copyOutput('${window.escapeHtml(output).replace(/'/g, "\\'")}')">
                                    <i class="bi bi-clipboard"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        } else {
            resultsDiv.innerHTML = `
                <div class="card border-danger">
                    <div class="card-header bg-danger">
                        <i class="bi bi-x-circle-fill"></i> ${action} Failed
                    </div>
                    <div class="card-body">
                        <div class="d-flex align-items-start gap-2">
                            <i class="bi bi-x-circle-fill text-danger"></i>
                            <div class="flex-grow-1">
                                <span class="badge bg-danger mb-2">${method.name}</span>
                                <div class="small text-secondary mb-1">
                                    <strong>Input:</strong>
                                </div>
                                <code class="d-block mb-2 text-break">${window.escapeHtml(input.substring(0, 100))}${input.length > 100 ? '...' : ''}</code>
                                <div class="alert alert-danger mb-0 py-2">
                                    ${window.escapeHtml(error)}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
    }

    function addToHistory(item) {
        // Avoid duplicates based on input+output
        const exists = conversionHistory.some(h => 
            h.input === item.input && h.output === item.output && h.methodKey === item.methodKey
        );
        
        if (!exists) {
            conversionHistory.unshift(item);
            // Keep only last 10
            if (conversionHistory.length > 10) {
                conversionHistory = conversionHistory.slice(0, 10);
            }
            updateHistoryDisplay();
        }
    }

    function updateHistoryDisplay() {
        const historyDiv = document.getElementById('historyList');
        if (!historyDiv) return;

        if (conversionHistory.length === 0) {
            historyDiv.innerHTML = `
                <p class="text-secondary text-center small mb-0">
                    No conversions yet
                </p>
            `;
            return;
        }

        let html = '';
        conversionHistory.forEach((item) => {
            const date = new Date(item.timestamp).toLocaleString();
            const modeColor = item.mode === 'encode' ? 'success' : 'danger';
            const modeText = item.mode === 'encode' ? 'Encode' : 'Decode';
            
            html += `
                <div class="history-item mb-2 p-2">
                    <div class="d-flex justify-content-between align-items-start mb-1">
                        <div class="d-flex gap-1">
                            <span class="badge bg-${modeColor}">${modeText}</span>
                            <span class="badge bg-secondary">${item.method}</span>
                        </div>
                        <small class="text-secondary">${date}</small>
                    </div>
                    <div class="small mb-1">
                        <strong>In:</strong> <code class="text-truncate d-block">${window.escapeHtml(item.input.substring(0, 30))}${item.input.length > 30 ? '...' : ''}</code>
                    </div>
                    <div class="small">
                        <strong>Out:</strong> <code class="text-truncate d-block">${window.escapeHtml(item.output.substring(0, 30))}${item.output.length > 30 ? '...' : ''}</code>
                    </div>
                </div>
            `;
        });

        historyDiv.innerHTML = html;
    }

    window.copyOutput = function(text) {
        navigator.clipboard.writeText(text).then(() => {
            const resultsDiv = document.getElementById('encoderResults');
            const tempAlert = document.createElement('div');
            tempAlert.className = 'alert alert-success mt-2';
            tempAlert.innerHTML = '<i class="bi bi-check-circle-fill"></i> Copied to clipboard!';
            resultsDiv.insertBefore(tempAlert, resultsDiv.firstChild);
            setTimeout(() => tempAlert.remove(), 2000);
        });
    };

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'encoder-decoder',
        name: 'Encoder/Decoder',
        description: 'Encode and decode in 12 formats: Base64, URL, Hex, HTML, Unicode, ROT13, Binary, Morse with history tracking',
        icon: 'bi-arrow-left-right',
        category: 'purple',
        render: render,
        init: init
    });
})();
