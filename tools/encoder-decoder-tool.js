// ========================================
// ENCODER/DECODER TOOL (ENHANCED)
// Category: Purple Team
// ========================================

(function() {
    'use strict';

    let currentMode = 'encode'; // 'encode' or 'decode'

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
                // basic strictness so auto-decode isn't silent garbage
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
            
            <div class="row g-3">
                <div class="col-md-12">
                    <label for="encodingType" class="form-label">Encoding Type</label>
                    <select class="form-select" id="encodingType" onchange="updateEncodingInfo()">
                        ${methodOptions}
                    </select>
                    <div class="d-flex justify-content-between align-items-center mt-1">
                        <small id="encodingInfo" class="text-secondary"></small>
                        <span id="encoderModeBadge" class="badge bg-success">Mode: Encode</span>
                    </div>
                </div>
            </div>
            
            <div class="row g-3 mt-2">
                <div class="col-lg-5">
                    <label for="encoderInput" class="form-label">Input Text</label>
                    <textarea class="form-control font-monospace" id="encoderInput" rows="10" placeholder="Start typing to auto-encode/decode..."></textarea>
                    <div class="mt-2 d-flex justify-content-end">
                        <button class="btn btn-sm btn-outline-secondary" onclick="clearInput()">
                            <i class="bi bi-x-circle"></i> Clear
                        </button>
                    </div>
                </div>
                
                <div class="col-lg-2 d-flex align-items-center justify-content-center">
                    <button class="btn btn-outline-secondary btn-lg" onclick="swapInputOutput()" title="Swap Input and Output (and toggle mode)">
                        <i class="bi bi-arrow-left-right"></i>
                    </button>
                </div>
                
                <div class="col-lg-5">
                    <label for="encoderOutput" class="form-label">Output</label>
                    <textarea class="form-control font-monospace encoder-output-glow" id="encoderOutput" rows="10" readonly></textarea>
                    <div class="mt-2">
                        <button class="btn btn-outline-primary w-100" onclick="copyOutput()">
                            <i class="bi bi-clipboard"></i> Copy
                        </button>
                    </div>
                </div>
            </div>
            
            <div id="encoderResults" class="mt-3"></div>
            
            <div class="card bg-dark mt-3">
                <div class="card-header">
                    <i class="bi bi-info-circle"></i> Quick Reference
                </div>
                <div class="card-body">
                    <div class="row small">
                        <div class="col-md-6">
                            <h6>Common Use Cases</h6>
                            <ul>
                                <li><strong>Base64:</strong> Binary data in text format</li>
                                <li><strong>URL Encoding:</strong> Safe URL parameters</li>
                                <li><strong>HTML Entities:</strong> XSS prevention/bypass</li>
                                <li><strong>Unicode:</strong> JavaScript injection</li>
                            </ul>
                        </div>
                        <div class="col-md-6">
                            <h6>Testing Tips</h6>
                            <ul>
                                <li>Try double encoding for WAF bypass</li>
                                <li>Mix encoding types for obfuscation</li>
                                <li>Test different encodings in same parameter</li>
                                <li>Check for partial decoding vulnerabilities</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    function init() {
        window.updateEncodingInfo = function() {
            const type = document.getElementById('encodingType').value;
            const method = encodingMethods[type];
            document.getElementById('encodingInfo').textContent = method.description;
            // re-run transformation when method changes
            window.autoProcessText();
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

        window.autoProcessText = function() {
            const inputField = document.getElementById('encoderInput');
            const outputField = document.getElementById('encoderOutput');
            const resultsDiv = document.getElementById('encoderResults');
            const typeSelect = document.getElementById('encodingType');

            if (!inputField || !outputField || !resultsDiv || !typeSelect) return;

            const input = inputField.value;
            const type = typeSelect.value;

            if (!input) {
                outputField.value = '';
                outputField.classList.remove('output-active');
                resultsDiv.innerHTML = '';
                return;
            }

            try {
                const method = encodingMethods[type];
                const fn = currentMode === 'encode' ? method.encode : method.decode;
                const output = fn(input);
                outputField.value = output;
                outputField.classList.add('output-active');

                const actionTitle = currentMode === 'encode' ? 'Encoding' : 'Decoding';

                resultsDiv.innerHTML = `
                    <div class="alert alert-success mb-0">
                        <h6 class="alert-heading"><i class="bi bi-check-circle-fill"></i> ${actionTitle} Successful</h6>
                        <div class="row small">
                            <div class="col-md-4">
                                <strong>Method:</strong> ${method.name}
                            </div>
                            <div class="col-md-4">
                                <strong>Input Length:</strong> ${input.length} chars
                            </div>
                            <div class="col-md-4">
                                <strong>Output Length:</strong> ${output.length} chars
                            </div>
                        </div>
                    </div>
                `;
            } catch (error) {
                outputField.value = '';
                outputField.classList.remove('output-active');

                const actionTitle = currentMode === 'encode' ? 'Encoding' : 'Decoding';

                resultsDiv.innerHTML = `
                    <div class="alert alert-danger mb-0">
                        <strong><i class="bi bi-exclamation-triangle-fill"></i> ${actionTitle} Error:</strong> ${window.escapeHtml(error.message)}
                    </div>
                `;
            }
        };

        window.clearInput = function() {
            document.getElementById('encoderInput').value = '';
            document.getElementById('encoderOutput').value = '';
            document.getElementById('encoderOutput').classList.remove('output-active');
            document.getElementById('encoderResults').innerHTML = '';
        };
        
        window.copyOutput = function() {
            const output = document.getElementById('encoderOutput').value;
            if (!output) {
                document.getElementById('encoderResults').innerHTML = 
                    '<div class="alert alert-warning mb-0">No output to copy</div>';
                return;
            }
            navigator.clipboard.writeText(output).then(() => {
                document.getElementById('encoderResults').innerHTML = 
                    '<div class="alert alert-success mb-0"><i class="bi bi-check-circle-fill"></i> Copied to clipboard!</div>';
                setTimeout(() => {
                    document.getElementById('encoderResults').innerHTML = '';
                }, 2000);
            });
        };
        
        window.swapInputOutput = function() {
            const input = document.getElementById('encoderInput');
            const output = document.getElementById('encoderOutput');
            const resultsDiv = document.getElementById('encoderResults');

            const temp = input.value;
            input.value = output.value;
            output.value = temp;
            
            output.classList.remove('output-active');

            // Toggle mode: if we just moved encoded → input, we now want the opposite action
            currentMode = (currentMode === 'encode') ? 'decode' : 'encode';
            window.updateModeUI();

            // Status now refers to a previous state; clear and recompute
            resultsDiv.innerHTML = '';
            window.autoProcessText();
        };

        // hook auto-processing on input changes
        const inputField = document.getElementById('encoderInput');
        if (inputField) {
            inputField.addEventListener('input', window.autoProcessText);
        }

        // Initialize description + mode UI
        window.updateEncodingInfo();
        window.updateModeUI();
    }

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'encoder-decoder',
        name: 'Encoder/Decoder',
        description: 'Encode and decode in 11 formats: Base64, URL, Hex, HTML, Unicode, ROT13, Binary, Morse',
        icon: 'bi-arrow-left-right',
        category: 'purple',
        render: render,
        init: init
    });
})();