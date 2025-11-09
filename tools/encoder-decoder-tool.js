// ========================================
// ENCODER/DECODER TOOL (ENHANCED)
// Category: Purple Team
// ========================================

(function() {
    'use strict';

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
            decode: (str) => str.match(/.{2}/g).map(h => String.fromCharCode(parseInt(h, 16))).join('')
        },
        hexWithPrefix: {
            name: 'Hex (\\x format)',
            description: 'Hex with \\x prefix',
            encode: (str) => Array.from(str).map(c => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')).join(''),
            decode: (str) => str.split('\\x').slice(1).map(h => String.fromCharCode(parseInt(h, 16))).join('')
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
            decode: (str) => str.replace(/\\u([0-9a-fA-F]{4})/g, (m, p) => String.fromCharCode(parseInt(p, 16)))
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
            decode: (str) => str.split(' ').map(b => String.fromCharCode(parseInt(b, 2))).join('')
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
                return str.split(' ').map(c => morse[c] || c).join('');
            }
        }
    };

    function render() {
        const methodOptions = Object.entries(encodingMethods).map(([key, method]) => 
            `<option value="${key}">${method.name}</option>`
        ).join('');

        return `
            <div class="mb-4">
                <h4><i class="bi bi-arrow-left-right"></i> Encoder/Decoder</h4>
                <p class="text-secondary">Encode and decode payloads in multiple formats for security testing</p>
            </div>
            
            <div class="row g-3">
                <div class="col-md-6">
                    <label for="encodingType" class="form-label">Encoding Type</label>
                    <select class="form-select" id="encodingType" onchange="updateEncodingInfo()">
                        ${methodOptions}
                    </select>
                    <small id="encodingInfo" class="text-secondary"></small>
                </div>
                
                <div class="col-md-6">
                    <label class="form-label">Operations</label>
                    <div class="btn-group w-100" role="group">
                        <button class="btn btn-outline-primary" onclick="encodeText()">
                            <i class="bi bi-lock-fill"></i> Encode
                        </button>
                        <button class="btn btn-outline-warning" onclick="decodeText()">
                            <i class="bi bi-unlock-fill"></i> Decode
                        </button>
                    </div>
                </div>
            </div>
            
            <div class="row g-3 mt-2">
                <div class="col-lg-6">
                    <label for="encoderInput" class="form-label">Input Text</label>
                    <textarea class="form-control font-monospace" id="encoderInput" rows="10" placeholder="Enter text to encode/decode..."></textarea>
                    <button class="btn btn-sm btn-outline-secondary mt-2" onclick="clearInput()">
                        <i class="bi bi-x-circle"></i> Clear
                    </button>
                </div>
                
                <div class="col-lg-6">
                    <label for="encoderOutput" class="form-label">Output</label>
                    <textarea class="form-control font-monospace" id="encoderOutput" rows="10" readonly></textarea>
                    <div class="mt-2">
                        <button class="btn btn-sm btn-outline-primary" onclick="copyOutput()">
                            <i class="bi bi-clipboard"></i> Copy
                        </button>
                        <button class="btn btn-sm btn-outline-secondary" onclick="swapInputOutput()">
                            <i class="bi bi-arrow-down-up"></i> Swap
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
        };
        
        // Initialize with first method info
        window.updateEncodingInfo();

        window.encodeText = function() {
            const input = document.getElementById('encoderInput').value;
            const type = document.getElementById('encodingType').value;
            const outputField = document.getElementById('encoderOutput');
            const resultsDiv = document.getElementById('encoderResults');
            
            if (!input) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter text to encode</div>';
                outputField.value = '';
                return;
            }

            try {
                const method = encodingMethods[type];
                const output = method.encode(input);
                outputField.value = output;
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-success">
                        <h6 class="alert-heading"><i class="bi bi-check-circle-fill"></i> Encoding Successful</h6>
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
                resultsDiv.innerHTML = `
                    <div class="alert alert-danger">
                        <strong><i class="bi bi-exclamation-triangle-fill"></i> Encoding Error:</strong> ${window.escapeHtml(error.message)}
                    </div>
                `;
            }
        };

        window.decodeText = function() {
            const input = document.getElementById('encoderInput').value;
            const type = document.getElementById('encodingType').value;
            const outputField = document.getElementById('encoderOutput');
            const resultsDiv = document.getElementById('encoderResults');
            
            if (!input) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter text to decode</div>';
                outputField.value = '';
                return;
            }

            try {
                const method = encodingMethods[type];
                const output = method.decode(input);
                outputField.value = output;
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-success">
                        <h6 class="alert-heading"><i class="bi bi-check-circle-fill"></i> Decoding Successful</h6>
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
                resultsDiv.innerHTML = `
                    <div class="alert alert-danger">
                        <strong><i class="bi bi-exclamation-triangle-fill"></i> Decoding Error:</strong> ${window.escapeHtml(error.message)}
                        <p class="mb-0 small mt-2">Make sure the input is properly encoded with the selected method.</p>
                    </div>
                `;
            }
        };
        
        window.clearInput = function() {
            document.getElementById('encoderInput').value = '';
            document.getElementById('encoderOutput').value = '';
            document.getElementById('encoderResults').innerHTML = '';
        };
        
        window.copyOutput = function() {
            const output = document.getElementById('encoderOutput').value;
            if (!output) {
                document.getElementById('encoderResults').innerHTML = 
                    '<div class="alert alert-warning">No output to copy</div>';
                return;
            }
            navigator.clipboard.writeText(output).then(() => {
                document.getElementById('encoderResults').innerHTML = 
                    '<div class="alert alert-success"><i class="bi bi-check-circle-fill"></i> Copied to clipboard!</div>';
                setTimeout(() => {
                    document.getElementById('encoderResults').innerHTML = '';
                }, 2000);
            });
        };
        
        window.swapInputOutput = function() {
            const input = document.getElementById('encoderInput');
            const output = document.getElementById('encoderOutput');
            const temp = input.value;
            input.value = output.value;
            output.value = temp;
        };
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