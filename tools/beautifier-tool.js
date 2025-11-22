// ========================================
// BEAUTIFIER TOOL - PIPELINE ENABLED
// Category: Purple Team
// ========================================

(function() {
    'use strict';

    // ========================================
    // BEAUTIFY FUNCTIONS
    // ========================================

    function beautifyJSON(str) {
        const obj = JSON.parse(str);
        return JSON.stringify(obj, null, 2);
    }

    function minifyJSON(str) {
        const obj = JSON.parse(str);
        return JSON.stringify(obj);
    }

    function validateJSON(str) {
        try {
            JSON.parse(str);
            return { valid: true };
        } catch (e) {
            return { valid: false, error: e.message };
        }
    }

    function beautifyXML(str) {
        const PADDING = '  ';
        const reg = /(>)(<)(\/*)/g;
        let pad = 0;
        
        str = str.replace(reg, '$1\n$2$3');
        
        return str.split('\n').map((node) => {
            let indent = 0;
            if (node.match(/.+<\/\w[^>]*>$/)) {
                indent = 0;
            } else if (node.match(/^<\/\w/)) {
                if (pad !== 0) {
                    pad -= 1;
                }
            } else if (node.match(/^<\w([^>]*[^\/])?>.*$/)) {
                indent = 1;
            } else {
                indent = 0;
            }
            
            const padding = PADDING.repeat(pad);
            pad += indent;
            
            return padding + node;
        }).join('\n');
    }

    function detectFormat(str) {
        str = str.trim();
        
        // Try JSON first
        if ((str.startsWith('{') && str.endsWith('}')) || (str.startsWith('[') && str.endsWith(']'))) {
            try {
                JSON.parse(str);
                return 'json';
            } catch (e) {
                // Not valid JSON
            }
        }
        
        // Try XML
        if (str.startsWith('<?xml') || (str.startsWith('<') && str.includes('>'))) {
            return 'xml';
        }
        
        // Default to JSON
        return 'json';
    }

    // ========================================
    // PIPELINE PROCESSING
    // ========================================

    async function processPipeline(input) {
        try {
            const format = detectFormat(input);
            let beautified;
            
            if (format === 'json') {
                beautified = beautifyJSON(input);
            } else if (format === 'xml') {
                beautified = beautifyXML(input);
            } else {
                return {
                    success: false,
                    error: 'Unsupported format for beautification'
                };
            }
            
            return {
                success: true,
                output: beautified,
                metadata: {
                    format: format,
                    inputLength: input.length,
                    outputLength: beautified.length
                }
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    // ========================================
    // SINGLE TOOL MODE RENDER
    // ========================================

    function render() {
        return `
            <div class="section-header">
                <h3 class="mb-1 d-flex align-items-center gap-2">
                    <i class="bi bi-magic"></i>
                    <span>Code Beautifier</span>
                </h3>
                <p class="text-secondary mb-0">
                    Beautify and format JSON, XML, and other code
                </p>
            </div>

            <div class="row g-3 mt-2">
                <div class="col-lg-6">
                    <div class="card bg-dark h-100">
                        <div class="card-header">
                            <i class="bi bi-code-square"></i> Input
                        </div>
                        <div class="card-body d-flex flex-column">
                            <textarea 
                                class="form-control font-monospace flex-grow-1" 
                                id="beautifierInput" 
                                rows="15" 
                                placeholder="Paste your code here..."
                            ></textarea>
                            <div class="form-text" id="beautifierValidation"></div>
                            
                            <div class="d-flex gap-2 mt-3">
                                <button class="btn btn-primary" onclick="beautifyCode()">
                                    <i class="bi bi-stars"></i> Beautify
                                </button>
                                <button class="btn btn-danger" onclick="minifyCode()">
                                    <i class="bi bi-dash-square"></i> Minify
                                </button>
                                <button class="btn btn-outline-secondary" onclick="clearBeautifier()">
                                    <i class="bi bi-x-circle"></i> Clear
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-lg-6">
                    <div class="card bg-dark h-100">
                        <div class="card-header">
                            <i class="bi bi-file-code"></i> Output
                        </div>
                        <div class="card-body d-flex flex-column">
                            <textarea 
                                class="form-control font-monospace flex-grow-1" 
                                id="beautifierOutput" 
                                rows="15" 
                                readonly
                            ></textarea>
                            
                            <div class="d-flex gap-2 mt-3">
                                <button class="btn btn-outline-success" onclick="copyBeautifierOutput()">
                                    <i class="bi bi-clipboard"></i> Copy
                                </button>
                                <button class="btn btn-outline-info" onclick="downloadBeautifierOutput()">
                                    <i class="bi bi-download"></i> Download
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card bg-dark mt-3">
                <div class="card-header">
                    <i class="bi bi-lightbulb"></i> Features
                </div>
                <div class="card-body">
                    <div class="row small">
                        <div class="col-md-6">
                            <h6>Supported Formats:</h6>
                            <ul class="mb-0">
                                <li><strong>JSON:</strong> Full parse, beautify, minify, validate</li>
                                <li><strong>XML:</strong> Beautify and format</li>
                            </ul>
                        </div>
                        <div class="col-md-6">
                            <h6>Features:</h6>
                            <ul class="mb-0">
                                <li>Automatic format detection</li>
                                <li>Real-time validation</li>
                                <li>One-click beautification</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    function init() {
        const inputArea = document.getElementById('beautifierInput');

        // Sample JSON
        const sampleJSON = `{"user":{"name":"John Doe","email":"john@example.com","age":30},"active":true}`;
        inputArea.value = sampleJSON;

        // Auto-validate on input
        if (inputArea) {
            inputArea.addEventListener('input', () => {
                autoDetectAndValidate();
            });
            
            setTimeout(() => autoDetectAndValidate(), 100);
        }

        window.beautifyCode = function() {
            const input = document.getElementById('beautifierInput').value.trim();
            const output = document.getElementById('beautifierOutput');
            
            if (!input) {
                alert('Please enter some code first');
                return;
            }
            
            try {
                const format = detectFormat(input);
                let beautified;
                
                if (format === 'json') {
                    beautified = beautifyJSON(input);
                } else if (format === 'xml') {
                    beautified = beautifyXML(input);
                } else {
                    alert('Unsupported format');
                    return;
                }
                
                output.value = beautified;
            } catch (e) {
                alert('Beautify failed: ' + e.message);
            }
        };

        window.minifyCode = function() {
            const input = document.getElementById('beautifierInput').value.trim();
            const output = document.getElementById('beautifierOutput');
            
            if (!input) {
                alert('Please enter some code first');
                return;
            }
            
            try {
                const minified = minifyJSON(input);
                output.value = minified;
            } catch (e) {
                alert('Minify failed: ' + e.message);
            }
        };

        window.clearBeautifier = function() {
            document.getElementById('beautifierInput').value = '';
            document.getElementById('beautifierOutput').value = '';
            document.getElementById('beautifierValidation').innerHTML = '';
        };

        window.copyBeautifierOutput = function() {
            const output = document.getElementById('beautifierOutput');
            if (!output.value) {
                alert('Nothing to copy');
                return;
            }
            
            navigator.clipboard.writeText(output.value).then(() => {
                alert('Copied to clipboard!');
            });
        };

        window.downloadBeautifierOutput = function() {
            const output = document.getElementById('beautifierOutput').value;
            if (!output) {
                alert('Nothing to download');
                return;
            }
            
            window.downloadFile('beautified.json', output, 'text/plain');
        };
    }

    function autoDetectAndValidate() {
        const input = document.getElementById('beautifierInput').value.trim();
        const validation = document.getElementById('beautifierValidation');
        
        if (!input) {
            validation.innerHTML = '';
            return;
        }
        
        const format = detectFormat(input);
        
        if (format === 'json') {
            const result = validateJSON(input);
            if (result.valid) {
                validation.innerHTML = '<span class="text-success"><i class="bi bi-check-circle-fill"></i> Valid JSON</span>';
            } else {
                validation.innerHTML = '<span class="text-danger"><i class="bi bi-x-circle-fill"></i> Invalid: ' + window.escapeHtml(result.error) + '</span>';
            }
        } else {
            validation.innerHTML = '<span class="text-info"><i class="bi bi-info-circle-fill"></i> Format: ' + format.toUpperCase() + '</span>';
        }
    }

    // Register the tool with pipeline support
    window.registerCyberSuiteTool({
        id: 'beautifier',
        name: 'Code Beautifier',
        description: 'Format and beautify JSON/XML code',
        icon: 'bi-magic',
        category: 'purple',
        
        // Pipeline configuration
        inputTypes: ['json', 'xml', 'text', 'any'],  // Accepts various formats
        outputType: 'text',                           // Outputs formatted text
        
        processPipeline: processPipeline,
        
        // Single tool mode
        render: render,
        init: init
    });
})();