// ========================================
// BEAUTIFIER & FORMAT CONVERTER TOOL
// Category: Purple Team
// ========================================

(function() {
    'use strict';

    let currentFormat = 'json';
    let parsedData = null;
    let searchQuery = '';

    const formats = {
        json: {
            name: 'JSON',
            icon: 'bi-file-earmark-code',
            beautify: beautifyJSON,
            validate: validateJSON,
            parse: parseJSON,
            minify: minifyJSON,
            supportsTree: true,
            supportsConversion: true
        },
        xml: {
            name: 'XML',
            icon: 'bi-file-earmark-xml',
            beautify: beautifyXML,
            validate: validateXML,
            parse: parseXML,
            minify: minifyXML,
            supportsTree: true,
            supportsConversion: true
        },
        html: {
            name: 'HTML',
            icon: 'bi-file-earmark-code-fill',
            beautify: beautifyHTML,
            validate: validateHTML,
            parse: null,
            minify: minifyHTML,
            supportsTree: false,
            supportsConversion: false
        },
        css: {
            name: 'CSS',
            icon: 'bi-palette',
            beautify: beautifyCSS,
            validate: validateCSS,
            parse: null,
            minify: minifyCSS,
            supportsTree: false,
            supportsConversion: false
        },
        javascript: {
            name: 'JavaScript',
            icon: 'bi-braces',
            beautify: beautifyJS,
            validate: validateJS,
            parse: null,
            minify: minifyJS,
            supportsTree: false,
            supportsConversion: false
        },
        sql: {
            name: 'SQL',
            icon: 'bi-database',
            beautify: beautifySQL,
            validate: validateSQL,
            parse: null,
            minify: minifySQL,
            supportsTree: false,
            supportsConversion: false
        }
    };

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

    function parseJSON(str) {
        return JSON.parse(str);
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

    function minifyXML(str) {
        return str.replace(/>\s+</g, '><').trim();
    }

    function validateXML(str) {
        try {
            const parser = new DOMParser();
            const doc = parser.parseFromString(str, 'text/xml');
            const parseError = doc.querySelector('parsererror');
            
            if (parseError) {
                return { valid: false, error: parseError.textContent };
            }
            return { valid: true };
        } catch (e) {
            return { valid: false, error: e.message };
        }
    }

    function parseXML(str) {
        const parser = new DOMParser();
        const doc = parser.parseFromString(str, 'text/xml');
        return xmlToObject(doc.documentElement);
    }

    function xmlToObject(node) {
        const obj = {};
        
        if (node.nodeType === 1) {
            if (node.attributes.length > 0) {
                obj['@attributes'] = {};
                for (let i = 0; i < node.attributes.length; i++) {
                    const attr = node.attributes[i];
                    obj['@attributes'][attr.nodeName] = attr.nodeValue;
                }
            }
        }
        
        if (node.hasChildNodes()) {
            for (let i = 0; i < node.childNodes.length; i++) {
                const child = node.childNodes[i];
                const nodeName = child.nodeName;
                
                if (child.nodeType === 3) {
                    const text = child.nodeValue.trim();
                    if (text) {
                        return text;
                    }
                } else {
                    if (typeof obj[nodeName] === 'undefined') {
                        obj[nodeName] = xmlToObject(child);
                    } else {
                        if (!Array.isArray(obj[nodeName])) {
                            obj[nodeName] = [obj[nodeName]];
                        }
                        obj[nodeName].push(xmlToObject(child));
                    }
                }
            }
        }
        
        return obj;
    }

    function beautifyHTML(str) {
        return beautifyXML(str);
    }

    function minifyHTML(str) {
        return str.replace(/>\s+</g, '><').replace(/\s{2,}/g, ' ').trim();
    }

    function validateHTML(str) {
        return { valid: true };
    }

    function beautifyCSS(str) {
        let result = str.replace(/\s*{\s*/g, ' {\n  ');
        result = result.replace(/;\s*/g, ';\n  ');
        result = result.replace(/\s*}\s*/g, '\n}\n\n');
        result = result.replace(/,\s*/g, ',\n');
        return result.trim();
    }

    function minifyCSS(str) {
        return str.replace(/\s+/g, ' ').replace(/\s*{\s*/g, '{').replace(/\s*}\s*/g, '}').replace(/\s*;\s*/g, ';').trim();
    }

    function validateCSS(str) {
        return { valid: true };
    }

    function beautifyJS(str) {
        let result = str;
        let indent = 0;
        const indentStr = '  ';
        
        result = result.replace(/({|}|;)/g, '$1\n');
        result = result.split('\n').map(line => {
            line = line.trim();
            if (!line) return '';
            
            if (line.includes('}')) indent = Math.max(0, indent - 1);
            const indented = indentStr.repeat(indent) + line;
            if (line.includes('{')) indent++;
            
            return indented;
        }).join('\n');
        
        return result;
    }

    function minifyJS(str) {
        return str.replace(/\s+/g, ' ').replace(/\s*([{}();,:])\s*/g, '$1').trim();
    }

    function validateJS(str) {
        try {
            new Function(str);
            return { valid: true };
        } catch (e) {
            return { valid: false, error: e.message };
        }
    }

    function beautifySQL(str) {
        const keywords = ['SELECT', 'FROM', 'WHERE', 'JOIN', 'LEFT JOIN', 'RIGHT JOIN', 'INNER JOIN', 'ON', 'AND', 'OR', 'ORDER BY', 'GROUP BY', 'HAVING', 'LIMIT', 'OFFSET', 'INSERT INTO', 'VALUES', 'UPDATE', 'SET', 'DELETE FROM'];
        
        let result = str;
        keywords.forEach(keyword => {
            const regex = new RegExp('\\b' + keyword + '\\b', 'gi');
            result = result.replace(regex, '\n' + keyword);
        });
        
        return result.trim();
    }

    function minifySQL(str) {
        return str.replace(/\s+/g, ' ').trim();
    }

    function validateSQL(str) {
        return { valid: true };
    }

    // ========================================
    // FORMAT DETECTION
    // ========================================

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
            const parser = new DOMParser();
            const doc = parser.parseFromString(str, 'text/xml');
            const parseError = doc.querySelector('parsererror');
            if (!parseError) {
                return 'xml';
            }
        }
        
        // Try HTML
        if (str.toLowerCase().includes('<!doctype html') || str.toLowerCase().includes('<html')) {
            return 'html';
        }
        
        // Try CSS
        if (str.includes('{') && str.includes('}') && str.includes(':') && str.includes(';')) {
            return 'css';
        }
        
        // Try SQL
        const sqlKeywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER', 'FROM', 'WHERE'];
        const upperStr = str.toUpperCase();
        if (sqlKeywords.some(kw => upperStr.includes(kw))) {
            return 'sql';
        }
        
        // Try JavaScript
        if (str.includes('function') || str.includes('=>') || str.includes('const') || str.includes('let') || str.includes('var')) {
            return 'javascript';
        }
        
        // Default to JSON
        return 'json';
    }

    // ========================================
    // CONVERSION FUNCTIONS
    // ========================================

    function convertFormat(fromFormat, toFormat, data) {
        if (fromFormat === toFormat) return data;
        
        try {
            let intermediate = null;
            
            if (fromFormat === 'json') {
                intermediate = JSON.parse(data);
            } else if (fromFormat === 'xml') {
                intermediate = parseXML(data);
            } else {
                throw new Error('Cannot convert from ' + fromFormat);
            }
            
            if (toFormat === 'json') {
                return JSON.stringify(intermediate, null, 2);
            } else if (toFormat === 'xml') {
                return objectToXML(intermediate);
            } else {
                throw new Error('Cannot convert to ' + toFormat);
            }
        } catch (e) {
            throw new Error('Conversion failed: ' + e.message);
        }
    }

    function objectToXML(obj, rootName = 'root') {
        let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
        
        function buildXML(obj, name) {
            if (obj === null || obj === undefined) {
                return `<${name}/>`;
            }
            
            if (typeof obj !== 'object') {
                return `<${name}>${escapeXML(String(obj))}</${name}>`;
            }
            
            if (Array.isArray(obj)) {
                return obj.map(item => buildXML(item, name)).join('\n');
            }
            
            let attrs = '';
            let children = '';
            
            for (const [key, value] of Object.entries(obj)) {
                if (key === '@attributes') {
                    attrs = Object.entries(value)
                        .map(([k, v]) => `${k}="${escapeXML(String(v))}"`)
                        .join(' ');
                } else {
                    children += buildXML(value, key) + '\n';
                }
            }
            
            if (children) {
                return `<${name}${attrs ? ' ' + attrs : ''}>\n${children}</${name}>`;
            } else {
                return `<${name}${attrs ? ' ' + attrs : ''}/>`;
            }
        }
        
        return xml + buildXML(obj, rootName);
    }

    function escapeXML(str) {
        return str.replace(/[<>&'"]/g, c => {
            switch (c) {
                case '<': return '&lt;';
                case '>': return '&gt;';
                case '&': return '&amp;';
                case "'": return '&apos;';
                case '"': return '&quot;';
            }
        });
    }

    // ========================================
    // TREE VISUALIZATION
    // ========================================

function buildTreeView(data, path = '', query = '') {
    const queryLower = query.toLowerCase();
    const numericQuery = query && !isNaN(Number(query)) ? Number(query) : null;
    
    function matchesSearch(key, value) {
        if (!query) return true;

        // Exact numeric match when the query is numeric
        if (numericQuery !== null) {
            if (typeof value === 'number' && value === numericQuery) return true;
            if (typeof key === 'number' && key === numericQuery) return true;
        }

        const keyStr = String(key);
        const valStr = String(value);
        const keyMatch = keyStr.toLowerCase().includes(queryLower);
        const valueMatch = valStr.toLowerCase().includes(queryLower);
        return keyMatch || valueMatch;
    }
        
        function hasMatchingChild(obj) {
            if (!query) return true;
            if (obj === null || typeof obj !== 'object') {
                return matchesSearch('', obj);
            }
            
            if (Array.isArray(obj)) {
                return obj.some((item, idx) => matchesSearch(idx, item) || hasMatchingChild(item));
            }
            
            return Object.entries(obj).some(([key, value]) => 
                matchesSearch(key, value) || hasMatchingChild(value)
            );
        }
        
        if (data === null) {
            if (!matchesSearch('', 'null')) return '';
            return '<span class="tree-value tree-null">null</span>';
        }
        
        if (typeof data !== 'object') {
            if (!matchesSearch('', data)) return '';
            const type = typeof data;
            const valueClass = `tree-value tree-${type}`;
            const displayValue = type === 'string' ? `"${window.escapeHtml(data)}"` : String(data);
            return `<span class="${valueClass}">${displayValue}</span>`;
        }
        
        if (Array.isArray(data)) {
            const filteredItems = [];
            data.forEach((item, idx) => {
                const itemPath = path ? path + '[' + idx + ']' : '[' + idx + ']';
                if (!query || matchesSearch(idx, item) || hasMatchingChild(item)) {
                    filteredItems.push({ idx, item, itemPath });
                }
            });
            
            if (filteredItems.length === 0) return '';
            
            const count = filteredItems.length;
            const id = 'tree-' + Math.random().toString(36).substr(2, 9);
            
            let html = `
                <div class="tree-node">
                    <span class="tree-toggle" onclick="toggleTreeNode('${id}')">
                        <i class="bi bi-caret-down-fill"></i>
                    </span>
                    <span class="tree-bracket">[</span>
                    <span class="tree-count badge bg-secondary">${count} items</span>
                    <div id="${id}" class="tree-children" style="display: block;">
            `;
            
            filteredItems.forEach(({ idx, item, itemPath }) => {
                const childHtml = buildTreeView(item, itemPath, query);
                if (childHtml) {
                    html += `
                        <div class="tree-item">
                            <span class="tree-key">${idx}:</span>
                            ${childHtml}
                        </div>
                    `;
                }
            });
            
            html += `
                    </div>
                    <span class="tree-bracket">]</span>
                </div>
            `;
            
            return html;
        }
        
        const filteredKeys = [];
        Object.entries(data).forEach(([key, value]) => {
            const keyPath = path ? path + '.' + key : key;
            if (!query || matchesSearch(key, value) || hasMatchingChild(value)) {
                filteredKeys.push({ key, value, keyPath });
            }
        });
        
        if (filteredKeys.length === 0) return '';
        
        const count = filteredKeys.length;
        const id = 'tree-' + Math.random().toString(36).substr(2, 9);
        
        let html = `
            <div class="tree-node">
                <span class="tree-toggle" onclick="toggleTreeNode('${id}')">
                    <i class="bi bi-caret-down-fill"></i>
                </span>
                <span class="tree-bracket">{</span>
                <span class="tree-count badge bg-secondary">${count} properties</span>
                <div id="${id}" class="tree-children" style="display: block;">
        `;
        
        filteredKeys.forEach(({ key, value, keyPath }) => {
            const childHtml = buildTreeView(value, keyPath, query);
            if (childHtml) {
                html += `
                    <div class="tree-item">
                        <span class="tree-key">"${window.escapeHtml(key)}":</span>
                        ${childHtml}
                    </div>
                `;
            }
        });
        
        html += `
                </div>
                <span class="tree-bracket">}</span>
            </div>
        `;
        
        return html;
    }

    window.toggleTreeNode = function(id) {
        const node = document.getElementById(id);
        const toggle = node.previousElementSibling.previousElementSibling;
        
        if (node.style.display === 'none') {
            node.style.display = 'block';
            toggle.innerHTML = '<i class="bi bi-caret-down-fill"></i>';
        } else {
            node.style.display = 'none';
            toggle.innerHTML = '<i class="bi bi-caret-right-fill"></i>';
        }
    };

    // ========================================
    // STATISTICS
    // ========================================

    function getStatistics(data) {
        const stats = {
            totalKeys: 0,
            totalArrays: 0,
            totalObjects: 0,
            totalStrings: 0,
            totalNumbers: 0,
            totalBooleans: 0,
            totalNulls: 0,
            maxDepth: 0
        };
        
        function analyze(obj, depth = 0) {
            stats.maxDepth = Math.max(stats.maxDepth, depth);
            
            if (obj === null) {
                stats.totalNulls++;
                return;
            }
            
            if (typeof obj !== 'object') {
                if (typeof obj === 'string') stats.totalStrings++;
                else if (typeof obj === 'number') stats.totalNumbers++;
                else if (typeof obj === 'boolean') stats.totalBooleans++;
                return;
            }
            
            if (Array.isArray(obj)) {
                stats.totalArrays++;
                obj.forEach(item => analyze(item, depth + 1));
            } else {
                stats.totalObjects++;
                stats.totalKeys += Object.keys(obj).length;
                Object.values(obj).forEach(val => analyze(val, depth + 1));
            }
        }
        
        analyze(data);
        return stats;
    }

    // ========================================
    // RENDER & INIT
    // ========================================

    function render() {
        return `
            <div class="section-header">
                <h3 class="mb-1 d-flex align-items-center gap-2">
                    <i class="bi bi-magic"></i>
                    <span>Code Beautifier & Format Converter</span>
                </h3>
                <p class="text-secondary mb-0">
                    Beautify, minify, validate, and convert between JSON, XML, HTML, CSS, JavaScript, and SQL
                </p>
            </div>

            <div class="row g-3 mt-2">
                <div class="col-lg-6">
                    <div class="card bg-dark h-100">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <div>
                                <i class="bi bi-code-square"></i> Editor
                            </div>
                            <span id="detectedFormat" class="badge bg-secondary">
                                <i class="bi bi-file-earmark-code"></i> JSON
                            </span>
                        </div>
                        <div class="card-body d-flex flex-column">
                            <div class="mb-3 flex-grow-1 d-flex flex-column">
                                <label for="beautifierInput" class="form-label">Input</label>
                                <textarea 
                                    class="form-control font-monospace flex-grow-1" 
                                    id="beautifierInput" 
                                    rows="10" 
                                    placeholder="Paste your code here..."
                                ></textarea>
                                <div class="form-text" id="beautifierValidation"></div>
                            </div>

                            <div class="d-flex gap-2 flex-wrap mb-3">
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

                            <div class="mb-3" id="conversionButtons" style="display: none;">
                                <label class="form-label">Convert To</label>
                                <div class="btn-group w-100" role="group">
                                    <button class="btn btn-outline-secondary" onclick="convertTo('json')">
                                        <i class="bi bi-file-earmark-code"></i> JSON
                                    </button>
                                    <button class="btn btn-outline-secondary" onclick="convertTo('xml')">
                                        <i class="bi bi-file-earmark-xml"></i> XML
                                    </button>
                                </div>
                            </div>

                            <div class="mb-3 flex-grow-1 d-flex flex-column">
                                <label for="beautifierOutput" class="form-label">Output</label>
                                <textarea 
                                    class="form-control font-monospace flex-grow-1" 
                                    id="beautifierOutput" 
                                    rows="10" 
                                    readonly
                                ></textarea>
                            </div>

                            <div class="d-flex gap-2">
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

                <div class="col-lg-6">
                    <div class="card bg-dark h-100" id="treeVisualizerCard" style="display: none;">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <div>
                                <i class="bi bi-diagram-3"></i> Tree Visualizer
                            </div>
                            <div class="btn-group btn-group-sm" role="group">
                                <button class="btn btn-success" onclick="expandAllTreeNodes()">
                                    <i class="bi bi-arrows-expand"></i> Expand All
                                </button>
                                <button class="btn btn-danger" onclick="collapseAllTreeNodes()">
                                    <i class="bi bi-arrows-collapse"></i> Collapse All
                                </button>
                            </div>
                        </div>
                        <div class="card-body d-flex flex-column">
                            <div class="mb-3">
                                <div class="input-group">
                                    <span class="input-group-text">
                                        <i class="bi bi-search"></i>
                                    </span>
                                    <input 
                                        type="text" 
                                        class="form-control" 
                                        id="beautifierSearch" 
                                        placeholder="Filter tree by keys or values..."
                                    >
                                </div>
                                <small class="text-secondary d-block mt-1" id="searchResults"></small>
                            </div>

                            <div id="beautifierTree" class="beautifier-tree-view flex-grow-1">
                                <p class="text-secondary text-center">
                                    Beautify JSON or XML to see the tree visualization
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row g-3 mt-2" id="statisticsRow" style="display: none;">
                <div class="col-12">
                    <div class="card bg-dark">
                        <div class="card-header">
                            <i class="bi bi-graph-up"></i> Statistics
                        </div>
                        <div class="card-body">
                            <div id="beautifierStats" class="row g-3"></div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card bg-dark mt-3">
                <div class="card-header">
                    <i class="bi bi-lightbulb"></i> Features & Tips
                </div>
                <div class="card-body">
                    <div class="row small">
                        <div class="col-md-6">
                            <h6>Supported Formats:</h6>
                            <ul class="mb-3">
                                <li><strong>JSON:</strong> Full parse, beautify, minify, validate</li>
                                <li><strong>XML:</strong> Parse to tree, beautify, validate, convert to JSON</li>
                                <li><strong>HTML:</strong> Beautify and minify</li>
                                <li><strong>CSS:</strong> Format and compress stylesheets</li>
                                <li><strong>JavaScript:</strong> Basic beautification</li>
                                <li><strong>SQL:</strong> Format queries for readability</li>
                            </ul>
                        </div>
                        <div class="col-md-6">
                            <h6>Features:</h6>
                            <ul class="mb-0">
                                <li>Automatic format detection</li>
                                <li>Real-time validation with error messages</li>
                                <li>Interactive tree visualization with expand/collapse</li>
                                <li>Live search/filter in tree view</li>
                                <li>Format conversion (JSON ↔ XML)</li>
                                <li>Comprehensive statistics (depth, counts, types)</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    function init() {
        const inputArea = document.getElementById('beautifierInput');
        const searchInput = document.getElementById('beautifierSearch');

        // Load sample data
        const sampleJSON = `{
  "user": {
    "name": "John Doe",
    "email": "john@example.com",
    "age": 30,
    "address": {
      "street": "123 Main St",
      "city": "New York",
      "zip": "10001"
    },
    "hobbies": ["reading", "coding", "gaming"],
    "active": true
  },
  "metadata": {
    "created": "2024-01-15",
    "version": "1.0"
  }
}`;
        
        inputArea.value = sampleJSON;
        
        // Auto-detect and validate on input
        if (inputArea) {
            inputArea.addEventListener('input', () => {
                autoDetectAndValidate();
            });
            
            // Initial validation
            setTimeout(() => autoDetectAndValidate(), 100);
        }

        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                searchQuery = e.target.value;
                if (parsedData) {
                    updateTreeView(parsedData);
                }
            });
        }

        // Global functions
        window.beautifyCode = function() {
            const input = document.getElementById('beautifierInput').value.trim();
            const output = document.getElementById('beautifierOutput');
            
            if (!input) {
                showNotification('Please enter some code first', 'warning');
                return;
            }
            
            try {
                const format = formats[currentFormat];
                const beautified = format.beautify(input);
                output.value = beautified;
                
                if (format.parse && format.supportsTree) {
                    parsedData = format.parse(input);
                    updateTreeView(parsedData);
                    updateStatistics(parsedData);
                    showTreeAndStats(true);
                } else {
                    showTreeAndStats(false);
                }
                
                showNotification('Code beautified successfully!', 'success');
            } catch (e) {
                showNotification('Beautify failed: ' + e.message, 'danger');
            }
        };

        window.minifyCode = function() {
            const input = document.getElementById('beautifierInput').value.trim();
            const output = document.getElementById('beautifierOutput');
            
            if (!input) {
                showNotification('Please enter some code first', 'warning');
                return;
            }
            
            try {
                const format = formats[currentFormat];
                if (!format.minify) {
                    showNotification('Minify not supported for ' + format.name, 'warning');
                    return;
                }
                const minified = format.minify(input);
                output.value = minified;
                showNotification('Code minified successfully!', 'success');
            } catch (e) {
                showNotification('Minify failed: ' + e.message, 'danger');
            }
        };

        window.convertTo = function(targetFormat) {
            const input = document.getElementById('beautifierInput').value.trim();
            const output = document.getElementById('beautifierOutput');
            
            if (!input) {
                showNotification('Please enter some code first', 'warning');
                return;
            }
            
            if (!formats[currentFormat].supportsConversion) {
                showNotification('Conversion not supported from ' + formats[currentFormat].name, 'warning');
                return;
            }
            
            try {
                const converted = convertFormat(currentFormat, targetFormat, input);
                output.value = converted;
                showNotification('Converted to ' + targetFormat.toUpperCase() + '!', 'success');
            } catch (e) {
                showNotification('Conversion failed: ' + e.message, 'danger');
            }
        };

        window.clearBeautifier = function() {
            document.getElementById('beautifierInput').value = '';
            document.getElementById('beautifierOutput').value = '';
            document.getElementById('beautifierValidation').innerHTML = '';
            document.getElementById('beautifierSearch').value = '';
            parsedData = null;
            searchQuery = '';
            showTreeAndStats(false);
        };

        window.copyBeautifierOutput = function() {
            const output = document.getElementById('beautifierOutput');
            if (!output.value) {
                showNotification('Nothing to copy', 'warning');
                return;
            }
            
            navigator.clipboard.writeText(output.value).then(() => {
                showNotification('Copied to clipboard!', 'success');
            });
        };

        window.downloadBeautifierOutput = function() {
            const output = document.getElementById('beautifierOutput').value;
            if (!output) {
                showNotification('Nothing to download', 'warning');
                return;
            }
            
            const extensions = {
                json: 'json',
                xml: 'xml',
                html: 'html',
                css: 'css',
                javascript: 'js',
                sql: 'sql'
            };
            
            const filename = 'beautified.' + extensions[currentFormat];
            window.downloadFile(filename, output, 'text/plain');
            showNotification('Downloaded as ' + filename, 'success');
        };

        window.expandAllTreeNodes = function() {
            document.querySelectorAll('.tree-children').forEach(node => {
                node.style.display = 'block';
            });
            document.querySelectorAll('.tree-toggle').forEach(toggle => {
                toggle.innerHTML = '<i class="bi bi-caret-down-fill"></i>';
            });
        };

        window.collapseAllTreeNodes = function() {
            document.querySelectorAll('.tree-children').forEach(node => {
                node.style.display = 'none';
            });
            document.querySelectorAll('.tree-toggle').forEach(toggle => {
                toggle.innerHTML = '<i class="bi bi-caret-right-fill"></i>';
            });
        };
    }

    function autoDetectAndValidate() {
        const input = document.getElementById('beautifierInput').value.trim();
        const validation = document.getElementById('beautifierValidation');
        const formatBadge = document.getElementById('detectedFormat');
        const conversionButtons = document.getElementById('conversionButtons');
        
        if (!input) {
            validation.innerHTML = '';
            formatBadge.innerHTML = '<i class="bi bi-file-earmark-code"></i> JSON';
            currentFormat = 'json';
            conversionButtons.style.display = 'none';
            return;
        }
        
        // Detect format
        const detectedFormat = detectFormat(input);
        currentFormat = detectedFormat;
        
        // Update badge
        const format = formats[detectedFormat];
        formatBadge.innerHTML = `<i class="${format.icon}"></i> ${format.name}`;
        
        // Show/hide conversion buttons
        if (format.supportsConversion) {
            conversionButtons.style.display = 'block';
        } else {
            conversionButtons.style.display = 'none';
        }
        
        // Validate
        const result = format.validate(input);
        
        if (result.valid) {
            validation.innerHTML = '<span class="text-success"><i class="bi bi-check-circle-fill"></i> Valid ' + format.name + '</span>';
        } else {
            validation.innerHTML = '<span class="text-danger"><i class="bi bi-x-circle-fill"></i> Invalid: ' + window.escapeHtml(result.error) + '</span>';
        }
    }

    function showTreeAndStats(show) {
        const treeCard = document.getElementById('treeVisualizerCard');
        const statsRow = document.getElementById('statisticsRow');
        
        if (show) {
            treeCard.style.display = 'block';
            statsRow.style.display = 'block';
        } else {
            treeCard.style.display = 'none';
            statsRow.style.display = 'none';
        }
    }

    function updateTreeView(data) {
        const treeDiv = document.getElementById('beautifierTree');
        const searchResults = document.getElementById('searchResults');
        
        try {
            const treeHtml = buildTreeView(data, '', searchQuery);
            
            if (!treeHtml && searchQuery) {
                treeDiv.innerHTML = '<p class="text-warning text-center">No matches found for "' + window.escapeHtml(searchQuery) + '"</p>';
                searchResults.textContent = 'No matches found';
                searchResults.className = 'text-warning d-block mt-1';
            } else if (searchQuery) {
                treeDiv.innerHTML = treeHtml;
                searchResults.textContent = 'Showing filtered results';
                searchResults.className = 'text-success d-block mt-1';
            } else {
                treeDiv.innerHTML = treeHtml;
                searchResults.textContent = '';
            }
        } catch (e) {
            treeDiv.innerHTML = '<p class="text-danger">Error building tree: ' + window.escapeHtml(e.message) + '</p>';
        }
    }

    function buildBeautifierStatsHtml(stats) {
        return `
                <div class="col-md-3 col-sm-6">
                    <div class="stat-card">
                        <div class="stat-icon text-primary">
                            <i class="bi bi-layers"></i>
                        </div>
                        <div class="stat-content">
                            <div class="stat-value">${stats.maxDepth}</div>
                            <div class="stat-label">Max Depth</div>
                        </div>
                    </div>
                </div>
                <div class="col-md-3 col-sm-6">
                    <div class="stat-card">
                        <div class="stat-icon text-success">
                            <i class="bi bi-key"></i>
                        </div>
                        <div class="stat-content">
                            <div class="stat-value">${stats.totalKeys}</div>
                            <div class="stat-label">Total Keys</div>
                        </div>
                    </div>
                </div>
                <div class="col-md-3 col-sm-6">
                    <div class="stat-card">
                        <div class="stat-icon text-info">
                            <i class="bi bi-boxes"></i>
                        </div>
                        <div class="stat-content">
                            <div class="stat-value">${stats.totalObjects}</div>
                            <div class="stat-label">Objects</div>
                        </div>
                    </div>
                </div>
                <div class="col-md-3 col-sm-6">
                    <div class="stat-card">
                        <div class="stat-icon text-warning">
                            <i class="bi bi-list-ul"></i>
                        </div>
                        <div class="stat-content">
                            <div class="stat-value">${stats.totalArrays}</div>
                            <div class="stat-label">Arrays</div>
                        </div>
                    </div>
                </div>
                <div class="col-md-3 col-sm-6">
                    <div class="stat-card">
                        <div class="stat-icon text-primary">
                            <i class="bi bi-quote"></i>
                        </div>
                        <div class="stat-content">
                            <div class="stat-value">${stats.totalStrings}</div>
                            <div class="stat-label">Strings</div>
                        </div>
                    </div>
                </div>
                <div class="col-md-3 col-sm-6">
                    <div class="stat-card">
                        <div class="stat-icon text-success">
                            <i class="bi bi-hash"></i>
                        </div>
                        <div class="stat-content">
                            <div class="stat-value">${stats.totalNumbers}</div>
                            <div class="stat-label">Numbers</div>
                        </div>
                    </div>
                </div>
                <div class="col-md-3 col-sm-6">
                    <div class="stat-card">
                        <div class="stat-icon text-info">
                            <i class="bi bi-toggle-on"></i>
                        </div>
                        <div class="stat-content">
                            <div class="stat-value">${stats.totalBooleans}</div>
                            <div class="stat-label">Booleans</div>
                        </div>
                    </div>
                </div>
                <div class="col-md-3 col-sm-6">
                    <div class="stat-card">
                        <div class="stat-icon text-secondary">
                            <i class="bi bi-x-circle"></i>
                        </div>
                        <div class="stat-content">
                            <div class="stat-value">${stats.totalNulls}</div>
                            <div class="stat-label">Nulls</div>
                        </div>
                    </div>
                </div>
        `;
    }

    function updateStatistics(data) {
        const statsDiv = document.getElementById('beautifierStats');
        try {
            const stats = getStatistics(data);
            statsDiv.innerHTML = buildBeautifierStatsHtml(stats);
        } catch (e) {
            statsDiv.innerHTML = '<p class="text-danger">Error calculating statistics: ' + window.escapeHtml(e.message) + '</p>';
        }
    }

    function showNotification(message, type = 'info') {
        const colors = {
            success: 'success',
            danger: 'danger',
            warning: 'warning',
            info: 'info'
        };
        
        const existing = document.querySelector('.beautifier-notification');
        if (existing) existing.remove();
        
        const notification = document.createElement('div');
        notification.className = `alert alert-${colors[type]} beautifier-notification`;
        notification.style.cssText = 'position: fixed; top: 80px; right: 20px; z-index: 9999; min-width: 300px; animation: slideInRight 0.3s ease;';
        notification.innerHTML = `
            <i class="bi bi-${type === 'success' ? 'check-circle-fill' : type === 'danger' ? 'x-circle-fill' : type === 'warning' ? 'exclamation-triangle-fill' : 'info-circle-fill'}"></i>
            ${window.escapeHtml(message)}
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOutRight 0.3s ease';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }

    // ========================================
    // PIPELINE INTEGRATION
    // ========================================

    function renderBeautifierPipelineForm(expectedFormat, stepIndex) {
        const suffix = typeof stepIndex === 'number' ? stepIndex : expectedFormat;
        const textareaId = `beautifierPipelineInput-${expectedFormat}-${suffix}`;
        const statusId = `${textareaId}-status`;
        const sampleBtnId = `${textareaId}-sample`;
        const placeholder = expectedFormat === 'xml'
            ? '<root>\n  <item>Value</item>\n</root>'
            : '{\n  "name": "CyberSuite",\n  "valid": true\n}';
        const title = expectedFormat === 'xml' ? 'XML pipeline input' : 'JSON pipeline input';

        return `
            <div class="card bg-dark pipeline-input-card">
                <div class="card-header d-flex align-items-center gap-2">
                    <i class="bi bi-code-slash"></i>
                    <span>${title}</span>
                    <button class="btn btn-sm btn-outline-info ms-auto" type="button" id="${sampleBtnId}">
                        <i class="bi bi-magic"></i> Sample
                    </button>
                </div>
                <div class="card-body">
                    <textarea
                        class="form-control font-monospace"
                        id="${textareaId}"
                        rows="6"
                        placeholder="${window.escapeHtml(placeholder)}"
                        spellcheck="false"
                    ></textarea>
                    <div id="${statusId}" class="text-secondary small mt-2">Provide valid ${expectedFormat.toUpperCase()} to start the pipeline.</div>
                </div>
            </div>
        `;
    }

    function initBeautifierPipelineForm(expectedFormat, context = {}) {
        const suffix = typeof context.index === 'number' ? context.index : expectedFormat;
        const textareaId = `beautifierPipelineInput-${expectedFormat}-${suffix}`;
        const statusId = `${textareaId}-status`;
        const sampleBtnId = `${textareaId}-sample`;

        const textarea = document.getElementById(textareaId);
        const status = document.getElementById(statusId);
        const sampleBtn = document.getElementById(sampleBtnId);

        const sampleValue = expectedFormat === 'xml'
            ? '<root>\n  <item>Value</item>\n</root>'
            : '{\n  "name": "CyberSuite",\n  "valid": true\n}';

        const setStatus = (msg, cls) => {
            if (!status) return;
            status.textContent = msg;
            status.className = `small mt-2 ${cls}`;
        };

        const validate = () => {
            if (!textarea) return;
            const val = textarea.value.trim();
            if (!val) {
                setStatus(`Provide valid ${expectedFormat.toUpperCase()} to start the pipeline.`, 'text-secondary');
                return;
            }
            try {
                if (expectedFormat === 'xml') {
                    parseXML(val);
                } else {
                    JSON.parse(val);
                }
                setStatus('Looks valid.', 'text-success');
            } catch (e) {
                setStatus(`Invalid ${expectedFormat.toUpperCase()}: ${e.message}`, 'text-danger');
            }
        };

        if (textarea) {
            textarea.addEventListener('input', validate);
        }
        if (sampleBtn && textarea) {
            sampleBtn.addEventListener('click', () => {
                textarea.value = sampleValue;
                validate();
                textarea.focus();
            });
        }
    }

    async function beautifierPipelineProcess(input, expectedFormat = 'any', context = {}) {
        try {
            let dataObj;
            let workingInput = input;
            let detectedFormat = 'json';

            const isEmptyValue = (val) => {
                if (val === null || val === undefined) return true;
                if (typeof val === 'string') return val.trim().length === 0;
                return false;
            };

            const getScopedElement = (id) => {
                if (context && typeof context.stepIndex === 'number') {
                    const root = document.getElementById(`pipelineToolBody-${context.stepIndex}`);
                    if (root) {
                        const scoped = root.querySelector(`#${id}`);
                        if (scoped) return scoped;
                    }
                }
                return document.getElementById(id);
            };

            const firstInputId = `beautifierPipelineInput-${expectedFormat}-${typeof context.stepIndex === 'number' ? context.stepIndex : expectedFormat}`;
            const firstInputEl = getScopedElement(firstInputId);
            const useFirstInput = context && context.isFirst && firstInputEl;

            if (useFirstInput) {
                const raw = (firstInputEl.value || '').trim();
                if (!raw) {
                    return {
                        success: false,
                        error: `Beautifier ${expectedFormat.toUpperCase()} input is required for the first step.`
                    };
                }
                try {
                    if (expectedFormat === 'xml') {
                        parseXML(raw);
                    } else {
                        JSON.parse(raw);
                    }
                    workingInput = raw;
                } catch (e) {
                    return {
                        success: false,
                        error: `Invalid ${expectedFormat.toUpperCase()} in pipeline input: ${e.message}`
                    };
                }
            } else if (isEmptyValue(workingInput)) {
                const inputArea = getScopedElement('beautifierInput');
                if (inputArea && inputArea.value.trim().length > 0) {
                    workingInput = inputArea.value;
                }
            }

            // Accept either a JSON string, XML string, or a plain JS object
            if (typeof workingInput === 'string') {
                const trimmed = workingInput.trim();
                const wantsXml = expectedFormat === 'xml';
                if (wantsXml || trimmed.startsWith('<')) {
                    try {
                        dataObj = parseXML(trimmed);
                        detectedFormat = 'xml';
                    } catch (e) {
                        return {
                            success: false,
                            error: 'Beautifier pipeline expected valid XML; parse failed: ' + e.message
                        };
                    }
                } else {
                    try {
                        dataObj = JSON.parse(workingInput);
                        detectedFormat = 'json';
                    } catch (e) {
                        return {
                            success: false,
                            error: 'Beautifier pipeline expected a JSON string but failed to parse: ' + e.message
                        };
                    }
                }
            } else if (workingInput !== null && typeof workingInput === 'object') {
                if (expectedFormat === 'xml') {
                    return {
                        success: false,
                        error: 'Beautifier XML block expects XML text input.'
                    };
                }
                dataObj = workingInput;
                detectedFormat = 'json';
            } else {
                return {
                    success: false,
                    error: 'Beautifier pipeline expected JSON or XML input. Provide data in the Beautifier panel or connect an upstream tool.'
                };
            }

            // Update internal state
            currentFormat = detectedFormat;
            parsedData = dataObj;

            // Pretty-print JSON
            const prettyJson =
                detectedFormat === 'xml' && typeof workingInput === 'string'
                    ? beautifyXML(workingInput.trim())
                    : JSON.stringify(dataObj, null, 2);

            // Build a static tree HTML for pipeline output as well
            let treeHtml = '';
            try {
                treeHtml = buildTreeView(dataObj, '', '');
            } catch (treeErr) {
                console.warn('Beautifier pipeline tree build failed:', treeErr);
            }

            // Build statistics HTML for pipeline output
            let stats = null;
            let statsHtml = '';
            try {
                stats = getStatistics(dataObj);
                statsHtml = buildBeautifierStatsHtml(stats);
            } catch (statsErr) {
                console.warn('Beautifier pipeline stats build failed:', statsErr);
            }

            // Build a compact HTML view for pipeline step output
            const html = `
                <div class="card bg-dark border-secondary">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span>
                            <i class="bi bi-magic"></i>
                            Beautified ${detectedFormat.toUpperCase()} (Pipeline)
                        </span>
                        <span class="badge bg-secondary">Beautifier</span>
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <label class="form-label">Pretty ${detectedFormat.toUpperCase()}</label>
                            <pre class="mb-0"><code>${window.escapeHtml(prettyJson)}</code></pre>
                        </div>
                        ${
                            treeHtml
                                ? `
                                    <hr class="text-secondary" />
                                    <div>
                                        <h6 class="small text-uppercase text-secondary mb-2">
                                            <i class="bi bi-diagram-3"></i> Tree View
                                        </h6>
                                        <div class="beautifier-tree-view">
                                            ${treeHtml}
                                        </div>
                                    </div>
                                  `
                                : ''
                        }
                        ${
                            statsHtml
                                ? `
                                    <hr class="text-secondary" />
                                    <div>
                                        <h6 class="small text-uppercase text-secondary mb-2">
                                            <i class="bi bi-graph-up"></i> Statistics
                                        </h6>
                                        <div class="row g-3">
                                            ${statsHtml}
                                        </div>
                                    </div>
                                  `
                                : ''
                        }
                    </div>
                </div>
            `;

            // Try to sync the beautifier UI if it is rendered (single-tool or pipeline start)
            try {
                const inputArea       = getScopedElement('beautifierInput');
                const outputArea      = getScopedElement('beautifierOutput');
                const validation      = getScopedElement('beautifierValidation');
                const formatBadge     = getScopedElement('detectedFormat');
                const conversionBtns  = getScopedElement('conversionButtons');
                const treeContainer   = getScopedElement('beautifierTree');
                const statsContainer  = getScopedElement('beautifierStats');

                if (inputArea) {
                    inputArea.value = prettyJson;
                }
                if (outputArea) {
                    outputArea.value = prettyJson;
                }
                if (formatBadge) {
                    formatBadge.innerHTML = '<i class="bi bi-file-earmark-code"></i> JSON';
                }
                if (validation) {
                    validation.innerHTML = '<span class="text-success"><i class="bi bi-check-circle-fill"></i> Valid JSON (from pipeline)</span>';
                }
                if (conversionBtns) {
                    conversionBtns.style.display = 'block';
                }

                // Only try to render tree/stats if their containers exist (tool workspace is mounted)
                if (treeContainer && statsContainer) {
                    updateTreeView(dataObj);
                    updateStatistics(dataObj);
                    showTreeAndStats(true);
                }
            } catch (uiError) {
                console.warn('Beautifier pipeline UI update failed:', uiError);
                // Non-fatal for the pipeline: we still return success as long as data processing worked
            }

            return {
                success: true,
                // Keep JSON as an object; for XML return beautified string
                output: detectedFormat === 'xml' ? prettyJson : dataObj,
                metadata: {
                    prettyPrinted: true,
                    source: 'beautifier-tool',
                    type: detectedFormat,
                    treeHtml,
                    stats,
                    html
                }
            };
        } catch (e) {
            return {
                success: false,
                error: 'Beautifier pipeline error: ' + e.message
            };
        }
    }

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'beautifier',
        name: 'Code Beautifier',
        description: 'Auto-detect & beautify JSON, XML, HTML, CSS, JS, SQL with tree view, live filtering and statistics',
        icon: 'bi-magic',
        category: 'purple',
        render: render,
        init: init,
        // Pipeline integration split into JSON and XML blocks
        pipelineBlocks: [
            {
                id: 'json',
                name: 'Beautify JSON',
                description: 'Pretty print JSON with tree view and stats',
                inputTypes: ['json'],
                outputType: 'json',
                processPipeline: (input, ctx) => beautifierPipelineProcess(input, 'json', ctx),
                renderPipelineForm: ({ stepIndex }) => renderBeautifierPipelineForm('json', stepIndex),
                initPipeline: ({ index }) => initBeautifierPipelineForm('json', { index }),
                renderPipelineOutput: function({ output, metadata }) {
                    if (metadata && typeof metadata.html === 'string') {
                        return metadata.html;
                    }

                    let treeHtml = metadata && metadata.treeHtml ? metadata.treeHtml : '';
                    let statsHtml = '';
                    if (metadata && metadata.stats) {
                        statsHtml = buildBeautifierStatsHtml(metadata.stats);
                    }

                    const prettyJson = JSON.stringify(output, null, 2);

                    return `
                        <div class="card bg-dark border-secondary">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <span>
                                    <i class="bi bi-magic"></i>
                                    Beautified JSON (Pipeline)
                                </span>
                                <span class="badge bg-secondary">Beautifier</span>
                            </div>
                            <div class="card-body">
                                <div class="mb-3">
                                    <label class="form-label">Pretty JSON</label>
                                    <pre class="mb-0"><code>${window.escapeHtml(prettyJson)}</code></pre>
                                </div>
                                ${
                                    treeHtml
                                        ? `
                                            <hr class="text-secondary" />
                                            <div>
                                                <h6 class="small text-uppercase text-secondary mb-2">
                                                    <i class="bi bi-diagram-3"></i> Tree View
                                                </h6>
                                                <div class="beautifier-tree-view">
                                                    ${treeHtml}
                                                </div>
                                            </div>
                                          `
                                        : ''
                                }
                                ${
                                    statsHtml
                                        ? `
                                            <hr class="text-secondary" />
                                            <div>
                                                <h6 class="small text-uppercase text-secondary mb-2">
                                                    <i class="bi bi-graph-up"></i> Statistics
                                                </h6>
                                                <div class="row g-3">
                                                    ${statsHtml}
                                                </div>
                                            </div>
                                          `
                                        : ''
                                }
                            </div>
                        </div>
                    `;
                },
                hint: 'Input: JSON string or object. Output: pretty JSON + stats.'
            },
            {
                id: 'xml',
                name: 'Beautify XML',
                description: 'Pretty print XML with tree view',
                inputTypes: ['xml'],
                outputType: 'text',
                processPipeline: (input, ctx) => beautifierPipelineProcess(input, 'xml', ctx),
                renderPipelineForm: ({ stepIndex }) => renderBeautifierPipelineForm('xml', stepIndex),
                initPipeline: ({ index }) => initBeautifierPipelineForm('xml', { index }),
                renderPipelineOutput: function({ metadata, output }) {
                    if (metadata && typeof metadata.html === 'string') {
                        return metadata.html;
                    }
                    const treeHtml = metadata && metadata.treeHtml ? metadata.treeHtml : '';
                    const prettyXml = typeof output === 'string' ? output : '';
                    return `
                        <div class="card bg-dark border-secondary">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <span>
                                    <i class="bi bi-magic"></i>
                                    Beautified XML (Pipeline)
                                </span>
                                <span class="badge bg-secondary">Beautifier</span>
                            </div>
                            <div class="card-body">
                                <div class="mb-3">
                                    <label class="form-label">Pretty XML</label>
                                    <pre class="mb-0"><code>${window.escapeHtml(prettyXml)}</code></pre>
                                </div>
                                ${
                                    treeHtml
                                        ? `
                                            <hr class="text-secondary" />
                                            <div>
                                                <h6 class="small text-uppercase text-secondary mb-2">
                                                    <i class="bi bi-diagram-3"></i> Tree View
                                                </h6>
                                                <div class="beautifier-tree-view">
                                                    ${treeHtml}
                                                </div>
                                            </div>
                                          `
                                        : ''
                                }
                            </div>
                        </div>
                    `;
                },
                hint: 'Input: XML string. Output: pretty XML and tree view.'
            }
        ],
        processPipeline: (input, ctx) => beautifierPipelineProcess(input, 'any', ctx)
    });
})();
