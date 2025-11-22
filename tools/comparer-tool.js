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
            parse: parseHTML,
            minify: minifyHTML,
            supportsTree: true,
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

    // Utility: Escape HTML
    window.escapeHtml = function(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    };

    // ==========================
    // JSON HANDLERS
    // ==========================

    function beautifyJSON(str) {
        try {
            const obj = JSON.parse(str);
            return JSON.stringify(obj, null, 4);
        } catch (e) {
            throw new Error('Invalid JSON: ' + e.message);
        }
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

    function minifyJSON(str) {
        try {
            const obj = JSON.parse(str);
            return JSON.stringify(obj);
        } catch (e) {
            throw new Error('Invalid JSON: ' + e.message);
        }
    }

    // ==========================
    // XML HANDLERS
    // ==========================

    function beautifyXML(str) {
        try {
            const parser = new DOMParser();
            const xmlDoc = parser.parseFromString(str, 'text/xml');
            const parseError = xmlDoc.querySelector('parsererror');
            
            if (parseError) {
                throw new Error(parseError.textContent);
            }

            const serializer = new XMLSerializer();
            const xmlStr = serializer.serializeToString(xmlDoc);
            
            // Pretty print by adding newlines and indentation
            let formatted = '';
            const reg = /(>)(<)(\/*)/g;
            let pad = 0;
            
            str = xmlStr.replace(reg, '$1\n$2$3');
            
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

                const padding = '    '.repeat(pad);
                pad += indent;
                return padding + node;
            }).join('\n');
        } catch (e) {
            throw new Error('Invalid XML: ' + e.message);
        }
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
    function parseHTML(str) {
        const parser = new DOMParser();
        const doc = parser.parseFromString(str, 'text/html');
        const root = doc.documentElement || doc;
        return xmlToObject(root);
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
                
                if (child.nodeType === 3) { // text node
                    const text = child.nodeValue.trim();
                    if (text.length > 0) {
                        obj['#text'] = text;
                    }
                } else if (child.nodeType === 1) { // element node
                    const childName = child.nodeName;
                    if (typeof obj[childName] === 'undefined') {
                        obj[childName] = xmlToObject(child);
                    } else {
                        if (!Array.isArray(obj[childName])) {
                            obj[childName] = [obj[childName]];
                        }
                        obj[childName].push(xmlToObject(child));
                    }
                }
            }
        }
        
        return obj;
    }

    function minifyXML(str) {
        try {
            const parser = new DOMParser();
            const xmlDoc = parser.parseFromString(str, 'text/xml');
            const parseError = xmlDoc.querySelector('parsererror');
            
            if (parseError) {
                throw new Error(parseError.textContent);
            }

            const serializer = new XMLSerializer();
            let xmlStr = serializer.serializeToString(xmlDoc);
            
            // Remove whitespace between tags
            xmlStr = xmlStr.replace(/>[\s\r\n]+</g, '><').trim();
            return xmlStr;
        } catch (e) {
            throw new Error('Invalid XML: ' + e.message);
        }
    }

    // ==========================
    // HTML HANDLERS
    // ==========================

    function beautifyHTML(str) {
        try {
            // Simple HTML beautifier
            let formatted = '';
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

                const padding = '    '.repeat(pad);
                pad += indent;
                return padding + node;
            }).join('\n');
        } catch (e) {
            throw new Error('Invalid HTML: ' + e.message);
        }
    }

    function validateHTML(str) {
        try {
            const parser = new DOMParser();
            const doc = parser.parseFromString(str, 'text/html');
            // HTML parser in many browsers doesn't strictly validate,
            // so we just check that the result is non-empty.
            if (!doc.documentElement) {
                return { valid: false, error: 'Unable to parse HTML' };
            }
            return { valid: true };
        } catch (e) {
            return { valid: false, error: e.message };
        }
    }

    function minifyHTML(str) {
        // Very basic HTML minification
        return str.replace(/\n/g, '')
                  .replace(/\s{2,}/g, ' ')
                  .replace(/>\s+</g, '><')
                  .trim();
    }

    // ==========================
    // CSS HANDLERS
    // ==========================

    function beautifyCSS(str) {
        try {
            // Very basic beautifier, adds newlines and indentation
            let formatted = '';
            let indent = 0;
            const rules = str.split('}');
            
            rules.forEach(rule => {
                rule = rule.trim();
                if (!rule) return;
                
                const parts = rule.split('{');
                if (parts.length === 2) {
                    formatted += parts[0].trim() + ' {\n';
                    const declarations = parts[1].split(';');
                    
                    declarations.forEach(decl => {
                        decl = decl.trim();
                        if (!decl) return;
                        formatted += '    ' + decl + ';\n';
                    });
                    
                    formatted += '}\n\n';
                }
            });
            
            return formatted.trim();
        } catch (e) {
            throw new Error('Invalid CSS: ' + e.message);
        }
    }

    function validateCSS(str) {
        // Basic validation: check for matching braces and semicolons
        let openBraces = (str.match(/{/g) || []).length;
        let closeBraces = (str.match(/}/g) || []).length;
        
        if (openBraces !== closeBraces) {
            return { valid: false, error: 'Mismatched braces in CSS' };
        }
        
        return { valid: true };
    }

    function minifyCSS(str) {
        // Simple CSS minifier
        return str
            .replace(/\/\*[\s\S]*?\*\//g, '') // remove comments
            .replace(/\s+/g, ' ')            // collapse whitespace
            .replace(/\s*([{}:;,])\s*/g, '$1') // remove space around symbols
            .replace(/;}/g, '}')             // remove last semicolon
            .trim();
    }

    // ==========================
    // JAVASCRIPT HANDLERS
    // ==========================

    function beautifyJS(str) {
        try {
            // Basic indentation based on braces
            let formatted = '';
            let indent = 0;
            const lines = str.split('\n');
            
            lines.forEach(line => {
                line = line.trim();
                if (!line) return;
                
                if (line.match(/^}/)) {
                    indent = Math.max(indent - 1, 0);
                }
                
                formatted += '    '.repeat(indent) + line + '\n';
                
                if (line.match(/{[^}]*$/)) {
                    indent++;
                }
            });
            
            return formatted.trim();
        } catch (e) {
            throw new Error('Error beautifying JavaScript: ' + e.message);
        }
    }

    function validateJS(str) {
        try {
            new Function(str);
            return { valid: true };
        } catch (e) {
            return { valid: false, error: e.message };
        }
    }

    function minifyJS(str) {
        // Note: this is a very naive JS minifier and not suitable for production use
        return str
            .replace(/\/\/.*$/gm, '')       // remove single-line comments
            .replace(/\/\*[\s\S]*?\*\//g, '') // remove multi-line comments
            .replace(/\s+/g, ' ')           // collapse whitespace
            .replace(/\s*([{}();,=:+\-*\/<>])\s*/g, '$1') // remove spaces around symbols
            .trim();
    }

    // ==========================
    // SQL HANDLERS
    // ==========================

    function beautifySQL(str) {
        try {
            // Basic SQL formatter
            const keywords = [
                'SELECT', 'FROM', 'WHERE', 'GROUP BY', 'ORDER BY', 'HAVING',
                'JOIN', 'LEFT JOIN', 'RIGHT JOIN', 'INNER JOIN', 'OUTER JOIN',
                'ON', 'LIMIT', 'OFFSET', 'INSERT', 'INTO', 'VALUES',
                'UPDATE', 'SET', 'DELETE'
            ];

            let formatted = str;
            
            keywords.forEach(keyword => {
                const regex = new RegExp('\\b' + keyword + '\\b', 'gi');
                formatted = formatted.replace(regex, '\n' + keyword);
            });
            
            formatted = formatted.replace(/\s+/g, ' ').trim();
            
            // Add indentation after SELECT and WHERE
            formatted = formatted.replace(/SELECT/g, 'SELECT\n    ')
                                 .replace(/WHERE/g, '\nWHERE\n    ');
            
            return formatted.trim();
        } catch (e) {
            throw new Error('Error beautifying SQL: ' + e.message);
        }
    }

    function validateSQL(str) {
        // Very basic validation: check for common keywords
        const hasSelect = /\bSELECT\b/i.test(str);
        const hasFrom = /\bFROM\b/i.test(str);
        
        if (hasSelect && !hasFrom) {
            return { valid: false, error: 'SELECT statement must include a FROM clause' };
        }
        
        return { valid: true };
    }

    function minifySQL(str) {
        // Simple SQL minifier
        return str
            .replace(/--.*$/gm, '')         // remove single-line comments
            .replace(/\/\*[\s\S]*?\*\//g, '') // remove multi-line comments
            .replace(/\s+/g, ' ')           // collapse whitespace
            .trim();
    }

    // ==========================
    // FORMAT DETECTION
    // ==========================

    function detectFormat(str) {
        const trimmed = str.trim();
        
        // JSON detection
        if ((trimmed.startsWith('{') && trimmed.endsWith('}')) ||
            (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
            try {
                JSON.parse(trimmed);
                return 'json';
            } catch (e) {}
        }

        // XML detection
        if (trimmed.startsWith('<') && trimmed.endsWith('>')) {
            try {
                const parser = new DOMParser();
                const doc = parser.parseFromString(trimmed, 'text/xml');
                if (!doc.querySelector('parsererror') && doc.documentElement.nodeName !== 'html') {
                    return 'xml';
                }
            } catch (e) {}
        }

        // HTML detection
        if (/<\/?[a-z][\s\S]*>/i.test(trimmed)) {
            try {
                const parser = new DOMParser();
                const doc = parser.parseFromString(trimmed, 'text/html');
                if (doc.documentElement) {
                    return 'html';
                }
            } catch (e) {}
        }

        // CSS detection
        if (/[{].*[}]/s.test(trimmed) && /[a-z-]+\s*:\s*[^;]+;/.test(trimmed)) {
            return 'css';
        }

        // SQL detection (simple)
        if (/^\s*(SELECT|INSERT|UPDATE|DELETE)\b/i.test(trimmed)) {
            return 'sql';
        }

        // JavaScript detection
        if (/function\s+|\(\)\s*=>|=>\s*{/.test(trimmed)) {
            return 'javascript';
        }

        // Default to JSON
        return 'json';
    }

    // ==========================
    // TREE VIEW & STATISTICS
    // ==========================

    function buildTreeView(data, path = '', query = '') {
        const queryLower = query.toLowerCase();
        const numericQuery = query && !isNaN(Number(query)) ? Number(query) : null;
        
        function matchesSearch(key, value) {
            if (!query) return true;
            
            // Exact numeric match when the query itself is numeric
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

        function renderNode(key, value, currentPath) {
            const isObject = value && typeof value === 'object' && !Array.isArray(value);
            const isArray = Array.isArray(value);
            const hasChildren = isObject || isArray;
            const shouldShow = matchesSearch(key, value) || (hasChildren && hasMatchingChild(value));
            
            if (!shouldShow) return '';
            
            const nodePath = currentPath ? `${currentPath}.${key}` : String(key);
            const displayKey = key === '' ? '(root)' : key;
            
            if (!hasChildren) {
                const valueType = value === null ? 'null' : typeof value;
                const valueClass = `tree-value-${valueType}`;
                
                return `
                    <div class="tree-item">
                        <span class="tree-key">${window.escapeHtml(displayKey)}:</span>
                        <span class="tree-value ${valueClass}">${window.escapeHtml(String(value))}</span>
                    </div>
                `;
            }
            
            const childrenHtml = [];
            
            if (isArray) {
                value.forEach((item, idx) => {
                    const childHtml = renderNode(idx, item, nodePath);
                    if (childHtml) {
                        childrenHtml.push(childHtml);
                    }
                });
            } else {
                Object.entries(value).forEach(([childKey, childValue]) => {
                    const childHtml = renderNode(childKey, childValue, nodePath);
                    if (childHtml) {
                        childrenHtml.push(childHtml);
                    }
                });
            }
            
            if (childrenHtml.length === 0 && query && !matchesSearch(key, '')) {
                return '';
            }
            
            const valueType = isArray ? 'Array' : 'Object';
            const childrenCount = isArray ? value.length : Object.keys(value).length;
            
            return `
                <div class="tree-node">
                    <div class="tree-node-header">
                        <span class="tree-toggle" data-path="${window.escapeHtml(nodePath)}">
                            <i class="bi bi-caret-right-fill"></i>
                        </span>
                        <span class="tree-key">${window.escapeHtml(displayKey)}</span>
                        <span class="tree-meta">(${valueType}, ${childrenCount} ${childrenCount === 1 ? 'item' : 'items'})</span>
                    </div>
                    <div class="tree-children" data-path="${window.escapeHtml(nodePath)}">
                        ${childrenHtml.join('')}
                    </div>
                </div>
            `;
        }

        if (data === null || typeof data !== 'object') {
            return `
                <div class="tree-node">
                    <div class="tree-node-header">
                        <span class="tree-key">(value)</span>
                        <span class="tree-value tree-value-${typeof data}">${window.escapeHtml(String(data))}</span>
                    </div>
                </div>
            `;
        }

        let html = '<div class="tree-root">';

        if (Array.isArray(data)) {
            data.forEach((item, idx) => {
                const nodeHtml = renderNode(idx, item, '');
                if (nodeHtml) {
                    html += nodeHtml;
                }
            });
        } else {
            Object.entries(data).forEach(([key, value]) => {
                const nodeHtml = renderNode(key, value, '');
                if (nodeHtml) {
                    html += nodeHtml;
                }
            });
        }

        html += '</div>';
        return html;
    }

    function getStatistics(data) {
        const stats = {
            maxDepth: 0,
            totalKeys: 0,
            totalValues: 0,
            totalArrays: 0,
            totalObjects: 0,
            totalStrings: 0,
            totalNumbers: 0,
            totalBooleans: 0,
            totalNulls: 0
        };

        function traverse(node, depth) {
            if (depth > stats.maxDepth) {
                stats.maxDepth = depth;
            }

            if (node === null) {
                stats.totalNulls++;
                stats.totalValues++;
                return;
            }

            const type = typeof node;

            if (type === 'string') {
                stats.totalStrings++;
                stats.totalValues++;
                return;
            }

            if (type === 'number') {
                stats.totalNumbers++;
                stats.totalValues++;
                return;
            }

            if (type === 'boolean') {
                stats.totalBooleans++;
                stats.totalValues++;
                return;
            }

            if (Array.isArray(node)) {
                stats.totalArrays++;
                stats.totalValues++;
                node.forEach(item => traverse(item, depth + 1));
                return;
            }

            if (type === 'object') {
                stats.totalObjects++;
                const entries = Object.entries(node);
                stats.totalKeys += entries.length;
                stats.totalValues++;
                
                entries.forEach(([key, value]) => {
                    traverse(value, depth + 1);
                });
            }
        }

        traverse(data, 1);
        return stats;
    }

    // ==========================
    // UI RENDERING
    // ==========================

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
                                <i class="bi bi-input-cursor-text"></i> Input
                                <span id="detectedFormat" class="badge bg-secondary ms-2">
                                    <i class="bi bi-file-earmark-code"></i> JSON
                                </span>
                            </div>
                            <div class="btn-group btn-group-sm" role="group">
                                <button class="btn btn-outline-light" onclick="beautifyCode()">
                                    <i class="bi bi-brush"></i> Beautify
                                </button>
                                <button class="btn btn-outline-light" onclick="minifyCode()">
                                    <i class="bi bi-compress"></i> Minify
                                </button>
                            </div>
                        </div>
                        <div class="card-body d-flex flex-column">
                            <div class="mb-3">
                                <textarea 
                                    class="form-control font-monospace" 
                                    id="beautifierInput" 
                                    rows="12" 
                                    placeholder="Paste or type your JSON, XML, HTML, CSS, JavaScript, or SQL here..."
                                ></textarea>
                            </div>
                            <div id="beautifierValidation" class="small mb-2"></div>
                        </div>
                    </div>
                </div>

                <div class="col-lg-6">
                    <div class="card bg-dark h-100">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <div>
                                <i class="bi bi-output"></i> Output
                            </div>
                            <div class="btn-group btn-group-sm" role="group">
                                <button class="btn btn-outline-secondary" onclick="clearBeautifier()">
                                    <i class="bi bi-x-circle"></i> Clear
                                </button>
                                <button class="btn btn-outline-secondary" onclick="copyBeautifierOutput()">
                                    <i class="bi bi-clipboard"></i> Copy
                                </button>
                                <button class="btn btn-outline-info" onclick="downloadBeautifierOutput()">
                                    <i class="bi bi-download"></i> Download
                                </button>
                            </div>
                        </div>
                        <div class="card-body d-flex flex-column">
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
                        </div>
                    </div>
                </div>
            </div>

            <div class="row g-3 mt-2">
                <div class="col-lg-6">
                    <div class="card bg-dark h-100">
                        <div class="card-header">
                            <i class="bi bi-diagram-3"></i> Tree View & Structure
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

                <div class="col-lg-6">
                    <div class="card bg-dark h-100" id="treeVisualizerCard" style="display: none;">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <div>
                                <i class="bi bi-diagram-3"></i> Visualizer
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
                            <!-- Tree mode (JSON / XML / HTML) -->
                            <div id="beautifierTreeWrapper" class="d-flex flex-column flex-grow-1">
                                <div class="mb-3">
                                    <div class="input-group">
                                        <span class="input-group-text">
                                            <i class="bi bi-search"></i>
                                        </span>
                                        <input
                                            type="text"
                                            class="form-control"
                                            id="beautifierSearch"
                                            placeholder="Filter tree by keys or values."
                                        >
                                    </div>
                                    <small class="text-secondary d-block mt-1" id="searchResults"></small>
                                </div>

                                <div id="beautifierTree" class="beautifier-tree-view flex-grow-1">
                                    <p class="text-secondary text-center">
                                        Beautify JSON, XML or HTML to see the tree visualization
                                    </p>
                                </div>
                            </div>

                            <!-- Output preview for non-tree formats (JS, SQL, etc.) -->
                            <div id="beautifierOutputPreviewWrapper" class="mt-3" style="display: none;">
                                <label class="form-label small text-secondary mb-1">
                                    <i class="bi bi-code-square"></i> Output Preview
                                </label>
                                <pre id="beautifierOutputPreview" class="beautifier-output-preview"></pre>
                            </div>

                            <!-- HTML live render -->
                            <div id="beautifierHtmlPreviewWrapper" class="mt-3" style="display: none;">
                                <label class="form-label small text-secondary mb-1">
                                    <i class="bi bi-window-sidebar"></i> HTML Render
                                </label>
                                <div class="beautifier-html-preview">
                                    <iframe id="beautifierHtmlPreview" sandbox=""></iframe>
                                </div>
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
                    <div class="row g-3">
                        <div class="col-md-6">
                            <h6>Supported Formats:</h6>
                            <ul class="mb-3">
                                <li><strong>JSON:</strong> Full parse, beautify, minify, validate</li>
                                <li><strong>XML:</strong> Parse to tree, beautify, validate, convert to JSON</li>
                                <li><strong>HTML:</strong> Beautify, tree view and live preview</li>
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
                                <li>Tree view for hierarchical formats (JSON, XML, HTML)</li>
                                <li>Statistics on depth, keys, and value types</li>
                                <li>Copy & download output in one click</li>
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
    "roles": ["admin", "editor"],
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
    }

    // Expose public functions
    window.renderBeautifierTool = function(containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;
        
        container.innerHTML = render();
        init();

        // Initialize tree event listeners
        document.addEventListener('click', (e) => {
            if (e.target.closest('.tree-toggle')) {
                const toggle = e.target.closest('.tree-toggle');
                const path = toggle.getAttribute('data-path');
                const children = document.querySelector(`.tree-children[data-path="${CSS.escape(path)}"]`);
                
                if (children) {
                    const isCollapsed = children.style.display === 'none' || !children.style.display;
                    children.style.display = isCollapsed ? 'block' : 'none';
                    toggle.innerHTML = isCollapsed 
                        ? '<i class="bi bi-caret-down-fill"></i>'
                        : '<i class="bi bi-caret-right-fill"></i>';
                }
            }
        });

        // Expand/collapse all controls
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
        const inputEl = document.getElementById('beautifierInput');
        const input = inputEl ? inputEl.value.trim() : '';
        const validation = document.getElementById('beautifierValidation');
        const formatBadge = document.getElementById('detectedFormat');
        const conversionButtons = document.getElementById('conversionButtons');
        
        if (!input) {
            validation.innerHTML = '';
            formatBadge.innerHTML = '<i class="bi bi-file-earmark-code"></i> JSON';
            currentFormat = 'json';
            if (conversionButtons) conversionButtons.style.display = 'none';
            parsedData = null;
            searchQuery = '';
            clearOutputPreview();
            clearHtmlPreview();
            showTreeAndStats(false);
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
            if (conversionButtons) conversionButtons.style.display = 'block';
        } else if (conversionButtons) {
            conversionButtons.style.display = 'none';
        }
        
        // Validate
        const result = format.validate(input);
        
        if (result.valid) {
            validation.innerHTML = '<span class="text-success"><i class="bi bi-check-circle-fill"></i> Valid ' + format.name + '</span>';
            
            try {
                const output = document.getElementById('beautifierOutput');
                clearOutputPreview();
                clearHtmlPreview();
                
                if (typeof format.beautify === 'function' && output) {
                    const beautified = format.beautify(input);
                    output.value = beautified;
                    
                    if (format.parse && format.supportsTree) {
                        parsedData = format.parse(input);
                        updateTreeView(parsedData);
                        updateStatistics(parsedData);
                        showTreeAndStats(true);
                        
                        if (detectedFormat === 'html') {
                            showHtmlPreview(beautified);
                        }
                    } else {
                        showTreeAndStats(false);
                        
                        if (detectedFormat === 'javascript' || detectedFormat === 'sql') {
                            showOutputPreview(beautified);
                        }
                    }
                } else if (format.parse && format.supportsTree) {
                    parsedData = format.parse(input);
                    updateTreeView(parsedData);
                    updateStatistics(parsedData);
                    showTreeAndStats(true);
                }
            } catch (e) {
                console.error(e);
            }
        } else {
            validation.innerHTML = '<span class="text-danger"><i class="bi bi-x-circle-fill"></i> Invalid: ' + window.escapeHtml(result.error) + '</span>';
            parsedData = null;
            showTreeAndStats(false);
            clearOutputPreview();
            clearHtmlPreview();
        }
    }
    
    function showTreeAndStats(show) {
        const treeCard = document.getElementById('treeVisualizerCard');
        const statsRow = document.getElementById('statisticsRow');
        const treeWrapper = document.getElementById('beautifierTreeWrapper');
        const previewWrapper = document.getElementById('beautifierOutputPreviewWrapper');
        const htmlPreviewWrapper = document.getElementById('beautifierHtmlPreviewWrapper');
        
        if (!treeCard || !statsRow) return;
        
        if (show) {
            if (treeWrapper) {
                treeWrapper.style.display = 'flex';
            }
            statsRow.style.display = 'block';
            treeCard.style.display = 'block';
        } else {
            if (treeWrapper) {
                treeWrapper.style.display = 'none';
            }
            statsRow.style.display = 'none';
            
            const hasPreview =
                (previewWrapper && previewWrapper.style.display !== 'none') ||
                (htmlPreviewWrapper && htmlPreviewWrapper.style.display !== 'none');
            
            if (!hasPreview) {
                treeCard.style.display = 'none';
            }
        }
    }
    
    function updateTreeView(data) {
        const treeDiv = document.getElementById('beautifierTree');
        const searchResults = document.getElementById('searchResults');
        
        try {
            const treeHtml = buildTreeView(data, '', searchQuery);
            
            if (!treeHtml && searchQuery) {
                treeDiv.innerHTML = `
                    <p class="text-warning text-center">
                        No results found for "<strong>${window.escapeHtml(searchQuery)}</strong>"
                    </p>
                `;
                searchResults.textContent = 'No matching keys or values found.';
            } else {
                treeDiv.innerHTML = treeHtml;
                if (searchQuery) {
                    searchResults.textContent = 'Filtered by: "' + searchQuery + '"';
                } else {
                    searchResults.textContent = '';
                }
            }
        } catch (e) {
            treeDiv.innerHTML = `
                <p class="text-danger text-center">
                    Error rendering tree: ${window.escapeHtml(e.message)}
                </p>
            `;
        }
    }

    function updateStatistics(data) {
        const statsDiv = document.getElementById('beautifierStats');
        try {
            const stats = getStatistics(data);
            
            statsDiv.innerHTML = `
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
                            <div class="stat-label">Keys</div>
                        </div>
                    </div>
                </div>
                <div class="col-md-3 col-sm-6">
                    <div class="stat-card">
                        <div class="stat-icon text-warning">
                            <i class="bi bi-123"></i>
                        </div>
                        <div class="stat-content">
                            <div class="stat-value">${stats.totalValues}</div>
                            <div class="stat-label">Values</div>
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
        } catch (e) {
            statsDiv.innerHTML = '<p class="text-danger">Error calculating statistics: ' + window.escapeHtml(e.message) + '</p>';
        }
    }
    function showOutputPreview(content) {
        const card = document.getElementById('treeVisualizerCard');
        const previewWrapper = document.getElementById('beautifierOutputPreviewWrapper');
        const preview = document.getElementById('beautifierOutputPreview');
        const treeWrapper = document.getElementById('beautifierTreeWrapper');
    
        if (!card || !previewWrapper || !preview) return;
    
        if (content) {
            preview.textContent = content;
            previewWrapper.style.display = 'block';
            card.style.display = 'block';
            if (treeWrapper) {
                treeWrapper.style.display = 'none';
            }
        } else {
            preview.textContent = '';
            previewWrapper.style.display = 'none';
        }
    }
    
    function clearOutputPreview() {
        const previewWrapper = document.getElementById('beautifierOutputPreviewWrapper');
        const preview = document.getElementById('beautifierOutputPreview');
        if (preview) preview.textContent = '';
        if (previewWrapper) previewWrapper.style.display = 'none';
    }
    
    function showHtmlPreview(html) {
        const card = document.getElementById('treeVisualizerCard');
        const wrapper = document.getElementById('beautifierHtmlPreviewWrapper');
        const iframe = document.getElementById('beautifierHtmlPreview');
    
        if (!card || !wrapper || !iframe) return;
    
        iframe.srcdoc = html || '';
        wrapper.style.display = html ? 'block' : 'none';
    
        if (html) {
            card.style.display = 'block';
        }
    }
    
    function clearHtmlPreview() {
        const wrapper = document.getElementById('beautifierHtmlPreviewWrapper');
        const iframe = document.getElementById('beautifierHtmlPreview');
        if (iframe) iframe.srcdoc = '';
        if (wrapper) wrapper.style.display = 'none';
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
        notification.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 9999; min-width: 300px; animation: slideInRight 0.3s ease;';
        notification.innerHTML = `
            <div class="d-flex align-items-center">
                <div class="flex-grow-1">
                    ${window.escapeHtml(message)}
                </div>
                <button type="button" class="btn-close ms-2" aria-label="Close"></button>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        notification.querySelector('.btn-close').addEventListener('click', () => {
            notification.remove();
        });
        
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 4000);
    }

    // ==========================
    // PUBLIC CONTROLS
    // ==========================

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
            
            // Reset previews
            clearOutputPreview();
            clearHtmlPreview();
            
            if (format.parse && format.supportsTree) {
                parsedData = format.parse(input);
                updateTreeView(parsedData);
                updateStatistics(parsedData);
                showTreeAndStats(true);
                
                if (currentFormat === 'html') {
                    // For HTML: tree + live render
                    showHtmlPreview(beautified);
                }
            } else {
                showTreeAndStats(false);
                
                // For JS and SQL: render output on the right
                if (currentFormat === 'javascript' || currentFormat === 'sql') {
                    showOutputPreview(beautified);
                }
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
        
        try {
            const sourceFormat = formats[currentFormat];
            const target = formats[targetFormat];
            
            if (!sourceFormat.parse || !target.beautify) {
                showNotification('Conversion not supported between these formats', 'warning');
                return;
            }
            
            const data = sourceFormat.parse(input);
            let converted;
            
            if (targetFormat === 'json') {
                converted = JSON.stringify(data, null, 4);
            } else if (targetFormat === 'xml') {
                // Simple JSON to XML conversion
                converted = jsonToXml(data);
            } else {
                showNotification('Conversion to ' + target.name + ' not implemented', 'warning');
                return;
            }
            
            output.value = converted;
            showNotification('Converted to ' + target.name + ' successfully!', 'success');
            
            if (target.parse && target.supportsTree) {
                parsedData = target.parse(converted);
                updateTreeView(parsedData);
                updateStatistics(parsedData);
                showTreeAndStats(true);
            } else {
                showTreeAndStats(false);
            }
        } catch (e) {
            showNotification('Conversion failed: ' + e.message, 'danger');
        }
    };

    function jsonToXml(obj, nodeName) {
        let xml = '';
        
        if (Array.isArray(obj)) {
            obj.forEach((item) => {
                xml += jsonToXml(item, nodeName);
            });
        } else if (typeof obj === 'object' && obj !== null) {
            const keys = Object.keys(obj);
            
            if (nodeName) {
                xml += `<${nodeName}>`;
            }
            
            keys.forEach((key) => {
                if (key === '@attributes') {
                    return;
                }
                
                const value = obj[key];
                
                if (typeof value === 'object') {
                    xml += jsonToXml(value, key);
                } else {
                    xml += `<${key}>${window.escapeHtml(String(value))}</${key}>`;
                }
            });
            
            if (nodeName) {
                xml += `</${nodeName}>`;
            }
        } else {
            if (nodeName) {
                xml += `<${nodeName}>${window.escapeHtml(String(obj))}</${nodeName}>`;
            }
        }
        
        return xml;
    }

    window.clearBeautifier = function() {
        document.getElementById('beautifierInput').value = '';
        document.getElementById('beautifierOutput').value = '';
        document.getElementById('beautifierValidation').innerHTML = '';
        document.getElementById('beautifierSearch').value = '';
        parsedData = null;
        searchQuery = '';
        clearOutputPreview();
        clearHtmlPreview();
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
        const output = document.getElementById('beautifierOutput');
        if (!output.value) {
            showNotification('Nothing to download', 'warning');
            return;
        }
        
        const format = formats[currentFormat];
        const blob = new Blob([output.value], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `beautified_${format.name.toLowerCase()}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        
        URL.revokeObjectURL(url);
        showNotification('Download started', 'info');
    };

})();