// ========================================
// HTTP REQUEST CONVERTER TOOL
// Category: Purple Team
// ========================================

(function() {
    'use strict';

    let conversionHistory = [];
    let detectedFormat = null;

    // ------------------------
    // Robust parsing helpers
    // ------------------------
    function normalizeNewlines(str) {
        return String(str || '').replace(/\r\n/g, '\n');
    }

    function stripLineContinuations(str) {
        // Join shell line continuations: \\ + newline
        return String(str || '').replace(/\\\n/g, ' ');
    }

    function splitOnFirst(str, sep) {
        const s = String(str || '');
        const idx = s.indexOf(sep);
        if (idx === -1) return [s, ''];
        return [s.slice(0, idx), s.slice(idx + sep.length)];
    }

    function getHeader(headers, name) {
        const target = String(name || '').toLowerCase();
        for (const [k, v] of Object.entries(headers || {})) {
            if (String(k).toLowerCase() === target) return v;
        }
        return undefined;
    }

    function tokenizeShellCommand(input) {
        // Minimal shell-like tokenizer to correctly handle payloads and headers with quotes.
        // Supports: single quotes, double quotes (with backslash escapes), and backslash escapes outside quotes.
        const s = stripLineContinuations(normalizeNewlines(input)).trim();
        const tokens = [];
        let i = 0;

        while (i < s.length) {
            while (i < s.length && /\s/.test(s[i])) i++;
            if (i >= s.length) break;

            let token = '';
            while (i < s.length) {
                const ch = s[i];

                if (/\s/.test(ch)) break;

                if (ch === "'") {
                    i++;
                    while (i < s.length && s[i] !== "'") {
                        token += s[i++];
                    }
                    if (i < s.length && s[i] === "'") i++;
                    continue;
                }

                if (ch === '"') {
                    i++;
                    while (i < s.length && s[i] !== '"') {
                        if (s[i] === '\\' && i + 1 < s.length) {
                            token += s[i + 1];
                            i += 2;
                        } else {
                            token += s[i++];
                        }
                    }
                    if (i < s.length && s[i] === '"') i++;
                    continue;
                }

                if (ch === '\\' && i + 1 < s.length) {
                    token += s[i + 1];
                    i += 2;
                    continue;
                }

                token += ch;
                i++;
            }

            tokens.push(token);
            while (i < s.length && /\s/.test(s[i])) i++;
        }

        return tokens;
    }

    function parseHeaderLine(line) {
        const [k, v] = splitOnFirst(line, ':');
        return {
            key: k.trim(),
            value: v.trim()
        };
    }

    function escapeSingleQuotesForShell(value) {
        return String(value ?? '').replace(/'/g, "'\\''");
    }

    function jsStringLiteral(value) {
        return JSON.stringify(String(value ?? ''));
    }

    function base64Utf8(str) {
        const s = String(str ?? '');
        try {
            return btoa(unescape(encodeURIComponent(s)));
        } catch {
            // Fallback in case of unexpected environments
            return btoa(s);
        }
    }

    function buildURLFromRequest(req) {
        try {
            return new URL(req.url);
        } catch {
            const host = getHeader(req.headers || {}, 'host') || 'example.com';
            // Default scheme is https when unknown
            return new URL(req.url || '/', `https://${host}`);
        }
    }

    function findMatchingBracket(str, startIndex, openChar, closeChar) {
        // Finds the matching closing bracket for a bracket at startIndex.
        // Ignores brackets inside single/double/template strings.
        const s = String(str || '');
        let depth = 0;
        let inSingle = false;
        let inDouble = false;
        let inTemplate = false;
        let esc = false;

        for (let i = startIndex; i < s.length; i++) {
            const ch = s[i];

            if (esc) {
                esc = false;
                continue;
            }

            // Escape handling inside strings
            if ((inSingle || inDouble || inTemplate) && ch === '\\') {
                esc = true;
                continue;
            }

            if (!inDouble && !inTemplate && ch === "'") {
                inSingle = !inSingle;
                continue;
            }
            if (!inSingle && !inTemplate && ch === '"') {
                inDouble = !inDouble;
                continue;
            }
            if (!inSingle && !inDouble && ch === '`') {
                inTemplate = !inTemplate;
                continue;
            }

            if (inSingle || inDouble || inTemplate) continue;

            if (ch === openChar) depth++;
            if (ch === closeChar) {
                depth--;
                if (depth === 0) return i;
            }
        }

        return -1;
    }

    function tryParseJsObjectLiteralToJson(objLiteralSource) {
        // Best-effort parser for simple JS object literals used in JSON.stringify({ ... }).
        // Supports literals like: {"a":"b", a: 1, ok: true, nested: {"x":"y"}}
        // Returns a JSON string on success; otherwise null.
        try {
            const src = String(objLiteralSource || '').trim();
            if (!src.startsWith('{') || !src.endsWith('}')) return null;

            // Convert to JSON-ish by quoting unquoted keys and using double quotes.
            // This is intentionally conservative and will fail-fast on complex JS.
            let s = src;

            // Quote bare keys: {a: 1} -> {"a": 1}
            s = s.replace(/([{,]\s*)([A-Za-z_$][\w$]*)(\s*:)/g, '$1"$2"$3');

            // Replace single-quoted strings with double-quoted strings (naive but useful).
            // NOTE: This will not handle every edge case (escaped quotes inside), but is far better than truncation.
            s = s.replace(/'([^'\\]*(?:\\.[^'\\]*)*)'/g, (m, inner) => {
                const unescaped = inner.replace(/\\'/g, "'").replace(/\\\\/g, "\\");
                return JSON.stringify(unescaped);
            });

            // Now attempt JSON.parse
            const parsed = JSON.parse(s);
            return JSON.stringify(parsed);
        } catch {
            return null;
        }
    }

    function makePhpNowdoc(body) {
        const content = String(body ?? '');
        let delim = 'PAYLOAD';
        // Ensure delimiter doesn't appear as a standalone line in the payload.
        while (new RegExp(`(^|\\n)${delim};(\\n|$)`).test(content)) {
            delim = `${delim}_X`;
        }
        return { delim, content };
    }

    function makePowerShellBodySnippet(body) {
        const content = String(body ?? '');
        const hasSingleTermLine = /(^|\r?\n)'@\r?\n/.test(content) || /\r?\n'@$/.test(content) || /^'@\r?\n/.test(content);
        const hasDoubleTermLine = /(^|\r?\n)"@\r?\n/.test(content) || /\r?\n"@$/.test(content) || /^"@\r?\n/.test(content);

        if (!hasSingleTermLine) {
            return `$body = @'\n${content}\n'@\n`;
        }
        if (!hasDoubleTermLine) {
            return `$body = @"\n${content}\n"@\n`;
        }

        // Fallback: base64 (UTF-8)
        const b64 = base64Utf8(content);
        return `$bodyBytes = [System.Convert]::FromBase64String('${b64}')\n$body = [System.Text.Encoding]::UTF8.GetString($bodyBytes)\n`;
    }

    // Request parsing and conversion logic
    const requestFormats = {
        curl: {
            name: 'cURL',
            detect: (input) => {
                return input.trim().startsWith('curl ') || input.includes('curl ');
            },
            parse: (input) => {
                const request = {
                    method: 'GET',
                    url: '',
                    headers: {},
                    body: '',
                    cookies: []
                };

                const tokens = tokenizeShellCommand(input);
                if (!tokens.length) return request;

                // Find the actual curl token (input may contain snippets or prefixes)
                let start = tokens.findIndex(t => t === 'curl');
                if (start === -1) start = 0;

                const dataParts = [];

                const takeNext = (i) => (i + 1 < tokens.length ? tokens[i + 1] : '');

                for (let i = start + 1; i < tokens.length; i++) {
                    const t = tokens[i];
                    if (!t) continue;

                    // Support attached forms like -XPOST, -HAccept:..., -dfoo=bar
                    const isAttached = (flag) => t.startsWith(flag) && t.length > flag.length;

                    // URL: first non-flag token (or explicit --url)
                    if (!t.startsWith('-') && !request.url) {
                        request.url = t;
                        continue;
                    }

                    // Method
                    if (t === '-X' || t === '--request' || isAttached('-X') || isAttached('--request=')) {
                        const m = (t === '-X' || t === '--request') ? takeNext(i) : (t.startsWith('-X') ? t.slice(2) : t.split('=')[1]);
                        if (m) request.method = String(m).toUpperCase();
                        if (t === '-X' || t === '--request') i++;
                        continue;
                    }

                    // HEAD shortcut
                    if (t === '-I' || t === '--head') {
                        request.method = 'HEAD';
                        continue;
                    }

                    // URL flag
                    if (t === '--url' || t.startsWith('--url=')) {
                        const u = (t === '--url') ? takeNext(i) : t.split('=').slice(1).join('=');
                        if (u) request.url = u;
                        if (t === '--url') i++;
                        continue;
                    }

                    // Headers
                    if (t === '-H' || t === '--header' || isAttached('-H') || t.startsWith('--header=')) {
                        const headerLine = (t === '-H' || t === '--header') ? takeNext(i) : (t.startsWith('-H') ? t.slice(2) : t.split('=').slice(1).join('='));
                        if (headerLine) {
                            const { key, value } = parseHeaderLine(headerLine);
                            if (key) {
                                request.headers[key] = value;
                                if (key.toLowerCase() === 'cookie') {
                                    request.cookies = value.split(';').map(c => c.trim()).filter(Boolean);
                                }
                            }
                        }
                        if (t === '-H' || t === '--header') i++;
                        continue;
                    }

                    // Cookies
                    if (t === '-b' || t === '--cookie' || isAttached('-b') || t.startsWith('--cookie=')) {
                        const cookieStr = (t === '-b' || t === '--cookie') ? takeNext(i) : (t.startsWith('-b') ? t.slice(2) : t.split('=').slice(1).join('='));
                        if (cookieStr) {
                            request.cookies = cookieStr.split(';').map(c => c.trim()).filter(Boolean);
                            // Also keep Cookie header in sync unless one is already present
                            if (!getHeader(request.headers, 'cookie')) {
                                request.headers['Cookie'] = request.cookies.join('; ');
                            }
                        }
                        if (t === '-b' || t === '--cookie') i++;
                        continue;
                    }

                    // Body/data
                    const isDataFlag = (flag) => t === flag || t.startsWith(flag + '=');
                    const isShortData = t === '-d' || isAttached('-d');
                    if (isShortData || isDataFlag('--data') || isDataFlag('--data-raw') || isDataFlag('--data-binary') || isDataFlag('--data-ascii') || isDataFlag('--data-urlencode')) {
                        const dataVal = (t === '-d')
                            ? takeNext(i)
                            : (isAttached('-d')
                                ? t.slice(2)
                                : (t.includes('=') ? t.split('=').slice(1).join('=') : takeNext(i)));

                        if (typeof dataVal === 'string') {
                            dataParts.push(dataVal);
                            if (!request.method || request.method === 'GET') request.method = 'POST';
                        }

                        // advance when value is in next token
                        if (t === '-d' || (!t.includes('=') && (t.startsWith('--data') || t.startsWith('--data-raw') || t.startsWith('--data-binary') || t.startsWith('--data-ascii') || t.startsWith('--data-urlencode')))) {
                            i++;
                        }
                        continue;
                    }
                }

                if (dataParts.length) {
                    request.body = dataParts.join('&');
                }

                return request;
            }
        },
        burp: {
            name: 'Burp Suite Raw',
            detect: (input) => {
                const lines = normalizeNewlines(input).trim().split('\n');
                if (lines.length === 0) return false;
                const firstLine = lines[0].trim();
                return /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP\/\d\.\d$/i.test(firstLine);
            },
            parse: (input) => {
                const lines = normalizeNewlines(input).trim().split('\n');
                const request = {
                    method: 'GET',
                    url: '',
                    headers: {},
                    body: '',
                    cookies: [],
                    httpVersion: 'HTTP/1.1'
                };

                // Parse request line
                const requestLine = lines[0].trim();
                const requestMatch = requestLine.match(/^(\w+)\s+(\S+)\s+(HTTP\/\d\.\d)$/i);
                if (requestMatch) {
                    request.method = requestMatch[1].toUpperCase();
                    request.url = requestMatch[2];
                    request.httpVersion = requestMatch[3];
                }

                // Parse headers
                let i = 1;
                let bodyStart = -1;
                for (; i < lines.length; i++) {
                    const line = lines[i];
                    if (line.trim() === '') {
                        bodyStart = i + 1;
                        break;
                    }
                    const colonIndex = line.indexOf(':');
                    if (colonIndex > 0) {
                        const key = line.substring(0, colonIndex).trim();
                        const value = line.substring(colonIndex + 1).trim();
                        request.headers[key] = value;

                        if (key.toLowerCase() === 'cookie') {
                            request.cookies = value.split(';').map(c => c.trim());
                        }
                    }
                }

                // Parse body
                if (bodyStart > 0 && bodyStart < lines.length) {
                    request.body = lines.slice(bodyStart).join('\n');
                }

                // Build full URL from Host header (case-insensitive) with a better protocol heuristic
                const hostHeader = getHeader(request.headers, 'host');
                if (hostHeader) {
                    if (!request.url.startsWith('http://') && !request.url.startsWith('https://')) {
                        // Heuristic: http for :80, https for :443, otherwise https
                        const isHttp = /:80$/.test(hostHeader);
                        const protocol = isHttp ? 'http://' : 'https://';
                        request.url = protocol + hostHeader + request.url;
                    }
                }

                return request;
            }
        },
        raw: {
            name: 'Raw HTTP',
            detect: (input) => {
                return requestFormats.burp.detect(input);
            },
            parse: (input) => {
                return requestFormats.burp.parse(input);
            }
        },
        fetch: {
            name: 'JavaScript Fetch',
            detect: (input) => {
                return input.includes('fetch(') && (input.includes('method:') || input.includes('headers:'));
            },
            parse: (input) => {
                const request = {
                    method: 'GET',
                    url: '',
                    headers: {},
                    body: '',
                    cookies: []
                };

                const src = normalizeNewlines(input);

                try {
                    // Extract URL from fetch(<url>, ...)
                    const fetchIdx = src.indexOf('fetch');
                    if (fetchIdx === -1) return request;

                    const openParen = src.indexOf('(', fetchIdx);
                    if (openParen === -1) return request;

                    // Find first string literal after "fetch("
                    let i = openParen + 1;
                    while (i < src.length && /\s/.test(src[i])) i++;
                    const quote = src[i];
                    if (quote !== '\'' && quote !== '"' && quote !== '`') return request;

                    // Read string literal
                    i++;
                    let urlVal = '';
                    let esc = false;
                    while (i < src.length) {
                        const ch = src[i];
                        if (esc) {
                            urlVal += ch;
                            esc = false;
                            i++;
                            continue;
                        }
                        if (ch === '\\') {
                            esc = true;
                            i++;
                            continue;
                        }
                        if (ch === quote) {
                            i++;
                            break;
                        }
                        urlVal += ch;
                        i++;
                    }
                    request.url = urlVal;

                    // Find options object (best effort)
                    const comma = src.indexOf(',', i);
                    if (comma === -1) return request;
                    const firstBrace = src.indexOf('{', comma);
                    if (firstBrace === -1) return request;
                    const endBrace = findMatchingBracket(src, firstBrace, '{', '}');
                    if (endBrace === -1) return request;

                    const opts = src.slice(firstBrace, endBrace + 1);

                    // Method
                    const methodMatch = opts.match(/\bmethod\s*:\s*(['"`])([\s\S]*?)\1/i);
                    if (methodMatch) request.method = methodMatch[2].trim().toUpperCase();

                    // Headers object - supports headers: {...} or headers: new Headers({...})
                    let headersSource = null;
                    const headersNewHeadersIdx = opts.search(/\bheaders\s*:\s*new\s+Headers\s*\(/i);
                    if (headersNewHeadersIdx !== -1) {
                        const open = opts.indexOf('(', headersNewHeadersIdx);
                        const innerStart = opts.indexOf('{', open);
                        if (innerStart !== -1) {
                            const innerEnd = findMatchingBracket(opts, innerStart, '{', '}');
                            if (innerEnd !== -1) headersSource = opts.slice(innerStart, innerEnd + 1);
                        }
                    } else {
                        const headersIdx = opts.search(/\bheaders\s*:\s*\{/i);
                        if (headersIdx !== -1) {
                            const innerStart = opts.indexOf('{', headersIdx);
                            const innerEnd = findMatchingBracket(opts, innerStart, '{', '}');
                            if (innerEnd !== -1) headersSource = opts.slice(innerStart, innerEnd + 1);
                        }
                    }

                    if (headersSource) {
                        const pairRe = /(['"`])([^'"`]+)\1\s*:\s*(['"`])([\s\S]*?)\3\s*(,|})/g;
                        let m;
                        while ((m = pairRe.exec(headersSource)) !== null) {
                            request.headers[m[2]] = m[4];
                            if (m[2].toLowerCase() === 'cookie') {
                                request.cookies = String(m[4]).split(';').map(c => c.trim()).filter(Boolean);
                            }
                        }
                    }

                    // Body: supports string literal or JSON.stringify(<object-literal>)
                    const bodyStringMatch = opts.match(/\bbody\s*:\s*(['"`])([\s\S]*?)\1\s*(,|})/i);
                    if (bodyStringMatch) {
                        request.body = bodyStringMatch[2];
                    } else {
                        const stringifyIdx = opts.search(/\bbody\s*:\s*JSON\.stringify\s*\(/i);
                        if (stringifyIdx !== -1) {
                            const open = opts.indexOf('(', stringifyIdx);
                            const close = findMatchingBracket(opts, open, '(', ')');
                            if (open !== -1 && close !== -1) {
                                const inner = opts.slice(open + 1, close).trim();
                                const json = tryParseJsObjectLiteralToJson(inner);
                                request.body = json ?? `JSON.stringify(${inner})`;
                            }
                        }
                    }

                } catch (e) {
                    console.error('Error parsing fetch request:', e);
                }

                return request;
            }
        },
        python: {
            name: 'Python Requests',
            detect: (input) => {
                return input.includes('requests.') && (input.includes('.get(') || input.includes('.post(') ||
                    input.includes('.put(') || input.includes('.delete(') || input.includes('.patch('));
            },
            parse: (input) => {
                const request = {
                    method: 'GET',
                    url: '',
                    headers: {},
                    body: '',
                    cookies: []
                };

                const src = normalizeNewlines(input);

                try {
                    // Method + URL
                    const methodMatch = src.match(/requests\.(get|post|put|delete|patch|head|options)\s*\(\s*(["'])([\s\S]*?)\2/si);
                    if (methodMatch) {
                        request.method = methodMatch[1].toUpperCase();
                        request.url = methodMatch[3];
                    }

                    // headers={...}
                    const headersIdx = src.search(/\bheaders\s*=\s*\{/i);
                    if (headersIdx !== -1) {
                        const start = src.indexOf('{', headersIdx);
                        const end = findMatchingBracket(src, start, '{', '}');
                        if (start !== -1 && end !== -1) {
                            const dictSrc = src.slice(start + 1, end);
                            const pairRe = /(["'])([^"']+)\1\s*:\s*(["'])([\s\S]*?)\3\s*(,|$)/g;
                            let m;
                            while ((m = pairRe.exec(dictSrc)) !== null) {
                                request.headers[m[2]] = m[4];
                                if (m[2].toLowerCase() === 'cookie') {
                                    request.cookies = String(m[4]).split(';').map(c => c.trim()).filter(Boolean);
                                }
                            }
                        }
                    }

                    // data=... or json=...
                    const dataIdx = src.search(/\b(data|json)\s*=\s*/i);
                    if (dataIdx !== -1) {
                        const afterEq = src.slice(dataIdx).replace(/^\s*(data|json)\s*=\s*/i, '');
                        const trimmed = afterEq.trimStart();

                        if (trimmed.startsWith('{')) {
                            const start = src.indexOf('{', dataIdx);
                            const end = findMatchingBracket(src, start, '{', '}');
                            if (start !== -1 && end !== -1) {
                                request.body = src.slice(start, end + 1);
                            }
                        } else if (trimmed.startsWith('"') || trimmed.startsWith("'")) {
                            const q = trimmed[0];
                            // Find matching quote with escapes
                            let j = dataIdx + src.slice(dataIdx).indexOf(q) + 1;
                            let out = '';
                            let esc = false;
                            while (j < src.length) {
                                const ch = src[j];
                                if (esc) {
                                    out += ch;
                                    esc = false;
                                    j++;
                                    continue;
                                }
                                if (ch === '\\') {
                                    esc = true;
                                    j++;
                                    continue;
                                }
                                if (ch === q) break;
                                out += ch;
                                j++;
                            }
                            request.body = out;
                        }
                    }

                } catch (e) {
                    console.error('Error parsing python requests:', e);
                }

                return request;
            }
        }
    };

    const converters = {
        curl: (req) => {
            let cmd = `curl -X ${req.method}`;
            
            // Add URL
            cmd += ` '${req.url}'`;

            // Add headers
            Object.entries(req.headers).forEach(([key, value]) => {
                if (key.toLowerCase() !== 'cookie') {
                    const headerLine = `${key}: ${value}`;
                    cmd += ` \\\n  -H '${escapeSingleQuotesForShell(headerLine)}'`;
                }
            });

            // Add cookies
            if (req.cookies && req.cookies.length > 0) {
                cmd += ` \\\n  -b '${escapeSingleQuotesForShell(req.cookies.join('; '))}'`;
            }

            // Add body
            if (req.body) {
                cmd += ` \\\n  --data-raw '${escapeSingleQuotesForShell(req.body)}'`;
            }

            return cmd;
        },
        burp: (req) => {
            const url = buildURLFromRequest(req);
            let raw = `${req.method} ${url.pathname}${url.search} ${req.httpVersion || 'HTTP/1.1'}\n`;
            
            // Add Host header first
            raw += `Host: ${url.host}\n`;

            // Add other headers
            Object.entries(req.headers).forEach(([key, value]) => {
                if (key.toLowerCase() !== 'host') {
                    raw += `${key}: ${value}\n`;
                }
            });

            // Add body
            if (req.body) {
                raw += `\n${req.body}`;
            }

            return raw;
        },
        fetch: (req) => {
            let code = `fetch(${jsStringLiteral(req.url)}, {\n`;
            code += `  method: ${jsStringLiteral(req.method)}`;

            if (Object.keys(req.headers).length > 0) {
                code += `,\n  headers: {\n`;
                Object.entries(req.headers).forEach(([key, value], index, arr) => {
                    code += `    ${jsStringLiteral(key)}: ${jsStringLiteral(value)}`;
                    if (index < arr.length - 1) code += ',';
                    code += '\n';
                });
                code += `  }`;
            }

            if (req.body) {
                code += `,\n  body: ${jsStringLiteral(req.body)}`;
            }

            code += `\n})`;
            return code;
        },
        python: (req) => {
            let code = `import requests\n\n`;
            code += `url = ${jsStringLiteral(req.url)}\n`;

            if (Object.keys(req.headers).length > 0) {
                code += `\nheaders = {\n`;
                Object.entries(req.headers).forEach(([key, value]) => {
                    code += `    ${jsStringLiteral(key)}: ${jsStringLiteral(value)},\n`;
                });
                code += `}\n`;
            }

            if (req.body) {
                code += `\ndata = ${jsStringLiteral(req.body)}\n`;
            }

            code += `\nresponse = requests.${String(req.method || 'GET').toLowerCase()}(url`;
            if (Object.keys(req.headers).length > 0) code += `, headers=headers`;
            if (req.body) code += `, data=data`;
            code += `)\n`;
            code += `print(response.text)`;

            return code;
        },
        nodejs: (req) => {
            const url = buildURLFromRequest(req);
            const isHttps = url.protocol === 'https:';
            
            let code = `const ${isHttps ? 'https' : 'http'} = require('${isHttps ? 'https' : 'http'}');\n\n`;
            code += `const options = {\n`;
            code += `  hostname: ${jsStringLiteral(url.hostname)},\n`;
            if (url.port) code += `  port: ${url.port},\n`;
            code += `  path: ${jsStringLiteral(url.pathname + url.search)},\n`;
            code += `  method: ${jsStringLiteral(req.method)}`;

            if (Object.keys(req.headers).length > 0) {
                code += `,\n  headers: {\n`;
                Object.entries(req.headers).forEach(([key, value]) => {
                    code += `    ${jsStringLiteral(key)}: ${jsStringLiteral(value)},\n`;
                });
                code += `  }`;
            }

            code += `\n};\n\n`;
            code += `const req = ${isHttps ? 'https' : 'http'}.request(options, (res) => {\n`;
            code += `  let data = '';\n`;
            code += `  res.on('data', (chunk) => { data += chunk; });\n`;
            code += `  res.on('end', () => { console.log(data); });\n`;
            code += `});\n\n`;

            if (req.body) {
                code += `req.write(${jsStringLiteral(req.body)});\n`;
            }

            code += `req.end();`;
            return code;
        },
        php: (req) => {
            let code = `<?php\n\n`;
            code += `$url = ${jsStringLiteral(req.url)};\n`;

            code += `\n$ch = curl_init($url);\n`;
            code += `curl_setopt($ch, CURLOPT_CUSTOMREQUEST, ${jsStringLiteral(req.method)});\n`;
            code += `curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);\n`;

            if (Object.keys(req.headers).length > 0) {
                code += `\n$headers = [\n`;
                Object.entries(req.headers).forEach(([key, value]) => {
                    // Keep header line intact; PHP strings are safest with JSON escaping + trimming quotes
                    const headerLine = `${key}: ${value}`;
                    code += `    ${jsStringLiteral(headerLine)},\n`;
                });
                code += `];\n`;
                code += `curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);\n`;
            }

            if (req.body) {
                const { delim, content } = makePhpNowdoc(req.body);
                code += `\n$data = <<<'${delim}'\n${content}\n${delim};\n`;
                code += `curl_setopt($ch, CURLOPT_POSTFIELDS, $data);\n`;
            }

            code += `\n$response = curl_exec($ch);\n`;
            code += `curl_close($ch);\n\n`;
            code += `echo $response;\n`;
            code += `?>`;

            return code;
        },
        powershell: (req) => {
            let code = `$uri = ${jsStringLiteral(req.url)}\n`;

            if (Object.keys(req.headers).length > 0) {
                code += `\n$headers = @{\n`;
                Object.entries(req.headers).forEach(([key, value]) => {
                    code += `    ${jsStringLiteral(key)} = ${jsStringLiteral(value)}\n`;
                });
                code += `}\n`;
            }

            if (req.body) {
                code += `\n` + makePowerShellBodySnippet(req.body);
            }

            code += `\nInvoke-WebRequest -Uri $uri -Method ${String(req.method || 'GET')}`;
            if (Object.keys(req.headers).length > 0) code += ` -Headers $headers`;
            if (req.body) code += ` -Body $body`;

            return code;
        },
        wget: (req) => {
            let cmd = `wget --method=${req.method}`;

            // Add headers
            Object.entries(req.headers).forEach(([key, value]) => {
                const headerLine = `${key}: ${value}`;
                cmd += ` \\\n  --header='${escapeSingleQuotesForShell(headerLine)}'`;
            });

            // Add body
            if (req.body) {
                cmd += ` \\\n  --body-data='${escapeSingleQuotesForShell(req.body)}'`;
            }

            cmd += ` \\\n  '${req.url}'`;
            return cmd;
        }
    };

    function detectFormat(input) {
        for (const [key, format] of Object.entries(requestFormats)) {
            if (format.detect(input)) {
                return key;
            }
        }
        return null;
    }

    function render() {
        const outputFormats = Object.keys(converters);
        
        return `
            <div class="section-header">
                <h3 class="mb-1 d-flex align-items-center gap-2">
                    <i class="bi bi-arrow-left-right"></i>
                    <span>HTTP Request Converter</span>
                </h3>
                <p class="text-secondary mb-0">
                    Convert HTTP requests between multiple formats with automatic format detection
                </p>
            </div>

            <div class="row g-3 mt-2">
                <div class="col-lg-6">
                    <div class="card bg-dark">
                        <div class="card-header">
                            <i class="bi bi-box-arrow-in-down"></i> Input Request
                        </div>
                        <div class="card-body">
                            <div class="mb-3">
                                <label class="form-label">Paste your request</label>
                                <textarea 
                                    class="form-control font-monospace" 
                                    id="requestInput" 
                                    rows="12" 
                                    placeholder="Paste cURL, Burp Suite raw request, Fetch, Python requests, or any supported format..."
                                    style="font-size: 0.85rem;"
                                ></textarea>
                                <div class="mt-2 d-flex justify-content-between align-items-center">
                                    <div>
                                        <span class="text-secondary small">Detected format: </span>
                                        <span id="detectedFormat" class="badge bg-info">None</span>
                                    </div>
                                    <div class="d-flex gap-2">
                                        <button class="btn btn-sm btn-outline-secondary" onclick="clearRequestInput()">
                                            <i class="bi bi-x-circle"></i> Clear
                                        </button>
                                        <button class="btn btn-sm btn-outline-info" onclick="loadSampleRequest()">
                                            <i class="bi bi-file-earmark-text"></i> Load Sample
                                        </button>
                                    </div>
                                </div>
                            </div>

                            <button class="btn btn-primary w-100" onclick="convertRequest()">
                                <i class="bi bi-arrow-repeat"></i> Convert Request
                            </button>
                        </div>
                    </div>
                </div>
                <div class="col-lg-6" id="convertedOutputsCol" style="display:none;">
                    <div class="card bg-dark">
                        <div class="card-header">
                            <i class="bi bi-box-arrow-up"></i> Converted Outputs
                        </div>
                        <div class="card-body">
                            <div id="conversionResults"></div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row g-3 mt-2">
                <div class="col-12">
                    <div class="card bg-dark">
                        <div class="card-header">
                            <i class="bi bi-info-circle"></i> Supported Formats
                        </div>
                        <div class="card-body">
                            <div class="row small">
                                <div class="col-md-4">
                                    <h6>Input Formats:</h6>
                                    <ul class="mb-0">
                                        <li><strong>cURL</strong> - Command-line HTTP client</li>
                                        <li><strong>Burp Suite</strong> - Raw HTTP request format</li>
                                        <li><strong>JavaScript Fetch</strong> - Modern browser API</li>
                                        <li><strong>Python Requests</strong> - Popular HTTP library</li>
                                    </ul>
                                </div>
                                <div class="col-md-4">
                                    <h6>Output Formats:</h6>
                                    <ul class="mb-0">
                                        <li><strong>cURL</strong> - Universal command-line tool</li>
                                        <li><strong>Burp Suite</strong> - Security testing format</li>
                                        <li><strong>Fetch</strong> - JavaScript browser/Node.js</li>
                                        <li><strong>Python</strong> - Python requests library</li>
                                        <li><strong>Node.js</strong> - Native HTTP module</li>
                                    </ul>
                                </div>
                                <div class="col-md-4">
                                    <h6>Additional Outputs:</h6>
                                    <ul class="mb-0">
                                        <li><strong>PHP</strong> - cURL extension</li>
                                        <li><strong>PowerShell</strong> - Invoke-WebRequest</li>
                                        <li><strong>wget</strong> - GNU utility</li>
                                    </ul>
                                </div>
                            </div>
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
                            <h6>How to Use:</h6>
                            <ul class="mb-0">
                                <li>Paste any HTTP request in a supported format</li>
                                <li>The tool automatically detects the format</li>
                                <li>Click "Convert Request" to see all formats</li>
                                <li>Copy any output format with one click</li>
                            </ul>
                        </div>
                        <div class="col-md-6">
                            <h6>Pro Tips:</h6>
                            <ul class="mb-0">
                                <li>Works great with Burp Suite's "Copy to file" feature</li>
                                <li>Preserves headers, cookies, and request body</li>
                                <li>Perfect for documentation and bug reports</li>
                                <li>Quick way to test requests in different tools</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    function init() {
        const inputField = document.getElementById('requestInput');
        
        if (inputField) {
            inputField.addEventListener('input', () => {
                const input = inputField.value.trim();
                const format = detectFormat(input);
                const formatBadge = document.getElementById('detectedFormat');
                
                if (formatBadge) {
                    if (format) {
                        formatBadge.textContent = requestFormats[format].name;
                        formatBadge.className = 'badge bg-success';
                    } else {
                        formatBadge.textContent = input ? 'Unknown' : 'None';
                        formatBadge.className = input ? 'badge bg-warning' : 'badge bg-info';
                    }
                }
            });
        }

        window.convertRequest = function() {
            const inputField = document.getElementById('requestInput');
            const resultsDiv = document.getElementById('conversionResults');
            
            if (!inputField || !resultsDiv) return;

            const input = inputField.value.trim();
            const outputsCol = document.getElementById('convertedOutputsCol');
            if (outputsCol) outputsCol.style.display = '';
            
            if (!input) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-warning mb-0">
                        <i class="bi bi-exclamation-triangle"></i> Please paste a request to convert
                    </div>
                `;
                return;
            }

            const format = detectFormat(input);
            
            if (!format) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-danger mb-0">
                        <i class="bi bi-x-circle"></i> Could not detect request format. Please check your input.
                    </div>
                `;
                return;
            }

            try {
                const parsedRequest = requestFormats[format].parse(input);
                
                let html = `
                    <div class="alert alert-success mb-3">
                        <i class="bi bi-check-circle-fill"></i> Successfully parsed <strong>${requestFormats[format].name}</strong> request
                    </div>
                `;

                // Generate all conversions
                Object.entries(converters).forEach(([key, converter]) => {
                    try {
                        const converted = converter(parsedRequest);
                        const formatName = key.charAt(0).toUpperCase() + key.slice(1);
                        
                        html += `
                            <div class="card bg-dark border-secondary mb-2">
                                <div class="card-header py-2 d-flex justify-content-between align-items-center">
                                    <span class="badge bg-secondary">${formatName}</span>
                                    <button class="btn btn-sm btn-outline-success" onclick="copyConversion('${key}', this)">
                                        <i class="bi bi-clipboard"></i> Copy
                                    </button>
                                </div>
                                <div class="card-body p-2">
                                    <pre class="mb-0" style="font-size: 0.8rem; max-height: 200px; overflow-y: auto; white-space: pre-wrap; word-break: break-all;"><code id="conversion-${key}">${window.escapeHtml(converted)}</code></pre>
                                </div>
                            </div>
                        `;
                    } catch (err) {
                        console.error(`Error converting to ${key}:`, err);
                    }
                });

                resultsDiv.innerHTML = html;

                // Save to history
                addToHistory({
                    inputFormat: requestFormats[format].name,
                    request: parsedRequest,
                    timestamp: new Date().toISOString()
                });

            } catch (error) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-danger mb-0">
                        <i class="bi bi-x-circle"></i> Error parsing request: ${window.escapeHtml(error.message)}
                    </div>
                `;
            }
        };

        window.copyConversion = function(format, button) {
            const codeElement = document.getElementById(`conversion-${format}`);
            if (!codeElement) return;

            const text = codeElement.textContent;
            navigator.clipboard.writeText(text).then(() => {
                const originalHtml = button.innerHTML;
                button.innerHTML = '<i class="bi bi-check-circle-fill"></i> Copied!';
                button.classList.remove('btn-outline-success');
                button.classList.add('btn-success');
                
                setTimeout(() => {
                    button.innerHTML = originalHtml;
                    button.classList.add('btn-outline-success');
                    button.classList.remove('btn-success');
                }, 2000);
            });
        };

        window.clearRequestInput = function() {
            document.getElementById('requestInput').value = '';
            document.getElementById('conversionResults').innerHTML = '';
            const formatBadge = document.getElementById('detectedFormat');
            if (formatBadge) {
                formatBadge.textContent = 'None';
                formatBadge.className = 'badge bg-info';
            }
            const outputsCol = document.getElementById('convertedOutputsCol');
            if (outputsCol) outputsCol.style.display = 'none';
        };

        window.loadSampleRequest = function() {
            const sample = `curl -X POST 'https://api.example.com/users' \\
  -H 'Content-Type: application/json' \\
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' \\
  -H 'User-Agent: Mozilla/5.0' \\
  --data-raw '{"username":"testuser","email":"test@example.com"}'`;
            
            document.getElementById('requestInput').value = sample;
            
            // Trigger input event to update format detection
            const event = new Event('input', { bubbles: true });
            document.getElementById('requestInput').dispatchEvent(event);
        };
    }

    function addToHistory(item) {
        conversionHistory.unshift(item);
        if (conversionHistory.length > 10) {
            conversionHistory = conversionHistory.slice(0, 10);
        }
    }

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'request-converter',
        name: 'HTTP Request Converter',
        description: 'Convert HTTP requests between cURL, Burp Suite, Fetch, Python, PHP, PowerShell and more with auto-detection',
        icon: 'bi-arrow-left-right',
        category: 'purple',
        render: render,
        init: init
    });
})();