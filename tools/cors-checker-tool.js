

// ========================================
// CORS MISCONFIGURATION CHECKER
// Category: Purple Team
// ========================================

(function() {
    'use strict';

    function render() {
        return `
            <div class="mb-4">
                <h4><i class="bi bi-globe2"></i> CORS Misconfiguration Checker</h4>
                <p class="text-secondary">Test endpoints for permissive or unsafe CORS responses</p>
            </div>
            
            <div class="card">
                <div class="card-body">
                    <div class="row g-3">
                        <div class="col-md-7">
                            <label for="corsUrl" class="form-label">Target URL</label>
                            <input type="url" id="corsUrl" class="form-control" placeholder="https://api.example.com">
                        </div>
                        <div class="col-md-5">
                            <label for="corsOrigin" class="form-label">Origin to Test</label>
                            <input type="text" id="corsOrigin" class="form-control" placeholder="https://evil.com" value="https://evil.com">
                        </div>
                    </div>
                    
                    <div class="mt-3 d-flex gap-2">
                        <button class="btn btn-primary" onclick="checkCors()">
                            <i class="bi bi-play-fill"></i> Check CORS
                        </button>
                    </div>
                    
                    <div id="corsResults" class="mt-3"></div>
                </div>
            </div>
        `;
    }

    function init() {
        window.checkCors = async function() {
            const url = document.getElementById('corsUrl').value;
            const origin = document.getElementById('corsOrigin').value;
            const resultsDiv = document.getElementById('corsResults');
            
            if (!url) {
                resultsDiv.innerHTML = `<div class="alert alert-danger" role="alert">Enter a URL.</div>`;
                return;
            }

            resultsDiv.innerHTML = '<div class="results"><div class="result-item info"><div class="result-title">Testing<span class="loading"></span></div></div></div>';

            try {
                const response = await fetch(url, {
                    method: 'GET',
                    mode: 'cors',
                    credentials: 'include'
                });
                
                const results = [];
                const acao = response.headers.get('access-control-allow-origin');
                const acac = response.headers.get('access-control-allow-credentials');
                
                if (acao === '*') {
                    results.push({
                        type: 'danger',
                        title: '🚨 CRITICAL: Wildcard CORS',
                        desc: 'Access-Control-Allow-Origin is set to "*" - allows any origin!'
                    });
                } else if (acao === origin) {
                    results.push({
                        type: 'danger',
                        title: '🚨 CRITICAL: Origin Reflection',
                        desc: `Server reflects the Origin header. Exploitable!`
                    });
                } else if (acao) {
                    results.push({
                        type: 'warning',
                        title: '⚠️ CORS Enabled',
                        desc: `Allowed origin: ${acao}`
                    });
                } else {
                    results.push({
                        type: 'success',
                        title: '✓ Properly Configured',
                        desc: 'No CORS headers allow this origin'
                    });
                }
                
                if (acac === 'true') {
                    results.push({
                        type: 'warning',
                        title: '⚠️ Credentials Allowed',
                        desc: 'Access-Control-Allow-Credentials is true'
                    });
                }
                
                window.displayResults('corsResults', results);
            } catch (error) {
                resultsDiv.innerHTML = `<div class="alert alert-danger" role="alert">CORS blocked: ${error.message}</div>`;
            }
        };
    }

    window.registerCyberSuiteTool({
        id: 'cors-checker',
        name: 'CORS Misconfiguration Checker',
        description: 'Verify CORS headers for security issues',
        icon: 'bi-globe2',
        category: 'purple',
        render: render,
        init: init
    });
})();
