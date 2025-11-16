// ========================================
// WELL-KNOWN WORDLISTS REPOSITORY
// Category: Red Team
// Now fed dynamically from SecLists GitHub
// ========================================

(function() {
    'use strict';

    const SECLISTS_API_BASE = 'https://api.github.com/repos/danielmiessler/SecLists/contents/';
    const SECLISTS_SOURCE_LABEL = 'SecLists (GitHub)';
    const ALLOWED_EXTENSIONS = /\.(txt|csv|lst|list|wordlist)$/i;

    // Categories + where to pull from in SecLists
    // You can tweak/add paths as you like.
    const wordlists = {
        passwords: {
            name: 'Password Lists',
            icon: 'bi-key-fill',
            color: 'primary',
            lists: [],
            sources: [
                { path: 'Passwords/Common-Credentials' },
                { path: 'Passwords/darkweb2017' },
                { path: 'Passwords/Leaked-Databases' },
                { path: 'Passwords/Software' },
                { path: 'Passwords/Default-Credentials' }
            ]
        },

        usernames: {
            name: 'Username Lists',
            icon: 'bi-person-fill',
            color: 'primary',
            lists: [],
            sources: [
                { path: 'Usernames' },
                { path: 'Usernames/Names' }
            ]
        },

        web_discovery: {
            name: 'Web Discovery',
            icon: 'bi-globe',
            color: 'primary',
            lists: [],
            sources: [
                { path: 'Discovery/Web-Content' }
            ]
        },

        subdomain: {
            name: 'Subdomain Lists',
            icon: 'bi-diagram-3-fill',
            color: 'primary',
            lists: [],
            sources: [
                { path: 'Discovery/DNS' }
            ]
        },

        fuzzing: {
            name: 'Fuzzing Lists',
            icon: 'bi-bug-fill',
            color: 'primary',
            lists: [],
            sources: [
                { path: 'Fuzzing' }
            ]
        },

        // Narrow subsets (reuse paths with filters on filenames)

        parameters: {
            name: 'Parameter Names',
            icon: 'bi-input-cursor-text',
            color: 'primary',
            lists: [],
            sources: [
                {
                    path: 'Discovery/Web-Content',
                    filter: (item) =>
                        ['burp-parameter-names.txt', 'ParameterMiner-Parameters.txt', 'graphql.txt'].includes(item.name)
                }
            ]
        },

        default_creds: {
            name: 'Default Credentials',
            icon: 'bi-shield-lock-fill',
            color: 'primary',
            lists: [],
            sources: [
                {
                    path: 'Passwords/Default-Credentials',
                    filter: (item) =>
                        item.name.toLowerCase().includes('default-passwords') ||
                        item.name.toLowerCase().includes('tomcat') ||
                        item.name.toLowerCase().includes('scada')
                }
            ]
        },

        file_extensions: {
            name: 'File Extensions',
            icon: 'bi-file-earmark-code',
            color: 'primary',
            lists: [],
            sources: [
                {
                    path: 'Discovery/Web-Content',
                    filter: (item) =>
                        ['web-extensions.txt', 'backup-file-extensions.txt', 'CGI-Extensions-Common.txt']
                            .includes(item.name)
                }
            ]
        },

        cms_specific: {
            name: 'CMS-Specific',
            icon: 'bi-wordpress',
            color: 'primary',
            lists: [],
            sources: [
                { path: 'Discovery/Web-Content/CMS' }
            ]
        },

        cloud: {
    name: 'Cloud Services',
    icon: 'bi-cloud-fill',
    color: 'primary',
    lists: [],
    sources: [
        {
            // Look in web content wordlists…
            path: 'Discovery/Web-Content',
            // …and keep anything that *looks* cloud-related
            filter: (item) => {
                const t = ((item.path || '') + ' ' + (item.name || '')).toLowerCase();
                return /(aws|s3|bucket|gcp|google[-_ ]?cloud|azure|cloud)/.test(t);
            }
        },
        {
            // Optional: also scan DNS lists for cloud-ish stuff
            path: 'Discovery/DNS',
            filter: (item) => {
                const t = ((item.path || '') + ' ' + (item.name || '')).toLowerCase();
                return /(aws|s3|bucket|gcp|azure|cloud)/.test(t);
            }
        }
    ]
},

        iot: {
            name: 'IoT & Embedded',
            icon: 'bi-router-fill',
            color: 'primary',
            lists: [],
            sources: [
                {
                    path: 'Passwords/Default-Credentials',
                    filter: (item) =>
                        item.name.toLowerCase().includes('iot') ||
                        item.name.toLowerCase().includes('scada')
                }
            ]
        }
    };

    function formatBytes(bytes) {
        if (typeof bytes !== 'number' || isNaN(bytes) || bytes <= 0) {
            return 'Unknown';
        }
        const sizes = ['bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        const value = bytes / Math.pow(1024, i);
        return `${value.toFixed(i === 0 ? 0 : 1)} ${sizes[i]}`;
    }

    function render() {
        return `
            <style>
                .wordlist-card {
                    background: #161b22;
                    border: 1px solid #30363d;
                    border-radius: 6px;
                    padding: 1rem;
                    margin-bottom: 0.5rem;
                    transition: all 0.2s;
                }
                .wordlist-card:hover {
                    border-color: #58a6ff;
                    background: #1c2128;
                }
                .category-section {
                    margin-bottom: 2rem;
                }
                .category-badge {
                    font-size: 0.85rem;
                    padding: 0.4rem 0.8rem;
                }
                .wordlist-stats {
                    font-size: 0.75rem;
                    color: #8b949e;
                }
                .filter-badge {
                    cursor: pointer;
                    transition: all 0.2s;
                }
                .filter-badge:hover {
                    transform: scale(1.05);
                }
                .filter-badge.active {
                    background-color: #0d6efd !important;
                }
                @media (max-width: 768px) {
                    .reset-filters-btn {
                        margin-top: 0.5rem;
                    }
                }
            </style>
            
            <div class="mb-3">
                <h4><i class="bi bi-list-ul"></i> Well-Known Wordlists Repository</h4>
                <p class="text-secondary small mb-0">Access popular SecLists wordlists for security testing (fetched live from GitHub)</p>
            </div>
            
            <div class="row mb-3">
                <div class="col-md-8 mb-2 mb-md-0">
                    <div class="input-group">
                        <span class="input-group-text bg-dark border-secondary">
                            <i class="bi bi-search"></i>
                        </span>
                        <input type="text" class="form-control border-secondary" id="wordlistSearch" 
                               placeholder="Search wordlists by name, description (path), or source...">
                    </div>
                </div>
                <div class="col-md-4">
                    <button class="btn btn-outline-secondary w-100 reset-filters-btn" onclick="resetWordlistFilters()">
                        <i class="bi bi-arrow-counterclockwise"></i> Reset Filters
                    </button>
                </div>
            </div>
            
            <!-- Category Filters -->
            <div class="mb-3">
                <small class="text-secondary d-block mb-2">Filter by category:</small>
                <div class="d-flex flex-wrap gap-2" id="categoryFilters"></div>
            </div>
            
            <!-- Statistics -->
            <div class="alert alert-info mb-3" id="wordlistStats">
                <span class="spinner-border spinner-border-sm me-2"></span>
                Initializing repository view...
            </div>
            
            <!-- Wordlist Content -->
            <div id="wordlistContent">
                <div class="alert alert-info">
                    <span class="spinner-border spinner-border-sm me-2"></span>
                    Loading wordlists directly from the SecLists GitHub repository...
                </div>
            </div>
        `;
    }

    function init() {
        let activeCategory = null;
        let isLoading = true;

        // Treat everything we generate as a direct file (download_url)
        function isDirectFile(url) {
            return true;
        }

        // Render category filters
        function renderCategoryFilters() {
            const filtersDiv = document.getElementById('categoryFilters');
            if (!filtersDiv) return;

            let html = '';
            Object.keys(wordlists).forEach(categoryKey => {
                const category = wordlists[categoryKey];
                const active = activeCategory === categoryKey ? 'active' : '';
                const bgColor = active ? category.color : 'secondary';
                const count = category.lists.length;

                html += `
                    <span class="badge bg-${bgColor} filter-badge ${active}" 
                          onclick="filterByCategory('${categoryKey}')">
                        <i class="bi ${category.icon}"></i> ${category.name} (${count})
                    </span>
                `;
            });

            filtersDiv.innerHTML = html;
        }

        // Calculate and display statistics
        function updateStats() {
            const statsDiv = document.getElementById('wordlistStats');
            if (!statsDiv) return;

            let totalLists = 0;
            let totalCategories = Object.keys(wordlists).length;

            Object.values(wordlists).forEach(category => {
                totalLists += category.lists.length;
            });

            if (isLoading) {
                statsDiv.innerHTML = `
                    <strong><i class="bi bi-info-circle"></i> Repository Statistics:</strong>
                    Fetching metadata from SecLists GitHub repository...
                `;
                return;
            }

            statsDiv.innerHTML = `
                <strong><i class="bi bi-info-circle"></i> Repository Statistics:</strong>
                ${totalCategories} categories • ${totalLists} wordlists • Source: ${SECLISTS_SOURCE_LABEL}
            `;
        }

        // Render wordlists
        function renderWordlists(searchQuery = '') {
            const contentDiv = document.getElementById('wordlistContent');
            if (!contentDiv) return;

            const query = searchQuery.trim().toLowerCase();
            let html = '';
            let visibleCount = 0;

            const categoriesToShow = activeCategory ? [activeCategory] : Object.keys(wordlists);

            categoriesToShow.forEach(categoryKey => {
                const category = wordlists[categoryKey];
                let categoryHtml = '';
                let categoryVisible = 0;

                category.lists.forEach(list => {
                    const matches =
                        !query ||
                        list.name.toLowerCase().includes(query) ||
                        (list.description && list.description.toLowerCase().includes(query)) ||
                        (list.source && list.source.toLowerCase().includes(query));

                    if (matches) {
                        categoryVisible++;
                        visibleCount++;

                        const isDirect = isDirectFile(list.url);

                        categoryHtml += `
                            <div class="wordlist-card">
                                <div class="d-flex justify-content-between align-items-start mb-2">
                                    <div class="flex-grow-1">
                                        <h6 class="mb-1">
                                            <i class="bi ${category.icon} text-${category.color}"></i>
                                            ${list.name}
                                        </h6>
                                        <p class="text-secondary small mb-2">${list.description || ''}</p>
                                        <div class="wordlist-stats">
                                            <span class="me-3"><i class="bi bi-hdd"></i> ${list.size}</span>
                                            <span class="me-3"><i class="bi bi-hash"></i> ${list.entries} entries</span>
                                            <span><i class="bi bi-tag"></i> ${list.source}</span>
                                        </div>
                                    </div>
                                </div>
                                <div class="d-flex gap-2 flex-wrap">
                                    ${isDirect ? `
                                        <button class="btn btn-sm btn-primary" onclick="downloadWordlist('${list.url}', '${list.name}')">
                                            <i class="bi bi-download"></i> Download
                                        </button>
                                        <button class="btn btn-sm btn-outline-secondary" onclick="previewWordlist('${list.url}', '${list.name}')">
                                            <i class="bi bi-eye"></i> Preview
                                        </button>
                                        <button class="btn btn-sm btn-outline-primary" onclick="copyUrl('${list.url}', this)">
                                            <i class="bi bi-clipboard"></i> Copy URL
                                        </button>
                                        <button class="btn btn-sm btn-outline-success" onclick="showCommands('${list.url}', '${list.name}')">
                                            <i class="bi bi-terminal"></i> CLI
                                        </button>
                                    ` : `
                                        <button class="btn btn-sm btn-warning" onclick="openInNewTab('${list.url}')">
                                            <i class="bi bi-box-arrow-up-right"></i> Open
                                        </button>
                                    `}
                                </div>
                            </div>
                        `;
                    }
                });

                if (categoryVisible > 0) {
                    html += `
                        <div class="category-section">
                            <h5 class="mb-3">
                                <i class="bi ${category.icon} text-${category.color}"></i>
                                ${category.name}
                                <span class="badge bg-${category.color} category-badge">${categoryVisible}</span>
                            </h5>
                            ${categoryHtml}
                        </div>
                    `;
                }
            });

            if (visibleCount === 0 && !isLoading) {
                html = `
                    <div class="alert alert-warning">
                        <i class="bi bi-exclamation-triangle"></i> No wordlists found matching your criteria.
                    </div>
                `;
            } else if (isLoading) {
                html = `
                    <div class="alert alert-info">
                        <span class="spinner-border spinner-border-sm me-2"></span>
                        Loading wordlists directly from the SecLists GitHub repository...
                    </div>
                `;
            }

            contentDiv.innerHTML = html;
        }

        // Load one category from SecLists (GitHub API)
        function loadCategory(categoryKey) {
            const category = wordlists[categoryKey];
            if (!category || !Array.isArray(category.sources)) return Promise.resolve();

            const filesSeen = new Set();

            const promises = category.sources.map(src => {
                const url = SECLISTS_API_BASE + encodeURIComponent(src.path);

                return fetch(url)
                    .then(resp => {
                        if (!resp.ok) {
                            throw new Error(`GitHub API error for ${src.path}: ${resp.status}`);
                        }
                        return resp.json();
                    })
                    .then(json => {
                        const items = Array.isArray(json) ? json : [json];

                        items.forEach(item => {
                            if (item.type !== 'file') return;
                            if (!item.name || !ALLOWED_EXTENSIONS.test(item.name)) return;
                            if (typeof src.filter === 'function' && !src.filter(item)) return;

                            const urlKey = item.download_url || item.html_url;
                            if (filesSeen.has(urlKey)) return;
                            filesSeen.add(urlKey);

                            category.lists.push({
                                name: item.name,
                                size: formatBytes(item.size),
                                entries: 'Unknown',
                                description: item.path,
                                url: item.download_url || item.html_url,
                                source: SECLISTS_SOURCE_LABEL,
                                type: 'direct'
                            });
                        });
                    })
                    .catch(err => {
                        console.error('Failed to load SecLists category', categoryKey, src.path, err);
                    });
            });

            return Promise.all(promises).then(() => {
                // Sort alphabetically
                category.lists.sort((a, b) => a.name.localeCompare(b.name));
            });
        }

        function loadAllCategories() {
            const keys = Object.keys(wordlists);

            Promise.all(keys.map(loadCategory))
                .then(() => {
                    isLoading = false;
                    renderCategoryFilters();
                    updateStats();
                    renderWordlists(document.getElementById('wordlistSearch').value);
                })
                .catch(err => {
                    console.error('Failed to load SecLists data', err);
                    isLoading = false;

                    const contentDiv = document.getElementById('wordlistContent');
                    if (contentDiv) {
                        contentDiv.innerHTML = `
                            <div class="alert alert-danger">
                                <i class="bi bi-exclamation-triangle"></i>
                                Error loading data from SecLists GitHub repository. Check console/network.
                            </div>
                        `;
                    }
                    updateStats();
                });
        }

        // Filter by category
        window.filterByCategory = function(categoryKey) {
            if (activeCategory === categoryKey) {
                activeCategory = null;
            } else {
                activeCategory = categoryKey;
            }

            renderCategoryFilters();
            renderWordlists(document.getElementById('wordlistSearch').value);
        };

        // Reset filters
        window.resetWordlistFilters = function() {
            activeCategory = null;
            const input = document.getElementById('wordlistSearch');
            if (input) input.value = '';
            renderCategoryFilters();
            renderWordlists();
        };

        // Download wordlist
        window.downloadWordlist = function(url, name) {
            const a = document.createElement('a');
            a.href = url;
            a.download = name;
            a.target = '_blank';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        };

        // Open in new tab
        window.openInNewTab = function(url) {
            window.open(url, '_blank');
        };

        // Preview wordlist (first 50 lines)
        window.previewWordlist = async function(url, name) {
            const contentDiv = document.getElementById('wordlistContent');
            if (!contentDiv) return;

            contentDiv.innerHTML = `
                <div class="card bg-dark mb-3">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h6 class="mb-0"><i class="bi bi-eye"></i> Preview: ${name}</h6>
                        <button class="btn btn-sm btn-outline-secondary" onclick="resetWordlistFilters()">
                            <i class="bi bi-x-lg"></i> Close
                        </button>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-info">
                            <span class="spinner-border spinner-border-sm me-2"></span>
                            Loading first 50 lines...
                        </div>
                    </div>
                </div>
            `;

            try {
                const response = await fetch(url);
                const text = await response.text();
                const lines = text.split('\n').slice(0, 50);

                contentDiv.innerHTML = `
                    <div class="card bg-dark mb-3">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h6 class="mb-0"><i class="bi bi-eye"></i> Preview: ${name}</h6>
                            <div>
                                <button class="btn btn-sm btn-primary me-2" onclick="downloadWordlist('${url}', '${name}')">
                                    <i class="bi bi-download"></i> Download
                                </button>
                                <button class="btn btn-sm btn-outline-secondary" onclick="resetWordlistFilters()">
                                    <i class="bi bi-x-lg"></i> Close
                                </button>
                            </div>
                        </div>
                        <div class="card-body">
                            <div class="alert alert-warning mb-3">
                                <i class="bi bi-info-circle"></i> Showing first 50 lines
                            </div>
                            <pre class="bg-black p-3 rounded" style="max-height: 500px; overflow-y: auto; font-size: 0.85rem;">${window.escapeHtml(lines.join('\n'))}</pre>
                        </div>
                    </div>
                `;
            } catch (error) {
                console.error('Preview error', error);
                contentDiv.innerHTML = `
                    <div class="card bg-dark mb-3">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h6 class="mb-0"><i class="bi bi-eye"></i> Preview: ${name}</h6>
                            <button class="btn btn-sm btn-outline-secondary" onclick="resetWordlistFilters()">
                                <i class="bi bi-x-lg"></i> Close
                            </button>
                        </div>
                        <div class="card-body">
                            <div class="alert alert-danger">
                                <i class="bi bi-exclamation-triangle"></i> Could not load preview. The file may be too large or CORS restrictions apply.
                                <br><br>
                                <button class="btn btn-sm btn-primary" onclick="downloadWordlist('${url}', '${name}')">
                                    <i class="bi bi-download"></i> Download Instead
                                </button>
                                <button class="btn btn-sm btn-info ms-2" onclick="openInNewTab('${url}')">
                                    <i class="bi bi-box-arrow-up-right"></i> Open
                                </button>
                            </div>
                        </div>
                    </div>
                `;
            }
        };

        // Copy URL
        window.copyUrl = async function(url, button) {
            try {
                await navigator.clipboard.writeText(url);
                const originalHTML = button.innerHTML;
                button.innerHTML = '<i class="bi bi-check-lg"></i> Copied!';
                button.classList.remove('btn-outline-primary');
                button.classList.add('btn-success');
                setTimeout(() => {
                    button.innerHTML = originalHTML;
                    button.classList.remove('btn-success');
                    button.classList.add('btn-outline-primary');
                }, 2000);
            } catch (err) {
                console.error('Failed to copy:', err);
            }
        };

        // Show CLI commands
        window.showCommands = function(url, name) {
            const contentDiv = document.getElementById('wordlistContent');
            if (!contentDiv) return;

            // Generate safe filename
            const safeFilename = name.replace(/[^a-zA-Z0-9.-]/g, '_');

            // Generate commands
            const wgetCmd = `wget "${url}" -O ${safeFilename}`;
            const curlCmd = `curl -L "${url}" -o ${safeFilename}`;
            const powershellCmd = `Invoke-WebRequest -Uri "${url}" -OutFile "${safeFilename}"`;
            const pythonCmd = `python3 -c "import urllib.request; urllib.request.urlretrieve('${url}', '${safeFilename}')"`;

            contentDiv.innerHTML = `
                <div class="card bg-dark mb-3">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h6 class="mb-0"><i class="bi bi-terminal"></i> CLI Download Commands: ${name}</h6>
                        <button class="btn btn-sm btn-outline-secondary" onclick="resetWordlistFilters()">
                            <i class="bi bi-x-lg"></i> Close
                        </button>
                    </div>
                    <div class="card-body">
                        <p class="text-secondary mb-3">Copy and paste these commands to download the wordlist:</p>
                        
                        <!-- wget -->
                        <div class="mb-3">
                            <div class="d-flex justify-content-between align-items-center mb-2">
                                <h6 class="mb-0"><i class="bi bi-download"></i> wget (Linux/Mac)</h6>
                                <button class="btn btn-sm btn-outline-primary" onclick="copyCommand(\`${window.escapeHtml(wgetCmd).replace(/`/g, '\\`')}\`, this)">
                                    <i class="bi bi-clipboard"></i> Copy
                                </button>
                            </div>
                            <pre class="bg-black p-2 rounded mb-0"><code>${window.escapeHtml(wgetCmd)}</code></pre>
                        </div>
                        
                        <!-- curl -->
                        <div class="mb-3">
                            <div class="d-flex justify-content-between align-items-center mb-2">
                                <h6 class="mb-0"><i class="bi bi-download"></i> curl (Linux/Mac)</h6>
                                <button class="btn btn-sm btn-outline-primary" onclick="copyCommand(\`${window.escapeHtml(curlCmd).replace(/`/g, '\\`')}\`, this)">
                                    <i class="bi bi-clipboard"></i> Copy
                                </button>
                            </div>
                            <pre class="bg-black p-2 rounded mb-0"><code>${window.escapeHtml(curlCmd)}</code></pre>
                        </div>
                        
                        <!-- PowerShell -->
                        <div class="mb-3">
                            <div class="d-flex justify-content-between align-items-center mb-2">
                                <h6 class="mb-0"><i class="bi bi-windows"></i> PowerShell (Windows)</h6>
                                <button class="btn btn-sm btn-outline-primary" onclick="copyCommand(\`${window.escapeHtml(powershellCmd).replace(/`/g, '\\`')}\`, this)">
                                    <i class="bi bi-clipboard"></i> Copy
                                </button>
                            </div>
                            <pre class="bg-black p-2 rounded mb-0"><code>${window.escapeHtml(powershellCmd)}</code></pre>
                        </div>
                        
                        <!-- Python -->
                        <div class="mb-0">
                            <div class="d-flex justify-content-between align-items-center mb-2">
                                <h6 class="mb-0"><i class="bi bi-code-slash"></i> Python (Cross-platform)</h6>
                                <button class="btn btn-sm btn-outline-primary" onclick="copyCommand(\`${window.escapeHtml(pythonCmd).replace(/`/g, '\\`')}\`, this)">
                                    <i class="bi bi-clipboard"></i> Copy
                                </button>
                            </div>
                            <pre class="bg-black p-2 rounded mb-0"><code>${window.escapeHtml(pythonCmd)}</code></pre>
                        </div>
                    </div>
                </div>
            `;
        };

        // Copy command
        window.copyCommand = async function(command, button) {
            try {
                await navigator.clipboard.writeText(command);
                const originalHTML = button.innerHTML;
                button.innerHTML = '<i class="bi bi-check-lg"></i> Copied!';
                button.classList.remove('btn-outline-primary');
                button.classList.add('btn-success');
                setTimeout(() => {
                    button.innerHTML = originalHTML;
                    button.classList.remove('btn-success');
                    button.classList.add('btn-outline-primary');
                }, 2000);
            } catch (err) {
                console.error('Failed to copy:', err);
            }
        };

        // Search functionality
        const searchInput = document.getElementById('wordlistSearch');
        if (searchInput) {
            searchInput.addEventListener('input', function() {
                renderWordlists(this.value);
            });
        }

        // Initial UI render, then async load from SecLists
        renderCategoryFilters();
        updateStats();
        renderWordlists();
        loadAllCategories();
    }

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'wordlist-repository',
        name: 'Wordlist Repository',
        description: 'Access SecLists wordlists (passwords, usernames, discovery, fuzzing, and more) directly from GitHub',
        icon: 'bi-list-ul',
        category: 'red',
        render: render,
        init: init
    });
})();