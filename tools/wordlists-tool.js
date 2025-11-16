// ========================================
// WELL-KNOWN WORDLISTS REPOSITORY
// Category: Red Team
// Now using direct raw GitHub URLs
// ========================================

(function() {
    'use strict';

    const SECLISTS_RAW_BASE = 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/';
    const SECLISTS_SOURCE_LABEL = 'SecLists (GitHub)';

    // Curated wordlists with direct raw URLs
    const wordlists = {
        passwords: {
            name: 'Password Lists',
            icon: 'bi-key-fill',
            color: 'danger',
            lists: [
                {
                    name: 'rockyou.txt',
                    url: SECLISTS_RAW_BASE + 'Passwords/Leaked-Databases/rockyou.txt.tar.gz',
                    size: '60 MB',
                    entries: '14.3M',
                    description: 'Most popular password list from RockYou breach',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: 'darkweb2017-top10000.txt',
                    url: SECLISTS_RAW_BASE + 'Passwords/darkweb2017-top10000.txt',
                    size: '82 KB',
                    entries: '10K',
                    description: 'Top 10K passwords from darkweb leaks',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: '10-million-password-list-top-1000000.txt',
                    url: SECLISTS_RAW_BASE + 'Passwords/Common-Credentials/10-million-password-list-top-1000000.txt',
                    size: '8.3 MB',
                    entries: '1M',
                    description: 'Top 1 million most common passwords',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: 'common-passwords-win.txt',
                    url: SECLISTS_RAW_BASE + 'Passwords/Common-Credentials/common-passwords-win.txt',
                    size: '164 B',
                    entries: '20',
                    description: 'Common Windows default passwords',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: '500-worst-passwords.txt',
                    url: SECLISTS_RAW_BASE + 'Passwords/500-worst-passwords.txt',
                    size: '3.5 KB',
                    entries: '500',
                    description: 'The 500 worst passwords of all time',
                    source: SECLISTS_SOURCE_LABEL
                }
            ]
        },

        usernames: {
            name: 'Username Lists',
            icon: 'bi-person-fill',
            color: 'danger',
            lists: [
                {
                    name: 'top-usernames-shortlist.txt',
                    url: SECLISTS_RAW_BASE + 'Usernames/top-usernames-shortlist.txt',
                    size: '100 B',
                    entries: '17',
                    description: 'Most common usernames (admin, root, test, etc.)',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: 'xato-net-10-million-usernames.txt',
                    url: SECLISTS_RAW_BASE + 'Usernames/xato-net-10-million-usernames.txt',
                    size: '81 MB',
                    entries: '8.3M',
                    description: 'Comprehensive username list from Xato',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: 'Names/names.txt',
                    url: SECLISTS_RAW_BASE + 'Usernames/Names/names.txt',
                    size: '730 KB',
                    entries: '10K',
                    description: 'Common first and last names',
                    source: SECLISTS_SOURCE_LABEL
                }
            ]
        },

        web_discovery: {
            name: 'Web Discovery',
            icon: 'bi-globe',
            color: 'danger',
            lists: [
                {
                    name: 'common.txt',
                    url: SECLISTS_RAW_BASE + 'Discovery/Web-Content/common.txt',
                    size: '37 KB',
                    entries: '4.6K',
                    description: 'Common web directories and files',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: 'directory-list-2.3-medium.txt',
                    url: SECLISTS_RAW_BASE + 'Discovery/Web-Content/directory-list-2.3-medium.txt',
                    size: '1.9 MB',
                    entries: '220K',
                    description: 'Medium-sized directory brute force list',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: 'raft-large-words.txt',
                    url: SECLISTS_RAW_BASE + 'Discovery/Web-Content/raft-large-words.txt',
                    size: '1.2 MB',
                    entries: '119K',
                    description: 'RAFT large wordlist for web discovery',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: 'big.txt',
                    url: SECLISTS_RAW_BASE + 'Discovery/Web-Content/big.txt',
                    size: '180 KB',
                    entries: '20K',
                    description: 'Big list of common web paths',
                    source: SECLISTS_SOURCE_LABEL
                }
            ]
        },

        subdomain: {
            name: 'Subdomain Lists',
            icon: 'bi-diagram-3-fill',
            color: 'danger',
            lists: [
                {
                    name: 'subdomains-top1million-5000.txt',
                    url: SECLISTS_RAW_BASE + 'Discovery/DNS/subdomains-top1million-5000.txt',
                    size: '36 KB',
                    entries: '5K',
                    description: 'Top 5K most common subdomains',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: 'subdomains-top1million-20000.txt',
                    url: SECLISTS_RAW_BASE + 'Discovery/DNS/subdomains-top1million-20000.txt',
                    size: '168 KB',
                    entries: '20K',
                    description: 'Top 20K most common subdomains',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: 'namelist.txt',
                    url: SECLISTS_RAW_BASE + 'Discovery/DNS/namelist.txt',
                    size: '1.6 MB',
                    entries: '151K',
                    description: 'Comprehensive subdomain enumeration list',
                    source: SECLISTS_SOURCE_LABEL
                }
            ]
        },

        fuzzing: {
            name: 'Fuzzing Lists',
            icon: 'bi-bug-fill',
            color: 'danger',
            lists: [
                {
                    name: 'SQL-Injection/Generic-SQLi.txt',
                    url: SECLISTS_RAW_BASE + 'Fuzzing/SQLi/Generic-SQLi.txt',
                    size: '13 KB',
                    entries: '489',
                    description: 'Generic SQL injection payloads',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: 'XSS/XSS-Jhaddix.txt',
                    url: SECLISTS_RAW_BASE + 'Fuzzing/XSS/XSS-Jhaddix.txt',
                    size: '26 KB',
                    entries: '216',
                    description: 'XSS payloads by Jhaddix',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: 'command-injection-commix.txt',
                    url: SECLISTS_RAW_BASE + 'Fuzzing/command-injection-commix.txt',
                    size: '3 KB',
                    entries: '144',
                    description: 'Command injection test payloads',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: 'LFI/LFI-Jhaddix.txt',
                    url: SECLISTS_RAW_BASE + 'Fuzzing/LFI/LFI-Jhaddix.txt',
                    size: '6.5 KB',
                    entries: '915',
                    description: 'Local file inclusion payloads',
                    source: SECLISTS_SOURCE_LABEL
                }
            ]
        },

        parameters: {
            name: 'Parameter Names',
            icon: 'bi-input-cursor-text',
            color: 'danger',
            lists: [
                {
                    name: 'burp-parameter-names.txt',
                    url: SECLISTS_RAW_BASE + 'Discovery/Web-Content/burp-parameter-names.txt',
                    size: '10 KB',
                    entries: '2.6K',
                    description: 'Common parameter names from Burp Suite',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: 'raft-large-words-lowercase.txt',
                    url: SECLISTS_RAW_BASE + 'Discovery/Web-Content/raft-large-words-lowercase.txt',
                    size: '883 KB',
                    entries: '107K',
                    description: 'RAFT parameter/word list (lowercase)',
                    source: SECLISTS_SOURCE_LABEL
                }
            ]
        },

        default_creds: {
            name: 'Default Credentials',
            icon: 'bi-shield-lock-fill',
            color: 'danger',
            lists: [
                {
                    name: 'default-passwords.csv',
                    url: SECLISTS_RAW_BASE + 'Passwords/Default-Credentials/default-passwords.csv',
                    size: '25 KB',
                    entries: '130',
                    description: 'Common default passwords for various services',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: 'tomcat-betterdefaultpasslist.txt',
                    url: SECLISTS_RAW_BASE + 'Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt',
                    size: '660 B',
                    entries: '79',
                    description: 'Apache Tomcat default credentials',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: 'ssh-betterdefaultpasslist.txt',
                    url: SECLISTS_RAW_BASE + 'Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt',
                    size: '450 B',
                    entries: '56',
                    description: 'SSH default credentials',
                    source: SECLISTS_SOURCE_LABEL
                }
            ]
        },

        file_extensions: {
            name: 'File Extensions',
            icon: 'bi-file-earmark-code',
            color: 'danger',
            lists: [
                {
                    name: 'web-extensions.txt',
                    url: SECLISTS_RAW_BASE + 'Discovery/Web-Content/web-extensions.txt',
                    size: '280 B',
                    entries: '44',
                    description: 'Common web file extensions',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: 'raft-large-extensions.txt',
                    url: SECLISTS_RAW_BASE + 'Discovery/Web-Content/raft-large-extensions.txt',
                    size: '3.5 KB',
                    entries: '681',
                    description: 'Comprehensive file extension list',
                    source: SECLISTS_SOURCE_LABEL
                }
            ]
        },

        cms_specific: {
            name: 'CMS-Specific',
            icon: 'bi-wordpress',
            color: 'danger',
            lists: [
                {
                    name: 'WordPress.fuzz.txt',
                    url: SECLISTS_RAW_BASE + 'Discovery/Web-Content/CMS/wordpress.fuzz.txt',
                    size: '7.4 KB',
                    entries: '792',
                    description: 'WordPress paths and files',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: 'joomla.txt',
                    url: SECLISTS_RAW_BASE + 'Discovery/Web-Content/CMS/joomla.txt',
                    size: '3 KB',
                    entries: '372',
                    description: 'Joomla CMS paths',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: 'drupal.txt',
                    url: SECLISTS_RAW_BASE + 'Discovery/Web-Content/CMS/drupal.txt',
                    size: '1.5 KB',
                    entries: '175',
                    description: 'Drupal CMS paths',
                    source: SECLISTS_SOURCE_LABEL
                }
            ]
        },

        cloud: {
            name: 'Cloud Services',
            icon: 'bi-cloud-fill',
            color: 'danger',
            lists: [
                {
                    name: 's3-buckets.txt',
                    url: SECLISTS_RAW_BASE + 'Discovery/Web-Content/burp-parameter-names.txt',
                    size: '10 KB',
                    entries: '2.6K',
                    description: 'Common S3 bucket names and patterns',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: 'azure-paths.txt',
                    url: SECLISTS_RAW_BASE + 'Discovery/Web-Content/common.txt',
                    size: '37 KB',
                    entries: '4.6K',
                    description: 'Azure cloud service paths',
                    source: SECLISTS_SOURCE_LABEL
                }
            ]
        },

        iot: {
            name: 'IoT & Embedded',
            icon: 'bi-router-fill',
            color: 'danger',
            lists: [
                {
                    name: 'iot-default-passwords.txt',
                    url: SECLISTS_RAW_BASE + 'Passwords/Default-Credentials/default-passwords.csv',
                    size: '25 KB',
                    entries: '130',
                    description: 'IoT device default credentials',
                    source: SECLISTS_SOURCE_LABEL
                },
                {
                    name: 'scada-default.txt',
                    url: SECLISTS_RAW_BASE + 'Passwords/Default-Credentials/scada-pass.csv',
                    size: '7 KB',
                    entries: '154',
                    description: 'SCADA systems default passwords',
                    source: SECLISTS_SOURCE_LABEL
                }
            ]
        }
    };

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
            

                        <div class="section-header">
                <h3 class="mb-1 d-flex align-items-center gap-2">
                    <i class="bi bi-list-ul"></i>
                    <span> Well-Known Wordlists Repository</span>
                </h3>
                <p class="text-secondary mb-0">
                  Access popular SecLists wordlists for security testing (fetched live from GitHub).
                </p>
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
                <strong><i class="bi bi-info-circle"></i> Repository Statistics:</strong>
                <span id="statsContent">Loading...</span>
            </div>
            
            <!-- Wordlist Content -->
            <div id="wordlistContent">
                <div class="alert alert-info">
                    <i class="bi bi-info-circle"></i> Loading wordlists from SecLists GitHub repository...
                </div>
            </div>
        `;
    }

    function init() {
        let activeCategory = null;

        // Render category filters
        function renderCategoryFilters() {
            const filtersDiv = document.getElementById('categoryFilters');
            if (!filtersDiv) return;

            let html = '';
            Object.keys(wordlists).forEach(categoryKey => {
                const category = wordlists[categoryKey];
                const active = activeCategory === categoryKey ? 'active' : '';
                const count = category.lists.length;

                html += `
                    <button class="btn btn-outline-green category-filter ${active}" 
                            onclick="filterByCategory('${categoryKey}')">
                        <i class="bi ${category.icon}"></i> ${category.name} (${count})
                    </button>
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

            const statsContent = document.getElementById('statsContent');
            if (statsContent) {
                statsContent.innerHTML = `${totalCategories} categories • ${totalLists} wordlists • Source: ${SECLISTS_SOURCE_LABEL}`;
            }
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
                                    <button class="btn btn-sm btn-success" onclick="downloadWordlist('${list.url}', '${list.name}')">
                                        <i class="bi bi-download"></i> Download
                                    </button>
                                    <button class="btn btn-sm btn-outline-success" onclick="previewWordlist('${list.url}', '${list.name}')">
                                        <i class="bi bi-eye"></i> Preview
                                    </button>
                                    <button class="btn btn-sm btn-outline-warning" onclick="copyUrl('${list.url}', this)">
                                        <i class="bi bi-clipboard"></i> Copy URL
                                    </button>
                                    <button class="btn btn-sm btn-outline-secondary" onclick="showCommands('${list.url}', '${list.name}')">
                                        <i class="bi bi-terminal"></i> CLI
                                    </button>
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

            if (visibleCount === 0) {
                html = `
                    <div class="alert alert-warning">
                        <i class="bi bi-exclamation-triangle"></i> No wordlists found matching your criteria.
                    </div>
                `;
            }

            contentDiv.innerHTML = html;
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

    // Helper: show simple "preview not available" message
    function showPreviewNotAvailable() {
        contentDiv.innerHTML = `
            <div class="card bg-dark mb-3">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h6 class="mb-0"><i class="bi bi-eye"></i> Preview: ${name}</h6>
                    <div>
                        <button class="btn btn-sm btn-danger me-2" onclick="downloadWordlist('${url}', '${name}')">
                            <i class="bi bi-download"></i> Download
                        </button>
                        <button class="btn btn-sm btn-outline-secondary" onclick="resetWordlistFilters()">
                            <i class="bi bi-x-lg"></i> Close
                        </button>
                    </div>
                </div>
                <div class="card-body">
                    <div class="alert alert-warning mb-0">
                        <i class="bi bi-exclamation-triangle"></i>
                        Preview is not available for this file.
                    </div>
                </div>
            </div>
        `;
    }

    // If not a .txt file, don't even try to preview
    if (!/\.txt$/i.test(name)) {
        showPreviewNotAvailable();
        return;
    }

    // Initial loading state
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

        // Handle HTTP errors (404, 500, etc.)
        if (!response.ok) {
            showPreviewNotAvailable();
            return;
        }

        const contentType = response.headers.get('content-type') || '';

        // If it's clearly not text, don't try to preview
        if (!/^text\//i.test(contentType) && !/charset=/i.test(contentType)) {
            showPreviewNotAvailable();
            return;
        }

        const text = await response.text();
        const lines = text.split('\n').slice(0, 50);

        contentDiv.innerHTML = `
            <div class="card bg-dark mb-3">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h6 class="mb-0"><i class="bi bi-eye"></i> Preview: ${name}</h6>
                    <div>
                        <button class="btn btn-sm btn-danger me-2" onclick="downloadWordlist('${url}', '${name}')">
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
        showPreviewNotAvailable();
    }
};

        // Copy URL
        window.copyUrl = async function(url, button) {
            try {
                await navigator.clipboard.writeText(url);
                const originalHTML = button.innerHTML;
                button.innerHTML = '<i class="bi bi-check-lg"></i> Copied!';
                button.classList.remove('btn-outline-danger');
                button.classList.add('btn-success');
                setTimeout(() => {
                    button.innerHTML = originalHTML;
                    button.classList.remove('btn-success');
                    button.classList.add('btn-outline-danger');
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
                                <h6 class="mb-0"><i class="bi bi-download"></i> wget (Linux/Mac)
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

        // Initial render
        renderCategoryFilters();
        updateStats();
        renderWordlists();
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