// ========================================
// WELL-KNOWN WORDLISTS REPOSITORY
// Category: Red Team
// ========================================

(function() {
    'use strict';

    const wordlists = {
        passwords: {
            name: 'Password Lists',
            icon: 'bi-key-fill',
            color: 'primary',
            lists: [
                {
                    name: 'rockyou.txt',
                    size: '139 MB',
                    entries: '14,344,391',
                    description: 'Most popular password list from RockYou breach',
                    url: 'https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt',
                    source: 'RockYou Breach',
                    type: 'direct'
                },
                {
                    name: 'rockyou2021.txt',
                    size: '92 GB',
                    entries: '8.4 billion',
                    description: 'Massive compilation of leaked passwords',
                    url: 'https://github.com/ohmybahgosh/RockYou2021.txt',
                    source: 'Multiple Breaches',
                    type: 'repo'
                },
                {
                    name: 'SecLists - Common Passwords',
                    size: '5 MB',
                    entries: '10,000+',
                    description: 'Top 10k most common passwords',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'darkweb2017-top10000.txt',
                    size: '80 KB',
                    entries: '10,000',
                    description: 'Top passwords from dark web 2017',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/darkweb2017-top10000.txt',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'Probable Wordlists',
                    size: 'Varies',
                    entries: 'Multiple sizes',
                    description: 'Probability-ordered password lists',
                    url: 'https://github.com/berzerk0/Probable-Wordlists',
                    source: 'berzerk0',
                    type: 'repo'
                },
                {
                    name: 'john.txt',
                    size: '3.4 MB',
                    entries: '3,559',
                    description: 'John the Ripper default wordlist',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Software/john.txt',
                    source: 'John the Ripper',
                    type: 'direct'
                },
                {
                    name: 'Keyboard Patterns',
                    size: '20 KB',
                    entries: '1,000+',
                    description: 'Common keyboard pattern passwords',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Keyboard-Combinations.txt',
                    source: 'SecLists',
                    type: 'direct'
                }
            ]
        },

        usernames: {
            name: 'Username Lists',
            icon: 'bi-person-fill',
            color: 'primary',
            lists: [
                {
                    name: 'Top Usernames',
                    size: '500 KB',
                    entries: '100,000',
                    description: 'Most common usernames',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'Names (US Census)',
                    size: '200 KB',
                    entries: '5,000+',
                    description: 'Common first and last names',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt',
                    source: 'US Census',
                    type: 'direct'
                },
                {
                    name: 'CIRT Default Usernames',
                    size: '15 KB',
                    entries: '800+',
                    description: 'Default usernames for various systems',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/cirt-default-usernames.txt',
                    source: 'CIRT',
                    type: 'direct'
                },
                {
                    name: 'xato-net-10-million',
                    size: '90 MB',
                    entries: '10 million',
                    description: 'Top 10 million usernames',
                    url: 'https://github.com/danielmiessler/SecLists/raw/master/Usernames/xato-net-10-million-usernames.txt',
                    source: 'Xato.net',
                    type: 'direct'
                }
            ]
        },

        web_discovery: {
            name: 'Web Discovery',
            icon: 'bi-globe',
            color: 'primary',
            lists: [
                {
                    name: 'directory-list-2.3-medium.txt',
                    size: '1.9 MB',
                    entries: '220,560',
                    description: 'Most popular web directory wordlist',
                    url: 'https://raw.githubusercontent.com/daviddias/node-dirbuster/master/lists/directory-list-2.3-medium.txt',
                    source: 'DirBuster',
                    type: 'direct'
                },
                {
                    name: 'common.txt',
                    size: '40 KB',
                    entries: '4,614',
                    description: 'Common directories and files',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'raft-large-directories.txt',
                    size: '270 KB',
                    entries: '62,284',
                    description: 'RAFT large directory list',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt',
                    source: 'RAFT',
                    type: 'direct'
                },
                {
                    name: 'big.txt',
                    size: '180 KB',
                    entries: '20,469',
                    description: 'Big list of web content',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'Apache.fuzz.txt',
                    size: '8 KB',
                    entries: '90+',
                    description: 'Apache-specific paths',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Apache.fuzz.txt',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'API-Endpoints',
                    size: '15 KB',
                    entries: '300+',
                    description: 'Common API endpoints',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'swagger.txt',
                    size: '2 KB',
                    entries: '30+',
                    description: 'Swagger/OpenAPI paths',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/swagger.txt',
                    source: 'SecLists',
                    type: 'direct'
                }
            ]
        },

        subdomain: {
            name: 'Subdomain Lists',
            icon: 'bi-diagram-3-fill',
            color: 'primary',
            lists: [
                {
                    name: 'subdomains-top1million-5000.txt',
                    size: '40 KB',
                    entries: '5,000',
                    description: 'Top 5k most common subdomains',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'subdomains-top1million-20000.txt',
                    size: '180 KB',
                    entries: '20,000',
                    description: 'Top 20k most common subdomains',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'fierce-hostlist.txt',
                    size: '2 KB',
                    entries: '80+',
                    description: 'Fierce DNS subdomain list',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/fierce-hostlist.txt',
                    source: 'Fierce',
                    type: 'direct'
                },
                {
                    name: 'n0kovo subdomains',
                    size: '3 MB',
                    entries: '300,000',
                    description: 'Massive subdomain list',
                    url: 'https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_huge.txt',
                    source: 'n0kovo',
                    type: 'direct'
                }
            ]
        },

        fuzzing: {
            name: 'Fuzzing Lists',
            icon: 'bi-bug-fill',
            color: 'primary',
            lists: [
                {
                    name: 'SQL Injection - Auth Bypass',
                    size: '15 KB',
                    entries: '90+',
                    description: 'SQL injection authentication bypass',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Fuzzing/Databases/SQLi/sqli.auth.bypass.txt',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'XSS Polyglots',
                    size: '5 KB',
                    entries: '20+',
                    description: 'XSS polyglot payloads',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Polyglots.txt',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'Command Injection',
                    size: '8 KB',
                    entries: '100+',
                    description: 'OS command injection payloads',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/command-injection-commix.txt',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'LFI - Local File Inclusion',
                    size: '15 KB',
                    entries: '200+',
                    description: 'LFI/Path traversal payloads',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt',
                    source: 'Jhaddix',
                    type: 'direct'
                },
                {
                    name: 'XXE - XML Injection',
                    size: '3 KB',
                    entries: '30+',
                    description: 'XXE attack payloads',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XXE-Injection.txt',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'SSRF - Server Side Request Forgery',
                    size: '2 KB',
                    entries: '40+',
                    description: 'SSRF testing payloads',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SSRF.txt',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'Template Injection',
                    size: '10 KB',
                    entries: '50+',
                    description: 'SSTI payloads for various engines',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/template-engines-special-vars.txt',
                    source: 'SecLists',
                    type: 'direct'
                }
            ]
        },

        parameters: {
            name: 'Parameter Names',
            icon: 'bi-input-cursor-text',
            color: 'primary',
            lists: [
                {
                    name: 'burp-parameter-names.txt',
                    size: '30 KB',
                    entries: '2,500+',
                    description: 'Common parameter names from Burp',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt',
                    source: 'Burp Suite',
                    type: 'direct'
                },
                {
                    name: 'ParameterMiner parameters',
                    size: '50 KB',
                    entries: '6,000+',
                    description: 'Parameters for cache poisoning',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/ParameterMiner-Parameters.txt',
                    source: 'ParameterMiner',
                    type: 'direct'
                },
                {
                    name: 'GraphQL queries',
                    size: '3 KB',
                    entries: '50+',
                    description: 'GraphQL introspection queries',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/graphql.txt',
                    source: 'SecLists',
                    type: 'direct'
                }
            ]
        },

        default_creds: {
            name: 'Default Credentials',
            icon: 'bi-shield-lock-fill',
            color: 'primary',
            lists: [
                {
                    name: 'Default Credentials',
                    size: '500 KB',
                    entries: '3,000+',
                    description: 'Default username/password combinations',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/default-passwords.csv',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'Router Default Passwords',
                    size: '40 KB',
                    entries: '400+',
                    description: 'Default passwords for routers',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/default-passwords.txt',
                    source: 'CIRT',
                    type: 'direct'
                },
                {
                    name: 'Tomcat Default Credentials',
                    size: '1 KB',
                    entries: '10+',
                    description: 'Apache Tomcat default creds',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt',
                    source: 'SecLists',
                    type: 'direct'
                }
            ]
        },

        file_extensions: {
            name: 'File Extensions',
            icon: 'bi-file-earmark-code',
            color: 'primary',
            lists: [
                {
                    name: 'Web Extensions',
                    size: '2 KB',
                    entries: '50+',
                    description: 'Common web file extensions',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/web-extensions.txt',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'Backup Extensions',
                    size: '1 KB',
                    entries: '30+',
                    description: 'Backup file extensions',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/backup-file-extensions.txt',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'CGI Extensions',
                    size: '500 bytes',
                    entries: '15+',
                    description: 'CGI script extensions',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CGI-Extensions-Common.txt',
                    source: 'SecLists',
                    type: 'direct'
                }
            ]
        },

        cms_specific: {
            name: 'CMS-Specific',
            icon: 'bi-wordpress',
            color: 'primary',
            lists: [
                {
                    name: 'WordPress Plugins',
                    size: '200 KB',
                    entries: '15,000+',
                    description: 'WordPress plugin names',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wordpress.fuzz.txt',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'Joomla',
                    size: '5 KB',
                    entries: '100+',
                    description: 'Joomla CMS paths',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/joomla.fuzz.txt',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'Drupal',
                    size: '3 KB',
                    entries: '60+',
                    description: 'Drupal CMS paths',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/drupal.fuzz.txt',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'SharePoint',
                    size: '10 KB',
                    entries: '200+',
                    description: 'SharePoint paths',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/sharepoint.txt',
                    source: 'SecLists',
                    type: 'direct'
                }
            ]
        },

        cloud: {
            name: 'Cloud Services',
            icon: 'bi-cloud-fill',
            color: 'primary',
            lists: [
                {
                    name: 'AWS S3 Bucket Names',
                    size: '5 KB',
                    entries: '100+',
                    description: 'Common S3 bucket names',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/aws-s3-bucket-names.txt',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'Azure Services',
                    size: '3 KB',
                    entries: '50+',
                    description: 'Azure service endpoints',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/azure-endpoints.txt',
                    source: 'SecLists',
                    type: 'direct'
                },
                {
                    name: 'GCP Bucket Names',
                    size: '2 KB',
                    entries: '40+',
                    description: 'Google Cloud Storage bucket names',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/gcp-bucket-names.txt',
                    source: 'SecLists',
                    type: 'direct'
                }
            ]
        },

        iot: {
            name: 'IoT & Embedded',
            icon: 'bi-router-fill',
            color: 'primary',
            lists: [
                {
                    name: 'IoT Default Passwords',
                    size: '30 KB',
                    entries: '500+',
                    description: 'Default passwords for IoT devices',
                    url: 'https://raw.githubusercontent.com/schadokar/iot-device-default-password-list/master/iot-passwords.csv',
                    source: 'GitHub',
                    type: 'direct'
                },
                {
                    name: 'SCADA Default Passwords',
                    size: '10 KB',
                    entries: '100+',
                    description: 'SCADA system default credentials',
                    url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/scada-pass.csv',
                    source: 'SecLists',
                    type: 'direct'
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
            
            <div class="mb-3">
                <h4><i class="bi bi-list-ul"></i> Well-Known Wordlists Repository</h4>
                <p class="text-secondary small mb-0">Access popular wordlists for security testing</p>
            </div>
            
            <div class="row mb-3">
                <div class="col-md-8 mb-2 mb-md-0">
                    <div class="input-group">
                        <span class="input-group-text bg-dark border-secondary">
                            <i class="bi bi-search"></i>
                        </span>
                        <input type="text" class="form-control border-secondary" id="wordlistSearch" 
                               placeholder="Search wordlists by name, description, or source...">
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
            <div class="alert alert-info mb-3" id="wordlistStats"></div>
            
            <!-- Wordlist Content -->
            <div id="wordlistContent"></div>
        `;
    }

    function init() {
        let activeCategory = null;
        
        // Check if URL is direct text file
        function isDirectFile(url) {
            return url.includes('raw.githubusercontent.com') || url.endsWith('.txt') || url.endsWith('.csv');
        }
        
        // Render category filters
        function renderCategoryFilters() {
            const filtersDiv = document.getElementById('categoryFilters');
            let html = '';
            
            Object.keys(wordlists).forEach(categoryKey => {
                const category = wordlists[categoryKey];
                const active = activeCategory === categoryKey ? 'active' : '';
                const bgColor = active ? 'primary' : 'secondary';
                html += `
                    <span class="badge bg-${bgColor} filter-badge ${active}" 
                          onclick="filterByCategory('${categoryKey}')">
                        <i class="bi ${category.icon}"></i> ${category.name} (${category.lists.length})
                    </span>
                `;
            });
            
            filtersDiv.innerHTML = html;
        }
        
        // Calculate and display statistics
        function updateStats() {
            let totalLists = 0;
            let totalCategories = Object.keys(wordlists).length;
            
            Object.values(wordlists).forEach(category => {
                totalLists += category.lists.length;
            });
            
            document.getElementById('wordlistStats').innerHTML = `
                <strong><i class="bi bi-info-circle"></i> Repository Statistics:</strong>
                ${totalCategories} categories • ${totalLists} wordlists • Sources: SecLists, RockYou, RAFT, and more
            `;
        }
        
        // Render wordlists
        function renderWordlists(searchQuery = '') {
            const contentDiv = document.getElementById('wordlistContent');
            let html = '';
            let visibleCount = 0;
            
            const query = searchQuery.toLowerCase();
            const categoriesToShow = activeCategory ? [activeCategory] : Object.keys(wordlists);
            
            categoriesToShow.forEach(categoryKey => {
                const category = wordlists[categoryKey];
                let categoryHtml = '';
                let categoryVisible = 0;
                
                category.lists.forEach(list => {
                    const matches = !query || 
                                   list.name.toLowerCase().includes(query) ||
                                   list.description.toLowerCase().includes(query) ||
                                   list.source.toLowerCase().includes(query);
                    
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
                                            ${!isDirect ? '<span class="badge bg-warning text-dark ms-2">Repository</span>' : ''}
                                        </h6>
                                        <p class="text-secondary small mb-2">${list.description}</p>
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
            
            if (visibleCount === 0) {
                html = `
                    <div class="alert alert-warning">
                        <i class="bi bi-exclamation-triangle"></i> No wordlists found matching your criteria.
                    </div`;
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
        document.getElementById('wordlistSearch').value = '';
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
    
    // Preview wordlist
    window.previewWordlist = async function(url, name) {
        const contentDiv = document.getElementById('wordlistContent');
        
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
    document.getElementById('wordlistSearch').addEventListener('input', function() {
        renderWordlists(this.value);
    });
    
    // Initialize
    renderCategoryFilters();
    updateStats();
    renderWordlists();
}

// Register the tool
window.registerCyberSuiteTool({
    id: 'wordlist-repository',
    name: 'Wordlist Repository',
    description: 'Access 80+ well-known wordlists for passwords, usernames, web discovery, fuzzing, and more',
    icon: 'bi-list-ul',
    category: 'red',
    render: render,
    init: init
});
})();