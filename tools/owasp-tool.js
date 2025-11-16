// ========================================
// OWASP TOP 10 EXPLORER
// Category: Purple Team
// ========================================

(function () {
    'use strict';

    /**
     * Helpers to build deep links to OWASP pages
     * for specific Top 10 entries (Web 2021/2025, ML 2023).
     */

    function toOwaspTitleSlug(title) {
        if (!title) return '';
        var cleaned = title.replace(/[^A-Za-z0-9]+/g, ' ').trim();
        if (!cleaned) return '';
        var parts = cleaned.split(/\s+/);
        return parts.map(function (w) {
            if (!w) return '';
            if (w.length === 1) return w.toUpperCase();
            return w.charAt(0).toUpperCase() + w.slice(1).toLowerCase();
        }).join('_');
    }

    function buildWebTop10ItemUrl(code, title, projectVersion) {
        if (!code) return null;
        var yearMatch = /:(\d{4})/.exec(code);
        var year = yearMatch ? yearMatch[1] : projectVersion;
        var codeMatch = /^(A\d{2})/.exec(code);
        if (!year || !codeMatch) return null;

        var prefix = codeMatch[1];
        var slug = toOwaspTitleSlug(title || '');
        if (!slug) return null;

        var base = 'https://owasp.org/Top10/';
        if (year === '2025') {
            base += '2025/';
        }

        return base + prefix + '_' + year + '-' + slug + '/';
    }

    function buildMlTop10ItemUrl(code, title) {
        if (!code) return null;
        var m = /^(ML\d{2}):(\d{4})/.exec(code);
        if (!m) return null;

        var idx = m[1];   // e.g. ML01
        var year = m[2];  // e.g. 2023
        var slug = toOwaspTitleSlug(title || '');
        if (!slug) return null;

        return 'https://owasp.org/www-project-machine-learning-security-top-10/docs/'
            + idx + '_' + year + '-' + slug;
    }

    /**
     * Configuration for OWASP "Top 10" style projects.
     */
    const OWASP_TOP10_PROJECTS = [
        {
            id: 'web-2025-rc1',
            family: 'web',
            name: 'Web Applications – OWASP Top 10:2025 RC1',
            version: '2025',
            isReleaseCandidate: true,
            officialProjectUrl: 'https://owasp.org/www-project-top-ten/',
            listUrl: 'https://owasp.org/Top10/2025/0x00_2025-Introduction/',
            itemPattern: /(A\d{2}:\d{4})\s*[-–]\s*(.+)/i,
            fallbackItems: [
                { code: 'A01:2021', title: 'Broken Access Control' },
                { code: 'A02:2021', title: 'Cryptographic Failures' },
                { code: 'A03:2021', title: 'Injection' },
                { code: 'A04:2021', title: 'Insecure Design' },
                { code: 'A05:2021', title: 'Security Misconfiguration' },
                { code: 'A06:2021', title: 'Vulnerable and Outdated Components' },
                { code: 'A07:2021', title: 'Identification and Authentication Failures' },
                { code: 'A08:2021', title: 'Software and Data Integrity Failures' },
                { code: 'A09:2021', title: 'Security Logging and Monitoring Failures' },
                { code: 'A10:2021', title: 'Server-Side Request Forgery (SSRF)' }
            ],
            buildItemUrl: function (item) {
                return buildWebTop10ItemUrl(item.code, item.title, '2025');
            }
        },
        {
    id: 'web-2021',
    family: 'web',
    name: 'Web Applications – OWASP Top 10:2021 (Current Release)',
    version: '2021',
    isReleaseCandidate: false,
    officialProjectUrl: 'https://owasp.org/www-project-top-ten/',
    // use canonical EN page, it has a clean bullet list
    listUrl: 'https://owasp.org/Top10/',
    // grab the code and the short title only (stop at next dash if present)
    itemPattern: /(A\d{2}:\d{4})\s*[–-]\s*([^–-]+)/i,
    fallbackItems: [
        { code: 'A01:2021', title: 'Broken Access Control' },
        { code: 'A02:2021', title: 'Cryptographic Failures' },
        { code: 'A03:2021', title: 'Injection' },
        { code: 'A04:2021', title: 'Insecure Design' },
        { code: 'A05:2021', title: 'Security Misconfiguration' },
        { code: 'A06:2021', title: 'Vulnerable and Outdated Components' },
        { code: 'A07:2021', title: 'Identification and Authentication Failures' },
        { code: 'A08:2021', title: 'Software and Data Integrity Failures' },
        { code: 'A09:2021', title: 'Security Logging and Monitoring Failures' },
        { code: 'A10:2021', title: 'Server-Side Request Forgery (SSRF)' }
    ],
    buildItemUrl: function (item) {
        return buildWebTop10ItemUrl(item.code, item.title, '2021');
    }
},
        {
    id: 'api-2023',
    family: 'api',
    name: 'API Security – OWASP API Security Top 10:2023',
    version: '2023',
    isReleaseCandidate: false,
    officialProjectUrl: 'https://owasp.org/www-project-api-security/',
    listUrl: 'https://owasp.org/API-Security/editions/2023/en/0x11-t10/',
    itemPattern: /(API\d:2023)\s*[-–]\s*(.+)/i,
    fallbackItems: [
        { code: 'API1:2023', title: 'Broken Object Level Authorization' },
        { code: 'API2:2023', title: 'Broken Authentication' },
        { code: 'API3:2023', title: 'Broken Object Property Level Authorization' },
        { code: 'API4:2023', title: 'Unrestricted Resource Consumption' },
        { code: 'API5:2023', title: 'Broken Function Level Authorization' },
        { code: 'API6:2023', title: 'Unrestricted Access to Sensitive Business Flows' },
        { code: 'API7:2023', title: 'Server Side Request Forgery' },
        { code: 'API8:2023', title: 'Security Misconfiguration' },
        { code: 'API9:2023', title: 'Improper Inventory Management' },
        { code: 'API10:2023', title: 'Unsafe Consumption of APIs' }
    ],
    fillMissingFromFallback: true   // <--- add this
},
        {
            id: 'mobile-2024',
            family: 'mobile',
            name: 'Mobile – OWASP Mobile Top 10:2024',
            version: '2024',
            isReleaseCandidate: false,
            officialProjectUrl: 'https://owasp.org/www-project-mobile-top-10/',
            listUrl: 'https://owasp.org/www-project-mobile-top-10/2023-risks/',
            itemPattern: /(M\d{1,2})\s*[:\-]\s*(.+)/i,
            fallbackItems: [
                { code: 'M1', title: 'Improper Credential Usage' },
                { code: 'M2', title: 'Inadequate Supply Chain Security' },
                { code: 'M3', title: 'Insecure Authentication / Authorization' },
                { code: 'M4', title: 'Insufficient Input / Output Validation' },
                { code: 'M5', title: 'Insecure Communication' },
                { code: 'M6', title: 'Inadequate Privacy Controls' },
                { code: 'M7', title: 'Inadequate Security Configuration' },
                { code: 'M8', title: 'Security Logging and Monitoring Failures' },
                { code: 'M9', title: 'Improper Platform Usage' },
                { code: 'M10', title: 'Code Quality and Build Setting Issues' }
            ]
        },
        {
            id: 'infra-2024',
            family: 'infrastructure',
            name: 'Infrastructure – OWASP Top 10 Infrastructure Security Risks:2024',
            version: '2024',
            isReleaseCandidate: false,
            officialProjectUrl: 'https://owasp.org/www-project-top-10-infrastructure-security-risks/',
            listUrl: 'https://owasp.org/www-project-top-10-infrastructure-security-risks/',
            itemPattern: /(ISR\d{2}:\d{4})\s*[-–]\s*(.+)/i,
            fallbackItems: [
                { code: 'ISR01:2024', title: 'Outdated Software' },
                { code: 'ISR02:2024', title: 'Insufficient Threat Detection' },
                { code: 'ISR03:2024', title: 'Insecure Configurations' },
                { code: 'ISR04:2024', title: 'Insecure Resource and User Management' },
                { code: 'ISR05:2024', title: 'Insecure Use of Cryptography' },
                { code: 'ISR06:2024', title: 'Insecure Network Access Management' },
                { code: 'ISR07:2024', title: 'Insecure Authentication Methods and Default Credentials' },
                { code: 'ISR08:2024', title: 'Information Leakage' },
                { code: 'ISR09:2024', title: 'Insecure Access to Resources and Management Components' },
                { code: 'ISR10:2024', title: 'Insufficient Business Continuity and Disaster Recovery' }
            ]
        },
        {
            id: 'cicd-2021',
            family: 'cicd',
            name: 'CI/CD – OWASP Top 10 CI/CD Security Risks',
            version: 'v1',
            isReleaseCandidate: false,
            officialProjectUrl: 'https://owasp.org/www-project-top-10-ci-cd-security-risks/',
            listUrl: 'https://owasp.org/www-project-top-10-ci-cd-security-risks/',
            itemPattern: /(CICD-SEC-\d)\s*[:\-]\s*(.+)/i,
            fallbackItems: [
                { code: 'CICD-SEC-1', title: 'Insufficient Flow Control Mechanisms' },
                { code: 'CICD-SEC-2', title: 'Poor Credential Hygiene' },
                { code: 'CICD-SEC-3', title: 'Insecure System Configuration' },
                { code: 'CICD-SEC-4', title: 'Inadequate Flow Integrity Controls' },
                { code: 'CICD-SEC-5', title: 'Third-Party and Open Source Risks' },
                { code: 'CICD-SEC-6', title: 'Inadequate Access Controls' },
                { code: 'CICD-SEC-7', title: 'Lack of Observability and Logging' },
                { code: 'CICD-SEC-8', title: 'Insecure Artifact Management' },
                { code: 'CICD-SEC-9', title: 'Insecure Build Pipelines' },
                { code: 'CICD-SEC-10', title: 'Unmanaged Dependencies and Tooling' }
            ]
        },
        {
            id: 'llm-2025',
            family: 'llm',
            name: 'GenAI – OWASP Top 10 for LLM Applications (v1.1)',
            version: '1.1',
            isReleaseCandidate: false,
            officialProjectUrl: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
            listUrl: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
            itemPattern: /(LLM\d{2})\s*:\s*(.+)/i,
            fallbackItems: [
                { code: 'LLM01', title: 'Prompt Injection' },
                { code: 'LLM02', title: 'Insecure Output Handling' },
                { code: 'LLM03', title: 'Training Data Poisoning' },
                { code: 'LLM04', title: 'Model Denial of Service' },
                { code: 'LLM05', title: 'Supply Chain Vulnerabilities' },
                { code: 'LLM06', title: 'Sensitive Information Disclosure' },
                { code: 'LLM07', title: 'Insecure Plugin Design' },
                { code: 'LLM08', title: 'Excessive Agency' },
                { code: 'LLM09', title: 'Overreliance' },
                { code: 'LLM10', title: 'Model Theft' }
            ]
        },
        {
            id: 'ml-2023',
            family: 'ml',
            name: 'Machine Learning – OWASP Machine Learning Security Top 10:2023',
            version: '2023',
            isReleaseCandidate: false,
            officialProjectUrl: 'https://owasp.org/www-project-machine-learning-security-top-10/',
            listUrl: 'https://owasp.org/www-project-machine-learning-security-top-10/',
            itemPattern: /(ML\d{2}:\d{4})\s+(.+)/i,
            fallbackItems: [
                { code: 'ML01:2023', title: 'Input Manipulation Attack' },
                { code: 'ML02:2023', title: 'Data Poisoning Attack' },
                { code: 'ML03:2023', title: 'Model Inversion Attack' },
                { code: 'ML04:2023', title: 'Membership Inference Attack' },
                { code: 'ML05:2023', title: 'Model Theft' },
                { code: 'ML06:2023', title: 'AI Supply Chain Attacks' },
                { code: 'ML07:2023', title: 'Transfer Learning Attack' },
                { code: 'ML08:2023', title: 'Model Skewing' },
                { code: 'ML09:2023', title: 'Output Integrity Attack' },
                { code: 'ML10:2023', title: 'Model Poisoning' }
            ],
            buildItemUrl: function (item) {
                return buildMlTop10ItemUrl(item.code, item.title);
            }
        }
    ];

    const state = {
        projects: OWASP_TOP10_PROJECTS,
        selectedProjectId: OWASP_TOP10_PROJECTS[0] ? OWASP_TOP10_PROJECTS[0].id : null,
        cache: {} // projectId -> { items, fetchedAt, source: 'live' | 'fallback' }
    };

    function escapeHtmlSafe(str) {
        if (!str && str !== 0) return '';
        if (window.escapeHtml) {
            return window.escapeHtml(str);
        }
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function render() {
    return `
        <div id="owaspTop10Root" class="owasp-top10-tool">

                        <div class="section-header">
                <h3 class="mb-1 d-flex align-items-center gap-2">
                    <i class="bi bi-shield-lock"></i>
                    <span>OWASP Top 10 Explorer</span>
                </h3>
                <p class="text-secondary mb-0">
                   Fetch and compare the latest OWASP Top 10-style risk lists directly from official sources.
                </p>
            </div>

            <div class="row gx-4 gy-4">

                <!-- LEFT COLUMN: selector + sources -->
                <div class="col-lg-4">
                    <div class="mb-3">
                        <div class="text-secondary text-uppercase small fw-semibold mb-2">
                            List selector
                        </div>

                        <div class="mb-3">
                            <label for="owaspTop10ProjectSelect" class="form-label small mb-1">
                                OWASP Project
                            </label>
                            <select class="form-select form-select-sm" id="owaspTop10ProjectSelect"></select>
                        </div>

                        <div class="mb-3 d-grid">
                            <button type="button" class="btn btn-success btn-sm" id="owaspTop10RefreshBtn">
                                <span class="spinner-border spinner-border-sm me-2 d-none"
                                      id="owaspTop10RefreshSpinner" role="status" aria-hidden="true"></span>
                                <i class="bi bi-arrow-clockwise me-1"></i>
                                Refresh from OWASP
                            </button>
                        </div>
                    </div>

                    <div class="small text-secondary" id="owaspTop10Meta"></div>
                </div>

                <!-- RIGHT COLUMN: table + status -->
                <div class="col-lg-8">
                    <div id="owaspTop10Status" class="small text-secondary mb-2"></div>

                    <div class="table-responsive owasp-top10-table-wrapper">
                        <table class="table table-dark table-striped table-sm align-middle mb-0">
                            <thead>
                                <tr>
                                    <th style="width:160px;">ID</th>
                                    <th>Title</th>
                                </tr>
                            </thead>
                            <tbody id="owaspTop10TableBody">
                                <tr>
                                    <td colspan="2" class="text-center py-4">
                                        <div class="spinner-border spinner-border-sm me-2" role="status"></div>
                                        Loading OWASP data...
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

            </div>
        </div>
    `;
}

    function init() {
        const root = document.getElementById('owaspTop10Root');
        if (!root) return;

        const select = root.querySelector('#owaspTop10ProjectSelect');
        const refreshBtn = root.querySelector('#owaspTop10RefreshBtn');
        const spinner = root.querySelector('#owaspTop10RefreshSpinner');

        if (select) {
            populateProjectSelect(select);
            select.addEventListener('change', function (e) {
                state.selectedProjectId = e.target.value;
                loadAndRenderCurrentProject();
            });
        }

        if (refreshBtn && spinner) {
            refreshBtn.addEventListener('click', function () {
                if (!state.selectedProjectId) return;
                delete state.cache[state.selectedProjectId];
                spinner.classList.remove('d-none');
                refreshBtn.disabled = true;
                var p = loadAndRenderCurrentProject();
                if (p && typeof p.finally === 'function') {
                    p.finally(function () {
                        spinner.classList.add('d-none');
                        refreshBtn.disabled = false;
                    });
                } else {
                    spinner.classList.add('d-none');
                    refreshBtn.disabled = false;
                }
            });
        }

        loadAndRenderCurrentProject();
    }

    function populateProjectSelect(selectEl) {
        const families = groupProjectsByFamily(state.projects);
        const familyOrder = Object.keys(families);

        selectEl.innerHTML = '';
        familyOrder.forEach(function (familyKey) {
            const group = families[familyKey];
            const optgroup = document.createElement('optgroup');
            optgroup.label = familyKey.toUpperCase();
            group.forEach(function (project) {
                const option = document.createElement('option');
                option.value = project.id;
                let label = project.name;
                if (project.isReleaseCandidate) {
                    label += ' [RC]';
                }
                option.textContent = label;
                if (project.id === state.selectedProjectId) {
                    option.selected = true;
                }
                optgroup.appendChild(option);
            });
            selectEl.appendChild(optgroup);
        });
    }

    function groupProjectsByFamily(projects) {
        return projects.reduce(function (acc, proj) {
            const key = proj.family || 'other';
            if (!acc[key]) acc[key] = [];
            acc[key].push(proj);
            return acc;
        }, {});
    }

    function getProjectSources(project) {
        const urls = [];
        if (project.officialProjectUrl) urls.push(project.officialProjectUrl);
        if (project.listUrl && urls.indexOf(project.listUrl) === -1) urls.push(project.listUrl);
        if (Array.isArray(project.additionalSourceUrls)) {
            project.additionalSourceUrls.forEach(function (u) {
                if (u && urls.indexOf(u) === -1) urls.push(u);
            });
        }
        return urls;
    }

    function loadAndRenderCurrentProject() {
        const project = state.projects.find(function (p) {
            return p.id === state.selectedProjectId;
        });
        if (!project) return Promise.resolve();

        const tbody = document.getElementById('owaspTop10TableBody');
        const statusEl = document.getElementById('owaspTop10Status');
        const metaEl = document.getElementById('owaspTop10Meta');

        if (!tbody || !statusEl || !metaEl) return Promise.resolve();

        if (!state.cache[project.id]) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="2" class="text-center py-4">
                        <div class="spinner-border spinner-border-sm me-2" role="status"></div>
                        Fetching latest list from OWASP...
                    </td>
                </tr>
            `;
            statusEl.textContent = '';
        }

        const sources = getProjectSources(project);
        const sourcesHtml = sources.length
            ? sources.map(function (u) {
                var human = u.replace(/^https?:\/\//i, '').replace(/\/$/, '');
                return `
                    <li>
                        <a href="${escapeHtmlSafe(u)}" target="_blank" rel="noopener noreferrer">
                            ${escapeHtmlSafe(human)}
                        </a>
                    </li>
                `;
            }).join('')
            : '<li class="text-secondary">No sources defined</li>';

        metaEl.innerHTML = `
            <div class="mb-1"><strong>Sources</strong></div>
            <ul class="owasp-top10-sources mb-2">
                ${sourcesHtml}
            </ul>
            <div><strong>Version:</strong> ${escapeHtmlSafe(project.version || 'n/a')}</div>
        `;

        if (state.cache[project.id]) {
            const cached = state.cache[project.id];
            renderItems(project, cached.items, {
                source: cached.source,
                fetchedAt: cached.fetchedAt
            });
            return Promise.resolve();
        }

        return fetch(project.listUrl, { method: 'GET' })
            .then(function (resp) {
                if (!resp.ok) {
                    throw new Error('HTTP ' + resp.status + ' when fetching ' + project.listUrl);
                }
                return resp.text();
            })
            .then(function (html) {
    const parsed = parseOwaspHtml(html, project);

    if (!parsed || !parsed.length) {
        if (project.fallbackItems && project.fallbackItems.length) {
            state.cache[project.id] = {
                items: normalizeItems(project.fallbackItems),
                fetchedAt: null,
                source: 'fallback'
            };
            renderItems(project, state.cache[project.id].items, {
                source: 'fallback'
            });
        } else {
            throw new Error('Could not detect any OWASP Top 10 entries in remote document.');
        }
    } else {
        const items = ensureAllFallbackCodesPresent(project, parsed);
        const fetchedAt = new Date();
        state.cache[project.id] = {
            items: items,
            fetchedAt: fetchedAt,
            source: 'live'
        };
        renderItems(project, items, {
            source: 'live',
            fetchedAt: fetchedAt
        });
    }
})
            .catch(function (err) {
                console.error('OWASP Top 10 fetch error for', project.id, err);
                if (project.fallbackItems && project.fallbackItems.length) {
                    const items = normalizeItems(project.fallbackItems);
                    state.cache[project.id] = {
                        items: items,
                        fetchedAt: null,
                        source: 'fallback'
                    };
                    renderItems(project, items, {
                        source: 'fallback',
                        note: 'Live fetch failed: ' + escapeHtmlSafe(err.message) + '. Showing built-in snapshot.'
                    });
                } else {
                    tbody.innerHTML = `
                        <tr>
                            <td colspan="2" class="text-center py-4 text-danger">
                                <i class="bi bi-exclamation-triangle-fill"></i>
                                Failed to load data from OWASP and no fallback list is configured.
                            </td>
                        </tr>
                    `;
                    statusEl.innerHTML = `
                        <div class="alert alert-danger mb-0">
                            <strong>Error:</strong> ${escapeHtmlSafe(err.message)}
                        </div>
                    `;
                }
            });
    }

    function normalizeItems(arr) {
        return arr.map(function (item) {
            return {
                code: item.code,
                title: item.title,
                text: item.code + ' - ' + item.title
            };
        });
    }

    function ensureAllFallbackCodesPresent(project, parsedItems) {
    // Only certain projects should merge fallback with live data
    if (!project.fillMissingFromFallback) {
        return Array.isArray(parsedItems) ? parsedItems : [];
    }

    var items = Array.isArray(parsedItems) ? parsedItems.slice() : [];

    if (!project.fallbackItems || !project.fallbackItems.length) {
        return items;
    }

    var seen = {};
    items.forEach(function (it) {
        if (it && it.code) {
            seen[it.code] = true;
        }
    });

    project.fallbackItems.forEach(function (fb) {
        if (!fb || !fb.code || seen[fb.code]) return;
        items.push({
            code: fb.code,
            title: fb.title,
            text: fb.code + ' - ' + fb.title
        });
    });

    return items;
}

    function parseOwaspHtml(html, project) {
        try {
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            const nodes = Array.prototype.slice.call(
                doc.querySelectorAll('li, p, td, h3, h4')
            );

            const seenCodes = {};
            const items = [];

            nodes.forEach(function (node) {
                const rawText = node.textContent || '';
                const text = rawText.replace(/\s+/g, ' ').trim();
                if (!text) return;

                const match = project.itemPattern.exec(text);
                if (!match) return;

                const code = match[1] ? match[1].trim() : '';
                const title = match[2] ? match[2].trim() : '';

                if (!code || seenCodes[code]) return;

                seenCodes[code] = true;
                items.push({
                    code: code,
                    title: title || text,
                    text: text
                });
            });

            return items;
        } catch (e) {
            console.error('Error parsing OWASP HTML for', project.id, e);
            return [];
        }
    }

function renderItems(project, items, context) {
    const tbody = document.getElementById('owaspTop10TableBody');
    const statusEl = document.getElementById('owaspTop10Status');

    if (!tbody || !statusEl) return;

    if (!items || !items.length) {
        tbody.innerHTML = `
            <tr>
                <td colspan="2" class="text-center py-4 text-secondary">
                    No entries found for this project.
                </td>
            </tr>
        `;
    } else {
        tbody.innerHTML = '';
        items.forEach(function (item) {
            const row = document.createElement('tr');
            row.title = item.text || '';

            const codeTd = document.createElement('td');
            codeTd.className = 'align-middle';

            var itemUrl = (typeof project.buildItemUrl === 'function')
                ? project.buildItemUrl(item)
                : null;

            if (itemUrl) {
                codeTd.innerHTML =
                    '<a href="' + escapeHtmlSafe(itemUrl) + '" target="_blank" rel="noopener noreferrer" class="owasp-id-link">' +
                        '<span class="owasp-id-pill">' +
                            '<span class="owasp-id-code">' + escapeHtmlSafe(item.code) + '</span>' +
                            '<i class="bi bi-box-arrow-up-right owasp-id-icon"></i>' +
                        '</span>' +
                    '</a>';
            } else {
                codeTd.innerHTML =
                    '<span class="owasp-id-pill">' +
                        '<span class="owasp-id-code">' + escapeHtmlSafe(item.code) + '</span>' +
                    '</span>';
            }

            const titleTd = document.createElement('td');
            titleTd.className = 'align-middle';
            titleTd.innerHTML = '<span class="vuln-list-title">' + escapeHtmlSafe(item.title) + '</span>';

            row.appendChild(codeTd);
            row.appendChild(titleTd);

            tbody.appendChild(row);
        });
    }

    // Compact, human-readable status
    const summaryParts = [];
    const count = items ? items.length : 0;

    summaryParts.push(count + ' entries');

    if (context && context.source === 'live') {
        summaryParts.push('Live · OWASP');
    } else if (context && context.source === 'fallback') {
        summaryParts.push('Snapshot · built-in');
    }

    if (context && context.source === 'live' && context.fetchedAt instanceof Date) {
        summaryParts.push('Updated: ' + context.fetchedAt.toLocaleString());
    }

    const summaryText = summaryParts.join(' • ');
    statusEl.innerHTML = '<div class="small">' + escapeHtmlSafe(summaryText) + '</div>';
}

    // Register the tool
    if (window && typeof window.registerCyberSuiteTool === 'function') {
        window.registerCyberSuiteTool({
            id: 'owasp-top10-explorer',
            name: 'OWASP Top 10 Explorer',
            description: 'Retrieve and compare all major OWASP Top 10-style lists (Web, API, Mobile, Infra, CI/CD, ML, LLM) from official sources.',
            icon: 'bi-shield-lock',
            category: 'purple',
            render: render,
            init: init
        });
    }
})();