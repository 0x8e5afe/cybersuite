// =====================
// Dynamic tools ticker with typing + deleting
// =====================

const toolPaths = [
    'tools/clickjacking-poc-tool.js',
    'tools/cors-checker-tool.js',
    'tools/csrf-poc-tool.js',
    'tools/cvss3-calculator-tool.js',
    'tools/encoder-decoder-tool.js',
    'tools/encryption-tool.js',
    'tools/hash-tool.js',
    'tools/prompt-injection-tool.js',
    'tools/hashcat-rule-generator-tool.js',
    'tools/comparer-tool.js',
    'tools/pentest-report-tool.js',
    'tools/steganography-tool.js',
    'tools/jwt-tool.js',
    'tools/xss-tool.js',
    'tools/owasp-tool.js',
    'tools/sqli-tool.js',
    'tools/sysmon-tool.js',
    'tools/windows-event-id-tool.js',
    'tools/wordlists-generator-tool.js',
    'tools/password-cracker-tool.js',
    'tools/password-generator-tool.js',
    'tools/headers-analyzer-tool.js',
    'tools/shells-generator-tool.js'
];

const toolPrettyNames = {
    'clickjacking-poc':          'Clickjacking PoC',
    'cors-checker':              'CORS Checker',
    'csrf-poc':                  'CSRF PoC',
    'cvss3-calculator':          'CVSS v3 Calculator',
    'encoder-decoder':           'Encoder / Decoder',
    'encryption':                'Encryption Utilities',
    'hash':                      'Hash Utilities',
    'prompt-injection':          'Prompt Injection Helper',
    'hashcat-rule-generator':    'Hashcat Rule Generator',
    'wordlists':                 'Wordlists Manager',
    'pentest-report':            'Pentest Report Helper',
    'steganography':             'Steganography Toolkit',
    'jwt':                       'JWT Analyzer',
    'xss':                       'XSS Payload Generator',
    'owasp':                     'OWASP Helper',
    'sqli':                      'SQLi Helper',
    'sysmon':                    'Sysmon Hunt Helper',
    'windows-event-id':          'Windows Event ID Explorer',
    'wordlists-generator':       'Wordlists Generator',
    'password-cracker':          'Password Cracker Helper',
    'password-generator':        'Password Generator',
    'headers-analyzer':          'HTTP Headers Analyzer',
    'shells-generator':          'Shells Generator'
};

function pathToKey(path) {
    const file = path.split('/').pop();
    return file
        .replace('.js', '')
        .replace(/-tool$/, '')
        .toLowerCase();
}

function toHumanReadableTool(path) {
    const key = pathToKey(path);
    if (toolPrettyNames[key]) {
        return toolPrettyNames[key];
    }

    return key
        .split('-')
        .map(word => word.length <= 3 ? word.toUpperCase()
            : word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
}

// Typewriter effect now on the search input placeholder instead of navbar
(function initToolTickerTypewriter() {
    const input = document.getElementById('toolSearch');
    if (!input) return;

    let lastIndex = -1;
    let currentText = '';
    let charIndex = 0;
    let isDeleting = false;

    function render(visibleText) {
        // Do not touch placeholder if user is interacting/typing
        if (document.activeElement === input) return;
        if (input.value && input.value.length > 0) return;

        // When no visible text, keep placeholder completely empty
        if (!visibleText) {
            input.setAttribute('placeholder', '');
            return;
        }

        const cursor = '▌';
        input.setAttribute('placeholder', visibleText + cursor);
    }

    function pickNextToolText() {
        if (toolPaths.length === 0) return '';
        if (toolPaths.length === 1) return toHumanReadableTool(toolPaths[0]);

        let idx;
        do {
            idx = Math.floor(Math.random() * toolPaths.length);
        } while (idx === lastIndex);

        lastIndex = idx;
        return toHumanReadableTool(toolPaths[idx]);
    }

    currentText = pickNextToolText();

    function typeLoop() {
        let delay;

        if (!isDeleting && charIndex < currentText.length) {
            // Typing
            charIndex++;
            render(currentText.slice(0, charIndex));
            delay = 90;
        } else if (!isDeleting && charIndex === currentText.length) {
            // Pause at full text
            isDeleting = true;
            delay = 1200;
        } else if (isDeleting && charIndex > 0) {
            // Deleting
            charIndex--;
            render(currentText.slice(0, charIndex));
            delay = 40;
        } else {
            // Finished deleting, choose new tool
            isDeleting = false;
            currentText = pickNextToolText();
            // Keep placeholder empty between suggestions
            render('');
            delay = 400;
        }

        setTimeout(typeLoop, delay);
    }

    // Clear placeholder when the user focuses the input
    input.addEventListener('focus', () => {
        input.setAttribute('placeholder', '');
    });

    typeLoop();
})();

// Scroll to Top Button Functionality

const scrollToTopBtn = document.getElementById('scrollToTopBtn');

window.addEventListener('scroll', () => {
    if (window.pageYOffset > 300) {
        scrollToTopBtn.classList.add('show');
    } else {
        scrollToTopBtn.classList.remove('show');
    }
});

scrollToTopBtn.addEventListener('click', () => {
    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
});

// ========================================
// CYBERSUITE - MODULAR CORE APPLICATION
// ========================================

const CATEGORY_INFO = {
    red: {
        name: 'Red Team Tools',
        icon: 'bi-crosshair',
        description: 'Offensive security and penetration testing',
        class: 'red-team',
        color: 'danger'
    },
    blue: {
        name: 'Blue Team Tools',
        icon: 'bi-shield-fill',
        description: 'Defensive security and monitoring',
        class: 'blue-team',
        color: 'blue'
    },
    purple: {
        name: 'Purple Team Tools',
        icon: 'bi-layers-fill',
        description: 'Tools for both offensive and defensive security',
        class: 'purple-team',
        color: 'purple'
    }
};

// Tool registry - tools will register themselves here
window.CYBERSUITE_TOOLS = window.CYBERSUITE_TOOLS || [];

let currentCategory = 'all';
let activeToolId = null;

// ========================================
// TOOL REGISTRATION SYSTEM
// ========================================

/**
 * Register a new tool in CyberSuite
 * @param {Object} toolConfig - Tool configuration object
 * @param {string} toolConfig.id - Unique tool identifier
 * @param {string} toolConfig.name - Display name
 * @param {string} toolConfig.description - Short description
 * @param {string} toolConfig.icon - Bootstrap icon class (e.g., 'bi-key-fill')
 * @param {string} toolConfig.category - 'red', 'blue', or 'purple'
 * @param {Function} toolConfig.render - Function that returns HTML string
 * @param {Function} toolConfig.init - Function to initialize tool functionality
 */
window.registerCyberSuiteTool = function(toolConfig) {
    // Validate tool config
    const required = ['id', 'name', 'description', 'icon', 'category', 'render', 'init'];
    for (const field of required) {
        if (!toolConfig[field]) {
            console.error(`Tool registration failed: missing ${field}`, toolConfig);
            return;
        }
    }
    
    // Check for duplicate IDs
    if (window.CYBERSUITE_TOOLS.find(t => t.id === toolConfig.id)) {
        console.warn(`Tool with id "${toolConfig.id}" already registered, skipping`);
        return;
    }
    
    // Validate category
    if (!['red', 'blue', 'purple'].includes(toolConfig.category)) {
        console.error(`Invalid category "${toolConfig.category}" for tool "${toolConfig.id}"`);
        return;
    }
    
    window.CYBERSUITE_TOOLS.push(toolConfig);
    console.log(`✓ Registered tool: ${toolConfig.name} [${toolConfig.category}]`);
};

// ========================================
// DYNAMIC TOOL LOADER
// ========================================

/**
 * Dynamically load all tools from the tools directory
 */
function loadAllTools() {
    const toolFiles = toolPaths;

    let loadedCount = 0;
    const totalTools = toolFiles.length;

    toolFiles.forEach(toolFile => {
        const script = document.createElement('script');
        script.src = toolFile;
        script.onload = () => {
            loadedCount++;
            console.log(`✓ Loaded tool: ${toolFile}`);
            
            if (loadedCount === totalTools) {
                setTimeout(initApp, 100);
            }
        };
        script.onerror = () => {
            console.error(`✗ Failed to load tool: ${toolFile}`);
            loadedCount++;
            if (loadedCount === totalTools) {
                setTimeout(initApp, 100);
            }
        };
        document.head.appendChild(script);
    });

    if (totalTools === 0) {
        setTimeout(initApp, 100);
    }
}

// ========================================
// INITIALIZATION
// ========================================

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        loadAllTools();
    });
} else {
    loadAllTools();
}

// ========================================
// MAIN APPLICATION
// ========================================

function initApp() {
    console.log('☕ CyberSuite initializing...');
    console.log(`📦 Loaded ${window.CYBERSUITE_TOOLS.length} tools`);
    
    renderToolsSections();
    setupCategoryFilters();
    setupSearch();
    
    console.log('✓ CyberSuite ready!');
}

function renderToolsSections() {
    const sectionsContainer = document.getElementById('toolsSections');
    sectionsContainer.innerHTML = '';

    // Group tools by category and sort each category by name
    const toolsByCategory = {
        red: window.CYBERSUITE_TOOLS
            .filter(t => t.category === 'red')
            .sort((a, b) => a.name.localeCompare(b.name)),
        blue: window.CYBERSUITE_TOOLS
            .filter(t => t.category === 'blue')
            .sort((a, b) => a.name.localeCompare(b.name)),
        purple: window.CYBERSUITE_TOOLS
            .filter(t => t.category === 'purple')
            .sort((a, b) => a.name.localeCompare(b.name))
        
    };

    // Render each category section
    for (const [category, tools] of Object.entries(toolsByCategory)) {
        if (tools.length === 0) continue;

        const info = CATEGORY_INFO[category];
        const section = document.createElement('div');
        section.className = `row mb-5 tools-section`;
        section.setAttribute('data-category', category);

        section.innerHTML = `
            <div class="col-12">
                <div class="section-header ${info.class}">
                    <h3 class="text-${info.color}">
                        <i class="bi ${info.icon}"></i> ${info.name}
                    </h3>
                    <p class="text-secondary mb-0">${info.description}</p>
                </div>
                <div class="row g-3" id="grid-${category}"></div>
            </div>
        `;

        sectionsContainer.appendChild(section);

        // Render tools in this category (already sorted)
        const grid = section.querySelector(`#grid-${category}`);
        tools.forEach(tool => {
            const card = document.createElement('div');
            card.className = 'col-12 col-sm-6 col-md-4 col-lg-3 col-xl-2';
            card.innerHTML = `
                <div class="card tool-card ${info.class} h-100" data-tool-id="${tool.id}" data-tool-name="${tool.name.toLowerCase()}" data-tool-desc="${tool.description.toLowerCase()}">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-start mb-2">
                            <h6 class="card-title mb-0">
                                <i class="bi ${tool.icon}"></i> ${tool.name}
                            </h6>
                            <!--<span class="badge bg-${info.color} badge-sm">${category}</span>-->
                        </div>
                        <p class="card-text text-secondary small">${tool.description}</p>
                    </div>
                </div>
            `;
            
            const cardElement = card.querySelector('.tool-card');
            cardElement.onclick = () => loadTool(tool.id);
            grid.appendChild(card);
        });
    }
}

function setupCategoryFilters() {
    const filters = document.querySelectorAll('.category-filter');
    
    filters.forEach(filter => {
        filter.addEventListener('click', () => {
            const category = filter.getAttribute('data-category');
            
            // Update active state
            filters.forEach(f => f.classList.remove('active'));
            filter.classList.add('active');
            
            // Filter sections
            filterToolsByCategory(category);
            currentCategory = category;
            
            // Close workspace when changing category
            closeWorkspace();
            
            // Clear search
            document.getElementById('toolSearch').value = '';
            performSearch('');
        });
    });
}

function filterToolsByCategory(category) {
    const sections = document.querySelectorAll('.tools-section');
    
    if (category === 'all') {
        sections.forEach(section => section.classList.remove('d-none'));
    } else {
        sections.forEach(section => {
            const sectionCategory = section.getAttribute('data-category');
            if (sectionCategory === category) {
                section.classList.remove('d-none');
            } else {
                section.classList.add('d-none');
            }
        });
    }
}

function loadTool(toolId) {
    const tool = window.CYBERSUITE_TOOLS.find(t => t.id === toolId);
    if (!tool) {
        console.error(`Tool not found: ${toolId}`);
        return;
    }
    
    // Update active state on cards
    document.querySelectorAll('.tool-card').forEach(card => {
        card.classList.remove('active');
    });
    
    const activeCard = document.querySelector(`[data-tool-id="${toolId}"]`);
    if (activeCard) {
        activeCard.classList.add('active');
    }
    
    activeToolId = toolId;

    // 🔹 Choose border class based on category
    let borderClass = '';
    switch (tool.category) {
        case 'red':
            borderClass = 'border-red';
            break;
        case 'blue':
            borderClass = 'border-blue';
            break;
        case 'purple':
            borderClass = 'border-purple';
            break;
    }
    
    // Render tool workspace
    const workspace = document.getElementById('workspace');
    try {
        workspace.innerHTML = `
            <div class="row mt-4">
                <div class="col-12">
                    <div class="card tool-workspace ${borderClass}">
                        <div class="card-body">
                            ${tool.render()}
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Initialize tool
        tool.init();
        
        // Scroll to workspace
        workspace.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        
        console.log(`✓ Loaded tool: ${tool.name}`);
    } catch (error) {
        console.error(`Error loading tool ${toolId}:`, error);
        workspace.innerHTML = `
            <div class="row mt-4">
                <div class="col-12">
                    <div class="alert alert-danger" role="alert">
                        <h5 class="alert-heading">Error Loading Tool</h5>
                        <p>${error.message}</p>
                    </div>
                </div>
            </div>
        `;
    }
}

function closeWorkspace() {
    const workspace = document.getElementById('workspace');
    workspace.innerHTML = '';
    
    document.querySelectorAll('.tool-card').forEach(card => {
        card.classList.remove('active');
    });
    
    activeToolId = null;
}

// ========================================
// SEARCH FUNCTIONALITY
// ========================================

function setupSearch() {
    const searchInput = document.getElementById('toolSearch');
    const clearButton = document.getElementById('clearSearch');
    const searchResults = document.getElementById('searchResults');
    
    searchInput.addEventListener('input', function() {
        const query = this.value.toLowerCase().trim();
        performSearch(query);
    });
    
    clearButton.addEventListener('click', function() {
        searchInput.value = '';
        performSearch('');
        searchInput.focus();
    });
    
    // Enter key to focus first result
    searchInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            const firstVisible = document.querySelector('.tool-card:not(.d-none)');
            if (firstVisible) {
                firstVisible.click();
            }
        }
    });
}

function performSearch(query) {
    const allCards = document.querySelectorAll('.tool-card');
    const searchResults = document.getElementById('searchResults');
    let visibleCount = 0;
    
    if (!query) {
        // Reset category filter view
        if (currentCategory === 'all') {
            document.querySelectorAll('.tools-section').forEach(section => {
                section.classList.remove('d-none');
            });
        } else {
            filterToolsByCategory(currentCategory);
        }
        
        // Show all card wrappers (so grid is full again)
        allCards.forEach(card => {
            const wrapper = card.parentElement;
            if (wrapper) {
                wrapper.classList.remove('d-none');
            }
        });
        
        searchResults.textContent = '';
        return;
    }

    // When searching, show all sections (so matches are visible)
    document.querySelectorAll('.tools-section').forEach(section => {
        section.classList.remove('d-none');
    });

    allCards.forEach(card => {
        const wrapper = card.parentElement;
        const name = card.getAttribute('data-tool-name') || '';
        const desc = card.getAttribute('data-tool-desc') || '';
        
        if (name.includes(query) || desc.includes(query)) {
            if (wrapper) wrapper.classList.remove('d-none');
            visibleCount++;
        } else {
            if (wrapper) wrapper.classList.add('d-none');
        }
    });

    if (visibleCount === 0) {
        searchResults.textContent = 'No tools match your search. Try different keywords.';
    } else if (visibleCount === 1) {
        searchResults.textContent = '1 tool found.';
    } else {
        searchResults.textContent = `${visibleCount} tools found.`;
    }
}

// ========================================
// UTILITY FUNCTIONS
// ========================================

/**
 * Copy text to clipboard with a tooltip-style feedback
 * @param {string} text - Text to copy
 * @param {HTMLElement} [triggerElement] - Element to show tooltip near
 */
window.copyToClipboard = function(text, triggerElement) {
    if (!navigator.clipboard) {
        // Fallback for older browsers
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.top = '-9999px';
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        
        try {
            document.execCommand('copy');
            showCopyFeedback(triggerElement);
        } catch (err) {
            console.error('Fallback: Oops, unable to copy', err);
        }
        
        document.body.removeChild(textarea);
        return;
    }

    navigator.clipboard.writeText(text)
        .then(() => showCopyFeedback(triggerElement))
        .catch(err => console.error('Async: Could not copy text: ', err));
};

/**
 * Show visual feedback after copying
 * @param {HTMLElement} triggerElement
 */
function showCopyFeedback(triggerElement) {
    if (!triggerElement) return;
    
    const originalHtml = triggerElement.innerHTML;
    triggerElement.innerHTML = '<i class="bi bi-check2"></i>';
    triggerElement.classList.add('text-success');
    
    setTimeout(() => {
        triggerElement.innerHTML = originalHtml;
        triggerElement.classList.remove('text-success');
    }, 800);
}

/**
 * Download a text file
 * @param {string} filename - Name of the file
 * @param {string|Blob} content - File content
 * @param {string} mimeType - MIME type (default: text/plain)
 */
window.downloadFile = function(filename, content, mimeType = 'text/plain') {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
};

/**
 * Escape HTML to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} Escaped HTML
 */
window.escapeHtml = function(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
};