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
    'tools/beautifier-tool.js',
    'tools/pentest-report-tool.js',
    'tools/steganography-tool.js',
    'tools/jwt-tool.js',
    'tools/xss-tool.js',
    'tools/owasp-tool.js',
    'tools/http-request-tool.js',
    'tools/sqli-tool.js',
    'tools/sysmon-tool.js',
    'tools/windows-event-id-tool.js',
    'tools/wordlists-generator-tool.js',
    'tools/wordlists-tool.js',
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
    if (!file.endsWith('.js')) return file.toLowerCase();

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


// =====================
// CYBERSUITE - PIPELINE EDITION
// =====================

// Tool registry
window.CYBERSUITE_TOOLS = window.CYBERSUITE_TOOLS || [];

// Pipeline state
let pipelineChain = [];
let currentMode = 'single';
let activeToolId = null;
let currentCategory = 'all';
let pipelineToolSearchQuery = '';
// Only these tools are allowed in the pipeline beta
const pipelineEnabledToolIds = new Set([
    'password-generator',
    'password-cracker',
    'beautifier',
    'encoder-decoder'
]);
const pipelineToolEnabled = tool => tool && pipelineEnabledToolIds.has(tool.id);
// Some tools might be restricted from starting the chain (currently all allowed)
const pipelineDisallowFirst = new Set();
const pipelineToolCanBeFirst = tool => tool && !pipelineDisallowFirst.has(tool.id);

// Helper to normalize IO types
const normalizeIoTypes = (value, fallback = ['any']) => {
    if (Array.isArray(value)) {
        return value.filter(Boolean);
    }
    if (typeof value === 'string' && value.trim() !== '') {
        return [value.trim()];
    }
    if (value == null || value === '') {
        return fallback.slice();
    }
    return [String(value)];
};

// ========================================
// TOOL REGISTRATION SYSTEM (ENHANCED)
// ========================================

/**
 * Enhanced tool registration that also sets up pipeline-related metadata
 * @param {Object} toolConfig
 * @param {string} toolConfig.id - Unique tool identifier
 * @param {string} toolConfig.name - User-friendly tool name
 * @param {string} toolConfig.description - Short description
 * @param {string} toolConfig.icon - Bootstrap icon class
 * @param {'red'|'blue'|'purple'} toolConfig.category - Tool category
 * @param {Function} toolConfig.render - Function that returns HTML for the tool workspace
 * @param {Function} toolConfig.init - Initialization function
 * @param {Array<string>} [toolConfig.inputTypes] - Supported input types for pipeline mode
 * @param {string} [toolConfig.outputType] - Output type produced by this tool
 * @param {Function} [toolConfig.processPipeline] - Async pipeline handler
 * @param {Function} [toolConfig.renderPipelineOutput] - Optional renderer for pipeline step output (receives {stepIndex, output, metadata, mode})
 */
window.registerCyberSuiteTool = function(toolConfig) {

    toolConfig.inputTypes = normalizeIoTypes(toolConfig.inputTypes, ['text']);
    toolConfig.outputType = (typeof toolConfig.outputType === 'string' && toolConfig.outputType.trim()) ? toolConfig.outputType : 'json';
    
    const required = ['id', 'name', 'description', 'icon', 'category', 'render', 'init'];
    for (const field of required) {
        if (!toolConfig[field]) {
            console.error(`Tool registration failed: missing ${field}`, toolConfig);
            return;
        }
    }
    
    if (window.CYBERSUITE_TOOLS.find(t => t.id === toolConfig.id)) {
        console.warn(`Tool with id "${toolConfig.id}" already registered, skipping`);
        return;
    }
    
    if (!['red', 'blue', 'purple'].includes(toolConfig.category)) {
        console.error(`Invalid category "${toolConfig.category}" for tool "${toolConfig.id}"`);
        return;
    }

    // Pipeline-related defaults
    if (!toolConfig.processPipeline) {
        toolConfig.processPipeline = async (input) => ({ success: false, error: 'Pipeline not supported' });
    }

    // Normalize pipeline block definitions; each tool can expose multiple pipeline blocks
    const pipelineBlocks = Array.isArray(toolConfig.pipelineBlocks) && toolConfig.pipelineBlocks.length
        ? toolConfig.pipelineBlocks
        : [{ id: 'default' }];

    toolConfig.__pipelineBlocks = pipelineBlocks.map((blockDef, idx) => {
        const blockId = blockDef.id || `block-${idx}`;
        const renderForm = blockDef.renderPipelineInputs || blockDef.renderPipelineForm || toolConfig.render;
        const initForm = blockDef.initPipeline || toolConfig.initPipeline || toolConfig.init;

        return {
            id: `${toolConfig.id}::${blockId}`,
            blockKey: blockId,
            name: blockDef.name || toolConfig.name,
            description: blockDef.description || toolConfig.description,
            icon: toolConfig.icon,
            category: toolConfig.category,
            inputTypes: normalizeIoTypes(blockDef.inputTypes, toolConfig.inputTypes),
            outputType: (typeof blockDef.outputType === 'string' && blockDef.outputType.trim()) ? blockDef.outputType : toolConfig.outputType,
            processPipeline: blockDef.processPipeline || toolConfig.processPipeline,
            renderPipelineOutput: blockDef.renderPipelineOutput || toolConfig.renderPipelineOutput,
            renderPipelineForm: renderForm,
            initPipeline: initForm,
            baseTool: toolConfig,
            hint: blockDef.hint || ''
        };
    });
    
    window.CYBERSUITE_TOOLS.push(toolConfig);
    console.log(`✓ Registered tool: ${toolConfig.name} [in:${toolConfig.inputTypes.join(',')} → out:${toolConfig.outputType}]`);
};

// ========================================
// MODE SWITCHING
// ========================================

window.switchMode = function(mode) {
    currentMode = mode;
    
    // toggle active button
    document.querySelectorAll('.mode-btn').forEach(btn => {
        const btnMode = btn.getAttribute('data-mode');
        btn.classList.toggle('active', btnMode === mode);
    });

    const pipelineToggle = document.querySelector('.mode-btn[data-mode="pipeline"]');
    if (pipelineToggle) {
        const isPipeline = mode === 'pipeline';
        pipelineToggle.innerHTML = `
            <span class="mode-icon"><i class="bi ${isPipeline ? 'bi-square-fill' : 'bi-stack'}"></i></span>
            <span class="mode-label">${isPipeline ? 'Normal mode' : 'Pipeline Mode (Experimental)'}</span>
        `;
        pipelineToggle.onclick = () => switchMode(isPipeline ? 'single' : 'pipeline');
    }
    
    const single   = document.getElementById('singleToolMode');
    const pipeline = document.getElementById('pipelineMode');
    
    if (single) {
        single.style.display = (mode === 'single') ? 'block' : 'none';
    }
    if (pipeline) {
        const showPipeline = (mode === 'pipeline');
        pipeline.style.display = showPipeline ? 'block' : 'none';

        if (showPipeline) {
            setupPipelineSearch();
            renderPipelineChain();
            renderAvailableTools();
            updateExecuteButton();
            if (window.bootstrap && bootstrap.Tooltip) {
                document.querySelectorAll('#pipelineMode [data-bs-toggle="tooltip"]').forEach(el => new bootstrap.Tooltip(el));
            }
        }
    }
};

// ========================================
// PIPELINE MANAGEMENT
// ========================================

function getPipelineBlocks() {
    const blocks = [];
    window.CYBERSUITE_TOOLS.forEach(tool => {
        if (!pipelineToolEnabled(tool)) return;
        if (Array.isArray(tool.__pipelineBlocks)) {
            tool.__pipelineBlocks.forEach(b => blocks.push(b));
        }
    });
    return blocks;
}

function findPipelineBlock(blockId) {
    return getPipelineBlocks().find(b => b.id === blockId);
}

function setupPipelineSearch() {
    const searchInput = document.getElementById('pipelineToolSearch');
    const clearBtn = document.getElementById('clearPipelineToolSearch');

    if (!searchInput || searchInput.dataset.bound === 'true') return;

    const updateQuery = () => {
        pipelineToolSearchQuery = (searchInput.value || '').trim();
        renderAvailableTools();
    };

    searchInput.addEventListener('input', updateQuery);
    searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            searchInput.value = '';
            pipelineToolSearchQuery = '';
            renderAvailableTools();
        }
    });

    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            searchInput.value = '';
            pipelineToolSearchQuery = '';
            searchInput.focus();
            renderAvailableTools();
        });
    }

    searchInput.dataset.bound = 'true';
}

function renderAvailableTools() {
    const container = document.getElementById('availableTools');
    if (!container) return;

    const searchInput = document.getElementById('pipelineToolSearch');
    if (searchInput && searchInput.value.trim() !== pipelineToolSearchQuery) {
        searchInput.value = pipelineToolSearchQuery;
    }
    
    const lastTool = pipelineChain.length > 0 ? pipelineChain[pipelineChain.length - 1] : null;
    const expectedInputType = lastTool ? lastTool.outputType : null;
    const query = (pipelineToolSearchQuery || '').trim();
    const queryLower = query.toLowerCase();
    
    const availableBlocks = getPipelineBlocks().filter(block => {
        if (pipelineChain.find(t => t.id === block.id)) return false;
        // Search filter
        if (query) {
            const nameMatch = (block.name || '').toLowerCase().includes(queryLower);
            const descMatch = (block.description || '').toLowerCase().includes(queryLower);
            if (!nameMatch && !descMatch) return false;
        }
        
        // If chain is empty, all tools available
        if (!lastTool) return pipelineToolCanBeFirst(block.baseTool);
        
        // Check if tool accepts output from last tool
        return block.inputTypes.includes(expectedInputType) || block.inputTypes.includes('any');
    });
    
    if (availableBlocks.length === 0) {
        const searchMsg = query
            ? `No pipeline tools match "${window.escapeHtml(pipelineToolSearchQuery)}".`
            : `No compatible tools available. Current chain output type: <strong>${expectedInputType || 'any'}</strong>`;
        container.innerHTML = `
            <div class="alert alert-warning mb-0">
                <small>${searchMsg}</small>
            </div>
        `;
        return;
    }
    
    const grouped = availableBlocks.reduce((acc, block) => {
        const key = block.baseTool?.id || 'other';
        if (!acc[key]) acc[key] = { tool: block.baseTool, blocks: [] };
        acc[key].blocks.push(block);
        return acc;
    }, {});

    container.innerHTML = Object.values(grouped).map(group => `
        <div class="mb-3 available-tool-group">
            <div class="d-flex align-items-center mb-2">
                <i class="bi ${group.tool?.icon || 'bi-stack'} me-2"></i>
                <strong>${group.tool?.name || 'Tool'}</strong>
            </div>
            ${group.blocks.map(block => `
                <div class="available-tool-card mb-2" onclick="addToolToPipeline('${block.id}')">
                    <div class="d-flex align-items-center gap-2">
                        <i class="bi ${block.icon} fs-5"></i>
                        <div class="flex-grow-1">
                            <div class="fw-bold d-flex align-items-center gap-1">
                                <span>${block.name}</span>
                                <i class="bi bi-question-circle-fill text-info hint-icon"
                                   title="${window.escapeHtml(block.hint || `Input: ${block.inputTypes.join(', ')} → Output: ${block.outputType}`)}"
                                   data-bs-toggle="tooltip"></i>
                            </div>
                            <small class="text-muted">${block.description}</small>
                            <div class="mt-1">
                                <span class="badge bg-warning" style="font-size: 0.65rem;">
                                    in: ${block.inputTypes.join(', ')}
                                </span>
                                <span class="badge bg-info" style="font-size: 0.65rem;">
                                    out: ${block.outputType}
                                </span>
                            </div>
                        </div>
                        <i class="bi bi-plus-circle text-success fs-4"></i>
                    </div>
                </div>
            `).join('')}
        </div>
    `).join('');

    if (window.bootstrap && bootstrap.Tooltip) {
        container.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => new bootstrap.Tooltip(el));
    }
}

window.addToolToPipeline = function(toolId) {
    const block = findPipelineBlock(toolId);
    if (!block || !pipelineToolEnabled(block.baseTool)) return;
    if (pipelineChain.length === 0 && !pipelineToolCanBeFirst(block.baseTool)) {
        alert('This tool cannot be the first step in the pipeline. Please add another tool before it.');
        return;
    }
    
    pipelineChain.push(block);
    resetPipelineOutput();
    renderPipelineChain();
    renderAvailableTools();
    updateExecuteButton();
};

function renderPipelineChain() {
    const container = document.getElementById('pipelineChain');
    if (!container) return;
    
    if (pipelineChain.length === 0) {
        container.innerHTML = `
            <div class="text-center text-muted py-5">
                <i class="bi bi-stack fs-1"></i>
                <p class="mt-2">No tools in pipeline yet. Add tools from the left panel.</p>
            </div>
        `;
        const compatEmpty = document.getElementById('chainCompatibility');
        if (compatEmpty) {
            compatEmpty.textContent = 'Empty';
            compatEmpty.className = 'badge bg-secondary ms-2';
        }
        const clearBtn = document.getElementById('clearPipelineBtn');
        if (clearBtn) {
            clearBtn.style.display = 'none';
        }
        const chainCount = document.getElementById('chainCount');
        if (chainCount) {
            chainCount.textContent = '';
        }
        const inputInfoEmpty = document.getElementById('inputTypeInfo');
        if (inputInfoEmpty) {
            inputInfoEmpty.style.display = 'none';
        }
        return;
    }
    
 container.innerHTML = pipelineChain.map((tool, index) => `
            <div class="pipeline-tool-card mb-3" data-pipeline-index="${index}">
                <div class="pipeline-tool-header">
                    <div class="d-flex align-items-center gap-2">
                        <span class="pipeline-tool-number">${index + 1}</span>
                        <i class="bi ${tool.icon}"></i>
                        <div class="flex-grow-1">
                            <div class="fw-bold d-flex align-items-center gap-1">
                                <span>${tool.name}</span>
                                <i class="bi bi-question-circle-fill text-info hint-icon"
                                   title="${window.escapeHtml(tool.hint || `Input: ${tool.inputTypes.join(', ')} → Output: ${tool.outputType}`)}"
                                   data-bs-toggle="tooltip"></i>
                            </div>
                            <div class="pipeline-io-badges mt-1">
                                <span class="badge bg-warning badge-io"><i class="bi bi-box-arrow-in-down"></i> ${tool.inputTypes.join(', ') || 'any'}</span>
                                <span class="badge bg-info badge-io"><i class="bi bi-box-arrow-up"></i> ${tool.outputType || 'data'}</span>
                            </div>
                        </div>
                        <div class="btn-group btn-group-sm">
                            ${index === 0 ? '' : `
                                <button class="btn btn-outline-secondary" onclick="moveToolUp(${index})">
                                    <i class="bi bi-arrow-up"></i>
                                </button>
                            `}
                            ${index === pipelineChain.length - 1 ? '' : `
                                <button class="btn btn-outline-secondary" onclick="moveToolDown(${index})">
                                    <i class="bi bi-arrow-down"></i>
                                </button>
                            `}
                            <button class="btn btn-outline-danger" onclick="removeToolFromPipeline(${index})">
                                <i class="bi bi-x"></i>
                            </button>
                        </div>
                </div>
            </div>
            <div class="pipeline-tool-body mt-2" id="pipelineToolBody-${index}"></div>
            <div class="pipeline-tool-output mt-2" id="pipelineToolOutput-${index}"></div>
            ${index < pipelineChain.length - 1 ? '<div class="pipeline-arrow"><i class="bi bi-arrow-down"></i></div>' : ''}
        </div>
    `).join('');
    
    const isCompatible = validatePipelineChain();
    const compat = document.getElementById('chainCompatibility');
    if (compat) {
        compat.textContent = isCompatible ? 'Valid' : 'Invalid';
        compat.className = `badge ${isCompatible ? 'bg-success' : 'bg-danger'} ms-2`;
    }
    const chainCount = document.getElementById('chainCount');
    if (chainCount) {
        chainCount.textContent = `• ${pipelineChain.length} block${pipelineChain.length === 1 ? '' : 's'}`;
    }
    const clearBtn = document.getElementById('clearPipelineBtn');
    if (clearBtn) {
        clearBtn.style.display = pipelineChain.length > 0 ? 'inline-flex' : 'none';
    }
    
    const inputInfo = document.getElementById('inputTypeInfo');
    if (inputInfo) {
        if (pipelineChain.length > 0) {
            inputInfo.textContent = `Expects: ${pipelineChain[0].inputTypes.join(' or ')}`;
            inputInfo.style.display = 'inline-block';
        } else {
            inputInfo.style.display = 'none';
        }
    }

    // Render each tool's UI inside its pipeline card:
    // - First tool: full normal UI (inputs visible)
    // - Subsequent tools: no input UI, only outputs when the pipeline runs
    pipelineChain.forEach((tool, index) => {
        const body = document.getElementById(`pipelineToolBody-${index}`);
        if (!body) return;

        const isFirst = index === 0;
        const renderForm = tool.renderPipelineForm;
        const hasCustomForm = typeof renderForm === 'function' && renderForm !== tool.baseTool?.render && renderForm !== tool.baseTool?.renderPipelineInputs;
        const shouldRenderCustomForm = hasCustomForm && (isFirst || renderForm.alwaysShow);
        const shouldRenderBaseForm = isFirst && !tool.suppressBaseRender && typeof tool.baseTool?.render === 'function';
        const wrapFirstIntro = (html) => {
            if (!isFirst) return html;
            return `
                <div class="pipeline-first-start">
                    <span class="badge bg-success d-inline-flex align-items-center gap-1">
                        <i class="bi bi-play-fill"></i> Pipeline start
                    </span>
                    <small class="text-secondary">Provide the initial input below. Downstream blocks will use this output.</small>
                </div>
                ${html}
            `;
        };

        body.classList.toggle('pipeline-first-body', isFirst);

        // First block shows its own input UI (custom form or the normal tool workspace)
        if (shouldRenderCustomForm) {
            try {
                const rendered = renderForm({ stepIndex: index, mode: 'pipeline' }) || '';
                body.innerHTML = wrapFirstIntro(rendered || `
                    <div class="text-muted small fst-italic d-flex align-items-center gap-2">
                        <i class="bi bi-diagram-3"></i>
                        This step consumes input from the pipeline. When it is first, use this form to provide the initial payload.
                    </div>
                `);
                body.classList.add('pipeline-embed');
                if (typeof tool.initPipeline === 'function') {
                    tool.initPipeline({ mode: 'pipeline', index: index });
                }
            } catch (e) {
                console.error(`Error initializing pipeline UI for tool ${tool.id}:`, e);
                body.innerHTML = `
                    <div class="alert alert-danger mb-0">
                        Failed to render tool UI in pipeline mode: ${window.escapeHtml(e.message)}
                    </div>
                `;
            }
        } else if (shouldRenderBaseForm) {
            try {
                body.innerHTML = wrapFirstIntro(tool.baseTool.render());
                body.classList.add('pipeline-embed');
                if (typeof tool.baseTool.initPipeline === 'function') {
                    tool.baseTool.initPipeline({ mode: 'pipeline', index });
                } else if (typeof tool.baseTool.init === 'function') {
                    tool.baseTool.init();
                }
            } catch (e) {
                console.error(`Error initializing pipeline UI for tool ${tool.id}:`, e);
                body.innerHTML = `
                    <div class="alert alert-danger mb-0">
                        Failed to render tool UI in pipeline mode: ${window.escapeHtml(e.message)}
                    </div>
                `;
            }
        } else {
            body.innerHTML = `
                <div class="text-muted small fst-italic d-flex align-items-center gap-2">
                    <i class="bi bi-stack"></i>
                    ${isFirst
                        ? 'This starting block needs an input UI. Use a block that exposes a form or enable its base UI for pipeline mode.'
                        : 'This step receives input from the previous tool. Its output will appear below after execution.'}
                </div>
            `;
        }

        // Safety net: if the first block still has no input fields, inject a simple text/JSON textarea
        if (isFirst && !body.querySelector('textarea, input[type="text"], input[type="number"]')) {
            const placeholder = `Enter ${tool.inputTypes && tool.inputTypes.length ? tool.inputTypes.join(' / ') : 'input'} for the first block`;
            const isEncoder = tool.baseTool && tool.baseTool.id === 'encoder-decoder';
            const textareaAttrs = isEncoder ? 'data-encoder-input data-default-pipeline-input' : 'data-default-pipeline-input';
            body.innerHTML = wrapFirstIntro(`
                <div class="card bg-dark pipeline-input-card">
                    <div class="card-header d-flex align-items-center gap-2">
                        <i class="bi bi-terminal"></i>
                        <span>Pipeline input</span>
                    </div>
                    <div class="card-body">
                        <textarea class="form-control font-monospace" rows="4" placeholder="${window.escapeHtml(placeholder)}" ${textareaAttrs}></textarea>
                        <small class="text-secondary d-block mt-2">This value seeds the pipeline when no custom form is available.</small>
                    </div>
                </div>
            `);
        }
    });

    if (window.bootstrap && bootstrap.Tooltip) {
        container.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => new bootstrap.Tooltip(el));
    }

}

function validatePipelineChain() {
    for (let i = 0; i < pipelineChain.length - 1; i++) {
        const current = pipelineChain[i];
        const next = pipelineChain[i + 1];
        
        if (!next.inputTypes.includes(current.outputType) && !next.inputTypes.includes('any')) {
            return false;
        }
    }
    return true;
}

function updatePipelineInputVisibility() {
    // No-op: shared pipeline input removed. Per-block UIs handle first-step input.
}

window.moveToolUp = function(index) {
    if (index === 0) return;
    [pipelineChain[index], pipelineChain[index - 1]] = [pipelineChain[index - 1], pipelineChain[index]];
    resetPipelineOutput();
    renderPipelineChain();
    renderAvailableTools();
    updateExecuteButton();
};

window.moveToolDown = function(index) {
    if (index === pipelineChain.length - 1) return;
    [pipelineChain[index], pipelineChain[index + 1]] = [pipelineChain[index + 1], pipelineChain[index]];
    resetPipelineOutput();
    renderPipelineChain();
    renderAvailableTools();
    updateExecuteButton();
};

window.removeToolFromPipeline = function(index) {
    pipelineChain.splice(index, 1);
    resetPipelineOutput();
    renderPipelineChain();
    renderAvailableTools();
    updateExecuteButton();
};

window.clearPipeline = function() {
    pipelineChain = [];
    renderPipelineChain();
    renderAvailableTools();
    updateExecuteButton();
    
    const outputCard = document.getElementById('pipelineOutputCard');
    if (outputCard) {
        outputCard.style.display = 'none';
    }
    const errorsDiv = document.getElementById('pipelineErrors');
    if (errorsDiv) {
        errorsDiv.innerHTML = '';
    }
    const chainCount = document.getElementById('chainCount');
    if (chainCount) {
        chainCount.textContent = '';
    }
    const clearBtn = document.getElementById('clearPipelineBtn');
    if (clearBtn) {
        clearBtn.style.display = 'none';
    }
    resetPipelineOutput();
};

// Home/logo click handler to return to normal mode
document.addEventListener('DOMContentLoaded', () => {
    const homeLogo = document.getElementById('homeLogo');
    if (homeLogo) {
        homeLogo.addEventListener('click', (e) => {
            e.preventDefault();
            switchMode('single');
            window.scrollTo({ top: 0, behavior: 'smooth' });
        });
    }
});

function updateExecuteButton() {
    const btn = document.getElementById('executePipelineBtn');
    if (!btn) return;
    
    btn.style.display = pipelineChain.length === 0 ? 'none' : 'inline-flex';
    btn.disabled = pipelineChain.length === 0 || !validatePipelineChain();
}

function resetPipelineOutput() {
    const outputCard = document.getElementById('pipelineOutputCard');
    const outputDiv = document.getElementById('pipelineOutput');
    const errorsDiv = document.getElementById('pipelineErrors');
    if (outputCard) {
        outputCard.style.display = 'none';
    }
    if (outputDiv) {
        outputDiv.innerHTML = '';
    }
    if (errorsDiv) {
        errorsDiv.innerHTML = '';
    }
}

// ========================================
// PIPELINE EXECUTION
// ========================================

// Render input + output for a single pipeline step inside its tool card (two accordions, raw view)
function renderPipelineStepOutput(stepIndex, tool, result, stepInput) {
    const stepEl = document.getElementById(`pipelineToolOutput-${stepIndex}`);
    if (!stepEl) return '';

    const output = result.output;
    const prettyInput = window.escapeHtml(
        typeof stepInput === 'object'
            ? JSON.stringify(stepInput, null, 2)
            : String(stepInput == null ? '' : stepInput)
    );
    const prettyOutput = window.escapeHtml(
        typeof output === 'object'
            ? JSON.stringify(output, null, 2)
            : String(output == null ? '' : output)
    );

    const accordionInId = `pipelineAccordionIn-${stepIndex}`;
    const collapseInId = `pipelineCollapseIn-${stepIndex}`;
    const accordionOutId = `pipelineAccordionOut-${stepIndex}`;
    const collapseOutId = `pipelineCollapseOut-${stepIndex}`;

    stepEl.innerHTML = `
        <div class="pipeline-tool-output">
            <div class="accordion mb-2 accordion-warning" id="${accordionInId}">
                <div class="accordion-item bg-dark text-light border border-warning">
                    <h2 class="accordion-header" id="${accordionInId}-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#${collapseInId}" aria-expanded="false" aria-controls="${collapseInId}">
                            <div class="d-flex flex-column">
                                <span class="fw-semibold text-warning">Step ${stepIndex + 1} - Input</span>
                                <small class="text-secondary">Raw data received by this block</small>
                            </div>
                        </button>
                    </h2>
                    <div id="${collapseInId}" class="accordion-collapse collapse" data-bs-parent="#${accordionInId}">
                        <div class="accordion-body">
                            <pre class="mb-0"><code>${prettyInput}</code></pre>
                        </div>
                    </div>
                </div>
            </div>
            <div class="accordion accordion-info" id="${accordionOutId}">
                <div class="accordion-item bg-dark text-light border border-info">
                    <h2 class="accordion-header" id="${accordionOutId}-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#${collapseOutId}" aria-expanded="false" aria-controls="${collapseOutId}">
                            <div class="d-flex flex-column">
                                <span class="fw-semibold text-blue">Step ${stepIndex + 1} - Output</span>
                                <small class="text-secondary">Raw output returned by this block</small>
                            </div>
                        </button>
                    </h2>
                    <div id="${collapseOutId}" class="accordion-collapse collapse" data-bs-parent="#${accordionOutId}">
                        <div class="accordion-body">
                            <pre class="mb-0"><code>${prettyOutput}</code></pre>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    if (window.bootstrap && bootstrap.Collapse) {
        const collapseIn = document.getElementById(collapseInId);
        if (collapseIn) new bootstrap.Collapse(collapseIn, { toggle: false });
        const collapseOut = document.getElementById(collapseOutId);
        if (collapseOut) new bootstrap.Collapse(collapseOut, { toggle: false });
    }

    return prettyOutput;
}

window.executePipeline = async function() {
    const outputCard = document.getElementById('pipelineOutputCard');
    const outputDiv = document.getElementById('pipelineOutput');
    const errorsDiv = document.getElementById('pipelineErrors');
    const runBtn = document.getElementById('executePipelineBtn');
    
    if (!outputCard || !outputDiv || !errorsDiv) {
        console.warn('Pipeline UI elements not found, aborting pipeline execution');
        return;
    }
    
    errorsDiv.innerHTML = '';
    if (outputDiv) {
        outputDiv.innerHTML = `
            <div class="d-flex align-items-center gap-2 text-secondary pipeline-loader">
                <div class="spinner-border spinner-border-sm text-success" role="status"></div>
                <span>Warming up the pipeline engine...</span>
            </div>
        `;
    }
    if (outputCard) {
        outputCard.style.display = 'block';
    }
    
    if (!validatePipelineChain()) {
        errorsDiv.innerHTML = '<div class="alert alert-danger mt-3">Pipeline chain is invalid. Check tool compatibility.</div>';
        return;
    }
    
    try {
        if (runBtn) {
            runBtn.classList.add('running');
            runBtn.disabled = true;
        }
        let currentData = '';
        const results = [];
        let lastStepResult = null;
        let lastTool = null;
        
        for (let i = 0; i < pipelineChain.length; i++) {
            const tool = pipelineChain[i];
            console.log(`Executing tool ${i + 1}/${pipelineChain.length}: ${tool.name}`);

            if (i === 0 && (currentData === '' || currentData == null)) {
                const fallbackInput = document.querySelector(`#pipelineToolBody-${i} [data-default-pipeline-input]`);
                if (fallbackInput && typeof fallbackInput.value === 'string' && fallbackInput.value.trim().length > 0) {
                    currentData = fallbackInput.value.trim();
                }
            }
            const stepInput = currentData;
            
            const result = await tool.processPipeline(currentData, {
                isFirst: i === 0,
                stepIndex: i,
                totalSteps: pipelineChain.length,
                pipelineInput: currentData,
                previousOutput: currentData
            });
            if (!result || !result.success) {
                throw new Error(result && result.error ? result.error : `Tool "${tool.name}" failed`);
            }
            
            currentData = result.output;
            const stepResult = {
                output: result.output,
                metadata: result.metadata || {}
            };
            results.push({
                tool: tool.name,
                ...stepResult
            });
            lastStepResult = stepResult;
            lastTool = tool;
            
            // Render this step's output inside its own tool box (collapsed accordion)
            renderPipelineStepOutput(i, tool, stepResult, stepInput);
        }
        
        // Render final summary and final output
        outputCard.style.display = 'block';
        await new Promise(resolve => setTimeout(resolve, 600));
        let finalHtml = '';
        if (lastTool && typeof lastTool.renderPipelineOutput === 'function' && lastStepResult) {
            try {
                const rendered = lastTool.renderPipelineOutput({
                    stepIndex: pipelineChain.length - 1,
                    output: lastStepResult.output,
                    metadata: lastStepResult.metadata || {},
                    mode: 'pipeline'
                });
                if (typeof rendered === 'string' && rendered.trim().length > 0) {
                    finalHtml = rendered;
                }
            } catch (e) {
                console.error(`Error rendering final pipeline output via tool ${lastTool.id}:`, e);
            }
        }

        if (!finalHtml) {
            const pretty = window.escapeHtml(
                typeof currentData === 'object'
                    ? JSON.stringify(currentData, null, 2)
                    : String(currentData)
            );
            finalHtml = `<pre class="mb-0"><code>${pretty}</code></pre>`;
        }

        outputDiv.innerHTML = `
            <div class="mb-3">
                <h6>Pipeline executed successfully!</h6>
                <p class="text-muted small">Processed through ${pipelineChain.length} tool(s)</p>
            </div>
            
                <div id="finalOutput">${finalHtml}</div>
        `;
        
        outputCard.scrollIntoView({ behavior: 'smooth' });
    } catch (error) {
        errorsDiv.innerHTML = `
            <div class="alert alert-danger mt-3">
                <strong>Pipeline Error:</strong> ${window.escapeHtml(error.message)}
            </div>
        `;
    } finally {
        if (runBtn) {
            runBtn.classList.remove('running');
            runBtn.disabled = pipelineChain.length === 0 || !validatePipelineChain();
        }
    }
};

window.copyPipelineOutput = function() {
    const finalOutput = document.getElementById('finalOutput');
    if (!finalOutput) return;
    
    const text = finalOutput.textContent || finalOutput.innerText || '';
    navigator.clipboard.writeText(text).then(() => {
        alert('Output copied to clipboard!');
    }).catch(err => {
        console.error('Failed to copy output:', err);
        alert('Failed to copy output to clipboard');
    });
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
// CATEGORY FILTERS & SEARCH
// ========================================

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
    
    const workspace = document.getElementById('workspace');
    try {
        workspace.innerHTML = `
            <div class="row mt-4">
                <div class="col-12">
                    <div class="card tool-workspace ${borderClass}">
                        ${
                            pipelineToolEnabled(tool) && pipelineToolCanBeFirst(tool)
                                ? `<button class="btn btn-sm btn-outline-success pipeline-add-btn pipeline-add-btn-workspace" onclick="addToolAsFirst('${tool.id}')" title="Add to pipeline">
                                        <i class="bi bi-stack"></i>
                                        <span>Add to pipeline</span>
                                   </button>`
                                : ''
                        }
                        <div class="card-body">
                            ${tool.render()}
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        tool.init();
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

function setupCategoryFilters() {
    const buttons = document.querySelectorAll('[data-category-filter]');
    const allButton = document.querySelector('[data-category-filter="all"]');
    
    buttons.forEach(button => {
        button.addEventListener('click', function() {
            const category = this.getAttribute('data-category-filter');
            currentCategory = category;
            
            buttons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
            
            filterToolsByCategory(category);
        });
    });
    
    if (allButton) {
        allButton.classList.add('active');
    }
}

function setupSearch() {
    const searchInput = document.getElementById('toolSearch');
    const clearButton = document.getElementById('clearSearch');
    const searchResults = document.getElementById('searchResults');
    
    if (!searchInput || !clearButton || !searchResults) return;

    searchInput.addEventListener('input', function() {
        const query = this.value.toLowerCase().trim();
        performSearch(query);
    });
    
    clearButton.addEventListener('click', function() {
        searchInput.value = '';
        performSearch('');
        searchInput.focus();
    });
    
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
        if (currentCategory === 'all') {
            document.querySelectorAll('.tools-section').forEach(section => {
                section.classList.remove('d-none');
            });
        } else {
            filterToolsByCategory(currentCategory);
        }
        
        allCards.forEach(card => {
            const wrapper = card.parentElement;
            if (wrapper) {
                wrapper.classList.remove('d-none');
            }
        });
        
        searchResults.textContent = '';
        return;
    }

    document.querySelectorAll('.tools-section').forEach(section => {
        section.classList.remove('d-none');
    });

    allCards.forEach(card => {
        const wrapper = card.parentElement;
        const name = (card.getAttribute('data-tool-name') || '').toLowerCase();
        const desc = (card.getAttribute('data-tool-desc') || '').toLowerCase();
        
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

function setupScrollButton() {
    const scrollToTopBtn = document.getElementById('scrollToTopBtn');
    
    if (scrollToTopBtn) {
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
    }
}

// ========================================
// UTILITY FUNCTIONS
// ========================================

window.copyToClipboard = function(text, triggerElement) {
    if (!navigator.clipboard) {
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

    navigator.clipboard.writeText(text).then(() => {
        showCopyFeedback(triggerElement);
    }).catch(err => {
        console.error('Async: Could not copy text: ', err);
    });
};

function showCopyFeedback(triggerElement) {
    if (!triggerElement) {
        console.log('Copied to clipboard');
        return;
    }

    const originalText = triggerElement.innerHTML;
    triggerElement.innerHTML = '<i class="bi bi-clipboard-check"></i>';
    triggerElement.classList.add('text-success');

    setTimeout(() => {
        triggerElement.innerHTML = originalText;
        triggerElement.classList.remove('text-success');
    }, 1000);
}

window.downloadFile = function(filename, content) {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
};

window.escapeHtml = function(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
};

// ========================================
// INITIALIZATION
// ========================================

function renderToolsSections() {
    const sectionsContainer = document.getElementById('toolsSections');
    if (!sectionsContainer) return;
    
    sectionsContainer.innerHTML = '';

    const toolsByCategory = {
        red: window.CYBERSUITE_TOOLS.filter(t => t.category === 'red').sort((a, b) => a.name.localeCompare(b.name)),
        blue: window.CYBERSUITE_TOOLS.filter(t => t.category === 'blue').sort((a, b) => a.name.localeCompare(b.name)),
        purple: window.CYBERSUITE_TOOLS.filter(t => t.category === 'purple').sort((a, b) => a.name.localeCompare(b.name))
    };

    const categoryInfo = {
        red: { name: 'Red Team Tools', icon: 'bi-crosshair', color: 'danger', class: 'red-team' },
        blue: { name: 'Blue Team Tools', icon: 'bi-shield-fill', color: 'blue', class: 'blue-team' },
        purple: { name: 'Purple Team Tools', icon: 'bi-layers-fill', color: 'purple', class: 'purple-team' }
    };

    for (const [category, tools] of Object.entries(toolsByCategory)) {
        if (tools.length === 0) continue;

        const info = categoryInfo[category];
        const section = document.createElement('div');
        section.className = 'row mb-5 tools-section';
        section.setAttribute('data-category', category);

        section.innerHTML = `
            <div class="col-12">
                <div class="section-header ${info.class}">
                    <h3 class="text-${info.color}">
                        <i class="bi ${info.icon}"></i> ${info.name}
                    </h3>
                </div>
                <div class="row g-3" id="grid-${category}"></div>
            </div>
        `;

        sectionsContainer.appendChild(section);

        const grid = section.querySelector(`#grid-${category}`);
        tools.forEach(tool => {
            const card = document.createElement('div');
            card.className = 'col-12 col-sm-6 col-md-4 col-lg-3 col-xl-2';
            const pipelineBadge = pipelineToolEnabled(tool)
                ? '<span class="pipeline-support" title="Supports pipeline mode"><i class="bi bi-stack"></i></span>'
                : '';
            card.innerHTML = `
                <div class="card tool-card ${info.class} h-100" data-tool-id="${tool.id}" data-tool-name="${tool.name.toLowerCase()}">
                    ${pipelineBadge}
                    <div class="card-body">
                        <h6 class="card-title mb-2">
                            <i class="bi ${tool.icon}"></i> ${tool.name}
                        </h6>
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

function initApp() {
    console.log('☕ CyberSuite initializing...');
    console.log(`📦 Loaded ${window.CYBERSUITE_TOOLS.length} tools`);
    
    renderToolsSections();
    setupCategoryFilters();
    setupSearch();
    setupScrollButton();
    
    console.log('✓ CyberSuite ready!');
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        loadAllTools();
    });
} else {
    loadAllTools();
}

// Allow adding a tool directly as first pipeline step from normal mode
window.addToolAsFirst = function(toolId) {
    const tool = window.CYBERSUITE_TOOLS.find(t => t.id === toolId);
    if (!tool || !pipelineToolEnabled(tool)) return;
    if (!pipelineToolCanBeFirst(tool)) {
        alert('This tool cannot be the first step in the pipeline. Add another tool before it.');
        return;
    }

    const block = (tool.__pipelineBlocks && tool.__pipelineBlocks[0]) ? tool.__pipelineBlocks[0] : null;
    if (!block) return;

    switchMode('pipeline');

    // Remove existing instance if present
    pipelineChain = pipelineChain.filter(t => t.baseTool?.id !== tool.id);
    pipelineChain.unshift(block);

    renderPipelineChain();
    renderAvailableTools();
    updateExecuteButton();

    const pipelineSection = document.getElementById('pipelineMode');
    if (pipelineSection) {
        pipelineSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
};
