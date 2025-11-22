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
    'beautifier'
]);
const pipelineToolEnabled = tool => tool && pipelineEnabledToolIds.has(tool.id);
// Some tools should not start the chain (e.g., Beautifier expects upstream data)
const pipelineDisallowFirst = new Set(['beautifier']);
const pipelineToolCanBeFirst = tool => tool && !pipelineDisallowFirst.has(tool.id);

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

    if (!Array.isArray(toolConfig.inputTypes)) {
        if (typeof toolConfig.inputTypes === 'string' && toolConfig.inputTypes.trim() !== '') {
            toolConfig.inputTypes = [toolConfig.inputTypes.trim()];
        } else if (toolConfig.inputTypes == null) {
            toolConfig.inputTypes = [];
        } else {
            // Fallback: coerce non-array, non-string inputTypes into an array
            toolConfig.inputTypes = [String(toolConfig.inputTypes)];
        }
    }

    if (typeof toolConfig.outputType !== 'string' || !toolConfig.outputType.trim()) {
        toolConfig.outputType = 'json';
    }
    
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
    if (!toolConfig.inputTypes) toolConfig.inputTypes = ['text'];
    if (!toolConfig.outputType) toolConfig.outputType = 'text';
    if (!toolConfig.processPipeline) {
        toolConfig.processPipeline = async (input) => ({ success: false, error: 'Pipeline not supported' });
    }
    
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
        pipelineToggle.innerHTML = isPipeline
            ? '<i class="bi bi-stack"></i> Normal mode'
            : '<i class="bi bi-stack"></i> Pipeline Mode (Beta)';
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
        }
    }
};

// ========================================
// PIPELINE MANAGEMENT
// ========================================

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
    
    const availableTools = window.CYBERSUITE_TOOLS.filter(tool => {
        // Pipeline beta exposes only a small subset of tools
        if (!pipelineToolEnabled(tool)) return false;

        // Search filter
        if (query) {
            const nameMatch = (tool.name || '').toLowerCase().includes(queryLower);
            const descMatch = (tool.description || '').toLowerCase().includes(queryLower);
            if (!nameMatch && !descMatch) return false;
        }

        // Tool already in chain
        if (pipelineChain.find(t => t.id === tool.id)) return false;
        
        // If chain is empty, all tools available
        if (!lastTool) return pipelineToolCanBeFirst(tool);
        
        // Check if tool accepts output from last tool
        return tool.inputTypes.includes(expectedInputType) || tool.inputTypes.includes('any');
    });
    
    if (availableTools.length === 0) {
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
    
    container.innerHTML = availableTools.map(tool => `
        <div class="available-tool-card" onclick="addToolToPipeline('${tool.id}')">
            <div class="d-flex align-items-center gap-2">
                <i class="bi ${tool.icon} fs-5"></i>
                <div class="flex-grow-1">
                    <div class="fw-bold">${tool.name}</div>
                    <small class="text-muted">${tool.description}</small>
                    <div class="mt-1">
                        <span class="badge bg-secondary" style="font-size: 0.65rem;">
                            in: ${tool.inputTypes.join(', ')}
                        </span>
                        <span class="badge bg-info" style="font-size: 0.65rem;">
                            out: ${tool.outputType}
                        </span>
                    </div>
                </div>
                <i class="bi bi-plus-circle text-success fs-4"></i>
            </div>
        </div>
    `).join('');
}

window.addToolToPipeline = function(toolId) {
    const tool = window.CYBERSUITE_TOOLS.find(t => t.id === toolId);
    if (!tool || !pipelineToolEnabled(tool)) return;
    if (pipelineChain.length === 0 && !pipelineToolCanBeFirst(tool)) {
        alert('This tool cannot be the first step in the pipeline. Please add another tool before it.');
        return;
    }
    
    pipelineChain.push(tool);
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
                <i class="bi bi-diagram-3 fs-1"></i>
                <p class="mt-2">No tools in pipeline yet. Add tools from the left panel.</p>
            </div>
        `;
        const compatEmpty = document.getElementById('chainCompatibility');
        if (compatEmpty) {
            compatEmpty.textContent = 'Empty';
            compatEmpty.className = 'badge bg-secondary ms-2';
        }
        const inputInfoEmpty = document.getElementById('inputTypeInfo');
        if (inputInfoEmpty) {
            inputInfoEmpty.style.display = 'none';
        }
        return;
    }
    
 container.innerHTML = pipelineChain.map((tool, index) => `
            <div class="pipeline-tool-card" data-pipeline-index="${index}">
                <div class="pipeline-tool-header">
                    <div class="d-flex align-items-center gap-2">
                        <span class="pipeline-tool-number">${index + 1}</span>
                        <i class="bi ${tool.icon}"></i>
                        <div class="flex-grow-1">
                            <div class="fw-bold">${tool.name}</div>
                            <div class="pipeline-io-badges mt-1">
                                <span class="badge bg-secondary badge-io"><i class="bi bi-box-arrow-in-down"></i> ${tool.inputTypes.join(', ') || 'any'}</span>
                                <span class="badge bg-info badge-io"><i class="bi bi-box-arrow-up"></i> ${tool.outputType || 'data'}</span>
                            </div>
                        </div>
                        <div class="btn-group btn-group-sm">
                            <button class="btn btn-outline-secondary" onclick="moveToolUp(${index})" ${index === 0 ? 'disabled' : ''}>
                                <i class="bi bi-arrow-up"></i>
                            </button>
                        <button class="btn btn-outline-secondary" onclick="moveToolDown(${index})" ${index === pipelineChain.length - 1 ? 'disabled' : ''}>
                            <i class="bi bi-arrow-down"></i>
                        </button>
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

        // Only the first tool in the chain exposes its full input UI
        if (index === 0) {
            try {
                body.innerHTML = tool.render();
                body.classList.add('pipeline-embed');
                if (typeof tool.initPipeline === 'function') {
                    // Optional: tools can define a specialized init for pipeline mode
                    tool.initPipeline({ mode: 'pipeline', index });
                } else if (typeof tool.init === 'function') {
                    tool.init();
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
            // For all other tools, do not render their input UI; they will only
            // display their outputs in the pipelineToolOutput area after execution.
            body.innerHTML = `
                <div class="text-muted small fst-italic">
                    This step receives input from the previous tool. Its output will appear here after the pipeline is executed.
                </div>
            `;
        }
    });
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

window.moveToolUp = function(index) {
    if (index === 0) return;
    [pipelineChain[index], pipelineChain[index - 1]] = [pipelineChain[index - 1], pipelineChain[index]];
    renderPipelineChain();
    renderAvailableTools();
    updateExecuteButton();
};

window.moveToolDown = function(index) {
    if (index === pipelineChain.length - 1) return;
    [pipelineChain[index], pipelineChain[index + 1]] = [pipelineChain[index + 1], pipelineChain[index]];
    renderPipelineChain();
    renderAvailableTools();
    updateExecuteButton();
};

window.removeToolFromPipeline = function(index) {
    pipelineChain.splice(index, 1);
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
};

function updateExecuteButton() {
    const btn = document.getElementById('executePipelineBtn');
    if (!btn) return;
    
    btn.style.display = pipelineChain.length === 0 ? 'none' : 'inline-flex';
    btn.disabled = pipelineChain.length === 0 || !validatePipelineChain();
}

// ========================================
// PIPELINE EXECUTION
// ========================================

// Render output for a single pipeline step inside its tool card
function renderPipelineStepOutput(stepIndex, tool, result) {
    const stepEl = document.getElementById(`pipelineToolOutput-${stepIndex}`);
    if (!stepEl) return;

    const output = result.output;
    const metadata = result.metadata || {};

    // If the tool provides its own pipeline output renderer, delegate to it.
    // The tool can return a full HTML snippet consistent with its normal mode UI.
    if (tool && typeof tool.renderPipelineOutput === 'function') {
        try {
            const html = tool.renderPipelineOutput({
                stepIndex,
                output,
                metadata,
                mode: 'pipeline'
            });

            if (typeof html === 'string' && html.trim().length > 0) {
                stepEl.innerHTML = html;
                return;
            }
        } catch (e) {
            console.error(`Error in renderPipelineOutput for tool ${tool.id}:`, e);
            // fall through to generic rendering
        }
    }

    // Generic fallback if the tool has no custom renderer:
    stepEl.innerHTML = `
        <div class="card bg-dark border-secondary">
            <div class="card-header py-1">
                <small>Step ${stepIndex + 1} output</small>
            </div>
            <div class="card-body">
                <pre class="mb-0"><code>${
                    window.escapeHtml(
                        typeof output === 'object'
                            ? JSON.stringify(output, null, 2)
                            : String(output)
                    )
                }</code></pre>
                ${
                    metadata && metadata.treeHtml
                        ? `
                            <hr class="text-secondary" />
                            <div class="beautifier-tree-view mt-2">
                                ${metadata.treeHtml}
                            </div>
                          `
                        : ''
                }
                ${
                    metadata && metadata.html
                        ? `
                            <hr class="text-secondary" />
                            <div class="pipeline-tool-html mt-2">
                                ${metadata.html}
                            </div>
                          `
                        : ''
                }
            </div>
        </div>
    `;
}

window.executePipeline = async function() {
    const inputEl = document.getElementById('pipelineInput');
    const outputCard = document.getElementById('pipelineOutputCard');
    const outputDiv = document.getElementById('pipelineOutput');
    const errorsDiv = document.getElementById('pipelineErrors');
    
    if (!outputCard || !outputDiv || !errorsDiv) {
        console.warn('Pipeline UI elements not found, aborting pipeline execution');
        return;
    }
    
    // Initial pipeline input can come from a dedicated field if present,
    // but it is no longer required; tools can also read from their own UI.
    const input = inputEl ? inputEl.value.trim() : '';
    errorsDiv.innerHTML = '';
    
    if (!validatePipelineChain()) {
        errorsDiv.innerHTML = '<div class="alert alert-danger mt-3">Pipeline chain is invalid. Check tool compatibility.</div>';
        return;
    }
    
    try {
        let currentData = input;
        const results = [];
        
        for (let i = 0; i < pipelineChain.length; i++) {
            const tool = pipelineChain[i];
            console.log(`Executing tool ${i + 1}/${pipelineChain.length}: ${tool.name}`);
            
            const result = await tool.processPipeline(currentData, {
                isFirst: i === 0,
                stepIndex: i,
                totalSteps: pipelineChain.length,
                pipelineInput: input,
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
            
            // Render this step's output inside its own tool box
            renderPipelineStepOutput(i, tool, stepResult);
        }
        
        // Render final summary and final output
        outputCard.style.display = 'block';
        const lastStepEl = document.getElementById(`pipelineToolOutput-${pipelineChain.length - 1}`);
        let finalHtml = lastStepEl ? lastStepEl.innerHTML : '';
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
            <div class="card bg-dark border-success">
                <div class="card-header bg-success">
                    <strong>Final Output</strong>
                </div>
                <div class="card-body">
                    <div id="finalOutput">${finalHtml}</div>
                </div>
            </div>
        `;
        
        outputCard.scrollIntoView({ behavior: 'smooth' });
    } catch (error) {
        errorsDiv.innerHTML = `
            <div class="alert alert-danger mt-3">
                <strong>Pipeline Error:</strong> ${window.escapeHtml(error.message)}
            </div>
        `;
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
                                ? `<button class="btn btn-sm btn-outline-success pipeline-add-btn pipeline-add-btn-workspace" onclick="addToolAsFirst('${tool.id}')" title="Add to a pipeline">
                                        <i class="bi bi-stack"></i>
                                        <span>Add to a pipeline</span>
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

    switchMode('pipeline');

    // Remove existing instance if present
    pipelineChain = pipelineChain.filter(t => t.id !== tool.id);
    pipelineChain.unshift(tool);

    renderPipelineChain();
    renderAvailableTools();
    updateExecuteButton();

    const pipelineSection = document.getElementById('pipelineMode');
    if (pipelineSection) {
        pipelineSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
};
