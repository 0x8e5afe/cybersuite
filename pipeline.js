// =====================
// CYBERSUITE - PIPELINE EDITION
// =====================

// Tool registry
window.CYBERSUITE_TOOLS = window.CYBERSUITE_TOOLS || [];

// Pipeline state
let pipelineChain = [];
let currentMode = 'single';
let activeToolId = null;

// ========================================
// TOOL REGISTRATION SYSTEM (ENHANCED)
// ========================================

window.registerCyberSuiteTool = function(toolConfig) {
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
    
    // Set default pipeline properties if not provided
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
    
    document.querySelectorAll('.mode-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelector(`[data-mode="${mode}"]`).classList.add('active');
    
    if (mode === 'single') {
        document.getElementById('singleToolMode').style.display = 'block';
        document.getElementById('pipelineMode').style.display = 'none';
    } else {
        document.getElementById('singleToolMode').style.display = 'none';
        document.getElementById('pipelineMode').style.display = 'block';
        renderAvailableTools();
    }
};

// ========================================
// PIPELINE MANAGEMENT
// ========================================

function renderAvailableTools() {
    const container = document.getElementById('availableTools');
    if (!container) return;
    
    const lastTool = pipelineChain.length > 0 ? pipelineChain[pipelineChain.length - 1] : null;
    const expectedInputType = lastTool ? lastTool.outputType : null;
    
    const availableTools = window.CYBERSUITE_TOOLS.filter(tool => {
        // Tool already in chain
        if (pipelineChain.find(t => t.id === tool.id)) return false;
        
        // If chain is empty, all tools available
        if (!lastTool) return true;
        
        // Check if tool accepts output from last tool
        return tool.inputTypes.includes(expectedInputType) || tool.inputTypes.includes('any');
    });
    
    if (availableTools.length === 0) {
        container.innerHTML = `
            <div class="alert alert-warning mb-0">
                <small>No compatible tools available. Current chain expects output type: <strong>${expectedInputType || 'any'}</strong></small>
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
    if (!tool) return;
    
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
        document.getElementById('chainCompatibility').textContent = 'Empty';
        document.getElementById('chainCompatibility').className = 'badge bg-secondary ms-2';
        return;
    }
    
    container.innerHTML = pipelineChain.map((tool, index) => `
        <div class="pipeline-tool-card">
            <div class="pipeline-tool-header">
                <div class="d-flex align-items-center gap-2">
                    <span class="pipeline-tool-number">${index + 1}</span>
                    <i class="bi ${tool.icon}"></i>
                    <div class="flex-grow-1">
                        <div class="fw-bold">${tool.name}</div>
                        <small class="text-muted">${tool.inputTypes.join(', ')} → ${tool.outputType}</small>
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
            ${index < pipelineChain.length - 1 ? '<div class="pipeline-arrow"><i class="bi bi-arrow-down"></i></div>' : ''}
        </div>
    `).join('');
    
    // Check chain compatibility
    const isCompatible = validatePipelineChain();
    document.getElementById('chainCompatibility').textContent = isCompatible ? 'Valid' : 'Invalid';
    document.getElementById('chainCompatibility').className = `badge ${isCompatible ? 'bg-success' : 'bg-danger'} ms-2`;
    
    // Update input type info
    const inputTypeInfo = document.getElementById('inputTypeInfo');
    if (pipelineChain.length > 0) {
        inputTypeInfo.textContent = `Expects: ${pipelineChain[0].inputTypes.join(' or ')}`;
        inputTypeInfo.style.display = 'inline-block';
    } else {
        inputTypeInfo.style.display = 'none';
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
    document.getElementById('pipelineOutputCard').style.display = 'none';
    document.getElementById('pipelineErrors').innerHTML = '';
};

function updateExecuteButton() {
    const btn = document.getElementById('executePipelineBtn');
    if (!btn) return;
    
    btn.disabled = pipelineChain.length === 0 || !validatePipelineChain();
}

// ========================================
// PIPELINE EXECUTION
// ========================================

window.executePipeline = async function() {
    const input = document.getElementById('pipelineInput').value.trim();
    const outputCard = document.getElementById('pipelineOutputCard');
    const outputDiv = document.getElementById('pipelineOutput');
    const errorsDiv = document.getElementById('pipelineErrors');
    
    errorsDiv.innerHTML = '';
    
    if (!input) {
        errorsDiv.innerHTML = '<div class="alert alert-warning mt-3">Please provide input data</div>';
        return;
    }
    
    if (!validatePipelineChain()) {
        errorsDiv.innerHTML = '<div class="alert alert-danger mt-3">Pipeline chain is invalid. Check tool compatibility.</div>';
        return;
    }
    
    try {
        let currentData = input;
        let results = [];
        
        for (let i = 0; i < pipelineChain.length; i++) {
            const tool = pipelineChain[i];
            
            console.log(`Executing tool ${i + 1}/${pipelineChain.length}: ${tool.name}`);
            
            const result = await tool.processPipeline(currentData);
            
            if (!result.success) {
                throw new Error(`Tool "${tool.name}" failed: ${result.error}`);
            }
            
            results.push({
                tool: tool.name,
                output: result.output,
                metadata: result.metadata || {}
            });
            
            currentData = result.output;
        }
        
        // Display results
        outputCard.style.display = 'block';
        outputDiv.innerHTML = `
            <div class="mb-3">
                <h6>Pipeline executed successfully!</h6>
                <p class="text-muted small">Processed through ${pipelineChain.length} tool(s)</p>
            </div>
            ${results.map((r, i) => `
                <div class="card bg-dark mb-2">
                    <div class="card-header">
                        <small>Step ${i + 1}: ${window.escapeHtml(r.tool)}</small>
                    </div>
                    <div class="card-body">
                        <pre class="mb-0"><code>${window.escapeHtml(typeof r.output === 'object' ? JSON.stringify(r.output, null, 2) : r.output)}</code></pre>
                    </div>
                </div>
            `).join('')}
            <div class="card bg-dark border-success">
                <div class="card-header bg-success">
                    <strong>Final Output</strong>
                </div>
                <div class="card-body">
                    <pre class="mb-0" id="finalOutput"><code>${window.escapeHtml(typeof currentData === 'object' ? JSON.stringify(currentData, null, 2) : currentData)}</code></pre>
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
    
    navigator.clipboard.writeText(finalOutput.textContent).then(() => {
        alert('Output copied to clipboard!');
    });
};

// ========================================
// SINGLE TOOL MODE (EXISTING FUNCTIONALITY)
// ========================================

function loadAllTools() {
    const toolFiles = [
        'tools/jwt-tool.js',
        'tools/beautifier-tool.js'
    ];

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

function initApp() {
    console.log('☕ CyberSuite initializing...');
    console.log(`📦 Loaded ${window.CYBERSUITE_TOOLS.length} tools`);
    
    renderToolsSections();
    setupSearch();
    setupScrollButton();
    
    console.log('✓ CyberSuite ready!');
}

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
            card.innerHTML = `
                <div class="card tool-card ${info.class} h-100" data-tool-id="${tool.id}" data-tool-name="${tool.name.toLowerCase()}">
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

function loadTool(toolId) {
    const tool = window.CYBERSUITE_TOOLS.find(t => t.id === toolId);
    if (!tool) return;
    
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
        case 'red': borderClass = 'border-red'; break;
        case 'blue': borderClass = 'border-blue'; break;
        case 'purple': borderClass = 'border-purple'; break;
    }
    
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

function setupSearch() {
    const searchInput = document.getElementById('toolSearch');
    const clearButton = document.getElementById('clearSearch');
    
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            const query = this.value.toLowerCase().trim();
            performSearch(query);
        });
    }
    
    if (clearButton) {
        clearButton.addEventListener('click', function() {
            searchInput.value = '';
            performSearch('');
            searchInput.focus();
        });
    }
}

function performSearch(query) {
    const allCards = document.querySelectorAll('.tool-card');
    const searchResults = document.getElementById('searchResults');
    let visibleCount = 0;
    
    if (!query) {
        document.querySelectorAll('.tools-section').forEach(section => {
            section.classList.remove('d-none');
        });
        
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
        const name = card.getAttribute('data-tool-name') || '';
        
        if (name.includes(query)) {
            if (wrapper) wrapper.classList.remove('d-none');
            visibleCount++;
        } else {
            if (wrapper) wrapper.classList.add('d-none');
        }
    });

    if (visibleCount === 0) {
        searchResults.textContent = 'No tools match your search.';
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
            if (triggerElement) showCopyFeedback(triggerElement);
        } catch (err) {
            console.error('Fallback: Oops, unable to copy', err);
        }
        
        document.body.removeChild(textarea);
        return;
    }

    navigator.clipboard.writeText(text)
        .then(() => {
            if (triggerElement) showCopyFeedback(triggerElement);
        })
        .catch(err => console.error('Async: Could not copy text: ', err));
};

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

window.downloadFile = function(filename, content, mimeType = 'text/plain') {
    const blob = new Blob([content], { type: mimeType });
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

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        loadAllTools();
    });
} else {
    loadAllTools();
}