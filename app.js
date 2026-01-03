const resources = window.CYBER_RESOURCES || [];
const COUNTER_BASE_URL = 'https://countapi.mileshilliard.com/api/v1';
const TYPE_ICONS = window.CYBER_TYPE_ICONS || {
    tool: 'fa-screwdriver-wrench'
};
const SEARCH_MIN_CHARS = 3;
const EMPTY_STATE_DEFAULT_MESSAGE = 'No resources found.';

resources.forEach((item) => {
    const name = (item.name || '').toLowerCase();
    const desc = (item.desc || '').toLowerCase();
    const details = (item.details || '').toLowerCase();
    const tags = Array.isArray(item.tags)
        ? item.tags.join(' ').toLowerCase()
        : '';
    item._searchText = `${name}\n${desc}\n${details}\n${tags}`;
});


let currentFilter = 'all';
let pinned = JSON.parse(localStorage.getItem('cybersuitePins')) || [];
let liked = [];
const likeCounts = {};

const elements = {
    grid: document.getElementById('gridContainer'),
    emptyState: document.getElementById('emptyState'),
    emptyStateMessage: document.getElementById('emptyStateMessage'),
    searchInput: document.getElementById('searchInput'),
    filterNav: document.getElementById('filterNav'),
    detailsModal: document.getElementById('detailsModal'),
    detailsContent: document.getElementById('detailsContent'),
    detailsTitle: document.getElementById('detailsTitle'),
    requestModal: document.getElementById('requestModal'),
    requestButton: document.getElementById('requestToolBtn'),
    requestForm: document.getElementById('requestForm'),
    requestWebsite: document.getElementById('requestWebsite'),
    requestSource: document.getElementById('requestSource'),
    confettiContainer: document.getElementById('confettiContainer'),
    resourceCountValue: document.getElementById('resourceCountValue'),
    scrollTopBtn: document.getElementById('scrollTopBtn'),
    loadMoreSentinel: document.getElementById('loadMoreSentinel')
};

let typingTimer = null;
const typingState = { index: 0, char: 0, deleting: false, paused: false };
let isSubmittingRequest = false;
let renderToken = 0;
let cardObserver = null;
let loadMoreObserver = null;
let renderCursor = 0;
let renderList = [];

function escapeHtml(value) {
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function renderMarkdown(md) {
    if (!md) return '';
    const codeBlocks = [];
    let working = md.replace(/```([\s\S]*?)```/g, (match, code) => {
        const token = `@@CODEBLOCK_${codeBlocks.length}@@`;
        codeBlocks.push(code);
        return token;
    });

    working = escapeHtml(working);
    const lines = working.split('\n');
    let html = '';
    let inList = false;

    const applyInline = (text) => {
        let out = text;
        out = out.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
        out = out.replace(/\*(.+?)\*/g, '<em>$1</em>');
        out = out.replace(/`([^`]+)`/g, '<code>$1</code>');
        out = out.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
        return out;
    };

    lines.forEach((line) => {
        const trimmed = line.trim();
        if (trimmed.startsWith('@@CODEBLOCK_')) {
            if (inList) {
                html += '</ul>';
                inList = false;
            }
            html += trimmed;
            return;
        }

        if (trimmed.startsWith('### ')) {
            if (inList) {
                html += '</ul>';
                inList = false;
            }
            html += `<h3>${applyInline(trimmed.replace(/^###\s+/, ''))}</h3>`;
            return;
        }
        if (trimmed.startsWith('## ')) {
            if (inList) {
                html += '</ul>';
                inList = false;
            }
            html += `<h2>${applyInline(trimmed.replace(/^##\s+/, ''))}</h2>`;
            return;
        }
        if (trimmed.startsWith('# ')) {
            if (inList) {
                html += '</ul>';
                inList = false;
            }
            html += `<h1>${applyInline(trimmed.replace(/^#\s+/, ''))}</h1>`;
            return;
        }

        if (/^[-*]\s+/.test(trimmed)) {
            if (!inList) {
                html += '<ul>';
                inList = true;
            }
            html += `<li>${applyInline(trimmed.replace(/^[-*]\s+/, ''))}</li>`;
            return;
        }

        if (inList) {
            html += '</ul>';
            inList = false;
        }

        if (trimmed.length === 0) {
            return;
        }

        html += `<p>${applyInline(trimmed)}</p>`;
    });

    if (inList) {
        html += '</ul>';
    }

    codeBlocks.forEach((code, index) => {
        const safeCode = escapeHtml(code.trim());
        html = html.replace(`@@CODEBLOCK_${index}@@`, `<pre><code>${safeCode}</code></pre>`);
    });

    return html;
}

function buildDetailsMarkdown(item) {
    const sameLink = item.source && item.source === item.url;
    const sourceLine = item.source && !sameLink ? `\n- [Source code](${item.source})` : '';
    const websiteLine = `- [Website](${item.url})\n`;
    return `# ${item.name}\n\n${item.desc}\n\n## Why it matters\n- Primary category: **${item.cat.toUpperCase()}**\n- Type: **${(item.type || 'tool').toUpperCase()}**\n- Best for: recon, testing, or lab work\n- Suggested workflow: bookmark, review docs, then integrate\n\n## Quick links\n${websiteLine}${sourceLine}\n- [Search for guides](https://www.google.com/search?q=${encodeURIComponent(item.name + ' security tool')})`;
}

function getResourceByName(name) {
    return resources.find((item) => item.name === name);
}

function openModal(modal) {
    modal.classList.remove('modal-hidden');
    modal.classList.add('modal-visible');
    document.body.classList.add('overflow-hidden');
}

function closeModal(modal) {
    modal.classList.add('modal-hidden');
    modal.classList.remove('modal-visible');
    document.body.classList.remove('overflow-hidden');
}

function openDetails(item) {
    if (!item) return;
    elements.detailsTitle.textContent = item.name;
    const markdown = item.details ? normalizeDetailsMarkdown(item.details, item.name) : buildDetailsMarkdown(item);
    elements.detailsContent.innerHTML = renderMarkdown(markdown);
    const activeQuery = elements.searchInput ? elements.searchInput.value.trim() : '';
    highlightInElement(elements.detailsContent, activeQuery);
    openModal(elements.detailsModal);
}

function normalizeDetailsMarkdown(markdown, title) {
    const trimmed = markdown.trim();
    const titlePattern = new RegExp(`^#\\s+${escapeRegExp(title)}\\s*\\n`, 'i');
    if (titlePattern.test(trimmed)) {
        return trimmed.replace(titlePattern, '');
    }
    return trimmed;
}

function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function highlightMatch(text, query) {
    const rawText = text || '';
    if (!query || query.length < SEARCH_MIN_CHARS) {
        return escapeHtml(rawText);
    }
    const lowerText = rawText.toLowerCase();
    const lowerQuery = query.toLowerCase();
    let startIndex = 0;
    let matchIndex = lowerText.indexOf(lowerQuery, startIndex);
    if (matchIndex === -1) {
        return escapeHtml(rawText);
    }
    let output = '';
    while (matchIndex !== -1) {
        output += escapeHtml(rawText.slice(startIndex, matchIndex));
        output += `<span class="search-highlight">${escapeHtml(rawText.slice(matchIndex, matchIndex + lowerQuery.length))}</span>`;
        startIndex = matchIndex + lowerQuery.length;
        matchIndex = lowerText.indexOf(lowerQuery, startIndex);
    }
    output += escapeHtml(rawText.slice(startIndex));
    return output;
}

function highlightInElement(container, query) {
    if (!container || !query || query.length < SEARCH_MIN_CHARS) {
        return;
    }
    const lowerQuery = query.toLowerCase();
    const nodes = [];
    const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT, {
        acceptNode: (node) => {
            if (!node.nodeValue || !node.nodeValue.trim()) {
                return NodeFilter.FILTER_REJECT;
            }
            const parent = node.parentNode;
            if (!parent || !parent.nodeName) {
                return NodeFilter.FILTER_REJECT;
            }
            const tag = parent.nodeName;
            if (tag === 'CODE' || tag === 'PRE' || tag === 'SCRIPT' || tag === 'STYLE') {
                return NodeFilter.FILTER_REJECT;
            }
            return node.nodeValue.toLowerCase().includes(lowerQuery)
                ? NodeFilter.FILTER_ACCEPT
                : NodeFilter.FILTER_REJECT;
        }
    });

    let currentNode = walker.nextNode();
    while (currentNode) {
        nodes.push(currentNode);
        currentNode = walker.nextNode();
    }

    nodes.forEach((node) => {
        const text = node.nodeValue;
        const lowerText = text.toLowerCase();
        let startIndex = 0;
        let matchIndex = lowerText.indexOf(lowerQuery, startIndex);
        if (matchIndex === -1) return;

        const fragment = document.createDocumentFragment();
        while (matchIndex !== -1) {
            if (matchIndex > startIndex) {
                fragment.appendChild(document.createTextNode(text.slice(startIndex, matchIndex)));
            }
            const mark = document.createElement('span');
            mark.className = 'search-highlight';
            mark.textContent = text.slice(matchIndex, matchIndex + lowerQuery.length);
            fragment.appendChild(mark);
            startIndex = matchIndex + lowerQuery.length;
            matchIndex = lowerText.indexOf(lowerQuery, startIndex);
        }
        if (startIndex < text.length) {
            fragment.appendChild(document.createTextNode(text.slice(startIndex)));
        }
        if (node.parentNode) {
            node.parentNode.replaceChild(fragment, node);
        }
    });
}

function showEmptyState(message = EMPTY_STATE_DEFAULT_MESSAGE) {
    if (elements.emptyStateMessage) {
        elements.emptyStateMessage.textContent = message;
    }
    elements.grid.classList.add('hidden');
    elements.emptyState.classList.remove('hidden');
    elements.emptyState.style.display = 'flex';
}

function hideEmptyState() {
    elements.grid.classList.remove('hidden');
    elements.emptyState.classList.add('hidden');
    elements.emptyState.style.display = 'none';
    if (elements.emptyStateMessage && elements.emptyStateMessage.textContent !== EMPTY_STATE_DEFAULT_MESSAGE) {
        elements.emptyStateMessage.textContent = EMPTY_STATE_DEFAULT_MESSAGE;
    }
}

function ensureCardObserver() {
    if (cardObserver) return;
    cardObserver = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            if (entry.isIntersecting) {
                entry.target.classList.add('is-visible');
                cardObserver.unobserve(entry.target);
            }
        });
    }, { threshold: 0.15 });
}

function ensureLoadMoreObserver(onLoadMore) {
    if (loadMoreObserver) return;
    loadMoreObserver = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            if (entry.isIntersecting) {
                onLoadMore();
            }
        });
    }, { rootMargin: '200px 0px' });
}

async function hydrateLikeCounts(items) {
    const pending = items.filter(item => likeCounts[item.name] === undefined);
    if (pending.length === 0) return;

    await Promise.all(pending.map(async item => {
        try {
            const response = await fetch(`${COUNTER_BASE_URL}/get/${likeKey(item.name)}`);
            const data = await response.json();
            likeCounts[item.name] = typeof data.value === 'number' ? data.value : 0;
        } catch (err) {
            likeCounts[item.name] = 0;
        }
    }));
}

function likeKey(itemName) {
    const safeName = itemName.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    return `cybersuite-love-${safeName}`;
}

async function likeItem(itemName) {
    const alreadyLiked = liked.includes(itemName);
    const currentCount = likeCounts[itemName] || 0;
    const nextCount = alreadyLiked ? Math.max(0, currentCount - 1) : currentCount + 1;

    try {
        const endpoint = alreadyLiked ? 'set' : 'hit';
        const url = alreadyLiked
            ? `${COUNTER_BASE_URL}/set/${likeKey(itemName)}?value=${nextCount}`
            : `${COUNTER_BASE_URL}/hit/${likeKey(itemName)}`;
        const response = await fetch(url);
        const data = await response.json();
        likeCounts[itemName] = typeof data.value === 'number' ? data.value : nextCount;
    } catch (err) {
        likeCounts[itemName] = nextCount;
    }

    if (alreadyLiked) {
        liked = liked.filter(name => name !== itemName);
    } else {
        liked.push(itemName);
    }

    const searchValue = elements.searchInput.value;
    renderCards(currentFilter, searchValue);
}

function togglePin(itemName) {
    if (pinned.includes(itemName)) {
        pinned = pinned.filter(f => f !== itemName);
    } else {
        pinned.push(itemName);
    }
    localStorage.setItem('cybersuitePins', JSON.stringify(pinned));

    const searchValue = elements.searchInput.value;
    renderCards(currentFilter, searchValue);
}

async function renderCards(filter = 'all', searchQuery = '') {
    elements.grid.innerHTML = '';
    const token = ++renderToken;
    const normalizedQuery = searchQuery.trim().toLowerCase();
    const shouldSearch = normalizedQuery.length >= SEARCH_MIN_CHARS;
    if (cardObserver) {
        cardObserver.disconnect();
        cardObserver = null;
    }
    if (loadMoreObserver) {
        loadMoreObserver.disconnect();
        loadMoreObserver = null;
    }

    if (normalizedQuery.length > 0 && !shouldSearch) {
        showEmptyState(`Type at least ${SEARCH_MIN_CHARS} characters to search.`);
        return;
    }

    const filtered = resources.filter(item => {
        if (shouldSearch && !item._searchText.includes(normalizedQuery)) {
            return false;
        }

        if (filter === 'all') return true;
        if (filter === 'pinned') return pinned.includes(item.name);
        return item.cat === filter;
    });

    await hydrateLikeCounts(filtered);
    filtered.sort((a, b) => {
        const aPinned = pinned.includes(a.name);
        const bPinned = pinned.includes(b.name);
        if (aPinned !== bPinned) return aPinned ? -1 : 1;
        const likeDiff = (likeCounts[b.name] || 0) - (likeCounts[a.name] || 0);
        if (likeDiff !== 0) return likeDiff;
        return a.name.localeCompare(b.name);
    });

    if (filtered.length === 0) {
        showEmptyState();
        return;
    }

    hideEmptyState();

    const buildCardHTML = (item) => {
        const isPinned = pinned.includes(item.name);
        const likeCount = likeCounts[item.name] || 0;
        const isLiked = liked.includes(item.name);
        const categoryColor = item.cat === 'red'
            ? 'text-red-400'
            : (item.cat === 'blue' ? 'text-blue-400' : (item.cat === 'purple' ? 'text-purple-400' : 'text-gray-400'));
        const titleText = shouldSearch
            ? highlightMatch(item.name, normalizedQuery)
            : escapeHtml(item.name || '');
        const descText = shouldSearch
            ? highlightMatch(item.desc, normalizedQuery)
            : escapeHtml(item.desc || '');

        const iconClass = TYPE_ICONS[item.type] || TYPE_ICONS.tool;
        const hasSource = Boolean(item.source);
        const websiteUrl = item.website || item.url;
        const sameLink = hasSource && item.source === websiteUrl;
        const showWebsite = !sameLink;
        const showSource = hasSource;
        const showBinaries = Boolean(item.binaries);
        const buttonCount = (showWebsite ? 1 : 0) + (showSource ? 1 : 0) + (showBinaries ? 1 : 0);
        const tagList = Array.isArray(item.tags)
            ? item.tags.map((tag) => String(tag || '').trim()).filter(Boolean)
            : [];
        const tagsMarkup = tagList.length
            ? `<div class="mt-3 flex flex-wrap gap-2">
                ${tagList.map((tag) => `<span class="resource-tag">${shouldSearch ? highlightMatch(tag, normalizedQuery) : escapeHtml(tag)}</span>`).join('')}
            </div>`
            : '';
        const actionButtons = buttonCount
            ? `
            <div class="mt-4 grid gap-2 grid-cols-3">
                ${showWebsite ? `<a href="${websiteUrl}" target="_blank" rel="noopener" data-action="open" class="resource-action-btn">
                    Website <i class="fa-solid fa-arrow-up-right-from-square ml-2 text-xs opacity-70"></i>
                </a>` : ''}
                ${showSource ? `<a href="${item.source}" target="_blank" rel="noopener" data-action="open" class="resource-action-btn">
                    Code <i class="fa-brands fa-github ml-2 text-xs opacity-70"></i>
                </a>` : ''}
                ${showBinaries ? `<a href="${item.binaries}" target="_blank" rel="noopener" data-action="open" class="resource-action-btn" aria-label="Download binaries">
                    Binaries <i class="fa-solid fa-box-archive ml-2 text-xs opacity-70"></i>
                </a>` : ''}
            </div>
        `
            : '';
        return `
            <article class="glass-card card-reveal cat-${item.cat} relative rounded-2xl p-5 flex flex-col justify-between group cursor-pointer" data-card="${item.name}">
                <div class="flex justify-between items-start mb-4">
                    <div class="w-12 h-12 rounded-xl bg-white/5 flex items-center justify-center text-xl text-white border border-white/5">
                        <i class="fa-solid ${iconClass}"></i>
                    </div>
                    <div class="flex items-center gap-2">
                        <button class="text-xl p-2 focus:outline-none" data-action="pin" data-name="${item.name}" aria-label="Pin ${item.name}">
                            <i class="fa-solid fa-thumbtack ${isPinned ? 'text-green-400' : 'text-gray-600'}"></i>
                        </button>
                        <button class="text-xl p-2 focus:outline-none" data-action="like" data-name="${item.name}" aria-label="Like ${item.name}">
                            <i class="fa-solid fa-heart heart-icon ${isLiked ? 'active' : 'text-gray-600'}"></i>
                            <span class="text-xs text-gray-400 ml-1" data-like-count="${item.name}">${likeCount}</span>
                        </button>
                    </div>
                </div>

                <div>
                    <span class="text-xs font-semibold uppercase tracking-wider ${categoryColor} mb-1 block opacity-80">
                        ${item.cat === 'red' ? 'Red' : (item.cat === 'blue' ? 'Blue' : (item.cat === 'purple' ? 'Purple' : 'Utility'))}
                    </span>
                    <h3 class="text-lg font-semibold text-white mb-1">${titleText}</h3>
                    <p class="text-sm text-gray-400 line-clamp-2">${descText}</p>
                    ${tagsMarkup}
                </div>

                ${actionButtons}
            </article>
        `;
    };

    const initialBatch = 6;
    const batchSize = 9;
    renderCursor = 0;
    renderList = filtered;

    const renderNextBatch = () => {
        if (token !== renderToken) return;
        const chunk = renderList.slice(renderCursor, renderCursor + batchSize);
        if (chunk.length === 0) {
            if (loadMoreObserver && elements.loadMoreSentinel) {
                loadMoreObserver.unobserve(elements.loadMoreSentinel);
            }
            return;
        }
        const html = chunk.map(buildCardHTML).join('');
        elements.grid.insertAdjacentHTML('beforeend', html);
        ensureCardObserver();
        elements.grid.querySelectorAll('.card-reveal:not(.is-visible)').forEach((card) => {
            cardObserver.observe(card);
        });
        renderCursor += batchSize;
    };

    const firstChunk = renderList.slice(0, initialBatch);
    renderCursor = initialBatch;
    elements.grid.insertAdjacentHTML('beforeend', firstChunk.map(buildCardHTML).join(''));
    ensureCardObserver();
    elements.grid.querySelectorAll('.card-reveal').forEach((card) => {
        cardObserver.observe(card);
    });

    if (elements.loadMoreSentinel) {
        ensureLoadMoreObserver(renderNextBatch);
        loadMoreObserver.observe(elements.loadMoreSentinel);
    }
}

function setActiveFilter(category) {
    currentFilter = category;
    document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
    const active = document.querySelector(`[data-filter="${category}"]`);
    if (active) active.classList.add('active');

    renderCards(currentFilter, elements.searchInput.value);
}

function handleGridClick(event) {
    const action = event.target.closest('[data-action]');
    if (action) {
        const name = action.getAttribute('data-name');
        if (action.getAttribute('data-action') === 'pin') {
            event.stopPropagation();
            togglePin(name);
        }
        if (action.getAttribute('data-action') === 'like') {
            event.stopPropagation();
            likeItem(name);
        }
        return;
    }

    const card = event.target.closest('[data-card]');
    if (!card) return;
    const item = getResourceByName(card.getAttribute('data-card'));
    openDetails(item);
}

function setupModalClose(modal) {
    modal.addEventListener('click', (event) => {
        if (event.target === modal) {
            closeModal(modal);
        }
    });
    modal.querySelectorAll('[data-close]').forEach((btn) => {
        btn.addEventListener('click', () => closeModal(modal));
    });
}

function handleKeydown(event) {
    if (event.key === 'Escape') {
        if (!elements.detailsModal.classList.contains('modal-hidden')) {
            closeModal(elements.detailsModal);
        }
        if (!elements.requestModal.classList.contains('modal-hidden')) {
            closeModal(elements.requestModal);
        }
    }
}

function validateRequestLinks() {
    const websiteValue = elements.requestWebsite.value.trim();
    const sourceValue = elements.requestSource.value.trim();
    const isValid = websiteValue.length > 0 || sourceValue.length > 0;
    const message = isValid ? '' : 'Provide a website or source code link.';
    elements.requestWebsite.setCustomValidity(message);
    elements.requestSource.setCustomValidity(message);
    return isValid;
}

function updateResourceCount() {
    if (!elements.resourceCountValue) return;
    elements.resourceCountValue.textContent = String(resources.length);
}

function startSearchAutoTyping() {
    if (!elements.searchInput) return;
    const names = resources.map((item) => item.name).filter(Boolean);
    if (names.length === 0) return;
    const basePlaceholder = elements.searchInput.getAttribute('placeholder') || '';

    const tick = () => {
        if (document.activeElement === elements.searchInput || elements.searchInput.value.trim() !== '') {
            elements.searchInput.setAttribute('placeholder', basePlaceholder);
            typingTimer = setTimeout(tick, 1200);
            return;
        }

        const name = names[typingState.index % names.length];
        if (!typingState.deleting) {
            typingState.char += 1;
            elements.searchInput.setAttribute('placeholder', `${name.slice(0, typingState.char)}`);
            if (typingState.char >= name.length) {
                typingState.deleting = true;
                typingTimer = setTimeout(tick, 1400);
                return;
            }
            typingTimer = setTimeout(tick, 70);
            return;
        }

        typingState.char -= 1;
        elements.searchInput.setAttribute('placeholder', `${name.slice(0, Math.max(0, typingState.char))}`);
        if (typingState.char <= 0) {
            typingState.deleting = false;
            typingState.index = (typingState.index + 1) % names.length;
            typingTimer = setTimeout(tick, 300);
            return;
        }
        typingTimer = setTimeout(tick, 45);
    };

    clearTimeout(typingTimer);
    typingTimer = setTimeout(tick, 900);
}

function launchConfetti() {
    if (!elements.confettiContainer) return;
    const colors = ['#37ff8b', '#12c37a', '#6bffac', '#f0f3f6', '#9aa0a6'];
    const total = 42;
    elements.confettiContainer.innerHTML = '';

    for (let i = 0; i < total; i += 1) {
        const piece = document.createElement('span');
        piece.className = 'confetti-piece';
        piece.style.left = `${Math.random() * 100}%`;
        piece.style.background = colors[i % colors.length];
        piece.style.animationDelay = `${Math.random() * 0.2}s`;
        piece.style.transform = `translateY(-20px) rotate(${Math.random() * 180}deg)`;
        elements.confettiContainer.appendChild(piece);
    }

    setTimeout(() => {
        if (elements.confettiContainer) {
            elements.confettiContainer.innerHTML = '';
        }
    }, 1600);
}

function clearUserInputs() {
    if (elements.searchInput) {
        elements.searchInput.value = '';
    }
    if (elements.requestForm) {
        elements.requestForm.reset();
    }
}

function init() {
    clearUserInputs();

    elements.searchInput.addEventListener('input', (e) => {
        renderCards(currentFilter, e.target.value);
    });

    elements.filterNav.addEventListener('click', (event) => {
        const button = event.target.closest('[data-filter]');
        if (!button) return;
        setActiveFilter(button.getAttribute('data-filter'));
    });

    elements.grid.addEventListener('click', handleGridClick);

    elements.requestButton.addEventListener('click', () => {
        openModal(elements.requestModal);
    });

    if (elements.requestForm) {
        elements.requestForm.addEventListener('submit', (event) => {
            if (!validateRequestLinks()) {
                event.preventDefault();
                elements.requestWebsite.reportValidity();
                return;
            }
            if (isSubmittingRequest) {
                return;
            }
            event.preventDefault();
            isSubmittingRequest = true;
            launchConfetti();
            setTimeout(() => {
                elements.requestForm.submit();
                isSubmittingRequest = false;
            }, 700);
        });
        [elements.requestWebsite, elements.requestSource].forEach((input) => {
            input.addEventListener('input', validateRequestLinks);
        });
    }

    setupModalClose(elements.detailsModal);
    setupModalClose(elements.requestModal);
    document.addEventListener('keydown', handleKeydown);

    if (elements.scrollTopBtn) {
        const toggleScrollTop = () => {
            if (window.scrollY > 400) {
                elements.scrollTopBtn.classList.add('visible');
            } else {
                elements.scrollTopBtn.classList.remove('visible');
            }
        };
        toggleScrollTop();
        window.addEventListener('scroll', toggleScrollTop, { passive: true });
        elements.scrollTopBtn.addEventListener('click', () => {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        });
    }

    updateResourceCount();
    startSearchAutoTyping();
    renderCards();
}

init();
