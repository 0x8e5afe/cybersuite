// ========================================
// TEXT / PAYLOAD COMPARISON TOOL
// Category: Purple Team
// File: tools/comparer-tool.js
// ========================================

(function () {
    'use strict';

function render() {
    return `
        <div class="section-header">
            <h3 class="mb-1 d-flex align-items-center gap-2">
                <i class="bi bi-lightning-charge"></i>
                <span>Comparer</span>
            </h3>
            <p class="text-secondary mb-0">
                Compare two payloads (requests, hashes, code, HTML, etc.) and inspect differences at a glance
            </p>
        </div>

        <div class="row g-3 mt-2">
            <div class="col-12">
                <div class="card bg-dark">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span>
                            <i class="bi bi-columns-gap"></i> Inputs
                        </span>
                    </div>
                    <div class="card-body">
                        <div class="row g-3">
                            <div class="col-md-6">
                                <label for="comparerInputA" class="form-label">Input A (baseline)</label>
                                <textarea
                                    id="comparerInputA"
                                    class="form-control"
                                    rows="10"
                                    aria-label="First text to compare"
                                    placeholder="Original payload, baseline request, reference hash list..."
                                ></textarea>
                                <small class="text-secondary d-block mt-1" id="comparerStatsA">
                                    Waiting for input…
                                </small>
                            </div>
                            <div class="col-md-6">
                                <label for="comparerInputB" class="form-label">Input B (candidate)</label>
                                <textarea
                                    id="comparerInputB"
                                    class="form-control"
                                    rows="10"
                                    aria-label="Second text to compare"
                                    placeholder="Modified payload, mutated request, new hash list..."
                                ></textarea>
                                <small class="text-secondary d-block mt-1" id="comparerStatsB">
                                    Waiting for input…
                                </small>
                            </div>
                        </div>

                        <div class="row g-2 align-items-center mt-3">
                            <div class="col-md-6">
                                <div class="form-check form-check-inline">
                                    <input
                                        class="form-check-input"
                                        type="checkbox"
                                        id="comparerIgnoreCase"
                                    >
                                    <label class="form-check-label" for="comparerIgnoreCase">
                                        Ignore case
                                    </label>
                                </div>
                                <div class="form-check form-check-inline">
                                    <input
                                        class="form-check-input"
                                        type="checkbox"
                                        id="comparerTrimWhitespace"
                                        checked
                                    >
                                    <label class="form-check-label" for="comparerTrimWhitespace">
                                        Trim surrounding whitespace
                                    </label>
                                </div>
                                <div class="form-check form-check-inline">
                                    <input
                                        class="form-check-input"
                                        type="checkbox"
                                        style="display:none"
                                        id="comparerLiveCompare"
                                        checked
                                    >
                                </div>
                            </div>
                            <div class="col-md-6 text-md-end">
                                <div class="btn-group" role="group" aria-label="Comparison controls">
                                    <button
                                        type="button"
                                        class="btn btn-primary"
                                        id="comparerCompareBtn"
                                    >
                                        <i class="bi bi-lightning-charge"></i> Compare
                                    </button>
                                    <button
                                        type="button"
                                        class="btn btn-outline-secondary"
                                        id="comparerSwapBtn"
                                    >
                                        <i class="bi bi-arrow-left-right"></i> Swap A/B
                                    </button>
                                    <button
                                        type="button"
                                        class="btn btn-outline-danger"
                                        id="comparerClearBtn"
                                    >
                                        <i class="bi bi-trash"></i> Clear
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div id="comparerDiffOutput" class="mt-3"></div>
    `;
}

    function init() {
        const inputA = document.getElementById('comparerInputA');
        const inputB = document.getElementById('comparerInputB');
        const statsA = document.getElementById('comparerStatsA');
        const statsB = document.getElementById('comparerStatsB');
        const compareBtn = document.getElementById('comparerCompareBtn');
        const swapBtn = document.getElementById('comparerSwapBtn');
        const clearBtn = document.getElementById('comparerClearBtn');
        const ignoreCaseCheckbox = document.getElementById('comparerIgnoreCase');
        const trimCheckbox = document.getElementById('comparerTrimWhitespace');
        const liveCheckbox = document.getElementById('comparerLiveCompare');
        const diffContainer = document.getElementById('comparerDiffOutput');

        if (
            !inputA || !inputB || !statsA || !statsB ||
            !compareBtn || !swapBtn || !clearBtn ||
            !ignoreCaseCheckbox || !trimCheckbox || !liveCheckbox ||
            !diffContainer
        ) {
            console.error('Comparer tool: missing one or more DOM elements');
            return;
        }

        function escapeHtml(str) {
            return str
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        function utf8Length(str) {
            if (typeof TextEncoder !== 'undefined') {
                return new TextEncoder().encode(str).length;
            }
            try {
                return unescape(encodeURIComponent(str)).length;
            } catch (e) {
                return str.length;
            }
        }

        function computeStats(text) {
            const words = (text.match(/\S+/g) || []).length;
            const lines = text.length ? text.split(/\r\n|\n|\r/).length : 0;
            return {
                chars: text.length,
                bytes: utf8Length(text),
                words,
                lines
            };
        }

        function formatStatsForSide(label, stats) {
            if (!stats) return '';
            return `${label}: ${stats.chars} chars, ${stats.bytes} bytes, ${stats.words} words, ${stats.lines} lines`;
        }

        // Row-aligned diff: no reordering, compare index-by-index
        function computeDiff(linesA, linesB, normalize) {
            const maxLen = Math.max(linesA.length, linesB.length);
            const result = [];

            for (let idx = 0; idx < maxLen; idx++) {
                const hasA = idx < linesA.length;
                const hasB = idx < linesB.length;
                const lineA = hasA ? linesA[idx] : null;
                const lineB = hasB ? linesB[idx] : null;

                if (hasA && hasB) {
                    const normA = normalize(lineA);
                    const normB = normalize(lineB);
                    if (normA === normB) {
                        result.push({
                            type: 'same',
                            lineA: idx,
                            lineB: idx,
                            textA: lineA,
                            textB: lineB
                        });
                    } else {
                        // Treat as one removal + one addition for counts
                        result.push({
                            type: 'removed',
                            lineA: idx,
                            lineB: null,
                            textA: lineA,
                            textB: null
                        });
                        result.push({
                            type: 'added',
                            lineA: null,
                            lineB: idx,
                            textA: null,
                            textB: lineB
                        });
                    }
                } else if (hasA) {
                    result.push({
                        type: 'removed',
                        lineA: idx,
                        lineB: null,
                        textA: lineA,
                        textB: null
                    });
                } else if (hasB) {
                    result.push({
                        type: 'added',
                        lineA: null,
                        lineB: idx,
                        textA: null,
                        textB: lineB
                    });
                }
            }

            return result;
        }

        // Character-level diff for modified lines
        function getCharDiff(strA, strB) {
            if (!strA || !strB) return null;
            
            const a = strA || '';
            const b = strB || '';
            
            // Find common prefix
            let prefixLen = 0;
            const minLen = Math.min(a.length, b.length);
            while (prefixLen < minLen && a[prefixLen] === b[prefixLen]) {
                prefixLen++;
            }
            
            // Find common suffix
            let suffixLen = 0;
            while (
                suffixLen < (minLen - prefixLen) &&
                a[a.length - 1 - suffixLen] === b[b.length - 1 - suffixLen]
            ) {
                suffixLen++;
            }
            
            return {
                prefixLen,
                suffixLen,
                changedA: a.slice(prefixLen, a.length - suffixLen),
                changedB: b.slice(prefixLen, b.length - suffixLen)
            };
        }

        function renderLineWithCharDiff(text, charDiff, side) {
            if (!text) return '';
            if (!charDiff) {
                // Grey text with dark background for spaces
                return `<span class="bg-dark text-muted">${escapeHtml(text)}</span>`;
            }
            
            const { prefixLen, suffixLen, changedA, changedB } = charDiff;
            const changed = side === 'A' ? changedA : changedB;
            
            const prefix = text.slice(0, prefixLen);
            const suffix = text.slice(text.length - suffixLen);
            
            const parts = [];
            if (prefix) {
                // Grey text with dark background
                parts.push(`<span class="bg-dark text-muted">${escapeHtml(prefix)}</span>`);
            }
            if (changed) {
                // Lighter color highlight for changes
                const bgClass = side === 'A' ? 'bg-danger bg-opacity-25 text-light' : 'bg-success bg-opacity-25 text-light';
                parts.push(`<span class="${bgClass}">${escapeHtml(changed)}</span>`);
            }
            if (suffix) {
                // Grey text with dark background
                parts.push(`<span class="bg-dark text-muted">${escapeHtml(suffix)}</span>`);
            }
            
            return parts.join('');
        }

        function tokenizeForDiff(str) {
            // Keep whitespace tokens so spacing is preserved when rendering
            return str.match(/\s+|[^\s]+/g) || [];
        }

        function computeWordDiff(lineA, lineB) {
            const tokensA = tokenizeForDiff(lineA);
            const tokensB = tokenizeForDiff(lineB);
            const m = tokensA.length;
            const n = tokensB.length;

            const lcs = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));
            for (let i = 1; i <= m; i++) {
                for (let j = 1; j <= n; j++) {
                    if (tokensA[i - 1] === tokensB[j - 1]) {
                        lcs[i][j] = lcs[i - 1][j - 1] + 1;
                    } else {
                        lcs[i][j] = Math.max(lcs[i - 1][j], lcs[i][j - 1]);
                    }
                }
            }

            const result = [];
            let i = m, j = n;
            while (i > 0 || j > 0) {
                if (i > 0 && j > 0 && tokensA[i - 1] === tokensB[j - 1]) {
                    result.unshift({ type: 'same', value: tokensA[i - 1] });
                    i--;
                    j--;
                } else if (j > 0 && (i === 0 || lcs[i][j - 1] >= lcs[i - 1][j])) {
                    result.unshift({ type: 'add', value: tokensB[j - 1] });
                    j--;
                } else {
                    result.unshift({ type: 'remove', value: tokensA[i - 1] });
                    i--;
                }
            }

            return result;
        }

        function buildWordLevelSegments(lineA, lineB) {
            const wordDiff = computeWordDiff(lineA, lineB);
            const segmentsA = [];
            const segmentsB = [];

            for (const part of wordDiff) {
                if (part.type === 'same') {
                    segmentsA.push({ text: part.value, kind: 'same' });
                    segmentsB.push({ text: part.value, kind: 'same' });
                } else if (part.type === 'remove') {
                    segmentsA.push({ text: part.value, kind: 'remove' });
                } else if (part.type === 'add') {
                    segmentsB.push({ text: part.value, kind: 'add' });
                }
            }

            return {
                segmentsA,
                segmentsB
            };
        }

        function levenshteinDistance(a, b) {
            const m = a.length;
            const n = b.length;
            if (m === 0) return n;
            if (n === 0) return m;
            const dp = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));
            for (let i = 0; i <= m; i++) dp[i][0] = i;
            for (let j = 0; j <= n; j++) dp[0][j] = j;

            for (let i = 1; i <= m; i++) {
                for (let j = 1; j <= n; j++) {
                    if (a[i - 1] === b[j - 1]) {
                        dp[i][j] = dp[i - 1][j - 1];
                    } else {
                        dp[i][j] = Math.min(
                            dp[i - 1][j] + 1,    // deletion
                            dp[i][j - 1] + 1,    // insertion
                            dp[i - 1][j - 1] + 1 // substitution
                        );
                    }
                }
            }
            return dp[m][n];
        }

        function normalizedSimilarity(a, b) {
            if (a === b) return 1;
            const maxLen = Math.max(a.length, b.length, 1);
            const distance = levenshteinDistance(a, b);
            return 1 - (distance / maxLen);
        }

        function renderSegments(segments, side) {
            if (!segments.length) {
                return '&nbsp;';
            }
            return segments.map(seg => {
                let cls = 'diff-chunk';
                if (seg.kind === 'add') {
                    cls += ' diff-inline-added';
                } else if (seg.kind === 'remove') {
                    cls += ' diff-inline-removed';
                } else {
                    cls += ' diff-inline-same';
                }
                return `<span class="${cls}">${escapeHtml(seg.text)}</span>`;
            }).join('');
        }

function buildLineDiffView(rawA, rawB) {
    const linesA = rawA.length ? rawA.split(/\r\n|\n|\r/) : [];
    const linesB = rawB.length ? rawB.split(/\r\n|\n|\r/) : [];

    if (linesA.length === 0 && linesB.length === 0) {
        return '';
    }

    function normalizeLine(line) {
        let s = line;
        if (trimCheckbox.checked) {
            s = s.trim();
        }
        if (ignoreCaseCheckbox.checked) {
            s = s.toLowerCase();
        }
        return s;
    }

    const diffResult = computeDiff(linesA, linesB, normalizeLine);
    const totalRemoved = diffResult.filter(d => d.type === 'removed').length;
    const totalAdded = diffResult.filter(d => d.type === 'added').length;
    
    let rowsHtml = '';
    let lineNumA = 1;
    let lineNumB = 1;

    let idx = 0;

    while (idx < diffResult.length) {
        const item = diffResult[idx];

        // Directly render unchanged lines and move on
        if (item.type === 'same') {
            const textA = `<span class="text-muted">${escapeHtml(item.textA || '') || '&nbsp;'}</span>`;
            const textB = `<span class="text-muted">${escapeHtml(item.textB || '') || '&nbsp;'}</span>`;
            rowsHtml += `
                <tr class="diff-line diff-line--same">
                    <td class="diff-line-num text-secondary align-top small text-end pe-2">${lineNumA}</td>
                    <td class="diff-cell diff-cell-same align-top small font-monospace">${textA}</td>
                    <td class="diff-line-num text-secondary align-top small text-end pe-2">${lineNumB}</td>
                    <td class="diff-cell diff-cell-same align-top small font-monospace">${textB}</td>
                </tr>
            `;
            lineNumA++;
            lineNumB++;
            idx++;
            continue;
        }

        // Collect contiguous hunk of removed/added lines
        const hunk = [];
        const removedLines = [];
        const addedLines = [];
        while (idx < diffResult.length && diffResult[idx].type !== 'same') {
            const entry = diffResult[idx];
            hunk.push(entry);
            if (entry.type === 'removed') {
                removedLines.push(entry);
            } else if (entry.type === 'added') {
                addedLines.push(entry);
            }
            idx++;
        }

        // Pair removed/addition lines within the hunk strictly by position (no reordering)
        const pairings = new Map();
        if (removedLines.length && addedLines.length) {
            const minCount = Math.min(removedLines.length, addedLines.length);
            for (let i = 0; i < minCount; i++) {
                pairings.set(removedLines[i], addedLines[i]);
            }
        }

        const renderedAdded = new Set();

        // Render removed lines (paired first)
        for (const entry of hunk.filter(e => e.type === 'removed')) {
            const matched = pairings.get(entry);
            if (matched) {
                const { segmentsA, segmentsB } = buildWordLevelSegments(entry.textA || '', matched.textB || '');
                const htmlA = renderSegments(segmentsA, 'A');
                const htmlB = renderSegments(segmentsB, 'B');
                rowsHtml += `
                    <tr class="diff-line diff-line--changed">
                        <td class="diff-line-num text-secondary align-top small text-end pe-2">${lineNumA}</td>
                        <td class="diff-cell diff-cell-removed align-top small font-monospace">${htmlA}</td>
                        <td class="diff-line-num text-secondary align-top small text-end pe-2">${lineNumB}</td>
                        <td class="diff-cell diff-cell-added align-top small font-monospace">${htmlB}</td>
                    </tr>
                `;
                lineNumA++;
                lineNumB++;
                renderedAdded.add(matched);
            } else {
                rowsHtml += `
                    <tr class="diff-line diff-line--removed">
                        <td class="diff-line-num text-secondary align-top small text-end pe-2">${lineNumA}</td>
                        <td class="diff-cell diff-cell-removed align-top small font-monospace">${escapeHtml(entry.textA || '') || '&nbsp;'}</td>
                        <td class="diff-line-num text-secondary align-top small text-end pe-2"></td>
                        <td class="diff-cell diff-cell-same align-top small font-monospace">&nbsp;</td>
                    </tr>
                `;
                lineNumA++;
            }
        }

        // Render remaining added lines
        for (const entry of hunk.filter(e => e.type === 'added')) {
            if (renderedAdded.has(entry)) continue;
            rowsHtml += `
                <tr class="diff-line diff-line--added">
                    <td class="diff-line-num text-secondary align-top small text-end pe-2"></td>
                    <td class="diff-cell diff-cell-same align-top small font-monospace">&nbsp;</td>
                    <td class="diff-line-num text-secondary align-top small text-end pe-2">${lineNumB}</td>
                    <td class="diff-cell diff-cell-added align-top small font-monospace">${escapeHtml(entry.textB || '') || '&nbsp;'}</td>
                </tr>
            `;
            lineNumB++;
        }
    }

    const summaryHtml = `
        <div class="diff-summary d-flex align-items-center justify-content-between flex-wrap gap-2 mb-2">
            <div class="d-flex align-items-center gap-2">
                <span class="diff-badge diff-badge-removed">
                    <i class="bi bi-dash-circle"></i> ${totalRemoved} removal${totalRemoved === 1 ? '' : 's'}
                </span>
                <span class="diff-badge diff-badge-added">
                    <i class="bi bi-plus-circle"></i> ${totalAdded} addition${totalAdded === 1 ? '' : 's'}
                </span>
            </div>
            <small class="text-secondary">Split view with inline highlights</small>
        </div>
    `;

    return `
        <div class="card bg-dark diff-card">
            <div class="card-header d-flex align-items-center gap-2">
                <i class="bi bi-diagram-3"></i>
                <span>Line-by-line Differences</span>
            </div>
            <div class="card-body pt-2">
                ${summaryHtml}
                <div class="table-responsive">
                    <table class="table table-sm table-borderless mb-0 diff-table">
                        <thead class="text-secondary">
                            <tr class="border-bottom">
                                <th style="width: 3rem;" class="text-end pe-2">#</th>
                                <th style="width: calc(50% - 1.5rem);" class="text-secondary">Input A</th>
                                <th style="width: 3rem;" class="text-end pe-2">#</th>
                                <th style="width: calc(50% - 1.5rem);" class="text-secondary">Input B</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${rowsHtml}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    `;
}

        function updatePerSideStats() {
            const textA = inputA.value || '';
            const textB = inputB.value || '';

            if (!textA && !textB) {
                statsA.textContent = 'Waiting for input…';
                statsB.textContent = 'Waiting for input…';
                return;
            }

            const sA = computeStats(textA);
            const sB = computeStats(textB);

            statsA.textContent = formatStatsForSide('A', sA);
            statsB.textContent = formatStatsForSide('B', sB);
        }

function runComparison() {
    const rawA = inputA.value || '';
    const rawB = inputB.value || '';

    updatePerSideStats();

    if (!rawA && !rawB) {
        diffContainer.innerHTML = `
            <div class="alert alert-warning" role="alert">
                <i class="bi bi-exclamation-triangle"></i>
                <strong>No input provided.</strong> Please enter text in at least one of the input fields to compare.
            </div>
        `;
        return;
    }

    diffContainer.innerHTML = buildLineDiffView(rawA, rawB);
}

function maybeLiveCompare() {
    updatePerSideStats();
    // If diff has been shown at least once, update it
    if (diffContainer.innerHTML !== '') {
        runComparison();
    }
}

compareBtn.addEventListener('click', runComparison);

swapBtn.addEventListener('click', function () {
    const tmp = inputA.value;
    inputA.value = inputB.value;
    inputB.value = tmp;
    maybeLiveCompare();
    inputA.focus();
});

clearBtn.addEventListener('click', function () {
    inputA.value = '';
    inputB.value = '';
    statsA.textContent = 'Waiting for input…';
    statsB.textContent = 'Waiting for input…';
    diffContainer.innerHTML = '';
});

inputA.addEventListener('input', maybeLiveCompare);
inputB.addEventListener('input', maybeLiveCompare);

ignoreCaseCheckbox.addEventListener('change', maybeLiveCompare);
trimCheckbox.addEventListener('change', maybeLiveCompare);
liveCheckbox.addEventListener('change', maybeLiveCompare);

updatePerSideStats();
    }

    window.registerCyberSuiteTool({
        id: 'comparer-tool',
        name: 'Text Comparer',
        description: 'Compare two texts or payloads, highlight differences, and count differing bytes/words/chars',
        icon: 'bi bi-file-diff',
        category: 'purple',
        render,
        init
    });
})();
