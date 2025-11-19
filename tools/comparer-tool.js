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

        // Simple LCS-based diff algorithm (optional alignment)
        function computeDiff(linesA, linesB, normalize) {
            const m = linesA.length;
            const n = linesB.length;
            
            // Build LCS table
            const lcs = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));
            
            for (let i = 1; i <= m; i++) {
                for (let j = 1; j <= n; j++) {
                    const normA = normalize(linesA[i - 1]);
                    const normB = normalize(linesB[j - 1]);
                    
                    if (normA === normB) {
                        lcs[i][j] = lcs[i - 1][j - 1] + 1;
                    } else {
                        lcs[i][j] = Math.max(lcs[i - 1][j], lcs[i][j - 1]);
                    }
                }
            }
            
            // Backtrack to build diff
            const result = [];
            let i = m, j = n;
            
            while (i > 0 || j > 0) {
                if (i > 0 && j > 0) {
                    const normA = normalize(linesA[i - 1]);
                    const normB = normalize(linesB[j - 1]);
                    
                    if (normA === normB) {
                        result.unshift({
                            type: 'same',
                            lineA: i - 1,
                            lineB: j - 1,
                            textA: linesA[i - 1],
                            textB: linesB[j - 1]
                        });
                        i--;
                        j--;
                    } else if (lcs[i - 1][j] >= lcs[i][j - 1]) {
                        result.unshift({
                            type: 'removed',
                            lineA: i - 1,
                            lineB: null,
                            textA: linesA[i - 1],
                            textB: null
                        });
                        i--;
                    } else {
                        result.unshift({
                            type: 'added',
                            lineA: null,
                            lineB: j - 1,
                            textA: null,
                            textB: linesB[j - 1]
                        });
                        j--;
                    }
                } else if (i > 0) {
                    result.unshift({
                        type: 'removed',
                        lineA: i - 1,
                        lineB: null,
                        textA: linesA[i - 1],
                        textB: null
                    });
                    i--;
                } else {
                    result.unshift({
                        type: 'added',
                        lineA: null,
                        lineB: j - 1,
                        textA: null,
                        textB: linesB[j - 1]
                    });
                    j--;
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
    
    let rowsHtml = '';
    let lineNumA = 1;
    let lineNumB = 1;

    for (const item of diffResult) {
        let bgClassA = '';
        let bgClassB = '';
        let contentA = '';
        let contentB = '';
        let lineDisplayA = '';
        let lineDisplayB = '';

        if (item.type === 'same') {
            // Same line - grey text with dark background
            contentA = `<span class="bg-dark text-muted">${escapeHtml(item.textA || '')}</span>`;
            contentB = `<span class="bg-dark text-muted">${escapeHtml(item.textB || '')}</span>`;
            lineDisplayA = lineNumA++;
            lineDisplayB = lineNumB++;
        } else if (item.type === 'removed') {
            // Removed from A - lighter red background on left
            bgClassA = 'bg-danger bg-opacity-10';
            contentA = `<span class="bg-dark text-light">${escapeHtml(item.textA || '')}</span>`;
            contentB = '';
            lineDisplayA = lineNumA++;
            lineDisplayB = '';
        } else if (item.type === 'added') {
            // Added to B - lighter green background on right
            bgClassB = 'bg-success bg-opacity-10';
            contentA = '';
            contentB = `<span class="bg-dark text-light">${escapeHtml(item.textB || '')}</span>`;
            lineDisplayA = '';
            lineDisplayB = lineNumB++;
        }

        // Check if this is a modified line (removed followed by added)
        const nextItem = diffResult[diffResult.indexOf(item) + 1];
        if (item.type === 'removed' && nextItem && nextItem.type === 'added') {
            // Normalize both lines to check if they're similar enough to be a modification
            const normA = normalizeLine(item.textA);
            const normB = normalizeLine(nextItem.textB);
            
            // This is likely a modified line - show character-level diff
            const charDiff = getCharDiff(normA, normB);
            if (charDiff && (charDiff.changedA || charDiff.changedB)) {
                bgClassA = 'bg-danger bg-opacity-10';
                bgClassB = 'bg-success bg-opacity-10';
                contentA = renderLineWithCharDiff(item.textA, charDiff, 'A');
                contentB = renderLineWithCharDiff(nextItem.textB, charDiff, 'B');
                lineDisplayA = lineNumA++;
                lineDisplayB = lineNumB++;
                
                // Output the combined row
                rowsHtml += `
                    <tr>
                        <td class="text-secondary align-top small text-end pe-2 ${bgClassA}" style="border-right: 1px solid #495057;">${lineDisplayA}</td>
                        <td class="align-top small font-monospace ${bgClassA}" style="white-space: pre-wrap; word-break: break-all; border-right: 1px solid #495057;">${contentA || '&nbsp;'}</td>
                        <td class="text-secondary align-top small text-end pe-2 ${bgClassB}" style="border-right: 1px solid #495057;">${lineDisplayB}</td>
                        <td class="align-top small font-monospace ${bgClassB}" style="white-space: pre-wrap; word-break: break-all;">${contentB || '&nbsp;'}</td>
                    </tr>
                `;
                
                // Skip the next item since we already processed it
                diffResult.splice(diffResult.indexOf(nextItem), 1);
                continue;
            }
        }

        rowsHtml += `
            <tr>
                <td class="text-secondary align-top small text-end pe-2 ${bgClassA}" style="border-right: 1px solid #495057;">${lineDisplayA}</td>
                <td class="align-top small font-monospace ${bgClassA}" style="white-space: pre-wrap; word-break: break-all; border-right: 1px solid #495057;">${contentA || '&nbsp;'}</td>
                <td class="text-secondary align-top small text-end pe-2 ${bgClassB}" style="border-right: 1px solid #495057;">${lineDisplayB}</td>
                <td class="align-top small font-monospace ${bgClassB}" style="white-space: pre-wrap; word-break: break-all;">${contentB || '&nbsp;'}</td>
            </tr>
        `;
    }

    return `
        <div class="card bg-dark">
            <div class="card-header">
                <i class="bi bi-diagram-3"></i> Line-by-line Differences
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-sm mb-0" style="border-collapse: collapse;">
                        <thead>
                            <tr class="text-secondary border-bottom">
                                <th style="width: 3rem;" class="text-end pe-2">#</th>
                                <th style="width: calc(50% - 1.5rem);">Input A</th>
                                <th style="width: 3rem;" class="text-end pe-2">#</th>
                                <th style="width: calc(50% - 1.5rem);">Input B</th>
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
        name: 'Comparer',
        description: 'Compare two texts or payloads, highlight differences, and count differing bytes/words/chars',
        icon: 'bi bi-file-diff',
        category: 'purple',
        render,
        init
    });
})();