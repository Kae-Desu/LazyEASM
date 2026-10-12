/*
 * Shared front-end code for every LazyEASM page (loaded by base.html).
 *
 * Buttons declare what they do with data attributes instead of inline
 * JavaScript built from server data:
 *   data-action="deep_scan|cancel_scan|delete|clear_field|save|scan|logout|generate_ai|regenerate_ai"
 *   data-asset-id, data-asset-type, data-asset-name, data-redirect (after delete)
 *   data-field (clear_field), data-vuln-id + data-cve-id (AI)
 * Status selects use data-status-url and data-csrf.
 */

// --- Theme ---
function initTheme() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    const icon = document.getElementById('theme-icon');
    document.documentElement.classList.toggle('dark', savedTheme === 'dark');
    if (icon) icon.classList.replace(savedTheme === 'dark' ? 'fa-moon' : 'fa-sun', savedTheme === 'dark' ? 'fa-sun' : 'fa-moon');
}

function toggleDarkMode() {
    const dark = !document.documentElement.classList.contains('dark');
    localStorage.setItem('theme', dark ? 'dark' : 'light');
    initTheme();
}

// --- Loading overlay, toasts ---
function showLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) { overlay.classList.remove('hidden'); overlay.classList.add('flex'); }
}

function showToast(message, type = 'info', duration = 4000) {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const toast = document.createElement('div');
    const bgColor = { success: 'bg-emerald-500', error: 'bg-red-500', warning: 'bg-amber-500', info: 'bg-blue-500' }[type] || 'bg-blue-500';
    toast.className = `${bgColor} text-white px-6 py-3 rounded-xl shadow-lg font-semibold text-sm pointer-events-auto transform transition-all duration-300 translate-y-[-20px] opacity-0`;
    toast.innerText = message;
    container.appendChild(toast);
    setTimeout(() => toast.classList.remove('translate-y-[-20px]', 'opacity-0'), 10);
    setTimeout(() => {
        toast.classList.add('translate-y-[-20px]', 'opacity-0');
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

// Pages can react after an action changes data (e.g. reload a table)
function notifyDataChanged() {
    if (typeof window.onDataChanged === 'function') window.onDataChanged();
}

function testWebhook() {
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = '/test_webhook';
    const csrf = document.querySelector('input[name="csrf_token"]');
    if (csrf) {
        const input = document.createElement('input');
        input.type = 'hidden'; input.name = 'csrf_token'; input.value = csrf.value;
        form.appendChild(input);
    }
    document.body.appendChild(form);
    form.submit();
}

// --- Confirmation dialog ---
let currentActionCallback = null;

function postForm(url, fields) {
    const formData = new FormData();
    Object.entries(fields).forEach(([k, v]) => formData.append(k, v));
    return fetch(url, { method: 'POST', headers: { 'X-Requested-With': 'XMLHttpRequest' }, body: formData })
        .then(res => res.json());
}

function openConfirmModal(type, extraData = null) {
    const modal = document.getElementById('actionModal');
    const content = document.getElementById('actionModalContent');
    const iconCont = document.getElementById('modalIconContainer');
    const icon = document.getElementById('modalIcon');
    const title = document.getElementById('modalTitle');
    const desc = document.getElementById('modalDesc');
    const confirmBtn = document.getElementById('modalConfirmBtn');

    iconCont.className = 'w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4 text-2xl ';
    confirmBtn.className = 'flex-1 py-4 text-sm font-bold transition-colors text-center ';

    const name = extraData && extraData.name ? extraData.name : 'this asset';
    const configs = {
        save: {
            icon: 'fa-save', color: 'bg-emerald-500/10 text-emerald-500',
            btn: 'text-emerald-500 hover:bg-emerald-50 dark:hover:bg-emerald-500/10',
            title: 'Update Configuration?',
            desc: 'This will modify the scanning engine behavior. Ensure all keys are valid.',
            action: () => document.querySelector('form[action="/save_config"]').submit()
        },
        scan: {
            icon: 'fa-bolt', color: 'bg-secondary/10 text-secondary',
            btn: 'text-secondary hover:bg-blue-50 dark:hover:bg-secondary/10',
            title: 'Initiate Scanning?',
            desc: 'Process assets now? This might generate significant network traffic.',
            action: () => { showLoading(); document.querySelector('form[action="/process_assets"]').submit(); }
        },
        delete: {
            icon: 'fa-trash-alt', color: 'bg-red-500/10 text-red-500',
            btn: 'text-red-500 hover:bg-red-50 dark:hover:bg-red-500/10',
            title: 'Remove Asset?',
            desc: `Remove ${name} from LazyEASM?`,
            action: () => {
                fetch(`/delete_asset/${encodeURIComponent(extraData.type)}/${encodeURIComponent(extraData.id)}`, { method: 'DELETE' })
                    .then(res => res.json())
                    .then(data => {
                        if (!data.success) return showToast(data.error || 'Delete failed', 'error');
                        showToast('Asset deleted', 'success');
                        if (extraData.redirect) setTimeout(() => { window.location.href = extraData.redirect; }, 500);
                        else notifyDataChanged();
                    })
                    .catch(() => showToast('Request failed', 'error'));
                closeActionModal();
            }
        },
        clear_field: {
            icon: 'fa-trash-alt', color: 'bg-red-500/10 text-red-500',
            btn: 'text-red-500 hover:bg-red-50 dark:hover:bg-red-500/10',
            title: 'Delete Configuration?',
            desc: 'This will immediately delete this configuration. You can always add it again later.',
            action: () => {
                const hiddenField = document.getElementById(`clear_${extraData}`);
                const input = document.querySelector(`input[name="${CSS.escape(extraData)}"]`);
                if (hiddenField) hiddenField.value = '1';
                if (input) input.value = '';
                closeActionModal();
                document.querySelector('form[action="/save_config"]').submit();
            }
        },
        logout: {
            icon: 'fa-sign-out-alt', color: 'bg-accent/10 text-accent',
            btn: 'text-accent hover:bg-slate-50 dark:hover:bg-white/5',
            title: 'End Session?',
            desc: 'Are you sure you want to log out?',
            action: () => { window.location.href = '/logout'; }
        },
        regenerate_ai: {
            icon: 'fa-sync-alt', color: 'bg-accent/10 text-accent', btn: 'text-accent hover:bg-accent/10',
            title: 'Regenerate AI Analysis?',
            desc: 'This will overwrite the current recommendation with a new one. Continue?',
            action: () => { queueGenerateAI(extraData.vulnId, extraData.cveId); closeActionModal(); }
        },
        deep_scan: {
            icon: 'fa-search-plus', color: 'bg-secondary/10 text-secondary',
            btn: 'text-secondary hover:bg-blue-50 dark:hover:bg-secondary/10',
            title: 'Run Phase 2 Deep Scan?',
            desc: `This will perform a full port scan (1-65535) and directory enumeration on ${name}.\n\nEstimated time: 5-15 minutes.\nThis task runs in the background.`,
            action: () => {
                postForm('/api/phase2/scan', { asset_id: extraData.id, asset_type: extraData.type, asset_name: extraData.name })
                    .then(data => {
                        if (!data.success) return showToast(data.error || 'Failed to queue scan', 'error');
                        showToast('Deep scan queued', 'success');
                        notifyDataChanged();
                    })
                    .catch(() => showToast('Request failed', 'error'));
                closeActionModal();
            }
        },
        cancel_scan: {
            icon: 'fa-times-circle', color: 'bg-amber-500/10 text-amber-500',
            btn: 'text-amber-500 hover:bg-amber-50 dark:hover:bg-amber-500/10',
            title: 'Cancel Queued Scan?',
            desc: `This will remove ${name} from the scan queue.\n\nThe scan has not started yet and can be re-queued later.`,
            action: () => {
                postForm('/api/phase2/cancel', { asset_name: extraData.name })
                    .then(data => {
                        if (!data.success) return showToast(data.error || 'Failed to cancel scan', 'error');
                        showToast('Scan cancelled', 'success');
                        notifyDataChanged();
                    })
                    .catch(() => showToast('Request failed', 'error'));
                closeActionModal();
            }
        }
    };

    const config = configs[type];
    if (!config) return;
    icon.className = `fas ${config.icon}`;
    iconCont.classList.add(...config.color.split(' '));
    confirmBtn.classList.add(...config.btn.split(' '));
    title.innerText = config.title;
    desc.innerText = config.desc;
    currentActionCallback = config.action;

    modal.classList.remove('hidden');
    modal.classList.add('flex');
    setTimeout(() => {
        content.classList.remove('scale-95', 'opacity-0');
        content.classList.add('scale-100', 'opacity-100');
    }, 10);
}

function closeActionModal() {
    const modal = document.getElementById('actionModal');
    const content = document.getElementById('actionModalContent');
    content.classList.add('scale-95', 'opacity-0');
    setTimeout(() => { modal.classList.add('hidden'); modal.classList.remove('flex'); }, 200);
}

function isModalOpen() {
    const modal = document.getElementById('actionModal');
    return modal && !modal.classList.contains('hidden');
}

// --- AI analysis queue (one request at a time) ---
const aiGenerationQueue = [];
let aiGenerationInProgress = false;

function setGenerateButton(vulnId, busy) {
    const btn = document.getElementById(`generate-btn-${vulnId}`);
    if (!btn) return;
    btn.disabled = busy;
    btn.innerHTML = busy ? '<i class="fas fa-spinner fa-spin mr-1"></i>Generating...'
                         : '<i class="fas fa-magic mr-1"></i>Generate AI Analysis ✨';
}

function queueGenerateAI(vulnId, cveId) {
    setGenerateButton(vulnId, true);
    aiGenerationQueue.push({ vulnId, cveId });
    showToast(`Queued (position ${aiGenerationQueue.length})`, 'info');
    processAIQueue();
}

function processAIQueue() {
    if (aiGenerationInProgress || aiGenerationQueue.length === 0) return;
    aiGenerationInProgress = true;
    const request = aiGenerationQueue.shift();
    generateAIInternal(request.vulnId, request.cveId).finally(() => {
        aiGenerationInProgress = false;
        processAIQueue();
    });
}

async function generateAIInternal(vulnId, cveId) {
    try {
        const response = await fetch('/generate_ai', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ vuln_id: vulnId })
        });
        const data = await response.json();
        if (!response.ok || data.error) {
            showToast(data.error || 'AI generation failed. Check the AI provider settings.', 'error');
            setGenerateButton(vulnId, false);
            return;
        }
        const recoDiv = document.getElementById(`reco-${vulnId}`);
        if (recoDiv) {
            recoDiv.innerHTML = `
                <div class="flex items-center space-x-2 mb-2">
                    <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                    <span class="text-[10px] font-bold text-emerald-400 uppercase tracking-widest">AI Analysis</span>
                </div>
                <p class="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed whitespace-pre-line">${escapeHtml(data.recommendation)}</p>
                <button type="button" data-action="regenerate_ai" data-vuln-id="${escapeHtml(String(vulnId))}" data-cve-id="${escapeHtml(cveId)}"
                        class="mt-3 text-[10px] text-accent hover:text-secondary font-bold transition-colors">
                    <i class="fas fa-sync-alt mr-1"></i>Regenerate Analysis
                </button>`;
        }
        showToast('AI analysis generated!', 'success');
    } catch (err) {
        showToast('Network error. Please try again.', 'error');
        setGenerateButton(vulnId, false);
    }
}

// --- Status dropdowns for CVEs and security findings ---
async function updateStatus(url, select) {
    const status = select.value;
    select.disabled = true;
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status, csrf_token: select.dataset.csrf })
        });
        const data = await response.json();
        if (!response.ok || !data.success) throw new Error(data.error || 'Failed to update status');
        select.dataset.previous = status;
        const card = select.closest('[data-status-card]');
        if (card) card.classList.toggle('opacity-60', status !== 'open');
        showToast('Finding status updated', 'success');
    } catch (err) {
        select.value = select.dataset.previous;
        showToast(err.message || 'Network error. Please try again.', 'error');
    } finally {
        select.disabled = false;
    }
}

// --- Formatting ---
function formatRelativeTime(timestamp) {
    if (!timestamp || timestamp === '-') return '-';
    try {
        const date = new Date(timestamp.replace(' ', 'T') + 'Z');
        const diffMins = Math.floor((new Date() - date) / 60000);
        const diffHours = Math.floor(diffMins / 60);
        const diffDays = Math.floor(diffHours / 24);
        const pad = n => String(n).padStart(2, '0');
        const formatted = `${pad(date.getDate())}-${pad(date.getMonth() + 1)}-${date.getFullYear()} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
        let relative = '';
        if (diffMins < 1) relative = 'just now';
        else if (diffMins < 60) relative = `${diffMins}m ago`;
        else if (diffHours < 24) relative = `${diffHours}h ago`;
        else if (diffDays < 7) relative = `${diffDays}d ago`;
        return relative ? `${formatted} (${relative})` : formatted;
    } catch (e) {
        return timestamp;
    }
}

// --- Wiring ---
document.addEventListener('click', (event) => {
    const el = event.target.closest('[data-action]');
    if (!el || el.disabled) return;
    const d = el.dataset;
    const asset = { id: d.assetId, type: d.assetType, name: d.assetName, redirect: d.redirect };
    switch (d.action) {
        case 'deep_scan':
        case 'cancel_scan':
        case 'delete':
            event.preventDefault(); event.stopPropagation();
            openConfirmModal(d.action, asset);
            break;
        case 'clear_field':
            event.preventDefault();
            openConfirmModal('clear_field', d.field);
            break;
        case 'generate_ai':
            event.stopPropagation();
            queueGenerateAI(Number(d.vulnId), d.cveId);
            break;
        case 'regenerate_ai':
            event.stopPropagation();
            openConfirmModal('regenerate_ai', { vulnId: Number(d.vulnId), cveId: d.cveId });
            break;
        case 'save':
        case 'scan':
        case 'logout':
            event.preventDefault();
            openConfirmModal(d.action);
            break;
        case 'test_notification':
            testWebhook();
            break;
    }
});

document.addEventListener('change', (event) => {
    const select = event.target.closest('select[data-status-url]');
    if (select) updateStatus(select.dataset.statusUrl, select);
});

document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    const confirmBtn = document.getElementById('modalConfirmBtn');
    if (confirmBtn) confirmBtn.onclick = () => { if (currentActionCallback) currentActionCallback(); };
});
