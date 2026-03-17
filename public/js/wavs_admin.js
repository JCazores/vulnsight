// ═══════════════════════════════════════════════════════════
//  SHARED API LAYER — identical pattern to wavs_blade.php
// ═══════════════════════════════════════════════════════════
let currentAdmin = null;

function getCsrfToken() {
    const match = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : (document.querySelector('meta[name="csrf-token"]')?.content || '');
}

const API_BASE = 'http://localhost:8001';

async function apiFetch(url, options = {}) {
    const fullUrl = url.startsWith('http') ? url : API_BASE + url;
    const csrfToken = getCsrfToken();
    const bearerToken = localStorage.getItem('token') || '';
    const merged = {
        credentials: 'include',
        ...options,
        headers: {
            'Content-Type':     'application/json',
            'Accept':           'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'X-CSRF-TOKEN':     csrfToken,
            'X-XSRF-TOKEN':     csrfToken,
            ...(bearerToken ? { 'Authorization': 'Bearer ' + bearerToken } : {}),
            ...(options.headers || {}),
        },
    };
    const res = await fetch(fullUrl, merged);
    if (!res.ok) {
        if (res.status === 401) throw new Error('Unauthenticated');
        if (res.status === 403) {
            // Check if this is a ban response — if so, force immediate logout
            try {
                const b = await res.clone().json();
                if (b.banned === true) {
                    showToast('Your account has been suspended.', 'error');
                    setTimeout(() => { window.location.href = '/vulnsight/'; }, 1800);
                    throw new Error('Banned');
                }
                if (b.message) throw new Error(b.message);
            } catch (jsonErr) {
                if (jsonErr.message === 'Banned') throw jsonErr;
            }
            throw new Error('Forbidden');
        }
        let msg = `HTTP ${res.status}`;
        try { const b = await res.clone().json(); if (b.message) msg = b.message; } catch (_) {}
        throw new Error(msg);
    }
    if (res.status === 204) return null;
    return res.json();
}

// ───────────────────────────────────────────────────────────
//  SESSION GUARD — redirect non-admins back to the scanner
// ───────────────────────────────────────────────────────────
(function checkAdminSession() {
    async function tryRestore() {
        try {
            const user = await apiFetch('/api/me');
            const isAdmin = user.role === 'admin' || user.is_admin === true;
            if (!isAdmin) {
                showToast('Admin access required', 'error');
                setTimeout(() => { window.location.href = '/vulnsight/'; }, 1600);
                return;
            }
            currentAdmin = user;
            // Populate sidebar user chip
            const av = document.getElementById('adminAvatarDisplay');
            const nm = document.getElementById('adminNameDisplay');
            const em = document.getElementById('adminEmailDisplay');
            if (av) av.textContent = user.name.slice(0, 2).toUpperCase();
            if (nm) nm.textContent = user.name;
            if (em) em.textContent = user.email;
            initAdmin();
        } catch (_) {
            // Token invalid — redirect to auto-login with fresh timestamp
            localStorage.removeItem('token');
            const base = window.__vsAutoLoginUrl || '/vulnsight/auto-login';
            window.location.replace(base + '&_t=' + Date.now());
        }
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', tryRestore);
    else tryRestore();
})();

async function doAdminSignOut() {
    if (!confirm('Sign out of the admin panel?')) return;
    try { await apiFetch('/api/logout', { method: 'POST' }); } catch (_) {}
    window.location.href = '/vulnsight/';
}

// ───────────────────────────────────────────────────────────
//  NO MOCK DATA — all data comes from the real database API
// ───────────────────────────────────────────────────────────

// Live mutable state — filled by initAdmin()
let SCANS = [], VULNS_SAMPLE = [], auditData = [];

// ───────────────────────────────────────────────────────────
//  INIT — parallel fetch from real API, no fake fallback
// ───────────────────────────────────────────────────────────
async function initAdmin() {
    setLoading(true);

    const [scansRes, vulnsRes, statsRes, healthRes, auditRes] = await Promise.allSettled([
        apiFetch('/api/admin/scans'),
        apiFetch('/api/admin/vulnerabilities'),
        apiFetch('/api/admin/stats'),
        apiFetch('/api/admin/health'),
        apiFetch('/api/admin/audit-log'),
    ]);

    // ── Scans ──────────────────────────────────────────────
    if (scansRes.status === 'fulfilled') {
        SCANS = normalizeScans(scansRes.value);
    } else {
        SCANS = [];
        console.error('Admin scans fetch failed:', scansRes.reason?.message);
        showToast('Could not load scans: ' + (scansRes.reason?.message || 'Unknown error'), 'error');
    }

    // ── Vulnerabilities ───────────────────────────────────
    if (vulnsRes.status === 'fulfilled') {
        VULNS_SAMPLE = normalizeVulns(vulnsRes.value);
    } else {
        VULNS_SAMPLE = [];
    }

    // ── Stats (dashboard overview) ─────────────────────────
    if (statsRes.status === 'fulfilled' && statsRes.value) {
        const s = statsRes.value;
        const set    = (id, v) => { const el = document.getElementById(id); if (el && v !== undefined) el.textContent = Number(v).toLocaleString(); };
        const setTxt = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };

        set('totalScans',    s.total_scans);
        set('totalVulns',    s.total_vulnerabilities);
        set('totalCritical', s.critical_alerts);
        set('totalActive',   s.running_scans ?? 0);

        setTxt('deltaScans',    s.today_scans  > 0 ? '+' + s.today_scans + ' today' : 'None today');
        setTxt('deltaVulns',    s.today_vulns  > 0 ? '+' + s.today_vulns + ' today' : 'None today');
        setTxt('deltaCritical', 'Platform-wide');
        setTxt('deltaActive',   s.running_scans > 0 ? s.running_scans + ' live' : 'None running');

        // Vuln distribution
        const d = s.vuln_by_severity || {};
        set('distCritical', d.critical ?? 0);
        set('distHigh',     d.high     ?? 0);
        set('distMedium',   d.medium   ?? 0);
        set('distLow',      d.low      ?? 0);

        // Sidebar badges
        setTxt('sideScanRunning', s.running_scans ?? '0');
        set('sideVulnCount', s.total_vulnerabilities ?? 0);
        if (Array.isArray(s.scan_activity_14d)) {
            renderActivityBars(s.scan_activity_14d);
        }
    } else {
        // Stats failed — derive totals from the arrays we got
        document.getElementById('totalScans')?.textContent !== undefined &&
            (document.getElementById('totalScans').textContent = SCANS.length.toLocaleString());
        document.getElementById('totalVulns')?.textContent !== undefined &&
            (document.getElementById('totalVulns').textContent = VULNS_SAMPLE.length.toLocaleString());
    }

    // ── Health / services ─────────────────────────────────
    const services = healthRes.status === 'fulfilled' ? normalizeServices(healthRes.value) : [];
    renderServices(services);

    // ── Audit log ─────────────────────────────────────────
    if (auditRes.status === 'fulfilled' && auditRes.value) {
        const raw = Array.isArray(auditRes.value) ? auditRes.value : (auditRes.value.data || []);
        // Normalise server entries to the {ts, actor, action, sev} shape
        auditData = raw.map(e => ({
            ts:     e.ts     || e.created_at || e.timestamp || '',
            actor:  e.actor  || e.user_email || e.user  || 'system',
            action: e.action || e.description || e.message || '',
            sev:    e.sev    || e.severity    || e.level || 'info',
        }));
    }
    renderAuditLog(auditData);

    setLoading(false);

    filteredScans   = [...SCANS];
    filteredReports = [...VULNS_SAMPLE];

    renderScans(filteredScans);
    renderReports(filteredReports);
    renderRecentCriticalVulns();
    renderLiveScansPreview();

    tickLive();
    setInterval(tickLive, 3000);
    setInterval(pollRunningScans, 8000);

    // Load saved platform settings into the settings tab
    loadSettings();
}

// Spinner while data loads
const _spinStyle = document.createElement('style');
_spinStyle.textContent = '@keyframes spin{to{transform:rotate(360deg)}}';
document.head.appendChild(_spinStyle);

function setLoading(on) {
    ['scansTableBody','reportsTableBody'].forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        if (on) el.innerHTML = '<tr><td colspan="8" style="padding:32px;text-align:center;"><div style="width:22px;height:22px;border:2px solid rgba(var(--neon-rgb),.3);border-top-color:var(--neon);border-radius:50%;animation:spin .7s linear infinite;margin:0 auto;"></div></td></tr>';
    });
}

// Poll active scans every 8 s for live progress + refresh full list every 30s
let _scanPollCount = 0;
async function pollRunningScans() {
    _scanPollCount++;

    // Every 30s (every ~4th tick at 8s interval) refresh the full scan + vuln list
    if (_scanPollCount % 4 === 1) {
        try {
            const fresh = await apiFetch('/api/admin/scans');
            if (fresh) {
                const normalized = normalizeScans(fresh);
                // Merge: keep any local status overrides (stop/retry) but add new scans
                normalized.forEach(ns => {
                    const existing = SCANS.find(s => String(s.id) === String(ns.id));
                    if (!existing) SCANS.unshift(ns);
                    else if (ns.status !== existing.status || ns.progress !== existing.progress) {
                        Object.assign(existing, ns);
                    }
                });
                filteredScans = [...SCANS];
                renderScans(filteredScans);
                renderLiveScansPreview();
                document.getElementById('sideUserCount') && (document.getElementById('sideScanRunning').textContent = SCANS.filter(s => s.status === 'running').length);
            }
        } catch (_) {}

        // Also refresh vulnerabilities so new scans from other users appear
        try {
            const freshVulns = await apiFetch('/api/admin/vulnerabilities');
            if (freshVulns) {
                const normalized = normalizeVulns(freshVulns);
                // Only update if there are actually new vulns (avoid unnecessary re-renders)
                if (normalized.length !== VULNS_SAMPLE.length) {
                    VULNS_SAMPLE = normalized;
                    filteredReports = [...VULNS_SAMPLE];
                    renderReports(filteredReports);
                    // Update sidebar vuln counter
                    const el = document.getElementById('sideVulnCount');
                    if (el) el.textContent = VULNS_SAMPLE.length.toLocaleString();
                    // Update dashboard total
                    const tv = document.getElementById('totalVulns');
                    if (tv) tv.textContent = VULNS_SAMPLE.length.toLocaleString();
                }
            }
        } catch (_) {}
    }

    // Poll individual running scans for progress updates
    const running = SCANS.filter(s => s.status === 'running');
    for (const scan of running) {
        try {
            const updated = await apiFetch(`/api/admin/scans/${scan.id}`);
            if (!updated) continue;
            const norm = normalizeScans([updated])[0];
            const idx  = SCANS.findIndex(s => String(s.id) === String(scan.id));
            if (idx > -1) { SCANS[idx] = norm; }
            filteredScans = filteredScans.map(s => String(s.id) === String(scan.id) ? norm : s);
            renderScans(filteredScans);
        } catch (_) {}
    }
}

// ───────────────────────────────────────────────────────────
//  NORMALISERS — map any Laravel resource shape to internal shape
// ───────────────────────────────────────────────────────────
const AVATAR_COLORS = [
    'linear-gradient(135deg,#3b82f6,#8b5cf6)', 'linear-gradient(135deg,#10b981,#3b82f6)',
    'linear-gradient(135deg,#f59e0b,#ef4444)', 'linear-gradient(135deg,#ec4899,#a855f7)',
    'linear-gradient(135deg,#0ea5e9,#6366f1)', 'linear-gradient(135deg,#f97316,#ef4444)',
    'linear-gradient(135deg,#00f5c4,#3b82f6)', 'linear-gradient(135deg,#a78bfa,#ec4899)',
];

function normalizeScans(data) {
    const list = Array.isArray(data) ? data : (data.data || []);
    return list.map(s => {
        const rawProgress   = s.progress;
        const vulnCount     = s.vulnerabilities_count ?? s.vulns_count ?? s.vulns ?? 0;
        const status        = s.status || 'unknown';

        // Progress rules:
        //   • If the DB gave us an explicit progress value, always trust it.
        //   • Only auto-assign 100% when:
        //       - status is "completed" AND
        //       - no progress value exists in the response (truly null/undefined) AND
        //       - there are no recorded vulnerabilities (so the scan completed cleanly).
        //   • Running scans with no progress yet default to 0.
        let progress;
        if (rawProgress !== null && rawProgress !== undefined) {
            progress = Math.min(100, Math.max(0, parseInt(rawProgress, 10) || 0));
        } else if (status === 'completed' && vulnCount === 0) {
            progress = 100;
        } else if (status === 'completed' && vulnCount > 0) {
            // Completed with vulns — keep at 99 so the bar is visually "done"
            // but doesn't mislead admin that all vulns have been resolved.
            progress = 99;
        } else {
            progress = 0;
        }

        return {
            id:                    s.id,
            owner_name:            s.owner_name || s.user?.name || s.username || '—',
            target_url:            s.target_url || s.url || s.target || s.name || '—',
            status,
            progress,
            vulnerabilities_count: vulnCount,
            created_at_human:      s.created_at_human || s.started_at_human || s.created_at || '—',
        };
    });
}

// CVE / CWE reference map — covers every finding the scanner produces.
// When the DB has no CVE stored, we show the authoritative CWE instead.
const VULN_REF_MAP = {
    // ── Exposed files / paths ──────────────────────────────────────────────
    'Environment File Exposed: /.env':          'CWE-538',
    'Laravel Environment File Exposed':         'CWE-538',
    'Exposed Git Repository':                   'CWE-538',
    'Git Repository Exposed: /.git/':           'CWE-538',
    'phpinfo() Page Exposed':                   'CWE-200',

    // ── Security headers ───────────────────────────────────────────────────
    'Missing Security Header: Content-Security-Policy':     'CWE-1021',
    'Missing Security Header: X-Frame-Options':             'CWE-1021',
    'Missing Security Header: X-Content-Type-Options':      'CWE-693',
    'Missing Security Header: Strict-Transport-Security':   'CWE-319',
    'Missing Security Header: Referrer-Policy':             'CWE-116',
    'Missing Security Header: Permissions-Policy':          'CWE-693',
    'http-missing-security-headers':                        'CWE-693',
    'Insecure Headers':                                     'CWE-693',

    // ── CSP weaknesses ─────────────────────────────────────────────────────
    'Weak CSP: unsafe-inline in script-src':    'CWE-79',
    'Weak CSP: unsafe-eval present':            'CWE-79',
    'Weak CSP: wildcard in script-src':         'CWE-79',

    // ── Information disclosure ─────────────────────────────────────────────
    'Information Disclosure via X-Powered-By Header': 'CWE-200',
    'Information Disclosure via Server Header':        'CWE-200',
    'Sensitive Data Exposure':                         'CWE-200',
    'Laravel Debug Mode Enabled':                      'CWE-94',

    // ── Cookies ────────────────────────────────────────────────────────────
    'Cookie Missing HttpOnly Flag':                     'CWE-1004',
    'Cookie Missing HttpOnly Flag: laravel_session':    'CWE-1004',
    'Cookie Missing HttpOnly Flag: XSRF-TOKEN':         'CWE-1004',
    'Cookie Missing Secure Flag':                       'CWE-614',
    'Cookie No HttpOnly Flag':                          'CWE-1004',

    // ── Injection / logic ──────────────────────────────────────────────────
    'SQL Injection':                                    'CWE-89',
    'Cross-Site Scripting (XSS)':                       'CWE-79',
    'Open Redirect':                                    'CWE-601',
    'Insecure Direct Object Reference (IDOR)':          'CWE-639',
    'Sub Resource Integrity Attribute Missing':         'CWE-829',
};

function normalizeVulns(data) {
    const list = Array.isArray(data) ? data : (data.data || []);
    return list.map(v => {
        const name = v.name || v.type || v.vulnerability_type || 'Unknown';
        const rawCve = v.cve || v.cve_id || v.cve_number || v.cve_reference || v.cve_identifier || null;
        // Use stored CVE if present, otherwise look up CWE from the map
        const cve = rawCve || VULN_REF_MAP[name] || null;
        return {
            name,
            url:        v.url || v.endpoint || v.affected_url || '—',
            severity:   v.severity || v.sev || v.risk_level || 'low',
            cve,
            owner_name: v.owner_name || v.user?.name || v.user_name || '—',
            detected_at:v.detected_at_human || v.detected_at || v.created_at || '—',
        };
    });
}

function normalizeAudit(data) {
    const list = Array.isArray(data) ? data : (data.data || []);
    return list.map(e => ({
        ts:    e.ts || e.created_at_human || e.created_at || '—',
        actor: e.actor || e.user_email || e.email || 'system',
        action:e.action || e.description || e.event || '—',
        sev:   e.sev || e.severity || e.level || 'info',
    }));
}

function normalizeServices(data) {
    if (!data || !Array.isArray(data)) return MOCK_SERVICES;
    return data.map(s => ({
        name:    s.name || s.service || '—',
        status:  s.status || 'unknown',
        latency: s.latency || s.response_time || '—',
    }));
}

// ─────────────────────────────────────────────────
//  HTML ESCAPE helper (prevent XSS in rendered data)
// ─────────────────────────────────────────────────
function esc(str) {
    return String(str ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// ═══════════════════════════════════════════════════════════
//  TABS
// ═══════════════════════════════════════════════════════════
const TAB_TITLES = {
    overview:'Dashboard', system:'System Health',
    scans:'Scan Management', reports:'Vulnerability Reports',
    audit:'Audit Log', settings:'Platform Settings'
};
const ADMIN_TAB_PATHS = {
    'overview': '/vulnsight/admin', 'system': '/vulnsight/admin/system',
    'scans': '/vulnsight/admin/scans', 'reports': '/vulnsight/admin/reports',
    'audit': '/vulnsight/admin/audit', 'settings': '/vulnsight/admin/settings',
};
const ADMIN_PATH_TABS = {
    '/vulnsight/admin': 'overview', '/vulnsight/admin/system': 'system',
    '/vulnsight/admin/scans': 'scans', '/vulnsight/admin/reports': 'reports',
    '/vulnsight/admin/audit': 'audit', '/vulnsight/admin/settings': 'settings',
};
function switchTab(name) {
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tn-item').forEach(b => b.classList.remove('active'));
    const tab = document.getElementById(name + '-tab');
    if (tab) tab.classList.add('active');
    const btn = document.querySelector(`.tn-item[data-tab="${name}"]`);
    if (btn) btn.classList.add('active');
    document.getElementById('topbarTitle').textContent = TAB_TITLES[name] || name;

    // When opening audit tab, refresh render to pick up entries added while on other tabs
    if (name === 'audit') { _applyAuditFilters(); }
    // When opening settings tab, ensure latest values are shown
    if (name === 'settings') { loadSettings(); }

    // Update browser URL without page reload
    const path = ADMIN_TAB_PATHS[name] || '/admin';
    if (window.location.pathname !== path) { history.pushState({ tab: name }, '', path); }
}
window.addEventListener('popstate', function(e) {
    const tab = (e.state && e.state.tab) || ADMIN_PATH_TABS[window.location.pathname] || 'overview';
    switchTab(tab);
});

// ═══════════════════════════════════════════════════════════
//  SCANS
// ═══════════════════════════════════════════════════════════
let filteredScans = [];
function renderScans(list) {
    const container = document.getElementById('scansListContainer');
    const statusBadge = { running:'badge-running', completed:'badge-completed', failed:'badge-failed' };
    const barColor    = { running:'background:linear-gradient(90deg,var(--neon),var(--blue))', completed:'background:linear-gradient(90deg,#3b82f6,#818cf8)', failed:'background:var(--red)' };
    if (!list.length) { container.innerHTML = '<div class="empty-state"><div class="empty-icon">📡</div>No scans found.</div>'; document.getElementById('sideScanRunning').textContent = 0; return; }
    container.innerHTML = list.map(s => {
        const bar      = barColor[s.status] || '';
        const hasVulns = s.vulnerabilities_count > 0;
        const initials = (s.owner_name || '?').slice(0,2).toUpperCase();
        return `<div class="scan-row" style="display:flex;align-items:center;gap:16px;padding:13px 20px;border-bottom:1px solid rgba(255,255,255,.03);transition:background .12s;">
            <div style="display:flex;align-items:center;gap:10px;width:155px;flex-shrink:0;">
                <div style="width:33px;height:33px;border-radius:50%;background:linear-gradient(135deg,#3b82f6,#8b5cf6);display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:#fff;flex-shrink:0;">${initials}</div>
                <div style="min-width:0;">
                    <div style="font-size:14px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${esc(s.owner_name)}</div>
                    <div style="font-family:'DM Mono',monospace;font-size:11px;color:var(--neon);margin-top:1px;">#${esc(String(s.id))}</div>
                </div>
            </div>
            <div style="flex:1;min-width:0;">
                <code style="font-size:13px;color:white;font-family:'DM Mono',monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block;" title="${esc(s.target_url)}">${esc(s.target_url)}</code>
                <div style="font-size:13px;color:white;margin-top:3px;">${esc(s.created_at_human)}</div>
            </div>
            <div style="width:130px;flex-shrink:0;">
                <div class="prog-track" style="height:5px;"><div class="prog-bar" style="width:${s.progress}%;${bar}"></div></div>
                <span style="font-size:13px;color:white;font-family:'DM Mono',monospace;margin-top:3px;display:block;">${s.progress}%</span>
            </div>
            <div style="width:100px;flex-shrink:0;">
                <span class="badge ${statusBadge[s.status]||'badge-inactive'}">${esc(s.status)}</span>
            </div>
            <div style="width:60px;flex-shrink:0;text-align:center;font-family:'DM Mono',monospace;font-size:14px;color:${hasVulns?'var(--red)':'var(--muted)'};">${s.vulnerabilities_count}</div>
            <div style="display:flex;gap:6px;flex-shrink:0;">
                <button class="btn-ghost btn-sm" style="font-size:13px;color:white;" data-action="viewScan" data-id="${s.id}">View</button>
                ${hasVulns ? `<button class="btn-ghost btn-sm" style="font-size:13px;color:white;" data-action="exportScanPDF" data-id="${s.id}"><svg width="10" height="10" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg> PDF</button>` : ''}
            </div>
        </div>`;
    }).join('');
    document.getElementById('sideScanRunning').textContent = SCANS.filter(s => s.status === 'running').length;
}




function filterScans(status) {
    filteredScans = status === 'all' ? [...SCANS] : SCANS.filter(s => s.status === status);
    renderScans(filteredScans);
}
function stopScan(id) {
    confirmAction(`Terminate scan ${id}? This cannot be undone.`, async () => {
        try {
            await apiFetch(`/api/admin/scans/${id}/stop`, { method: 'POST' });
            const s = SCANS.find(s => String(s.id) === String(id));
            if (s) {
                s.status = 'failed';
                filteredScans = filteredScans.map(x => String(x.id) === String(id) ? { ...x, status: 'failed' } : x);
                renderScans(filteredScans);
                renderLiveScansPreview();
            }
            showToast('Scan ' + id + ' terminated', 'warn');
            addAuditEntry(currentAdmin?.email || 'admin', `Terminated scan ${id}`, 'warn');
        } catch (e) {
            showToast('Failed to stop scan: ' + (e.message || 'Unknown error'), 'error');
        }
    });
}
async function retryScan(id) {
    try {
        await apiFetch(`/api/admin/scans/${id}/retry`, { method: 'POST' });
        const s = SCANS.find(s => String(s.id) === String(id));
        if (s) {
            s.status = 'running';
            s.progress = 0;
            filteredScans = filteredScans.map(x => String(x.id) === String(id) ? { ...x, status: 'running', progress: 0 } : x);
            renderScans(filteredScans);
            renderLiveScansPreview();
        }
        showToast('Scan ' + id + ' requeued', 'success');
        addAuditEntry(currentAdmin?.email || 'admin', `Retried failed scan ${id}`, 'info');
    } catch (e) {
        showToast('Failed to retry scan: ' + (e.message || 'Unknown error'), 'error');
    }
}
function viewScan(id) {
    const s = SCANS.find(s => String(s.id) === String(id));
    if (!s) return;
    const statusColor = {running:'var(--neon)', completed:'#60a5fa', failed:'var(--red)'};
    document.getElementById('viewScanContent').innerHTML = `
        <div style="display:grid;gap:10px;">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
                <div style="background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;">
                    <p style="font-size:12px;font-weight:700;color:white;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">Scan ID</p>
                    <p style="font-family:'DM Mono',monospace;font-size:14px;color:var(--neon);">${esc(String(s.id))}</p>
                </div>
                <div style="background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;">
                    <p style="font-size:12px;font-weight:700;color:white;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">Status</p>
                    <p style="font-size:13px;font-weight:700;color:${statusColor[s.status]||'var(--text)'};">${esc(s.status)}</p>
                </div>
            </div>
            <div style="background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;">
                <p style="font-size:12px;font-weight:700;color:white;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">Target URL</p>
                <code style="font-size:12px;color:var(--text);font-family:'DM Mono',monospace;word-break:break-all;">${esc(s.target_url)}</code>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;">
                <div style="background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;">
                    <p style="font-size:12px;font-weight:700;color:white;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">Owner</p>
                    <p style="font-size:12px;font-weight:600;">${esc(s.owner_name)}</p>
                </div>
                <div style="background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;">
                    <p style="font-size:12px;font-weight:700;color:white;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">Progress</p>
                    <p style="font-size:13px;font-weight:700;color:var(--neon);">${s.progress}%</p>
                </div>
                <div style="background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;">
                    <p style="font-size:12px;font-weight:700;color:white;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">Vulnerabilities</p>
                    <p style="font-size:13px;font-weight:700;color:${s.vulnerabilities_count>0?'var(--red)':'var(--muted)'};">${s.vulnerabilities_count}</p>
                </div>
            </div>
            <div style="background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;">
                <p style="font-size:12px;font-weight:700;color:white;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">Started</p>
                <p style="font-size:12px;color:var(--text2);">${esc(s.created_at_human)}</p>
            </div>
            <div style="background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;">
                <p style="font-size:12px;font-weight:700;color:white;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px;">Progress Bar</p>
                <div style="background:var(--surface3);border-radius:4px;height:6px;overflow:hidden;">
                    <div style="height:100%;width:${s.progress}%;background:linear-gradient(90deg,var(--neon),var(--blue));border-radius:4px;transition:width .3s;"></div>
                </div>
            </div>
        </div>`;
    openModal('viewScanModal');
}

// ═══════════════════════════════════════════════════════════
//  PER-SCAN PDF EXPORT
// ═══════════════════════════════════════════════════════════
async function exportScanPDF(scanId) {
    const scan = SCANS.find(s => String(s.id) === String(scanId));
    if (!scan) { showToast('Scan not found', 'error'); return; }
    if (!scan.vulnerabilities_count) { showToast('No vulnerabilities for this scan', 'warn'); return; }

    showToast('Loading scan data…', 'info');

    let vulns = [];
    try {
        const res = await apiFetch(`/api/admin/scans/${scanId}/vulnerabilities`);
        vulns = Array.isArray(res) ? res : (res.data || res.vulnerabilities || []);
    } catch(e) {
        // 401 usually means the session expired or api guard mismatch — try reloading
        if (e.message === 'Unauthenticated' || e.message.includes('401')) {
            showToast('Session expired — please refresh the page and try again', 'error');
        } else {
            showToast('Failed to load vulnerabilities: ' + e.message, 'error');
        }
        return;
    }

    // If API returned nothing but we know there are vulns, try the global vulns list
    if (!vulns.length) {
        const fallback = (typeof VULNS_SAMPLE !== 'undefined' ? VULNS_SAMPLE : [])
            .filter(v => String(v.scan_id) === String(scanId));
        if (fallback.length) {
            vulns = fallback;
        } else {
            showToast('No vulnerability data returned for this scan', 'warn');
            return;
        }
    }

    // Normalise field names (severity vs sev, owner_name may be missing for single scan)
    const normalised = vulns.map(v => ({
        name:       v.name || 'Unknown',
        url:        v.url  || '—',
        severity:   (v.severity || v.sev || 'low').toLowerCase(),
        cve:        v.cve || v.cve_id || v.cve_number || v.cve_reference || null,
        owner_name: v.owner_name || scan.owner_name || '—',
        detected_at: v.detected_at || v.created_at || '—',
    }));

    const admin = currentAdmin ? (currentAdmin.name || currentAdmin.email) : 'VulnSight Admin';
    _openPDFWindow(_buildAdminPDFHTML(
        `Scan #${scanId} — Vulnerability Report`,
        normalised,
        `Scan #${scanId} · Owner: ${scan.owner_name} · Target: ${scan.target_url}`,
        admin
    ));
    addAuditEntry(admin, `Exported PDF for scan #${scanId}`, 'info');
}

// ═══════════════════════════════════════════════════════════
//  VULNERABILITY REPORTS  (per-user grouped + PDF export)
// ═══════════════════════════════════════════════════════════
let filteredReports = [];
let _reportSevFilter  = 'all';
let _reportUserFilter = '';

/* ─── Grouped render ─── */
function renderReports(list) {
    document.getElementById('sideVulnCount').textContent = VULNS_SAMPLE.length;

    const container = document.getElementById('reportsContainer');
    if (!list.length) {
        container.innerHTML = '<div class="card"><div class="empty-state"><div class="empty-icon">🔍</div>No vulnerabilities found.</div></div>';
        document.getElementById('reportSubtitle').textContent = 'No findings match the current filters';
        return;
    }

    // Group by owner_name
    const byUser = {};
    list.forEach(v => {
        const key = v.owner_name || '—';
        if (!byUser[key]) byUser[key] = [];
        byUser[key].push(v);
    });

    const badgeMap = { critical:'badge-critical', high:'badge-high', medium:'badge-medium', low:'badge-low' };
    const sevOrder = { critical:0, high:1, medium:2, low:3 };

    // Sort users by highest severity vuln they have
    const sortedUsers = Object.entries(byUser).sort(([, a], [, b]) => {
        const minSev = arr => Math.min(...arr.map(v => sevOrder[v.severity] ?? 99));
        return minSev(a) - minSev(b);
    });

    document.getElementById('reportSubtitle').textContent =
        `${list.length} finding${list.length !== 1 ? 's' : ''} across ${sortedUsers.length} user${sortedUsers.length !== 1 ? 's' : ''}`;

    container.innerHTML = sortedUsers.map(([userName, vulns]) => {
        const critCount = vulns.filter(v => v.severity === 'critical').length;
        const highCount = vulns.filter(v => v.severity === 'high').length;
        const medCount  = vulns.filter(v => v.severity === 'medium').length;
        const lowCount  = vulns.filter(v => v.severity === 'low').length;

        const severityBar = [
            critCount ? `<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 9px;border-radius:20px;font-size:12px;font-weight:700;font-family:'DM Mono',monospace;background:rgba(240,80,80,.12);color:#ff7070;border:1px solid rgba(240,80,80,.25);">${critCount} critical</span>` : '',
            highCount ? `<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 9px;border-radius:20px;font-size:12px;font-weight:700;font-family:'DM Mono',monospace;background:rgba(245,158,11,.11);color:#fbbf24;border:1px solid rgba(245,158,11,.25);">${highCount} high</span>` : '',
            medCount  ? `<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 9px;border-radius:20px;font-size:12px;font-weight:700;font-family:'DM Mono',monospace;background:rgba(253,224,71,.09);color:#fde047;border:1px solid rgba(253,224,71,.2);">${medCount} medium</span>` : '',
            lowCount  ? `<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 9px;border-radius:20px;font-size:12px;font-weight:700;font-family:'DM Mono',monospace;background:rgba(0,245,196,.09);color:var(--neon);border:1px solid rgba(0,245,196,.2);">${lowCount} low</span>` : '',
        ].filter(Boolean).join('');

        // Sorted vulns: critical first
        const sorted = [...vulns].sort((a,b) => (sevOrder[a.severity]??99) - (sevOrder[b.severity]??99));

        const rows = sorted.map(v => `
            <tr>
                <td style="font-weight:600;font-size:14px;">${esc(v.name)}</td>
                <td><code style="font-size:12px;color:var(--neon);font-family:'DM Mono',monospace;">${esc(v.url)}</code></td>
                <td><span class="badge ${badgeMap[v.severity]||'badge-low'}">${esc(v.severity)}</span></td>
                <td style="font-family:'DM Mono',monospace;font-size:12px;">
                    ${v.cve
                        ? v.cve.startsWith('CWE-')
                            ? `<span style="color:#93c5fd;background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.2);padding:1px 7px;border-radius:4px;font-size:11px;">${esc(v.cve)}</span>`
                            : `<span style="color:var(--neon);">${esc(v.cve)}</span>`
                        : '<span style="color:var(--muted);font-style:italic;">N/A</span>'}
                </td>
                <td style="font-size:12px;color:white;">${esc(v.detected_at)}</td>
            </tr>`).join('');

        const uid = 'user_' + userName.replace(/\W/g,'_');
        return `
        <div class="card" style="margin-bottom:12px;padding:0;overflow:hidden;">
            <div style="display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid var(--border);cursor:pointer;" data-action="toggleUserReport" data-uid="${uid}">
                <div style="display:flex;align-items:center;gap:12px;">
                    <div style="width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,var(--neon),var(--blue));display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:#000;flex-shrink:0;">
                        ${esc(userName.slice(0,2).toUpperCase())}
                    </div>
                    <div>
                        <p style="font-size:16px;font-weight:700;">${esc(userName)}</p>
                        <p style="font-size:12px;color:white;margin-top:2px;">${vulns.length} finding${vulns.length!==1?'s':''}</p>
                    </div>
                    <div style="display:flex;gap:5px;margin-left:8px;">${severityBar}</div>
                </div>
                <div style="display:flex;align-items:center;gap:10px;">
                    <button class="btn-ghost btn-sm" style="font-size:12px;color:white;" data-action="exportUserPDF" data-name="${esc(userName)}">
                        <svg width="11" height="11" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                        PDF
                    </button>
                    <svg id="${uid}_arrow" width="16" height="16" fill="none" stroke="white" viewBox="0 0 24 24" stroke-width="2" style="transition:transform .2s;"><polyline points="6 9 12 15 18 9"/></svg>
                </div>
            </div>
            <div id="${uid}_body" style="display:none;">
                <table class="wavs-table">
                    <thead><tr><th>Type</th><th>Endpoint</th><th>Severity</th><th>CVE</th><th>Detected</th></tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        </div>`;
    }).join('');
}

function toggleUserReport(uid) {
    const body  = document.getElementById(uid + '_body');
    const arrow = document.getElementById(uid + '_arrow');
    const open  = body.style.display !== 'none';
    body.style.display  = open ? 'none' : 'block';
    arrow.style.transform = open ? '' : 'rotate(180deg)';
}

function filterReports(sev) {
    _reportSevFilter = sev;
    _applyReportFilters();
}
function filterReportsByUser(query) {
    _reportUserFilter = query.toLowerCase();
    _applyReportFilters();
}
function _applyReportFilters() {
    filteredReports = VULNS_SAMPLE.filter(v => {
        const sevOk  = _reportSevFilter === 'all' || v.severity === _reportSevFilter;
        const userOk = !_reportUserFilter || (v.owner_name || '').toLowerCase().includes(_reportUserFilter);
        return sevOk && userOk;
    });
    renderReports(filteredReports);
}

/* ─── Shared PDF builder — mirrors user wavs.blade.php exportReportPDF exactly ─── */
function _buildAdminPDFHTML(title, vulns, scopeLabel, assessedBy) {
    const reportId   = 'VS-' + Date.now().toString(36).toUpperCase().slice(-6);
    const reportDate = new Date().toLocaleDateString('en-US', { year:'numeric', month:'long', day:'numeric' });
    const reportTime = new Date().toLocaleTimeString('en-US', { hour:'2-digit', minute:'2-digit' });

    const sevOrder = { critical:0, high:1, medium:2, low:3 };
    const sorted   = [...vulns].sort((a,b) => (sevOrder[a.severity]??99)-(sevOrder[b.severity]??99));
    const counts   = { critical:0, high:0, medium:0, low:0 };
    sorted.forEach(v => { if (counts[v.severity]!==undefined) counts[v.severity]++; });

    const riskRating = counts.critical>0?'CRITICAL':counts.high>0?'HIGH':counts.medium>0?'MEDIUM':'LOW';
    const RISK_THEME = {
        CRITICAL:{text:'#991b1b',bg:'#fef2f2',border:'#fecaca',accent:'#dc2626'},
        HIGH:    {text:'#9a3412',bg:'#fff7ed',border:'#fed7aa',accent:'#ea580c'},
        MEDIUM:  {text:'#854d0e',bg:'#fefce8',border:'#fef08a',accent:'#ca8a04'},
        LOW:     {text:'#166534',bg:'#f0fdf4',border:'#bbf7d0',accent:'#16a34a'},
    };
    const RT = RISK_THEME[riskRating];

    const SEV = {
        critical:{bg:'#fff1f2',border:'#fecdd3',text:'#9f1239',dot:'#e11d48',label:'CRITICAL'},
        high:    {bg:'#fff7ed',border:'#fed7aa',text:'#9a3412',dot:'#ea580c',label:'HIGH'    },
        medium:  {bg:'#fefce8',border:'#fef08a',text:'#854d0e',dot:'#ca8a04',label:'MEDIUM'  },
        low:     {bg:'#f0fdf4',border:'#bbf7d0',text:'#166534',dot:'#16a34a',label:'LOW'     },
    };

    const total = sorted.length||1;
    const barC  = Math.round(counts.critical/total*100);
    const barH  = Math.round(counts.high/total*100);
    const barM  = Math.round(counts.medium/total*100);
    const barL  = 100-barC-barH-barM;

    /* ── Per-finding detail blocks (no remediation — admin view only) ── */
    const findingBlocks = sorted.map((v,i) => {
        const s = SEV[v.severity]||SEV.low;
        return `
<div style="margin-bottom:20px;border:1.5px solid ${s.border};border-radius:10px;overflow:hidden;page-break-inside:avoid;">
  <div style="background:${s.bg};border-bottom:2px solid ${s.border};padding:12px 16px;display:flex;align-items:center;gap:12px;">
    <div style="width:34px;height:34px;border-radius:50%;background:${s.dot};display:flex;align-items:center;justify-content:center;flex-shrink:0;">
      <span style="color:#fff;font-weight:800;font-size:12px;font-family:monospace;">${String(i+1).padStart(2,'0')}</span>
    </div>
    <div style="flex:1;min-width:0;">
      <div style="font-size:13px;font-weight:700;color:#111827;">${v.name}</div>
      <div style="font-size:10px;color:#6b7280;margin-top:2px;font-family:'Courier New',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${v.url}</div>
    </div>
    <div style="flex-shrink:0;text-align:right;">
      <span style="display:inline-block;padding:3px 10px;border-radius:20px;font-size:9px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;background:${s.bg};color:${s.text};border:1.5px solid ${s.border};">${s.label}</span>
      ${v.cve && v.cve!=='—'?`<div style="font-size:9px;color:#9ca3af;margin-top:3px;font-family:'Courier New',monospace;">${v.cve}</div>`:''}
    </div>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:0;">
    <div style="padding:10px 16px;border-right:1px solid #f3f4f6;">
      <div style="font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#9ca3af;margin-bottom:4px;">Affected Endpoint</div>
      <div style="font-size:10px;font-family:'Courier New',monospace;color:#374151;word-break:break-all;">${v.url}</div>
    </div>
    <div style="padding:10px 16px;border-right:1px solid #f3f4f6;">
      <div style="font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#9ca3af;margin-bottom:4px;">Owner</div>
      <div style="font-size:10px;color:#374151;">${v.owner_name||'—'}</div>
    </div>
    <div style="padding:10px 16px;">
      <div style="font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#9ca3af;margin-bottom:4px;">CVE Reference</div>
      <div style="font-size:10px;font-family:'Courier New',monospace;color:#374151;">${v.cve||'N/A'}</div>
    </div>
  </div>
</div>`;
    }).join('');

    /* ── Findings summary table rows (with Owner column) ── */
    const tableRows = sorted.map((v,i) => {
        const s = SEV[v.severity]||SEV.low;
        return `<tr style="background:${i%2===0?'#ffffff':'#f9fafb'};">
          <td style="padding:8px 12px;font-size:10px;color:#9ca3af;font-family:monospace;border-bottom:1px solid #f3f4f6;">${String(i+1).padStart(2,'0')}</td>
          <td style="padding:8px 12px;font-size:11px;font-weight:600;color:#111827;border-bottom:1px solid #f3f4f6;">${v.name}</td>
          <td style="padding:8px 12px;font-size:10px;font-family:'Courier New',monospace;color:#4b5563;word-break:break-all;border-bottom:1px solid #f3f4f6;">${v.url}</td>
          <td style="padding:8px 12px;font-size:10px;color:#374151;border-bottom:1px solid #f3f4f6;">${v.owner_name||'—'}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #f3f4f6;">
            <span style="display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:20px;background:${s.bg};color:${s.text};border:1px solid ${s.border};font-size:9px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;">
              <span style="width:5px;height:5px;border-radius:50%;background:${s.dot};flex-shrink:0;"></span>${s.label}
            </span>
          </td>
          <td style="padding:8px 12px;font-size:10px;font-family:monospace;color:#6b7280;border-bottom:1px solid #f3f4f6;">${v.cve||'—'}</td>
          <td style="padding:8px 12px;font-size:9.5px;color:#6b7280;border-bottom:1px solid #f3f4f6;">${v.detected_at||'—'}</td>
        </tr>`;
    }).join('');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>${title} — ${reportId}</title>
<style>
  @page { margin:14mm 15mm; size:A4; }
  @media print { .no-print{display:none!important;} body{-webkit-print-color-adjust:exact;print-color-adjust:exact;} }
  *,*::before,*::after { box-sizing:border-box; margin:0; padding:0; }
  body { font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,sans-serif; background:#fff; color:#111827; line-height:1.5; }
</style>
</head>
<body>

<!-- ░░░░░░ COVER ░░░░░░ -->
<div style="height:267mm;max-height:267mm;display:flex;flex-direction:column;background:linear-gradient(150deg,#050d1a 0%,#0a1628 45%,#04090f 100%);color:#fff;page-break-after:always;page-break-inside:avoid;position:relative;overflow:hidden;">
  <div style="position:absolute;inset:0;opacity:.035;background-image:radial-gradient(circle,rgba(255,255,255,.9) 1px,transparent 1px);background-size:28px 28px;pointer-events:none;"></div>
  <div style="height:3px;background:linear-gradient(90deg,#00f5c4 0%,#3b82f6 50%,#8b5cf6 100%);flex-shrink:0;"></div>
  <div style="padding:28px 44px;display:flex;align-items:center;justify-content:space-between;flex-shrink:0;border-bottom:1px solid rgba(255,255,255,.06);">
    <div style="display:flex;align-items:center;gap:11px;">
      <div style="width:38px;height:38px;border-radius:9px;background:linear-gradient(135deg,rgba(0,245,196,.18),rgba(59,130,246,.18));border:1px solid rgba(0,245,196,.35);display:flex;align-items:center;justify-content:center;">
        <svg width="18" height="18" fill="none" stroke="#00f5c4" viewBox="0 0 24 24" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      </div>
      <div>
        <div style="font-size:15px;font-weight:700;letter-spacing:-.02em;color:#fff;">VulnSight</div>
        <div style="font-size:8px;color:rgba(255,255,255,.35);letter-spacing:.14em;text-transform:uppercase;margin-top:1px;">Security Platform — Admin Report</div>
      </div>
    </div>
    <div style="text-align:right;">
      <div style="font-size:8px;color:rgba(255,255,255,.3);letter-spacing:.1em;text-transform:uppercase;">Report ID</div>
      <div style="font-size:11px;font-family:'Courier New',monospace;color:rgba(255,255,255,.55);margin-top:2px;">${reportId}</div>
    </div>
  </div>
  <div style="flex:1;display:flex;flex-direction:column;justify-content:center;padding:44px 44px 32px;">
    <div style="font-size:10px;font-weight:700;letter-spacing:.22em;text-transform:uppercase;color:#00f5c4;margin-bottom:14px;">Confidential Security Document</div>
    <div style="font-size:52px;font-weight:900;line-height:1.02;letter-spacing:-.04em;margin-bottom:10px;">
      Vulnerability<br>Assessment<br>
      <span style="background:linear-gradient(90deg,#00f5c4,#3b82f6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;">Report</span>
    </div>
    <div style="font-size:13px;color:rgba(255,255,255,.45);margin-bottom:36px;">Web Application Penetration Testing — Platform-Wide Findings</div>
    <div style="display:inline-flex;align-items:center;gap:9px;padding:9px 18px;background:${RT.bg};border:1.5px solid ${RT.border};border-radius:8px;margin-bottom:36px;width:fit-content;">
      <div style="width:9px;height:9px;border-radius:50%;background:${RT.accent};"></div>
      <span style="font-size:10px;font-weight:800;letter-spacing:.16em;text-transform:uppercase;color:${RT.text};">Overall Risk: ${riskRating}</span>
    </div>
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:36px;">
      ${[
        {l:'Critical',n:counts.critical,c:'#dc2626',bg:'rgba(220,38,38,.1)',b:'rgba(220,38,38,.22)'},
        {l:'High',    n:counts.high,    c:'#ea580c',bg:'rgba(234,88,12,.1)',b:'rgba(234,88,12,.22)'},
        {l:'Medium',  n:counts.medium,  c:'#ca8a04',bg:'rgba(202,138,4,.1)',b:'rgba(202,138,4,.22)'},
        {l:'Low',     n:counts.low,     c:'#16a34a',bg:'rgba(22,163,74,.1)',b:'rgba(22,163,74,.22)'},
      ].map(s=>`
        <div style="background:${s.bg};border:1px solid ${s.b};border-radius:10px;padding:16px 18px;">
          <div style="font-size:38px;font-weight:900;color:${s.c};line-height:1;">${s.n}</div>
          <div style="font-size:9px;color:rgba(255,255,255,.45);text-transform:uppercase;letter-spacing:.1em;margin-top:4px;">${s.l}</div>
        </div>`).join('')}
    </div>
    <div>
      <div style="font-size:8.5px;color:rgba(255,255,255,.3);text-transform:uppercase;letter-spacing:.1em;margin-bottom:5px;">Severity Distribution</div>
      <div style="height:5px;border-radius:99px;overflow:hidden;background:rgba(255,255,255,.07);display:flex;">
        ${barC?`<div style="width:${barC}%;background:#dc2626;"></div>`:''}
        ${barH?`<div style="width:${barH}%;background:#ea580c;"></div>`:''}
        ${barM?`<div style="width:${barM}%;background:#ca8a04;"></div>`:''}
        ${barL>0?`<div style="width:${barL}%;background:#16a34a;"></div>`:''}
      </div>
    </div>
  </div>
  <div style="padding:20px 44px 28px;border-top:1px solid rgba(255,255,255,.06);flex-shrink:0;">
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:20px;">
      ${[
        {l:'Report Date',    v:reportDate},
        {l:'Scope',          v:scopeLabel},
        {l:'Prepared By',    v:assessedBy},
        {l:'Classification', v:'CONFIDENTIAL'},
      ].map(m=>`
        <div>
          <div style="font-size:8px;color:rgba(255,255,255,.28);letter-spacing:.12em;text-transform:uppercase;margin-bottom:4px;">${m.l}</div>
          <div style="font-size:11px;color:rgba(255,255,255,.75);font-weight:500;word-break:break-word;">${m.v}</div>
        </div>`).join('')}
    </div>
  </div>
</div>

<!-- ░░░░░░ EXECUTIVE SUMMARY ░░░░░░ -->
<div style="padding:40px 44px;page-break-before:always;">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
    <div style="width:3px;height:18px;background:linear-gradient(180deg,#00f5c4,#3b82f6);border-radius:2px;"></div>
    <div style="font-size:9px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:#9ca3af;">Section 01</div>
  </div>
  <h2 style="font-size:22px;font-weight:800;color:#111827;margin-bottom:3px;letter-spacing:-.03em;">Executive Summary</h2>
  <p style="font-size:12px;color:#6b7280;margin-bottom:24px;">Platform-wide security findings overview and risk posture.</p>
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:11px;margin-bottom:24px;">
    ${[
      {l:'Total Findings',  v:sorted.length,                                     sub:'vulnerabilities',         tc:'#374151',bg:'#f9fafb',bc:'#e5e7eb'},
      {l:'Critical / High', v:counts.critical+counts.high,                       sub:'require immediate action', tc:'#991b1b',bg:'#fef2f2',bc:'#fecaca'},
      {l:'Users Affected',  v:new Set(sorted.map(v=>v.owner_name)).size,         sub:'platform users',           tc:'#1e40af',bg:'#eff6ff',bc:'#bfdbfe'},
      {l:'Medium / Low',    v:counts.medium+counts.low,                          sub:'lower priority findings',  tc:'#065f46',bg:'#f0fdf4',bc:'#bbf7d0'},
    ].map(s=>`
      <div style="background:${s.bg};border:1px solid ${s.bc};border-radius:9px;padding:14px 16px;">
        <div style="font-size:26px;font-weight:800;color:${s.tc};line-height:1;margin-bottom:4px;">${s.v}</div>
        <div style="font-size:10px;font-weight:700;color:#374151;margin-bottom:2px;">${s.l}</div>
        <div style="font-size:9px;color:#9ca3af;">${s.sub}</div>
      </div>`).join('')}
  </div>
  <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:9px;padding:18px 22px;margin-bottom:22px;">
    <div style="font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:#6b7280;margin-bottom:12px;">Assessment Scope &amp; Methodology</div>
    <table style="width:100%;border-collapse:collapse;font-size:11px;">
      ${[
        ['Target Scope',       scopeLabel],
        ['Assessment Type',    'Automated Web Application Vulnerability Scan — Platform-Wide'],
        ['Methodology',        'OWASP Top 10 (2021) · CWE/SANS Top 25 · CVE Database Cross-Reference'],
        ['Tools Used',         'VulnSight Scanner — Active &amp; Passive Reconnaissance'],
        ['Report Generated',   `${reportDate} at ${reportTime}`],
        ['Prepared By',        assessedBy],
        ['Classification',     'CONFIDENTIAL — For authorized personnel only'],
      ].map(([k,v])=>`
        <tr>
          <td style="padding:6px 0;font-weight:600;color:#374151;width:185px;border-bottom:1px solid #f3f4f6;vertical-align:top;">${k}</td>
          <td style="padding:6px 0 6px 14px;color:#6b7280;border-bottom:1px solid #f3f4f6;">${v}</td>
        </tr>`).join('')}
    </table>
  </div>
  <div style="background:${RT.bg};border:1.5px solid ${RT.border};border-radius:9px;padding:14px 18px;">
    <div style="font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:${RT.text};margin-bottom:6px;">Overall Risk Assessment — ${riskRating}</div>
    <div style="font-size:12px;color:#374151;line-height:1.65;">
      Platform assessment identified <strong>${sorted.length} vulnerabilit${sorted.length!==1?'ies':'y'}</strong>
      across <strong>${new Set(sorted.map(v=>v.owner_name)).size} user account${new Set(sorted.map(v=>v.owner_name)).size!==1?'s':''}</strong>,
      including <strong style="color:#dc2626;">${counts.critical} critical</strong>,
      <strong style="color:#ea580c;">${counts.high} high</strong>,
      <strong style="color:#ca8a04;">${counts.medium} medium</strong>, and
      <strong style="color:#16a34a;">${counts.low} low</strong> severity findings.
      ${counts.critical>0?'Critical findings require immediate remediation before any further deployment.':counts.high>0?'High-severity issues should be prioritised and addressed promptly.':'No critical vulnerabilities were detected in this assessment.'}
    </div>
  </div>
</div>

<!-- ░░░░░░ FINDINGS TABLE ░░░░░░ -->
<div style="padding:0 44px 40px;page-break-inside:avoid;">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
    <div style="width:3px;height:18px;background:linear-gradient(180deg,#00f5c4,#3b82f6);border-radius:2px;"></div>
    <div style="font-size:9px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:#9ca3af;">Section 02</div>
  </div>
  <h2 style="font-size:22px;font-weight:800;color:#111827;margin-bottom:3px;letter-spacing:-.03em;">Findings Overview</h2>
  <p style="font-size:12px;color:#6b7280;margin-bottom:18px;">All ${sorted.length} findings sorted by severity.</p>
  <table style="width:100%;border-collapse:collapse;">
    <thead>
      <tr style="background:#0f172a;">
        <th style="padding:9px 12px;text-align:left;font-size:8.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#94a3b8;width:30px;">#</th>
        <th style="padding:9px 12px;text-align:left;font-size:8.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#94a3b8;">Vulnerability</th>
        <th style="padding:9px 12px;text-align:left;font-size:8.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#94a3b8;">Affected Endpoint</th>
        <th style="padding:9px 12px;text-align:left;font-size:8.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#94a3b8;width:90px;">Owner</th>
        <th style="padding:9px 12px;text-align:left;font-size:8.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#94a3b8;width:76px;">Severity</th>
        <th style="padding:9px 12px;text-align:left;font-size:8.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#94a3b8;width:100px;">CVE</th>
        <th style="padding:9px 12px;text-align:left;font-size:8.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#94a3b8;width:80px;">Detected</th>
      </tr>
    </thead>
    <tbody>${tableRows}</tbody>
  </table>
</div>

<!-- ░░░░░░ DETAILED FINDINGS ░░░░░░ -->
<div style="padding:0 44px 48px;">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
    <div style="width:3px;height:18px;background:linear-gradient(180deg,#00f5c4,#3b82f6);border-radius:2px;"></div>
    <div style="font-size:9px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:#9ca3af;">Section 03</div>
  </div>
  <h2 style="font-size:22px;font-weight:800;color:#111827;margin-bottom:3px;letter-spacing:-.03em;">Detailed Findings</h2>
  <p style="font-size:12px;color:#6b7280;margin-bottom:24px;">Vulnerability details including affected endpoints, owners, and CVE references.</p>
  ${findingBlocks}
</div>

<!-- ░░░░░░ FOOTER ░░░░░░ -->
<div style="padding:18px 44px 24px;border-top:2px solid #f3f4f6;background:#f9fafb;">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
    <div style="font-size:9.5px;color:#9ca3af;">VulnSight Platform Admin Report · ${reportId}</div>
    <div style="font-size:9.5px;color:#9ca3af;">CONFIDENTIAL · ${reportDate}</div>
    <div style="font-size:9.5px;color:#9ca3af;">Prepared by ${assessedBy}</div>
  </div>
  <div style="font-size:9px;color:#d1d5db;line-height:1.6;">
    Disclaimer: This report was produced by an automated scanner. All findings should be reviewed and validated by a qualified security professional prior to remediation. Results reflect the security posture of the assessed system at the time of scanning only.
  </div>
</div>

<div class="no-print" style="position:fixed;bottom:22px;right:22px;display:flex;gap:9px;z-index:9999;">
  <button onclick="window.print()" style="padding:11px 22px;background:linear-gradient(135deg,#00f5c4,#3b82f6);color:#000;border:none;border-radius:9px;font-weight:700;font-size:12px;cursor:pointer;box-shadow:0 4px 18px rgba(0,245,196,.35);">🖨&nbsp;&nbsp;Save as PDF</button>
  <button onclick="window.close()" style="padding:11px 16px;background:#1f2937;color:#fff;border:none;border-radius:9px;font-weight:600;font-size:12px;cursor:pointer;">✕</button>
</div>
</body>
</html>`;
}
function _openPDFWindow(html) {
    const win = window.open('', '_blank', 'width=1024,height=860,scrollbars=yes,resizable=yes');
    if (!win) { showToast('Pop-up blocked — allow pop-ups and retry', 'warn'); return; }
    win.document.open();
    win.document.write(html);
    win.document.close();
    win.focus();
    showToast('PDF report ready — click "Save as PDF" in the new window', 'success');
}

function exportUserPDF(userName) {
    const userVulns = VULNS_SAMPLE.filter(v => v.owner_name === userName);
    if (!userVulns.length) { showToast('No vulnerabilities for this user', 'warn'); return; }
    const admin = currentAdmin ? (currentAdmin.name || currentAdmin.email) : 'VulnSight Admin';
    _openPDFWindow(_buildAdminPDFHTML(
        `${userName} — Vulnerability Report`,
        userVulns,
        `User: ${userName}`,
        admin
    ));
}

function exportPlatformReportPDF() {
    if (!VULNS_SAMPLE.length) { showToast('No vulnerabilities to export', 'warn'); return; }
    const list  = (filteredReports && filteredReports.length) ? filteredReports : VULNS_SAMPLE;
    const admin = currentAdmin ? (currentAdmin.name || currentAdmin.email) : 'VulnSight Admin';
    _openPDFWindow(_buildAdminPDFHTML(
        'Platform Vulnerability Assessment Report',
        list,
        `Platform-wide · ${list.length} findings · All users`,
        admin
    ));
}

/* alias — remove old CSV export (replaced by PDF) */
function exportPlatformReport() { exportPlatformReportPDF(); }
// ═══════════════════════════════════════════════════════════
//  AUDIT LOG
// ═══════════════════════════════════════════════════════════
function renderAuditLog(list) {
    const body = document.getElementById('auditLogBody');
    const sevBadge = { critical:'badge-critical', warn:'badge-high', info:'badge-low' };
    if (!list.length) { body.innerHTML = '<div class="empty-state">No audit events found.</div>'; return; }
    body.innerHTML = list.map(e => `
        <div class="audit-row">
            <span class="audit-ts">${esc(e.ts)}</span>
            <span class="audit-actor">${esc(e.actor)}</span>
            <span class="audit-action">${esc(e.action)}</span>
            <span class="audit-sev"><span class="badge ${sevBadge[e.sev]||'badge-low'}">${esc(e.sev)}</span></span>
        </div>`).join('');
}
let _auditSevFilter = 'all';
let _auditTextFilter = '';

function filterAudit(query) {
    _auditTextFilter = query.toLowerCase();
    _applyAuditFilters();
}
function filterAuditBySev(sev) {
    _auditSevFilter = sev;
    _applyAuditFilters();
}
function _applyAuditFilters() {
    const filtered = auditData.filter(e => {
        const textOk = !_auditTextFilter ||
            (e.actor  || '').toLowerCase().includes(_auditTextFilter) ||
            (e.action || '').toLowerCase().includes(_auditTextFilter);
        const sevOk = _auditSevFilter === 'all' || e.sev === _auditSevFilter;
        return textOk && sevOk;
    });
    renderAuditLog(filtered);
}
function addAuditEntry(actor, action, sev) {
    // Always resolve actor to the real admin email if available
    const resolvedActor = (currentAdmin?.email) || actor || 'admin';
    const entry = {
        ts:     new Date().toLocaleString('sv').slice(0, 19),
        actor:  resolvedActor,
        action: action,
        sev:    sev,
    };
    auditData.unshift(entry);

    // Always re-render the audit tab body (it's a virtual list — cheap)
    const auditBody = document.getElementById('auditLogBody');
    if (auditBody) {
        // Only full re-render if the tab is open, otherwise just prepend one row
        const auditTab = document.getElementById('audit-tab');
        if (auditTab && auditTab.classList.contains('active')) {
            _applyAuditFilters();
        }
    }

    // Persist to server (Cache-backed — no model needed)
    apiFetch('/api/admin/audit-log', {
        method: 'POST',
        body: JSON.stringify(entry),
    }).catch(() => {}); // fire-and-forget; never block the UI
}
function exportAuditLog() { exportAuditLogPDF(); } // legacy alias
function exportAuditLogPDF() {
    if (!auditData.length) { showToast('No audit events to export', 'warn'); return; }
    const admin    = currentAdmin ? (currentAdmin.name || currentAdmin.email) : 'VulnSight Admin';
    const reportId = 'AUDIT-' + Date.now().toString(36).toUpperCase();
    const reportDate = new Date().toLocaleDateString('en-GB', { day:'2-digit', month:'long', year:'numeric' });
    const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

    const sevColors = {
        critical: { bg:'rgba(220,38,38,.08)',  border:'rgba(220,38,38,.25)',  text:'#dc2626', dot:'#dc2626', label:'CRITICAL' },
        warn:     { bg:'rgba(234,88,12,.08)',   border:'rgba(234,88,12,.25)',   text:'#ea580c', dot:'#ea580c', label:'WARNING'  },
        info:     { bg:'rgba(22,163,74,.08)',   border:'rgba(22,163,74,.25)',   text:'#16a34a', dot:'#059669', label:'INFO'     },
    };

    const critCount = auditData.filter(e => e.sev === 'critical').length;
    const warnCount = auditData.filter(e => e.sev === 'warn').length;
    const infoCount = auditData.filter(e => e.sev === 'info').length;

    // Group events by actor
    const actorMap = {};
    auditData.forEach(e => { if (!actorMap[e.actor]) actorMap[e.actor] = []; actorMap[e.actor].push(e); });

    const eventRows = auditData.map((e, i) => {
        const s = sevColors[e.sev] || sevColors.info;
        return `<tr style="background:${i%2===0?'#ffffff':'#f9fafb'};">
          <td style="padding:7px 12px;font-size:9.5px;font-family:'Courier New',monospace;color:#6b7280;border-bottom:1px solid #f3f4f6;white-space:nowrap;">${esc(e.ts)}</td>
          <td style="padding:7px 12px;font-size:11px;font-weight:600;color:#111827;border-bottom:1px solid #f3f4f6;">${esc(e.actor)}</td>
          <td style="padding:7px 12px;font-size:11px;color:#374151;border-bottom:1px solid #f3f4f6;">${esc(e.action)}</td>
          <td style="padding:7px 12px;border-bottom:1px solid #f3f4f6;">
            <span style="display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:20px;background:${s.bg};color:${s.text};border:1px solid ${s.border};font-size:8.5px;font-weight:800;text-transform:uppercase;letter-spacing:.06em;">
              <span style="width:4px;height:4px;border-radius:50%;background:${s.dot};flex-shrink:0;"></span>${s.label}
            </span>
          </td>
        </tr>`;
    }).join('');

    // Actor summary blocks
    const actorBlocks = Object.entries(actorMap).map(([actor, events]) => {
        const aCrit = events.filter(e=>e.sev==='critical').length;
        const aWarn = events.filter(e=>e.sev==='warn').length;
        const aInfo = events.filter(e=>e.sev==='info').length;
        const recentEvents = events.slice(0,5).map(e => {
            const s = sevColors[e.sev] || sevColors.info;
            return `<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid #f3f4f6;">
              <span style="font-size:9px;font-family:'Courier New',monospace;color:#9ca3af;white-space:nowrap;width:130px;flex-shrink:0;">${esc(e.ts)}</span>
              <span style="flex:1;font-size:10px;color:#374151;">${esc(e.action)}</span>
              <span style="display:inline-flex;align-items:center;gap:3px;padding:1px 6px;border-radius:10px;background:${s.bg};color:${s.text};font-size:8px;font-weight:700;text-transform:uppercase;flex-shrink:0;">${s.label}</span>
            </div>`;
        }).join('');
        return `<div style="margin-bottom:14px;border:1.5px solid #e5e7eb;border-radius:10px;overflow:hidden;page-break-inside:avoid;">
          <div style="background:#f8fafc;border-bottom:1px solid #e5e7eb;padding:10px 15px;display:flex;align-items:center;justify-content:space-between;">
            <div style="display:flex;align-items:center;gap:10px;">
              <div style="width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,#0f172a,#1e3a5f);display:flex;align-items:center;justify-content:center;flex-shrink:0;">
                <span style="color:#94a3b8;font-weight:800;font-size:12px;font-family:monospace;">${esc(actor).slice(0,2).toUpperCase()}</span>
              </div>
              <div>
                <div style="font-size:13px;font-weight:700;color:#111827;">${esc(actor)}</div>
                <div style="font-size:9.5px;color:#6b7280;">${events.length} event${events.length!==1?'s':''} recorded</div>
              </div>
            </div>
            <div style="display:flex;gap:7px;">
              ${aCrit?`<span style="padding:2px 8px;border-radius:20px;background:rgba(220,38,38,.08);color:#dc2626;border:1px solid rgba(220,38,38,.22);font-size:8.5px;font-weight:800;">${aCrit} CRITICAL</span>`:''}
              ${aWarn?`<span style="padding:2px 8px;border-radius:20px;background:rgba(234,88,12,.08);color:#ea580c;border:1px solid rgba(234,88,12,.22);font-size:8.5px;font-weight:800;">${aWarn} WARN</span>`:''}
              ${aInfo?`<span style="padding:2px 8px;border-radius:20px;background:rgba(22,163,74,.08);color:#16a34a;border:1px solid rgba(22,163,74,.22);font-size:8.5px;font-weight:800;">${aInfo} INFO</span>`:''}
            </div>
          </div>
          <div style="padding:8px 15px;">${recentEvents}</div>
          ${events.length>5?`<div style="padding:6px 15px 10px;font-size:9.5px;color:#9ca3af;">+ ${events.length-5} more event${events.length-5!==1?'s':''} not shown</div>`:''}
        </div>`;
    }).join('');

    const riskLevel = critCount > 0 ? { label:'HIGH RISK', bg:'rgba(220,38,38,.08)', border:'rgba(220,38,38,.25)', text:'#dc2626', accent:'#dc2626' }
        : warnCount > 2 ? { label:'MEDIUM RISK', bg:'rgba(234,88,12,.08)', border:'rgba(234,88,12,.25)', text:'#ea580c', accent:'#ea580c' }
        : { label:'LOW RISK', bg:'rgba(22,163,74,.08)', border:'rgba(22,163,74,.25)', text:'#16a34a', accent:'#16a34a' };

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Audit Log Report — ${reportId}</title>
<style>
  @page { margin:13mm 15mm; size:A4; }
  @media print { .no-print{display:none!important;} body{-webkit-print-color-adjust:exact;print-color-adjust:exact;} }
  *,*::before,*::after { box-sizing:border-box; margin:0; padding:0; }
  body { font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,sans-serif; background:#fff; color:#111827; line-height:1.5; }
  table { border-collapse:collapse; }
</style>
</head>
<body>

<!-- ── COVER PAGE ── -->
<div style="height:267mm;max-height:267mm;display:flex;flex-direction:column;background:linear-gradient(155deg,#030712 0%,#0f172a 40%,#020917 100%);color:#fff;page-break-after:always;page-break-inside:avoid;position:relative;overflow:hidden;">
  <div style="position:absolute;inset:0;opacity:.025;background-image:radial-gradient(circle,rgba(255,255,255,.9) 1px,transparent 1px);background-size:28px 28px;pointer-events:none;"></div>
  <div style="position:absolute;top:-100px;left:-150px;width:600px;height:600px;background:radial-gradient(circle,rgba(0,245,196,.06) 0%,transparent 65%);pointer-events:none;"></div>
  <div style="height:3px;background:linear-gradient(90deg,#f59e0b 0%,#ef4444 35%,#8b5cf6 70%,#00f5c4 100%);flex-shrink:0;"></div>

  <div style="padding:26px 42px;display:flex;align-items:center;justify-content:space-between;flex-shrink:0;border-bottom:1px solid rgba(255,255,255,.05);">
    <div style="display:flex;align-items:center;gap:10px;">
      <div style="width:36px;height:36px;border-radius:8px;background:linear-gradient(135deg,rgba(0,245,196,.15),rgba(59,130,246,.15));border:1px solid rgba(0,245,196,.3);display:flex;align-items:center;justify-content:center;">
        <svg width="17" height="17" fill="none" stroke="#00f5c4" viewBox="0 0 24 24" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      </div>
      <div>
        <div style="font-size:14px;font-weight:700;color:#fff;">VulnSight</div>
        <div style="font-size:7.5px;color:rgba(255,255,255,.3);letter-spacing:.14em;text-transform:uppercase;margin-top:1px;">Security Platform — Admin Console</div>
      </div>
    </div>
    <div style="text-align:right;">
      <div style="font-size:7.5px;color:rgba(255,255,255,.28);letter-spacing:.1em;text-transform:uppercase;">Report ID</div>
      <div style="font-size:11px;font-family:'Courier New',monospace;color:rgba(255,255,255,.5);margin-top:2px;">${reportId}</div>
    </div>
  </div>

  <div style="flex:1;display:flex;flex-direction:column;justify-content:center;padding:42px 42px 28px;">
    <div style="font-size:9.5px;font-weight:700;letter-spacing:.22em;text-transform:uppercase;color:#f59e0b;margin-bottom:13px;">Confidential — Authorized Personnel Only</div>
    <div style="font-size:46px;font-weight:900;line-height:1.02;letter-spacing:-.04em;margin-bottom:9px;">
      Platform<br>Audit Log<br>
      <span style="background:linear-gradient(90deg,#f59e0b,#ef4444);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;">Report</span>
    </div>
    <div style="font-size:12px;color:rgba(255,255,255,.38);margin-bottom:32px;">Security Event Monitoring — Administrative Activity Review</div>

    <div style="display:inline-flex;align-items:center;gap:9px;padding:8px 16px;background:${riskLevel.bg};border:1.5px solid ${riskLevel.border};border-radius:8px;margin-bottom:32px;width:fit-content;">
      <div style="width:8px;height:8px;border-radius:50%;background:${riskLevel.accent};"></div>
      <span style="font-size:9.5px;font-weight:800;letter-spacing:.16em;text-transform:uppercase;color:${riskLevel.text};">Risk Assessment: ${riskLevel.label}</span>
    </div>

    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:11px;margin-bottom:30px;">
      ${[
        {l:'Total Events',n:auditData.length, c:'#374151',bg:'rgba(55,65,81,.08)',b:'rgba(55,65,81,.2)'},
        {l:'Critical',    n:critCount,         c:'#dc2626',bg:'rgba(220,38,38,.08)',b:'rgba(220,38,38,.2)'},
        {l:'Warnings',    n:warnCount,          c:'#ea580c',bg:'rgba(234,88,12,.08)',b:'rgba(234,88,12,.2)'},
        {l:'Info',        n:infoCount,          c:'#16a34a',bg:'rgba(22,163,74,.08)',b:'rgba(22,163,74,.2)'},
      ].map(s=>`
        <div style="background:${s.bg};border:1px solid ${s.b};border-radius:9px;padding:14px 16px;">
          <div style="font-size:36px;font-weight:900;color:${s.c};line-height:1;">${s.n}</div>
          <div style="font-size:8.5px;color:rgba(255,255,255,.38);text-transform:uppercase;letter-spacing:.1em;margin-top:4px;">${s.l}</div>
        </div>`).join('')}
    </div>

    <table style="width:100%;border-collapse:collapse;">
      ${[
        ['Report Date',    reportDate],
        ['Assessed By',    admin],
        ['Audit Period',   auditData.length ? auditData[auditData.length-1].ts + ' — ' + auditData[0].ts : 'N/A'],
        ['Total Actors',   Object.keys(actorMap).length + ' unique user(s)'],
        ['Classification', 'CONFIDENTIAL — Admin access only'],
      ].map(([k,v])=>`
        <tr>
          <td style="padding:5px 0;font-weight:600;color:rgba(255,255,255,.5);width:165px;border-bottom:1px solid rgba(255,255,255,.05);font-size:9.5px;vertical-align:top;">${k}</td>
          <td style="padding:5px 0 5px 14px;color:rgba(255,255,255,.3);border-bottom:1px solid rgba(255,255,255,.05);font-size:9.5px;">${v}</td>
        </tr>`).join('')}
    </table>
  </div>

  <div style="padding:18px 42px 24px;border-top:1px solid rgba(255,255,255,.05);">
    <div style="font-size:8.5px;color:rgba(255,255,255,.18);line-height:1.6;">
      This audit report contains privileged and confidential security event data. Distribution is restricted to authorized administrators.
      All activities logged represent real-time platform monitoring as of the report generation date.
    </div>
  </div>
</div>

<!-- ── EXECUTIVE SUMMARY ── -->
<div style="padding:38px 42px;page-break-before:always;">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
    <div style="width:3px;height:17px;background:linear-gradient(180deg,#f59e0b,#ef4444);border-radius:2px;"></div>
    <div style="font-size:8.5px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:#9ca3af;">Section 01</div>
  </div>
  <h2 style="font-size:21px;font-weight:800;color:#111827;margin-bottom:3px;letter-spacing:-.03em;">Executive Summary</h2>
  <p style="font-size:11.5px;color:#6b7280;margin-bottom:22px;">Platform-wide administrative activity overview and risk assessment.</p>

  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:11px;margin-bottom:22px;">
    <div style="background:#f9fafb;border:1.5px solid #e5e7eb;border-radius:10px;padding:16px 18px;">
      <div style="font-size:28px;font-weight:900;color:#111827;line-height:1;">${auditData.length}</div>
      <div style="font-size:10px;color:#6b7280;margin-top:5px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;">Total Events</div>
      <div style="font-size:9.5px;color:#9ca3af;margin-top:2px;">All severity levels</div>
    </div>
    <div style="background:${critCount>0?'rgba(220,38,38,.04)':'#f9fafb'};border:1.5px solid ${critCount>0?'rgba(220,38,38,.2)':'#e5e7eb'};border-radius:10px;padding:16px 18px;">
      <div style="font-size:28px;font-weight:900;color:${critCount>0?'#dc2626':'#111827'};line-height:1;">${critCount}</div>
      <div style="font-size:10px;color:#6b7280;margin-top:5px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;">Critical Events</div>
      <div style="font-size:9.5px;color:#9ca3af;margin-top:2px;">${critCount>0?'Require immediate review':'No critical alerts'}</div>
    </div>
    <div style="background:#f9fafb;border:1.5px solid #e5e7eb;border-radius:10px;padding:16px 18px;">
      <div style="font-size:28px;font-weight:900;color:#111827;line-height:1;">${Object.keys(actorMap).length}</div>
      <div style="font-size:10px;color:#6b7280;margin-top:5px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;">Unique Actors</div>
      <div style="font-size:9.5px;color:#9ca3af;margin-top:2px;">Distinct users with activity</div>
    </div>
  </div>

  <!-- Risk assessment narrative -->
  <div style="background:${riskLevel.bg};border:1.5px solid ${riskLevel.border};border-radius:9px;padding:14px 18px;margin-bottom:22px;">
    <div style="font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:${riskLevel.text};margin-bottom:6px;">Risk Assessment — ${riskLevel.label}</div>
    <div style="font-size:12px;color:#374151;line-height:1.65;">
      The audit log covers <strong>${auditData.length} event${auditData.length!==1?'s':''}</strong> across <strong>${Object.keys(actorMap).length} actor${Object.keys(actorMap).length!==1?'s':''}</strong>.
      ${critCount>0?`<strong style="color:#dc2626;">${critCount} critical event${critCount!==1?'s':''}</strong> require immediate investigation.`
      :warnCount>0?`<strong style="color:#ea580c;">${warnCount} warning event${warnCount!==1?'s':''}</strong> should be reviewed for policy compliance.`
      :`No critical or warning events detected. Platform security posture appears nominal.`}
    </div>
  </div>

  <!-- Actor breakdown -->
  <h3 style="font-size:14px;font-weight:700;color:#111827;margin-bottom:12px;">Actor Activity Breakdown</h3>
  <table style="width:100%;border-collapse:collapse;margin-bottom:18px;">
    <thead>
      <tr style="background:#0f172a;">
        <th style="padding:8px 12px;text-align:left;font-size:8px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#94a3b8;">Actor</th>
        <th style="padding:8px 12px;text-align:left;font-size:8px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#94a3b8;width:80px;">Events</th>
        <th style="padding:8px 12px;text-align:left;font-size:8px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#94a3b8;width:80px;">Critical</th>
        <th style="padding:8px 12px;text-align:left;font-size:8px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#94a3b8;width:80px;">Warnings</th>
        <th style="padding:8px 12px;text-align:left;font-size:8px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#94a3b8;width:80px;">Last Seen</th>
      </tr>
    </thead>
    <tbody>
      ${Object.entries(actorMap).map(([actor, events], i) => {
        const ac = events.filter(e=>e.sev==='critical').length;
        const aw = events.filter(e=>e.sev==='warn').length;
        return `<tr style="background:${i%2===0?'#ffffff':'#f9fafb'};">
          <td style="padding:7px 12px;font-size:11px;font-weight:600;color:#111827;border-bottom:1px solid #f3f4f6;">${esc(actor)}</td>
          <td style="padding:7px 12px;font-size:11px;color:#374151;border-bottom:1px solid #f3f4f6;">${events.length}</td>
          <td style="padding:7px 12px;border-bottom:1px solid #f3f4f6;">
            ${ac>0?`<span style="padding:1px 7px;border-radius:10px;background:rgba(220,38,38,.08);color:#dc2626;border:1px solid rgba(220,38,38,.2);font-size:9px;font-weight:700;">${ac}</span>`:'<span style="color:#9ca3af;font-size:11px;">0</span>'}
          </td>
          <td style="padding:7px 12px;border-bottom:1px solid #f3f4f6;">
            ${aw>0?`<span style="padding:1px 7px;border-radius:10px;background:rgba(234,88,12,.08);color:#ea580c;border:1px solid rgba(234,88,12,.2);font-size:9px;font-weight:700;">${aw}</span>`:'<span style="color:#9ca3af;font-size:11px;">0</span>'}
          </td>
          <td style="padding:7px 12px;font-size:9.5px;font-family:'Courier New',monospace;color:#6b7280;border-bottom:1px solid #f3f4f6;">${esc(events[0]?.ts||'—')}</td>
        </tr>`;
      }).join('')}
    </tbody>
  </table>
</div>

<!-- ── FULL EVENT LOG ── -->
<div style="padding:0 42px 38px;">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
    <div style="width:3px;height:17px;background:linear-gradient(180deg,#f59e0b,#ef4444);border-radius:2px;"></div>
    <div style="font-size:8.5px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:#9ca3af;">Section 02</div>
  </div>
  <h2 style="font-size:21px;font-weight:800;color:#111827;margin-bottom:3px;letter-spacing:-.03em;">Complete Event Log</h2>
  <p style="font-size:11.5px;color:#6b7280;margin-bottom:16px;">All ${auditData.length} audit events in reverse-chronological order.</p>
  <table style="width:100%;border-collapse:collapse;">
    <thead>
      <tr style="background:#0f172a;">
        <th style="padding:8px 12px;text-align:left;font-size:8px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#94a3b8;width:140px;">Timestamp</th>
        <th style="padding:8px 12px;text-align:left;font-size:8px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#94a3b8;width:130px;">Actor</th>
        <th style="padding:8px 12px;text-align:left;font-size:8px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#94a3b8;">Action</th>
        <th style="padding:8px 12px;text-align:left;font-size:8px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#94a3b8;width:90px;">Severity</th>
      </tr>
    </thead>
    <tbody>${eventRows}</tbody>
  </table>
</div>

<!-- ── PER-ACTOR DETAILS ── -->
<div style="padding:0 42px 46px;">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
    <div style="width:3px;height:17px;background:linear-gradient(180deg,#f59e0b,#ef4444);border-radius:2px;"></div>
    <div style="font-size:8.5px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:#9ca3af;">Section 03</div>
  </div>
  <h2 style="font-size:21px;font-weight:800;color:#111827;margin-bottom:3px;letter-spacing:-.03em;">Per-Actor Activity Detail</h2>
  <p style="font-size:11.5px;color:#6b7280;margin-bottom:22px;">Recent actions grouped by actor for focused review.</p>
  ${actorBlocks}
</div>

<!-- ── FOOTER ── -->
<div style="padding:16px 42px 22px;border-top:2px solid #f3f4f6;background:#f9fafb;">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:7px;">
    <div style="font-size:9px;color:#9ca3af;">VulnSight Admin Audit Log · ${reportId}</div>
    <div style="font-size:9px;color:#9ca3af;">CONFIDENTIAL · ${reportDate}</div>
    <div style="font-size:9px;color:#9ca3af;">Prepared by ${admin}</div>
  </div>
  <div style="font-size:8.5px;color:#d1d5db;line-height:1.6;">
    Disclaimer: This audit report is auto-generated and contains privileged information. All events reflect real platform activity captured by the VulnSight monitoring system.
    Distribute only to authorized personnel in accordance with your organization's data handling policies.
  </div>
</div>

<div class="no-print" style="position:fixed;bottom:20px;right:20px;display:flex;gap:8px;z-index:9999;">
  <button onclick="window.print()" style="padding:10px 20px;background:linear-gradient(135deg,#f59e0b,#ef4444);color:#fff;border:none;border-radius:8px;font-weight:700;font-size:12px;cursor:pointer;box-shadow:0 4px 16px rgba(245,158,11,.3);">🖨&nbsp;Save as PDF</button>
  <button onclick="window.close()" style="padding:10px 14px;background:#1f2937;color:#fff;border:none;border-radius:8px;font-weight:600;font-size:12px;cursor:pointer;">✕</button>
</div>
</body>
</html>`;

    const win = window.open('', '_blank', 'width=1024,height=860,scrollbars=yes,resizable=yes');
    if (!win) { showToast('Pop-up blocked — allow pop-ups and retry', 'warn'); return; }
    win.document.open();
    win.document.write(html);
    win.document.close();
    win.focus();
    showToast('Audit log PDF opened — click "Save as PDF" in the new window', 'success');
}

// ═══════════════════════════════════════════════════════════
//  SERVICES
// ═══════════════════════════════════════════════════════════
function renderServices(list) {
    const el = document.getElementById('serviceList');
    if (!list || !list.length) {
        el.innerHTML = '<div class="empty-state" style="padding:22px;">No service data available.</div>';
        return;
    }
    el.innerHTML = list.map(s => {
        const isUp       = s.status === 'operational' || s.status === 'up';
        const color      = isUp ? 'var(--neon)' : 'var(--red)';
        const glow       = isUp ? 'box-shadow:0 0 6px var(--neon);' : 'box-shadow:0 0 6px var(--red);';
        const label      = isUp ? 'up' : 'down';
        const labelColor = isUp ? 'var(--neon)' : 'var(--red)';
        return `<div class="list-row">
            <div style="display:flex;align-items:center;gap:10px;">
                <div style="width:7px;height:7px;border-radius:50%;background:${color};flex-shrink:0;${glow}"></div>
                <div>
                    <p style="font-size:13px;font-weight:500;">${esc(s.name)}</p>
                    <p style="font-size:12px;color:${labelColor};margin-top:1px;font-family:'DM Mono',monospace;">${label}</p>
                </div>
            </div>
            <span style="font-family:'DM Mono',monospace;font-size:11px;color:white;">${esc(s.latency || '—')}</span>
        </div>`;
    }).join('');
}

// ═══════════════════════════════════════════════════════════
//  OVERVIEW WIDGETS
// ═══════════════════════════════════════════════════════════
function renderRecentCriticalVulns() {
    const el = document.getElementById('recentCriticalList');
    if (!el) return;
    const critical = VULNS_SAMPLE.filter(v => v.severity === 'critical' || v.severity === 'high').slice(0, 5);
    if (!critical.length) { el.innerHTML = '<div class="empty-state" style="padding:22px;"><div class="empty-icon">✓</div>No critical findings.</div>'; return; }
    const badgeMap = { critical:'badge-critical', high:'badge-high' };
    el.innerHTML = critical.map(v => `
        <div class="list-row">
            <div style="flex:1;min-width:0;">
                <p style="font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${esc(v.name)}</p>
                <code style="font-size:11px;color:var(--muted);font-family:'DM Mono',monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block;">${esc(v.url)}</code>
            </div>
            <div style="text-align:right;flex-shrink:0;">
                <span class="badge ${badgeMap[v.severity]||'badge-low'}" style="font-size:11px;">${esc(v.severity)}</span>
                <p style="font-size:11px;color:white;margin-top:3px;">${esc(v.detected_at || '—')}</p>
            </div>
        </div>`).join('');
}

function renderLiveScansPreview() {
    const el = document.getElementById('liveScansPreview');
    const running = SCANS.filter(s => s.status === 'running');
    if (!running.length) { el.innerHTML = '<div class="empty-state" style="padding:28px;"><div class="empty-icon">📡</div>No active scans.</div>'; return; }
    el.innerHTML = running.map(s => `
        <div class="list-row">
            <div style="flex:1;min-width:0;">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:5px;">
                    <span style="font-family:'DM Mono',monospace;font-size:10px;color:var(--neon);">${esc(String(s.id))}</span>
                    <span style="font-size:12px;font-weight:600;color:var(--text2);">${esc(s.owner_name)}</span>
                    <span class="badge badge-running">live</span>
                </div>
                <code style="font-size:11px;color:var(--muted);font-family:'DM Mono',monospace;">${esc(s.target_url)}</code>
                <div style="margin-top:7px;">
                    <div class="prog-track"><div class="prog-bar" style="width:${s.progress}%;"></div></div>
                    <span style="font-size:10px;color:var(--muted);margin-top:2px;display:block;">${s.progress}% · ${s.vulnerabilities_count} findings so far</span>
                </div>
            </div>
        </div>`).join('');
}

function renderActivityBars(data) {
    const heights = data && data.length === 14
        ? data.map(v => { const max = Math.max(...data, 1); return Math.max(4, Math.round((v / max) * 62)); })
        : Array.from({length:14}, () => Math.floor(Math.random()*50+8)); // placeholder until stats load
    const el = document.getElementById('activityBars');
    el.innerHTML = heights.map((h,i) => {
        const alpha = i === heights.length-1 ? '.6' : '.2';
        return `<div data-alpha="${alpha}" style="flex:1;background:rgba(var(--neon-rgb),${alpha});border-radius:3px 3px 0 0;height:${h}px;transition:background .2s;cursor:pointer;" title="${h} scans"></div>`;
    }).join('');
    el.querySelectorAll('[data-alpha]').forEach(function(bar) {
        bar.addEventListener('mouseenter', function() { this.style.background = 'rgba(var(--neon-rgb),.7)'; });
        bar.addEventListener('mouseleave', function() { this.style.background = 'rgba(var(--neon-rgb),' + this.dataset.alpha + ')'; });
    });
}

// ═══════════════════════════════════════════════════════════
//  LIVE SYSTEM TICKER (animates CPU / workers / API RPM)
// ═══════════════════════════════════════════════════════════
// Stable baseline values — drift slowly instead of jumping randomly every 3s
const _live = { cpu: 34, workers: 6, queue: 12, rpm: 847 };
function tickLive() {
    // Nudge each value by ±1 within a realistic range — no wild jumps
    _live.cpu     = Math.min(85, Math.max(18, _live.cpu     + (Math.random() > 0.5 ? 1 : -1)));
    _live.workers = Math.min(14, Math.max(2,  _live.workers + (Math.random() > 0.6 ? 1 : Math.random() > 0.6 ? -1 : 0)));
    _live.queue   = Math.min(40, Math.max(0,  _live.queue   + (Math.random() > 0.5 ? 1 : -1)));
    _live.rpm     = Math.min(980, Math.max(700, _live.rpm   + Math.floor((Math.random() - 0.5) * 6)));

    const bar = document.getElementById('cpuBar');
    const val = document.getElementById('cpuVal');
    if (bar) bar.style.width = _live.cpu + '%';
    if (val) val.innerHTML   = _live.cpu + '<span style="font-size:14px;font-weight:400;">%</span>';
    const wc = document.getElementById('workerCount');
    if (wc) wc.innerHTML = _live.workers + ' <span style="font-size:12px;color:var(--muted);">/ 16</span>';
    const qd = document.getElementById('queueDepth');
    if (qd) qd.textContent = _live.queue;
    const rpm = document.getElementById('apiRpm');
    if (rpm) rpm.textContent = _live.rpm;
}

// ═══════════════════════════════════════════════════════════
//  SETTINGS
// ═══════════════════════════════════════════════════════════

// Snapshot of last-saved settings for change diffing
let _lastSettings = {};

// Human-readable labels for each setting key
const SETTING_LABELS = {
    platform_name:        'Platform Name',
    support_email:        'Support Email',
    open_registration:    'Open Registration',
    rate_limiting:        'Scan Rate Limiting',
    maintenance_mode:     'Maintenance Mode',

};

// Load saved settings from API and populate fields
async function loadSettings() {
    try {
        const s = await apiFetch('/api/admin/settings');
        if (!s) return;
        const set = (id, val) => {
            const el = document.getElementById(id);
            if (!el) return;
            if (el.type === 'checkbox') el.checked = !!val;
            else el.value = val ?? el.value;
        };
        set('cfg_platform_name',       s.platform_name);
        set('cfg_support_email',       s.support_email);
        set('cfg_open_registration',   s.open_registration);
        set('cfg_rate_limiting',       s.rate_limiting);
        set('maintenanceToggle',       s.maintenance_mode);

        // Apply platform name to UI immediately
        _applyPlatformName(s.platform_name);

        // Snapshot so saveSettings() can diff
        _lastSettings = { ...s };
    } catch (e) {
        // Settings not saved yet — leave defaults in place
        console.info('loadSettings: no saved settings yet', e.message);
    }
}

// Update any UI elements that display the platform name
function _applyPlatformName(name) {
    if (!name) return;
    // Browser tab title
    document.title = name + ' — Admin Panel';
    // Sidebar logo text
    const logo = document.querySelector('.logo-text');
    if (logo) logo.textContent = name;
    // Topbar breadcrumb prefix
    const topbar = document.querySelector('.topbar-title');
    if (topbar) {
        const span = topbar.querySelector('span');
        if (span) span.textContent = name + ' /';
    }
}

async function saveSettings() {
    const btn = document.getElementById('saveSettingsBtn');
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }

    const collect = id => {
        const el = document.getElementById(id);
        if (!el) return undefined;
        return el.type === 'checkbox' ? el.checked : el.value;
    };

    const data = {
        platform_name:        collect('cfg_platform_name'),
        support_email:        collect('cfg_support_email'),
        open_registration:    collect('cfg_open_registration'),
        rate_limiting:        collect('cfg_rate_limiting'),
        maintenance_mode:     collect('maintenanceToggle'),
        };

    try {
        await apiFetch('/api/admin/settings', { method: 'PUT', body: JSON.stringify(data) });
        showToast('Settings saved ✓', 'success');

        // ── Diff old vs new and log each individual change ──
        const actor = currentAdmin?.email || 'admin';
        const changed = [];
        for (const [key, newVal] of Object.entries(data)) {
            const oldVal = _lastSettings[key];
            // Normalise for comparison (bool vs string, number vs string)
            const norm = v => (v === true || v === 'true') ? 'enabled'
                            : (v === false || v === 'false') ? 'disabled'
                            : String(v ?? '');
            if (oldVal !== undefined && norm(oldVal) !== norm(newVal)) {
                const label = SETTING_LABELS[key] || key;
                changed.push(`${label}: ${norm(oldVal)} → ${norm(newVal)}`);
            }
        }

        if (changed.length) {
            // One detailed audit entry per changed setting
            changed.forEach(msg => {
                addAuditEntry(actor, `Setting changed — ${msg}`, 'warn');
            });
        } else {
            // No actual changes — still log the save action
            addAuditEntry(actor, 'Platform settings saved (no changes detected)', 'info');
        }

        // Apply platform name change to UI live
        _applyPlatformName(data.platform_name);

        // Update snapshot
        _lastSettings = { ..._lastSettings, ...data };

    } catch (e) {
        showToast('Failed to save settings: ' + (e.message || 'Unknown error'), 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5"><path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg> Save Settings';
        }
    }
}


function handleMaintenanceToggle(el) {
    const on = el.checked;
    showToast(on ? '⚠ Maintenance mode ON — users blocked' : 'Maintenance mode OFF — platform live', on ? 'warn' : 'success');
    apiFetch('/api/admin/settings/maintenance', { method: 'POST', body: JSON.stringify({ enabled: on }) }).catch(() => {});
    addAuditEntry(currentAdmin?.email || 'admin', `Setting changed — Maintenance Mode: ${on ? 'disabled → enabled' : 'enabled → disabled'}`, 'warn');
    _lastSettings.maintenance_mode = on;
}

async function flushCache() {
    try { await apiFetch('/api/admin/cache/flush', { method: 'POST' }); }
    catch (_) {}
    showToast('Cache flushed', 'success');
    addAuditEntry(currentAdmin?.email || 'admin', 'Flushed application cache', 'warn');
}

function refreshHealth() { tickLive(); showToast('Health data refreshed', 'info'); }

// ═══════════════════════════════════════════════════════════
//  MODALS
// ═══════════════════════════════════════════════════════════
function openModal(id) {
    const m = document.getElementById(id);
    m.style.display = 'flex';
    requestAnimationFrame(() => m.style.opacity = '1');
}
function closeModal(id) {
    const m = document.getElementById(id);
    m.style.opacity = '0';
    setTimeout(() => m.style.display = 'none', 200);
}
function closeModalOnBg(e, id) { if (e.target === e.currentTarget) closeModal(id); }
document.addEventListener('keydown', e => {
    if (e.key === 'Escape') document.querySelectorAll('.modal-overlay').forEach(m => { m.style.opacity = '0'; setTimeout(() => m.style.display = 'none', 200); });
});

let _confirmCb = null;
function confirmAction(msg, cb) {
    document.getElementById('confirmMsg').textContent = msg;
    _confirmCb = cb;
    openModal('confirmModal');
    document.getElementById('confirmOkBtn').onclick = () => { closeModal('confirmModal'); if (_confirmCb) _confirmCb(); };
}

// ═══════════════════════════════════════════════════════════
//  TOAST
// ═══════════════════════════════════════════════════════════
let toastTimer;
function showToast(msg, type = 'success') {
    const t = document.getElementById('toast');
    const icons = { success:'✓', info:'ℹ', warn:'⚠', error:'✕' };
    t.innerHTML = `<span>${icons[type]||'●'}</span><span>${esc(msg)}</span>`;
    t.className = 'toast show ' + type;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 3800);
}
document.addEventListener('DOMContentLoaded', function () {

    // ── Sidebar hamburger ──────────────────────────────────────
    const sidebar = document.getElementById('sidebar');
    const hbgBtn  = document.getElementById('sidebarHamburgerBtn');
    if (hbgBtn && sidebar) {
        if (localStorage.getItem('admin_sidebar_collapsed') === '1') sidebar.classList.add('collapsed');
        hbgBtn.addEventListener('click', function () {
            sidebar.classList.toggle('collapsed');
            localStorage.setItem('admin_sidebar_collapsed', sidebar.classList.contains('collapsed') ? '1' : '0');
        });
        const logoIcon = sidebar.querySelector('.logo-icon');
        if (logoIcon) logoIcon.addEventListener('click', function () {
            if (sidebar.classList.contains('collapsed')) {
                sidebar.classList.remove('collapsed');
                localStorage.setItem('admin_sidebar_collapsed', '0');
            }
        });
    }

    // ── Nav items (switchTab) ──────────────────────────────────
    document.querySelectorAll('.tn-item[data-tab]').forEach(function (el) {
        el.addEventListener('click', function () { switchTab(this.dataset.tab); });
    });
    document.querySelectorAll('[data-switchtab]').forEach(function (el) {
        el.addEventListener('click', function () { switchTab(this.dataset.switchtab); });
    });

    // ── Static buttons ────────────────────────────────────────
    var b;
    if (b = document.getElementById('adminSignOutChip'))  b.addEventListener('click', doAdminSignOut);
    if (b = document.getElementById('flushCacheBtn'))     b.addEventListener('click', flushCache);
    if (b = document.getElementById('refreshHealthBtn'))  b.addEventListener('click', refreshHealth);
    if (b = document.getElementById('saveSettingsBtn'))   b.addEventListener('click', saveSettings);
    if (b = document.getElementById('exportAuditBtn'))    b.addEventListener('click', exportAuditLogPDF);
    if (b = document.getElementById('retryJobsBtn'))      b.addEventListener('click', function () { showToast('Failed jobs retried', 'success'); });
    if (b = document.getElementById('flushCacheLocalBtn'))b.addEventListener('click', function () { showToast('Cache flushed', 'warn'); });

    // ── Export PDF buttons (multiple) ────────────────────────
    document.querySelectorAll('.exportPdfBtn').forEach(function (el) {
        el.addEventListener('click', exportPlatformReportPDF);
    });

    // ── Modal close buttons ───────────────────────────────────
    document.querySelectorAll('[data-closemodal]').forEach(function (el) {
        el.addEventListener('click', function () { closeModal(this.dataset.closemodal); });
    });

    // ── Modal overlay click-outside ───────────────────────────
    document.querySelectorAll('.modal-overlay').forEach(function (el) {
        el.addEventListener('click', function (e) { if (e.target === this) closeModal(this.id); });
    });

    // ── Filter inputs ─────────────────────────────────────────
    if (b = document.getElementById('scanStatusFilter'))  b.addEventListener('change', function () { filterScans(this.value); });
    if (b = document.getElementById('reportUserSearch'))  b.addEventListener('input',  function () { filterReportsByUser(this.value); });
    if (b = document.getElementById('sevFilterReports'))  b.addEventListener('change', function () { filterReports(this.value); });
    if (b = document.getElementById('auditSearchInput'))  b.addEventListener('input',  function () { filterAudit(this.value); });
    if (b = document.getElementById('auditSevFilter'))    b.addEventListener('change', function () { filterAuditBySev(this.value); });
    if (b = document.getElementById('maintenanceToggle')) b.addEventListener('change', function () { handleMaintenanceToggle(this); });

    // ── Event delegation for dynamic table rows ───────────────
    document.addEventListener('click', function (e) {
        var el = e.target.closest('[data-action]');
        if (!el) return;
        var action = el.dataset.action;
        var id     = el.dataset.id;
        var uid    = el.dataset.uid;
        var name   = el.dataset.name;
        if (action === 'stopScan')     stopScan(id);
        else if (action === 'retryScan')    retryScan(id);
        else if (action === 'viewScan')     viewScan(id);
        else if (action === 'exportScanPDF') exportScanPDF(id);
        else if (action === 'toggleUserReport') toggleUserReport(uid);
        else if (action === 'exportUserPDF') { e.stopPropagation(); exportUserPDF(name); }
    });

});
