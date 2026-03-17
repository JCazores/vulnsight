// @ts-nocheck
// ════════════════════════════════════════
// AUTH — with OTP email verification
// ════════════════════════════════════════
let currentUser = null;
let _pendingReg = null;   // stores { name, email, password } while OTP is open
let _otpTimer = null;
let _heartbeat = null;   // keeps admin panel user status "active"

// ── helpers ──────────────────────────────
function showMsg(id, text, type = 'err') {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = text;
    el.className = 'af-msg ' + type;
    el.style.display = text ? 'block' : 'none';
}
function clearMsg(id) { showMsg(id, ''); }

function setBusy(btnId, spinId, txtId, busy, label) {
    const btn = document.getElementById(btnId);
    const spin = document.getElementById(spinId);
    const txt = document.getElementById(txtId);
    if (!btn) return;
    btn.disabled = busy;
    if (spin) spin.style.display = busy ? 'block' : 'none';
    if (txt && label) txt.textContent = label;
}

function togglePw(inputId, btn) {
    const inp = document.getElementById(inputId);
    if (!inp) return;
    const isText = inp.type === 'text';
    inp.type = isText ? 'password' : 'text';
    btn.innerHTML = isText
        ? `<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`
        : `<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;
}

function calcPwStr(val) {
    const wrap = document.getElementById('pwStr');
    const bar = document.getElementById('pwStrBar');
    const lbl = document.getElementById('pwStrLbl');
    if (!wrap) return;
    wrap.style.display = val.length ? 'block' : 'none';
    let score = 0;
    if (val.length >= 8) score++;
    if (val.length >= 12) score++;
    if (/[A-Z]/.test(val) && /[a-z]/.test(val)) score++;
    if (/\d/.test(val)) score++;
    if (/[^A-Za-z0-9]/.test(val)) score++;
    const map = [
        { w: '15%', bg: '#f05050', txt: 'Too short' },
        { w: '30%', bg: '#f59e0b', txt: 'Weak' },
        { w: '55%', bg: '#fde047', txt: 'Fair' },
        { w: '78%', bg: '#22d3ee', txt: 'Good' },
        { w: '100%', bg: '#00f5c4', txt: 'Strong' },
    ];
    const m = map[Math.min(score, 4)];
    bar.style.width = m.w;
    bar.style.background = m.bg;
    lbl.textContent = m.txt;
    lbl.style.color = m.bg;
}

// ── Tab switcher ─────────────────────────
function switchAuthTab(tab) {
    document.getElementById('signinTab').classList.toggle('active', tab === 'signin');
    document.getElementById('signupTab').classList.toggle('active', tab === 'signup');
    document.getElementById('signinForm').style.display = tab === 'signin' ? 'block' : 'none';
    document.getElementById('signupForm').style.display = tab === 'signup' ? 'block' : 'none';
    document.getElementById('afTitle').textContent = tab === 'signin' ? 'Operator Login' : 'Request Access';
    document.getElementById('afSub').textContent = tab === 'signin'
        ? 'Authenticate to access the VulnSight platform.'
        : 'Register as a new security operator.';
    clearMsg('siMsg'); clearMsg('suMsg');
}

// ── Google Sign In ───────────────────────
// ── Maintenance mode ─────────────────────────────────────────
// Calls /api/status — returns { maintenance: true/false }
// Admins bypass the block (role=admin / is_admin=true on session).
async function checkMaintenance() {
    try {
        const res = await fetch(API_BASE + '/api/status', {
            credentials: 'include',
            headers: { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest' }
        });
        if (!res.ok) return false;            // if endpoint missing, don't block
        const data = await res.json();
        return data.maintenance === true;
    } catch (_) {
        return false;                          // network error → don't block
    }
}

function showMaintenanceScreen() {
    // If there is already a maintenance overlay, just show it
    let overlay = document.getElementById('maintenanceOverlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'maintenanceOverlay';
        overlay.style.cssText = [
            'position:fixed;inset:0;z-index:9999',
            'display:flex;flex-direction:column;align-items:center;justify-content:center',
            'background:linear-gradient(150deg,#050d1a 0%,#0a1628 55%,#04090f 100%)',
            'padding:24px;text-align:center',
        ].join(';');
        overlay.innerHTML = `
            <div style="position:absolute;inset:0;opacity:.04;pointer-events:none;
                background-image:radial-gradient(circle,rgba(255,255,255,.9) 1px,transparent 1px);
                background-size:28px 28px;"></div>

            <!-- logo -->
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:48px;">
                <div style="width:40px;height:40px;border-radius:10px;
                    background:linear-gradient(135deg,rgba(0,245,196,.15),rgba(59,130,246,.15));
                    border:1px solid rgba(0,245,196,.3);
                    display:flex;align-items:center;justify-content:center;">
                    <svg width="20" height="20" fill="none" stroke="#00f5c4" viewBox="0 0 24 24" stroke-width="2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                </div>
                <div>
                    <div style="font-size:16px;font-weight:700;color:#fff;letter-spacing:-.02em;">VulnSight</div>
                    <div style="font-size:10px;color:rgba(255,255,255,.35);letter-spacing:.12em;text-transform:uppercase;">Security Platform</div>
                </div>
            </div>

            <!-- icon -->
            <div style="width:80px;height:80px;border-radius:20px;margin-bottom:28px;
                background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.25);
                display:flex;align-items:center;justify-content:center;">
                <svg width="38" height="38" fill="none" stroke="#f59e0b" viewBox="0 0 24 24" stroke-width="1.5">
                    <path stroke-linecap="round" stroke-linejoin="round"
                        d="M11.42 15.17L17.25 21A2.652 2.652 0 0021 17.25l-5.877-5.877M11.42 15.17l2.496-3.03c.317-.384.74-.626 1.208-.766M11.42 15.17l-4.655 5.653a2.548 2.548 0 11-3.586-3.586l6.837-5.63m5.108-.233c.55-.164 1.163-.188 1.743-.14a4.5 4.5 0 004.486-6.336l-3.276 3.277a3.004 3.004 0 01-2.25-2.25l3.276-3.276a4.5 4.5 0 00-6.336 4.486c.091 1.076-.071 2.264-.904 2.95l-.102.085m-1.745 1.437L5.909 7.5H4.5L2.25 3.75l1.5-1.5L7.5 4.5v1.409l4.26 4.26m-1.745 1.437l1.745-1.437m6.615 8.206L15.75 15.75M4.867 19.125h.008v.008h-.008v-.008z"/>
                </svg>
            </div>

            <!-- heading -->
            <h1 style="font-size:28px;font-weight:800;color:#fff;margin-bottom:10px;letter-spacing:-.03em;line-height:1.1;">
                Under Maintenance
            </h1>
            <p style="font-size:14px;color:rgba(255,255,255,.5);max-width:380px;line-height:1.7;margin-bottom:32px;">
                VulnSight is currently undergoing scheduled maintenance.<br>
                We'll be back online shortly — please check back soon.
            </p>

            <!-- status pill -->
            <div style="display:inline-flex;align-items:center;gap:8px;
                padding:8px 18px;border-radius:99px;
                background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.25);">
                <span style="width:7px;height:7px;border-radius:50%;background:#f59e0b;
                    box-shadow:0 0 8px #f59e0b;animation:termBlink 1.4s ease-in-out infinite;
                    flex-shrink:0;"></span>
                <span style="font-size:12px;font-weight:700;color:#f59e0b;
                    letter-spacing:.1em;text-transform:uppercase;">Maintenance in progress</span>
            </div>

            <!-- retry button -->
            <button id="maintenanceRetryBtn"
                style="margin-top:28px;padding:10px 24px;border-radius:9px;border:none;cursor:pointer;
                    font-size:13px;font-weight:700;font-family:inherit;
                    background:rgba(255,255,255,.06);color:rgba(255,255,255,.55);
                    transition:all .2s;">
                ↻ &nbsp;Try again
            </button>`;

        document.body.appendChild(overlay);

        // Retry button — re-checks maintenance status
        document.getElementById('maintenanceRetryBtn').addEventListener('click', async () => {
            const still = await checkMaintenance();
            if (!still) {
                overlay.remove();
                // Restore the auth screen so user can log in now
                const authScreen = document.getElementById('authScreen');
                if (authScreen) authScreen.style.display = 'flex';
            }
        });
    }
    overlay.style.display = 'flex';

    // Hide everything else behind it
    const authScreen = document.getElementById('authScreen');
    const mainApp = document.getElementById('mainApp');
    if (authScreen) authScreen.style.display = 'none';
    if (mainApp) mainApp.style.display = 'none';
}


async function doGoogleSignIn() {
    // Redirect to Laravel's Google OAuth route.
    // IMPORTANT: Your Laravel GoogleController callback must redirect to
    //   /?google_login=1  on success  (so sessionStorage gets set)
    //   /?google_error=1  on failure
    // Example in GoogleController@callback:
    //   return redirect('/?google_login=1');
    if (await checkMaintenance()) { showMaintenanceScreen(); return; }
    window.location.href = '/auth/google';
}

// ── Sign In ──────────────────────────────
async function doSignIn() {
    clearMsg('siMsg');
    const email = document.getElementById('siEmail').value.trim().toLowerCase();
    const pass = document.getElementById('siPassword').value;
    if (!email || !pass) { showMsg('siMsg', 'Please fill in all fields.'); return; }
    setBusy('siBtn', 'siSpin', 'siBtnTxt', true, 'Signing in…');
    try {
        if (await checkMaintenance()) { showMaintenanceScreen(); return; }

        // ↓ ADD THESE TWO LINES — fixes login after logout
        await fetch(API_BASE + '/sanctum/csrf-cookie', { credentials: 'include' });

        const user = await apiFetch('/api/login', { method: 'POST', body: JSON.stringify({ email, password: pass }) });
        if (!user || !user.id) {
            showMsg('siMsg', 'Login failed — server returned an unexpected response.');
            return;
        }
        currentUser = user;
        // FIX: Mark session alive in sessionStorage — clears when browser/tab is fully closed
        sessionStorage.setItem('wavs_session_alive', '1');
        if (user.role === 'admin' || user.is_admin) {
            window.location.href = '/admin';
            return;
        }
        enterApp();
    } catch (e) {
        showMsg('siMsg', e.message || 'Invalid email or password.');
        document.getElementById('siPassword').classList.add('is-error');
        setTimeout(() => document.getElementById('siPassword')?.classList.remove('is-error'), 1800);
    } finally {
        setBusy('siBtn', 'siSpin', 'siBtnTxt', false, 'Sign In');
    }
}

// ── Sign Up (step 1 → send OTP) ──────────
async function doSignUp() {
    clearMsg('suMsg');
    const name = document.getElementById('suName').value.trim();
    const email = document.getElementById('suEmail').value.trim().toLowerCase();
    const pass = document.getElementById('suPassword').value;
    const conf = document.getElementById('suConfirm').value;
    if (!name || !email || !pass || !conf) { showMsg('suMsg', 'Please fill in all fields.'); return; }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { showMsg('suMsg', 'Please enter a valid email address.'); return; }
    if (pass.length < 8) { showMsg('suMsg', 'Password must be at least 8 characters.'); return; }
    if (pass !== conf) { showMsg('suMsg', 'Passwords do not match.'); return; }

    setBusy('suBtn', 'suSpin', 'suBtnTxt', true, 'Sending code…');
    try {
        if (await checkMaintenance()) { showMaintenanceScreen(); return; }

        await apiFetch('/api/otp/send', { method: 'POST', body: JSON.stringify({ email }) });
        _pendingReg = { name, email, password: pass, password_confirmation: conf };
        showOtpStep(email);
    } catch (e) {
        const msg = e.message || 'Could not send verification code. Try again.';
        showMsg('suMsg', msg);
        // If rate-limited, extract wait time and show countdown on button
        const waitMatch = msg.match(/(\d+)s/);
        const waitSec = waitMatch ? parseInt(waitMatch[1]) : 30;
        let remaining = waitSec;
        const btnTxt = document.getElementById('suBtnTxt');
        const btn = document.getElementById('suBtn');
        btn.disabled = true;
        const countdown = setInterval(() => {
            remaining--;
            if (btnTxt) btnTxt.textContent = `Wait ${remaining}s…`;
            if (remaining <= 0) {
                clearInterval(countdown);
                btn.disabled = false;
                if (btnTxt) btnTxt.textContent = 'Send Verification Code';
            }
        }, 1000);
    } finally {
        // Don't re-enable here — countdown handles it on 429, or enable immediately on other errors
        const btn = document.getElementById('suBtn');
        if (!btn.disabled) setBusy('suBtn', 'suSpin', 'suBtnTxt', false, 'Send Verification Code');
        document.getElementById('suSpin').style.display = 'none';
    }
}

// ── OTP UI ───────────────────────────────
function showOtpStep(email) {
    document.getElementById('authStep1').style.display = 'none';
    document.getElementById('otpStep').style.display = 'block';
    document.getElementById('otpEmailBadge').textContent = email;
    clearMsg('otpMsg');
    // Reset boxes
    for (let i = 0; i < 6; i++) {
        const b = document.getElementById('ob' + i);
        b.value = ''; b.className = 'otp-box';
    }
    document.getElementById('ob0').focus();
    document.getElementById('otpBtn').disabled = true;
    startOtpTimer(120);
    initOtpBoxes();
}

function backFromOtp() {
    clearInterval(_otpTimer);
    _pendingReg = null;
    document.getElementById('otpStep').style.display = 'none';
    document.getElementById('authStep1').style.display = 'block';
    clearMsg('otpMsg'); clearMsg('suMsg');
}

function initOtpBoxes() {
    for (let i = 0; i < 6; i++) {
        const box = document.getElementById('ob' + i);
        box.oninput = function (e) {
            // Allow only digits
            this.value = this.value.replace(/\D/g, '').slice(-1);
            this.classList.toggle('filled', !!this.value);
            if (this.value && i < 5) document.getElementById('ob' + (i + 1)).focus();
            checkOtpComplete();
        };
        box.onkeydown = function (e) {
            if (e.key === 'Backspace' && !this.value && i > 0) {
                document.getElementById('ob' + (i - 1)).focus();
            }
            if (e.key === 'Enter') doVerifyOtp();
        };
        box.onpaste = function (e) {
            e.preventDefault();
            const pasted = (e.clipboardData || window.clipboardData).getData('text').replace(/\D/g, '').slice(0, 6);
            for (let j = 0; j < pasted.length && j < 6; j++) {
                const b = document.getElementById('ob' + j);
                b.value = pasted[j];
                b.classList.add('filled');
            }
            const lastIdx = Math.min(pasted.length, 5);
            document.getElementById('ob' + lastIdx).focus();
            checkOtpComplete();
        };
    }
}

function checkOtpComplete() {
    const code = getOtpValue();
    document.getElementById('otpBtn').disabled = code.length < 6;
}

function getOtpValue() {
    let code = '';
    for (let i = 0; i < 6; i++) code += (document.getElementById('ob' + i)?.value || '');
    return code;
}

function startOtpTimer(seconds) {
    clearInterval(_otpTimer);
    const resendBtn = document.getElementById('otpResendBtn');
    const timerEl = document.getElementById('otpTimer');
    resendBtn.disabled = true;
    let remaining = seconds;
    function tick() {
        const m = String(Math.floor(remaining / 60)).padStart(2, '0');
        const s = String(remaining % 60).padStart(2, '0');
        timerEl.textContent = `(${m}:${s})`;
        if (remaining <= 0) {
            clearInterval(_otpTimer);
            resendBtn.disabled = false;
            timerEl.textContent = '';
        }
        remaining--;
    }
    tick();
    _otpTimer = setInterval(tick, 1000);
}

async function resendOtp() {
    if (!_pendingReg) return;
    clearMsg('otpMsg');
    document.getElementById('otpResendBtn').disabled = true;
    try {
        await apiFetch('/api/otp/send', { method: 'POST', body: JSON.stringify({ email: _pendingReg.email }) });
        showMsg('otpMsg', 'New code sent! Check your inbox.', 'ok');
        startOtpTimer(120);
    } catch (e) {
        showMsg('otpMsg', e.message || 'Could not resend. Try again.', 'err');
        document.getElementById('otpResendBtn').disabled = false;
    }
}

// ── OTP Verify + Register ─────────────────
async function doVerifyOtp() {
    if (!_pendingReg) return;
    const code = getOtpValue();
    if (code.length < 6) return;
    clearMsg('otpMsg');
    setBusy('otpBtn', 'otpSpin', 'otpBtnTxt', true, 'Verifying…');
    try {
        // Verify OTP first
        await apiFetch('/api/otp/verify', {
            method: 'POST',
            body: JSON.stringify({ email: _pendingReg.email, code })
        });
        // OTP valid → complete registration
        setBusy('otpBtn', 'otpSpin', 'otpBtnTxt', true, 'Creating account…');
        const user = await apiFetch('/api/register', {
            method: 'POST',
            body: JSON.stringify(_pendingReg)
        });
        clearInterval(_otpTimer);
        _pendingReg = null;
        currentUser = user;
        // FIX: Mark session alive in sessionStorage
        sessionStorage.setItem('wavs_session_alive', '1');
        enterApp();
        showToast('Welcome to VulnSight, ' + user.name + '!', 'success');
    } catch (e) {
        // Flash red on all boxes
        for (let i = 0; i < 6; i++) document.getElementById('ob' + i)?.classList.add('bad');
        setTimeout(() => {
            for (let i = 0; i < 6; i++) {
                const b = document.getElementById('ob' + i);
                if (b) { b.classList.remove('bad'); b.value = ''; b.classList.remove('filled'); }
            }
            document.getElementById('ob0')?.focus();
            document.getElementById('otpBtn').disabled = true;
        }, 700);
        showMsg('otpMsg', e.message || 'Invalid or expired code. Try again.', 'err');
    } finally {
        setBusy('otpBtn', 'otpSpin', 'otpBtnTxt', false, 'Verify & Create Account');
    }
}

// ── Enter app ────────────────────────────
async function enterApp() {
    document.getElementById('authScreen').style.display = 'none';
    document.getElementById('mainApp').style.display = 'block';
    document.getElementById('userAvatar').textContent = currentUser.name.slice(0, 2).toUpperCase();
    document.getElementById('userNameDisplay').textContent = currentUser.name;
    const isAdmin = currentUser.role === 'admin' || currentUser.is_admin === true;
    const adminNav = document.getElementById('adminNavSection');
    if (adminNav) adminNav.style.display = isAdmin ? 'block' : 'none';
    // Restore tab from URL path (deep linking / page refresh)
    const _initTab = PATH_TABS[window.location.pathname] || 'dashboard';
    switchTab(_initTab);
    showToast('Welcome back, ' + currentUser.name + '!', 'success');
    loadTargets(); loadCredentials();
    // Restore any scan that was running before the page refresh,
    // then load history (tryRestoreActiveScan must run first so
    // dbLoadHistory doesn't wrongly mark the live scan as 'stopped').
    await tryRestoreActiveScan();
    dbLoadHistory().then(() => updateHistoryBadge()); // Load scan history from DB

    // Vulns now loaded from DB when viewing a scan log — no localStorage restore needed

    // Heartbeat — ping every 90s so admin sees this user as "active"
    clearInterval(_heartbeat);
    apiFetch('/api/heartbeat', { method: 'POST' }).catch(() => { });
    _heartbeat = setInterval(() => {
        apiFetch('/api/heartbeat', { method: 'POST' }).catch(() => { });
    }, 90 * 1000);
}

// ── Sign out ─────────────────────────────
async function doSignOut() {
    if (!await customConfirm('Sign out?')) return;
    clearInterval(_heartbeat);
    _heartbeat = null;
    // FIX: Clear sessionStorage so browser-close detection resets
    sessionStorage.removeItem('wavs_session_alive');
    try { await apiFetch('/api/logout', { method: 'POST' }); } catch (_) { }
    // ↓ CHANGE TO THIS — reload gives a fresh CSRF cookie for next login
    window.location.reload();

    currentUser = null; _pendingReg = null;
    document.getElementById('mainApp').style.display = 'none';
    document.getElementById('authScreen').style.display = 'flex';
    document.getElementById('otpStep').style.display = 'none';
    document.getElementById('authStep1').style.display = 'block';
    switchAuthTab('signin');
    showToast('Signed out', 'info');
}

// ── Session restore ───────────────────────
(function checkSession() {
    const _sp = new URLSearchParams(window.location.search);

    // Google OAuth success: set sessionStorage flag BEFORE tryRestore runs,
    // otherwise the browser-close guard would kill the fresh OAuth session.
    if (_sp.get('google_login') === '1') {
        sessionStorage.setItem('wavs_session_alive', '1');
        history.replaceState({}, '', '/');
    }

    // Google OAuth failure
    if (_sp.get('google_error')) {
        setTimeout(() => showToast('Google sign-in failed — please try again or use email.', 'error'), 600);
        history.replaceState({}, '', '/');
    }

    async function tryRestore() {
        const authScreen = document.getElementById('authScreen');
        const mainApp = document.getElementById('mainApp');

        // Guard: bail safely if key elements aren't in the DOM yet
        if (!authScreen || !mainApp) {
            console.warn('tryRestore: DOM elements not found.');
            return;
        }

        // Maintenance check — block everyone (including already-logged-in users)
        // Admins are allowed through by the backend (/api/status returns maintenance:false for admins)
        if (await checkMaintenance()) { showMaintenanceScreen(); return; }

        // Always try /api/me first — if the server session is still valid,
        // restore the app regardless of sessionStorage (which is unreliable
        // across hard refreshes and tab restores). Only show login if the
        // server says the user is not authenticated (401).
        try {
            const user = await apiFetch('/api/me');
            currentUser = user;

            // Ensure the flag is set so future checks work
            sessionStorage.setItem('wavs_session_alive', '1');

            if (user.role === 'admin' || user.is_admin) {
                window.location.href = '/admin';
                return;
            }

            enterApp();
        } catch (_) {
            // /api/me returned 401 — session is genuinely gone (browser closed,
            // server restarted, token expired). Log out cleanly and show login.
            sessionStorage.removeItem('wavs_session_alive');
            try {
                await fetch(API_BASE + '/api/logout', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });
            } catch (_) { }
            authScreen.style.display = 'flex';
            mainApp.style.display = 'none';
        }
    }

    // ✅ Handles both cases: DOM still loading, or already ready (e.g. with defer)
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', tryRestore);
    } else {
        tryRestore();
    }

})();

// ════════════════════════════════════════
// TABS
// ════════════════════════════════════════
const TAB_TITLES = {
    targets: 'Target Management', authentication: 'Auth Vault',
    configuration: 'Scan Settings', 'scan-history': 'Scan History',
    'scan-detail': 'Scan Details'
};

// Tab name → URL path mapping
const TAB_PATHS = {
    'dashboard': '/',
    'vulnerabilities': '/vulnerabilities',
    'scan-history': '/scan-history',
    'targets': '/targets',
    'auth': '/auth-vault',
    'settings': '/settings',
    'scan-detail': '/scan-history',
};

// URL path → tab name mapping (for deep linking / back button)
const PATH_TABS = {
    '/': 'dashboard',
    '/vulnerabilities': 'vulnerabilities',
    '/scan-history': 'scan-history',
    '/targets': 'targets',
    '/auth-vault': 'auth',
    '/settings': 'settings',
};

function switchTab(name) {
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
    // Hide scan-detail sub-nav when navigating away from it
    if (name !== 'scan-detail' && name !== 'scan-history') {
        const navDetail = document.getElementById('navScanDetail');
        if (navDetail) navDetail.style.display = 'none';
    }
    const tab = document.getElementById(name + '-tab');
    if (tab) tab.classList.add('active');
    const btn = document.querySelector(`.nav-item[data-tab="${name}"]`);
    if (btn) btn.classList.add('active');
    document.getElementById('topbarTitle').textContent = TAB_TITLES[name] || name;

    // Update browser URL without page reload
    const path = TAB_PATHS[name] || '/';
    if (window.location.pathname !== path) {
        history.pushState({ tab: name }, '', path);
    }
}

// Handle browser back/forward buttons
window.addEventListener('popstate', function (e) {
    const tab = (e.state && e.state.tab) || PATH_TABS[window.location.pathname] || 'dashboard';
    switchTab(tab);
});

// ════════════════════════════════════════
// SCAN ENGINE
// ════════════════════════════════════════
let scanStatus = 'idle', scanProgress = 0, scanInterval = null, scanIntensity = 'standard';
let liveStats = { requestsSent: 0, urlsDiscovered: 0, vulnerabilitiesFound: 0, criticalIssues: 0, highIssues: 0, mediumIssues: 0, lowIssues: 0 };
let allVulns = [];
let _vulnBuffer = [];          // queued vulns waiting to be flushed to DB
let _vulnFlushTimer = null;    // debounce handle
// ─── FIXED SCAN LOGIC — replace everything between the markers below ──────────
// Changes:
//   1. Removed VULN_DB, PATHS, HTTP_METHODS, HTTP_STATUSES (all fake/hardcoded)
//   2. Removed tick() simulation entirely — ZAP only, no fake data
//   3. Added kill switch button (Force Stop)
//   4. Added scan timeout (default 10 min) — auto-stops if ZAP hangs
//   5. Added stall detector — warns if progress freezes for 2 min
//   6. Added error banner in UI when ZAP poll fails repeatedly
// ─────────────────────────────────────────────────────────────────────────────

let _lastSyncedProgress = -1;
let _lastFeedUrl = '';
let _pollErrors = 0;       // consecutive poll errors
let _scanStartTime = null;    // for timeout kill switch
let _lastProgressTime = null;    // for stall detection
let _lastProgressValue = -1;      // for stall detection
let _killTimer = null;    // scan timeout handle
let _stallTimer = null;    // stall detector handle
let _lastSeenVulnId = 0;       // for incremental vuln polling

const SCAN_TIMEOUT_MS = 5 * 60 * 1000;   // 5 minutes hard limit (spider 1min + active 2min + buffer)
const STALL_TIMEOUT_MS = 3 * 60 * 1000;   // warn if no response for 3 min
const MAX_POLL_ERRORS = 5;                 // consecutive errors before abort

const PHASES = [
    'Initializing…', 'Crawling pages…', 'Enumerating endpoints…',
    'Testing SQL injection…', 'Testing XSS…', 'Testing CSRF…',
    'Checking auth…', 'Testing IDOR…', 'Analyzing headers…',
    'Fuzzing inputs…', 'Generating report…', 'Finalizing…'
];

// VULN_FIX_DB — remediation guides shown in the vuln detail modal and PDF report.
// Keys must match the exact 'name' value produced by HeaderScanner.php and Nuclei templates.
const VULN_FIX_DB = {

    // ── HeaderScanner: CSP audit ──────────────────────────────────────────
    'Weak CSP: unsafe-inline in script-src': {
        summary: "The Content-Security-Policy header allows 'unsafe-inline' in script-src. This bypasses XSS protection entirely — an attacker who injects HTML can run arbitrary JavaScript without needing an external script.",
        steps: [
            "Open app/Http/Middleware/SecurityHeaders.php and confirm 'unsafe-inline' is NOT in $scriptSrc.",
            "Ensure the nonce is generated BEFORE $next($request) so Blade's csp_nonce() receives the correct value.",
            "Every <script> tag in Blade templates must carry nonce=\"{{ csp_nonce() }}\".",
            "Test your live CSP at https://csp-evaluator.withgoogle.com/ — it should show no high-risk findings.",
            "Re-run your scanner to confirm the finding is resolved.",
        ],
        ref: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src',
    },

    'Weak CSP: unsafe-eval present': {
        summary: "The CSP header permits 'unsafe-eval', which allows eval(), setTimeout(string), and new Function(string). An XSS payload can use these to execute attacker-controlled code even without inline scripts.",
        steps: [
            "Search your codebase for eval(), new Function(), setTimeout with a string argument.",
            "Refactor those calls to use function references: setTimeout(() => fn(), 1000) not setTimeout('fn()', 1000).",
            "Remove 'unsafe-eval' from script-src in SecurityHeaders.php once code no longer requires it.",
            "If a third-party library requires unsafe-eval, isolate it in a sandboxed iframe.",
            "Verify at https://csp-evaluator.withgoogle.com/",
        ],
        ref: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#unsafe_eval_expressions',
    },

    'Weak CSP: wildcard in script-src': {
        summary: "script-src contains a wildcard (*), which allows scripts from any domain and completely negates XSS protection.",
        steps: [
            "Replace the wildcard with an explicit list of trusted origins in SecurityHeaders.php.",
            "Safe origins: 'self', https://cdn.jsdelivr.net, https://cdnjs.cloudflare.com.",
            "Use a nonce for any inline or dynamically injected scripts.",
            "Test at https://csp-evaluator.withgoogle.com/ after updating.",
        ],
        ref: 'https://owasp.org/www-project-secure-headers/#content-security-policy',
    },

    // ── HeaderScanner: missing headers ────────────────────────────────────
    'Missing Security Header: Content-Security-Policy': {
        summary: "No Content-Security-Policy header was returned. Without CSP, the browser executes any inline script and loads resources from any origin, making the app highly vulnerable to XSS.",
        steps: [
            "Add a CSP header in app/Http/Middleware/SecurityHeaders.php.",
            "Start with: default-src 'self'; script-src 'self' 'nonce-{nonce}'; object-src 'none'.",
            "Generate a random nonce per request and inject it into every <script> tag via csp_nonce().",
            "Register SecurityHeaders in the middleware stack in bootstrap/app.php.",
            "Test progressively using Content-Security-Policy-Report-Only before enforcing.",
            "Validate at https://csp-evaluator.withgoogle.com/",
        ],
        ref: 'https://owasp.org/www-project-secure-headers/#content-security-policy',
    },

    'Missing Security Header: X-Frame-Options': {
        summary: "X-Frame-Options is absent. Your app can be embedded in an iframe on a malicious site, enabling clickjacking attacks that trick users into clicking hidden elements.",
        steps: [
            "Add X-Frame-Options: DENY in SecurityHeaders.php to block all framing.",
            "If the same origin needs to frame the app, use SAMEORIGIN instead.",
            "Alternatively, set frame-ancestors 'none' in your CSP — this supersedes X-Frame-Options in modern browsers.",
            "Verify: curl -I http://localhost:8000 | grep -i x-frame",
        ],
        ref: 'https://owasp.org/www-community/attacks/Clickjacking',
    },

    'Missing Security Header: X-Content-Type-Options': {
        summary: "X-Content-Type-Options: nosniff is missing. Browsers may MIME-sniff responses and execute files as a different type — treating a text file as JavaScript.",
        steps: [
            "Add $response->headers->set('X-Content-Type-Options', 'nosniff'); in SecurityHeaders.php.",
            "Ensure all API and static file responses include this header.",
            "Verify: curl -I http://localhost:8000 | grep -i x-content-type",
        ],
        ref: 'https://owasp.org/www-project-secure-headers/#x-content-type-options',
    },

    'Missing Security Header: Strict-Transport-Security': {
        summary: "The HSTS header is missing. Users who visit without https:// can be silently downgraded to HTTP by a MITM attacker, exposing session cookies and data.",
        steps: [
            "Add Strict-Transport-Security: max-age=31536000; includeSubDomains in SecurityHeaders.php.",
            "Only set this on HTTPS — skip it on localhost and HTTP environments.",
            "Set SESSION_SECURE_COOKIE=true in .env so session cookies are HTTPS-only.",
            "After deploying, consider submitting to the HSTS preload list at https://hstspreload.org/",
        ],
        ref: 'https://owasp.org/www-community/controls/HTTP_Strict_Transport_Security_Cheat_Sheet',
    },

    'Missing Security Header: Referrer-Policy': {
        summary: "Referrer-Policy is missing. Browsers send the full URL in the Referer header to external sites, which may leak sensitive query parameters like tokens or IDs.",
        steps: [
            "Add $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin'); in SecurityHeaders.php.",
            "This sends the full URL for same-origin requests but only the origin for cross-origin requests.",
            "Use no-referrer if your app never needs to share referrer information externally.",
        ],
        ref: 'https://owasp.org/www-project-secure-headers/#referrer-policy',
    },

    'Missing Security Header: Permissions-Policy': {
        summary: "Permissions-Policy is missing. Without it, third-party scripts can request access to sensitive browser APIs (camera, microphone, geolocation) on behalf of your users.",
        steps: [
            "Add Permissions-Policy: camera=(), microphone=(), geolocation=() in SecurityHeaders.php.",
            "Disable all APIs your app does not use.",
            "If a feature is needed, restrict it to self: camera=(self).",
            "Verify: curl -I http://localhost:8000 | grep -i permissions-policy",
        ],
        ref: 'https://owasp.org/www-project-secure-headers/#permissions-policy',
    },

    // ── HeaderScanner: dangerous / disclosure headers ─────────────────────
    'Information Disclosure via X-Powered-By Header': {
        summary: "The X-Powered-By header exposes your server technology (e.g. PHP/8.2). Attackers use this to identify version-specific vulnerabilities.",
        steps: [
            "In SecurityHeaders.php call header_remove('X-Powered-By'); and $response->headers->remove('X-Powered-By');",
            "In php.ini set expose_php = Off.",
            "Restart PHP-FPM after changing php.ini.",
            "Verify: curl -I http://localhost:8000 | grep -i x-powered-by (should return nothing)",
        ],
        ref: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server',
    },

    'Information Disclosure via Server Header': {
        summary: "The Server header reveals your web server software and version (e.g. nginx/1.18.0). This helps attackers search for known CVEs targeting your exact version.",
        steps: [
            "Nginx: add server_tokens off; in your nginx.conf http block.",
            "Apache: set ServerTokens Prod and ServerSignature Off in httpd.conf.",
            "Laravel: add $response->headers->remove('Server'); in SecurityHeaders.php.",
            "Verify: curl -I http://localhost:8000 | grep -i server (should be empty or generic)",
        ],
        ref: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server',
    },

    // ── HeaderScanner: cookie findings ───────────────────────────────────
    'Cookie Missing HttpOnly Flag': {
        summary: "A cookie is set without the HttpOnly attribute, meaning JavaScript can read it. Any XSS vulnerability in the app would allow an attacker to steal this cookie and hijack the session.",
        steps: [
            "In config/session.php set 'http_only' => true.",
            "Do not override with SESSION_COOKIE_HTTPONLY=false in .env.",
            "For manually set cookies, pass httpOnly: true in the Cookie constructor.",
            "Verify in DevTools: Application > Cookies — HttpOnly column should be checked for all auth cookies.",
        ],
        ref: 'https://owasp.org/www-community/HttpOnly',
    },

    'Cookie Missing HttpOnly Flag: laravel_session': {
        summary: "The laravel_session cookie lacks HttpOnly, allowing JavaScript to read the session ID. An XSS attack can steal this and fully hijack authenticated user sessions.",
        steps: [
            "In config/session.php set 'http_only' => true.",
            "Run php artisan config:clear after changing config.",
            "Verify in DevTools: Application > Cookies > laravel_session > HttpOnly ✓",
        ],
        ref: 'https://owasp.org/www-community/HttpOnly',
    },

    'Cookie Missing HttpOnly Flag: XSRF-TOKEN': {
        summary: "The XSRF-TOKEN cookie is readable by JavaScript — this is intentional in Laravel so Axios can read and send it as a request header. However, ensure the Secure flag is set in production.",
        steps: [
            "This is by design in Laravel — XSRF-TOKEN must be readable by JavaScript for CSRF protection to work.",
            "Ensure it has the Secure flag in production: SESSION_SECURE_COOKIE=true in .env.",
            "Ensure SameSite is Lax or Strict in config/session.php.",
            "If your scanner flags this, it is likely a false positive — validate manually before acting.",
        ],
        ref: 'https://laravel.com/docs/csrf',
    },

    'Cookie Missing Secure Flag': {
        summary: "A cookie is set without the Secure flag, meaning it can be sent over plain HTTP and intercepted by a network attacker.",
        steps: [
            "In .env set SESSION_SECURE_COOKIE=true.",
            "In config/session.php set 'secure' => env('SESSION_SECURE_COOKIE', true).",
            "Ensure your app is served exclusively over HTTPS in production.",
            "For manually set cookies, pass secure: true in the Cookie constructor.",
            "Note: expected on localhost (HTTP) — verify only in a production HTTPS environment.",
        ],
        ref: 'https://owasp.org/www-community/controls/SecureCookieAttribute',
    },

    // ── Nuclei / common findings ──────────────────────────────────────────
    'http-missing-security-headers': {
        summary: "One or more recommended HTTP security headers are missing. These headers reduce the attack surface for XSS, clickjacking, and information disclosure.",
        steps: [
            "Add all missing headers in SecurityHeaders.php: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.",
            "Register the middleware globally in bootstrap/app.php.",
            "Check your full header score at https://securityheaders.com/",
        ],
        ref: 'https://owasp.org/www-project-secure-headers/',
    },

    'Laravel Debug Mode Enabled': {
        summary: "APP_DEBUG=true is exposing full stack traces, environment variables, and database credentials in error responses. This is a critical information disclosure vulnerability.",
        steps: [
            "In .env set APP_DEBUG=false and APP_ENV=production.",
            "Run php artisan config:clear after the change.",
            "Configure a proper logging channel in config/logging.php so errors are still recorded.",
            "Never deploy with APP_DEBUG=true — use a restricted staging environment if debug output is needed.",
        ],
        ref: 'https://laravel.com/docs/configuration#debug-mode',
    },

    'Laravel Environment File Exposed': {
        summary: "The .env file is publicly accessible via HTTP. It contains your app key, database credentials, and API secrets — a critical breach if accessed by an attacker.",
        steps: [
            "Block .env access in your web server config immediately.",
            "Nginx: location ~ /\.env { deny all; return 404; }",
            "Apache: <FilesMatch \"^\\.env\"> Require all denied </FilesMatch>",
            "Rotate ALL credentials in .env (APP_KEY, DB_PASSWORD, API keys) — treat them as compromised.",
            "Run php artisan key:generate to regenerate APP_KEY.",
            "Check git history: git log --all --full-history -- .env",
        ],
        ref: 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
    },

    'SQL Injection': {
        summary: "User-supplied input is being inserted directly into a SQL query without parameterisation. An attacker can manipulate queries to dump, modify, or delete the entire database.",
        steps: [
            "Replace all raw DB::select() calls using string interpolation with parameterised queries: DB::select('SELECT * FROM users WHERE id = ?', [$id])",
            "Use Eloquent ORM — it uses PDO parameterisation by default.",
            "Never pass request input into whereRaw(), orderByRaw(), or groupByRaw() without bindings.",
            "Review all models and controllers for raw query string construction.",
        ],
        ref: 'https://owasp.org/www-community/attacks/SQL_Injection',
    },

    'Cross-Site Scripting (XSS)': {
        summary: "User input is rendered in an HTML response without escaping, allowing an attacker to inject scripts that execute in other users' browsers and steal sessions or data.",
        steps: [
            "Always use Blade's {{ $variable }} syntax — it HTML-escapes output automatically.",
            "Never use {!! $variable !!} with user-supplied data.",
            "Sanitise rich text with a whitelist-based HTML purifier (e.g. mews/purifier).",
            "Set a strong Content-Security-Policy to limit script execution even if XSS occurs.",
        ],
        ref: 'https://owasp.org/www-community/attacks/xss/',
    },

    'Open Redirect': {
        summary: "The application redirects to a user-controlled URL without validation, enabling phishing attacks using trusted-looking links.",
        steps: [
            "Never pass raw user input to redirect() or header('Location: ...').",
            "Validate redirect targets against an allowlist of permitted URLs.",
            "Use relative paths for internal redirects: redirect('/dashboard') is always safe.",
            "If external redirects are needed, validate against an explicit whitelist.",
        ],
        ref: 'https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet',
    },

    'Sensitive Data Exposure': {
        summary: "Sensitive internal data (config values, credentials, server paths, or env details) is returned in HTTP responses without authentication.",
        steps: [
            "Set APP_DEBUG=false and APP_ENV=production in .env.",
            "Remove or protect any routes returning config(), env(), or phpinfo() output.",
            "Ensure /api/* routes require auth:sanctum middleware.",
            "Audit JSON responses for fields exposing db_host, app_key, or file paths.",
        ],
        ref: 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
    },

    'Exposed Git Repository': {
        summary: "The .git directory is publicly accessible. An attacker can download your entire source code, commit history, and any secrets ever committed — including deleted files.",
        steps: [
            "Block .git access in your web server config immediately.",
            "Nginx: location ~ /\.git { deny all; return 404; }",
            "Apache: RedirectMatch 404 /\.git",
            "Rotate all credentials ever stored in the repo.",
            "Audit: git log --all -S 'password'",
            "Add .env to .gitignore: git ls-files | grep .env",
        ],
        ref: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage',
    },

    'phpinfo() Page Exposed': {
        summary: "A phpinfo() page is publicly accessible, disclosing PHP version, loaded extensions, environment variables, and file paths — a detailed map for attackers.",
        steps: [
            "Remove or restrict the route serving phpinfo().",
            "If needed for diagnostics, protect it behind IP allowlisting or HTTP Basic Auth.",
            "Remove any phpinfo.php from public/ directory.",
            "In php.ini set disable_functions = phpinfo",
        ],
        ref: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server',
    },

    'Insecure Direct Object Reference (IDOR)': {
        summary: "The app exposes internal object IDs in URLs and does not verify the requesting user owns the referenced resource, allowing users to access each other's data.",
        steps: [
            "Use Laravel Policies: $this->authorize('view', $scan) in every resource controller.",
            "Register policies in AuthServiceProvider.",
            "Always scope queries by user: Scan::where('id', $id)->where('user_id', auth()->id())->firstOrFail()",
            "Consider UUIDs or hashids instead of sequential integer IDs to prevent enumeration.",
        ],
        ref: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References',
    },

    'Sub Resource Integrity Attribute Missing': {
        summary: "External scripts or stylesheets are loaded without an integrity attribute. If the CDN is compromised, malicious code could be silently injected into your users' browsers.",
        steps: [
            "Generate SHA-384 hashes for each external resource at https://www.srihash.org/",
            "Add integrity=\"sha384-{hash}\" and crossorigin=\"anonymous\" to every external <script> and <link> tag.",
            "Example: <script src=\"https://cdn.jsdelivr.net/...\" integrity=\"sha384-abc123\" crossorigin=\"anonymous\"></script>",
            "Consider self-hosting critical assets to eliminate CDN dependency entirely.",
            "Note: SRI is only needed for external (CDN) resources — self-hosted assets do not require it.",
        ],
        ref: 'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity',
    },

    // ── Generic fallbacks ─────────────────────────────────────────────────
    'Insecure Headers': {
        summary: "One or more security-relevant HTTP response headers are missing or misconfigured.",
        steps: [
            "Add Content-Security-Policy with a nonce-based script-src.",
            "Add X-Frame-Options: DENY.",
            "Add X-Content-Type-Options: nosniff.",
            "Add Referrer-Policy: strict-origin-when-cross-origin.",
            "Add Permissions-Policy: camera=(), microphone=(), geolocation=()",
            "Verify at https://securityheaders.com/",
        ],
        ref: 'https://owasp.org/www-project-secure-headers/',
    },

    'Cookie No HttpOnly Flag': {
        summary: "A cookie is set without HttpOnly, making it readable by JavaScript. Any XSS vulnerability would allow an attacker to steal this cookie.",
        steps: [
            "In config/session.php set 'http_only' => true.",
            "Do not set SESSION_COOKIE_HTTPONLY=false in .env.",
            "For manually set cookies add httpOnly: true.",
            "Verify in DevTools: Application > Cookies > HttpOnly ✓",
        ],
        ref: 'https://owasp.org/www-community/HttpOnly',
    },

};

// State
let _pollSyncTimer = null;  // debounce DB sync during polling

// ── Error banner helpers ──────────────────────────────────────────────────────
function showScanError(msg) {
    let banner = document.getElementById('scanErrorBanner');
    if (!banner) {
        banner = document.createElement('div');
        banner.id = 'scanErrorBanner';
        banner.style.cssText = `
            display:flex;align-items:center;gap:10px;
            background:rgba(240,80,80,.12);border:1px solid rgba(240,80,80,.3);
            border-radius:8px;padding:10px 14px;margin-bottom:12px;
            font-size:13px;color:#f05050;font-weight:600;
        `;
        const progressSection = document.getElementById('progressSection');
        if (progressSection) progressSection.prepend(banner);
    }
    banner.innerHTML = `
        <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        <span>${msg}</span>
        <button data-action="close-scan-error"
            style="margin-left:auto;background:none;border:none;color:#f05050;cursor:pointer;font-size:16px;line-height:1;">×</button>
    `;
    banner.style.display = 'flex';
}

function clearScanError() {
    const b = document.getElementById('scanErrorBanner');
    if (b) b.style.display = 'none';
}

// ── Kill switch — force stop ──────────────────────────────────────────────────
async function forceStopScan() {
    // confirm() is blocked in sandboxed iframes — use inline confirmation instead
    const confirmed = await new Promise(resolve => {
        const overlay = document.createElement('div');
        overlay.style.cssText = 'position:fixed;inset:0;z-index:99999;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;';
        overlay.innerHTML = `
            <div style="background:#0f1623;border:1px solid rgba(240,80,80,.4);border-radius:14px;padding:28px 32px;max-width:340px;text-align:center;">
                <div style="font-size:32px;margin-bottom:12px;">⏹</div>
                <h3 style="color:#fff;font-size:16px;font-weight:700;margin:0 0 8px;">Force Stop Scan?</h3>
                <p style="color:#9ca3af;font-size:13px;margin:0 0 24px;">This will immediately stop the running scan.</p>
                <div style="display:flex;gap:10px;justify-content:center;">
                    <button id="vs-stop-cancel" style="padding:9px 22px;border-radius:8px;border:1px solid rgba(255,255,255,.15);background:transparent;color:#9ca3af;font-size:13px;font-weight:600;cursor:pointer;font-family:inherit;">Cancel</button>
                    <button id="vs-stop-confirm" style="padding:9px 22px;border-radius:8px;border:none;background:#ef4444;color:#fff;font-size:13px;font-weight:700;cursor:pointer;font-family:inherit;">Force Stop</button>
                </div>
            </div>`;
        document.body.appendChild(overlay);
        overlay.querySelector('#vs-stop-confirm').onclick = () => { document.body.removeChild(overlay); resolve(true); };
        overlay.querySelector('#vs-stop-cancel').onclick  = () => { document.body.removeChild(overlay); resolve(false); };
    });
    if (!confirmed) return;
    _clearScanTimers();
    _stopRateTicker();
    _updateScanTarget(null, null);
    const _sfHide = document.getElementById('scanFeed'); if (_sfHide) _sfHide.style.display = 'none';
    const elapsedDisplay = document.getElementById('elapsedDisplay');
    if (elapsedDisplay) elapsedDisplay.style.display = 'none';
    clearInterval(scanInterval);
    scanInterval = null;
    scanStatus = 'idle'; setStatus('idle');
    document.getElementById('startBtn').style.display = 'flex';
    document.getElementById('pauseBtn').style.display = 'none';
    document.getElementById('killBtn') && (document.getElementById('killBtn').style.display = 'none');
    document.getElementById('progressSection').style.display = 'none';
    document.getElementById('progressPlaceholder').style.display = 'block';
    document.getElementById('progressPhase').textContent = 'Stopped by user.';
    archiveCurrentScan('stopped');
    showToast('Scan force-stopped.', 'warn');
    const stopPromises = [];
    if (activeScanId) {
        stopPromises.push(apiFetch(`/api/scans/${activeScanId}/stop`, { method: 'POST' }).catch(() => {}));
    }
    if (activeScanLogId) {
        stopPromises.push(apiFetch(`/api/scan-logs/${activeScanLogId}`, {
            method: 'PATCH',
            body: JSON.stringify({ status: 'stopped' }),
        }).catch(() => {}));
    }
    await Promise.all(stopPromises);
}

function _clearScanTimers() {
    if (_killTimer) { clearTimeout(_killTimer); _killTimer = null; }
    if (_stallTimer) { clearTimeout(_stallTimer); _stallTimer = null; }
}

function _resetStallTimer() {
    if (_stallTimer) clearTimeout(_stallTimer);
    _stallTimer = setTimeout(() => {
        if (scanStatus !== 'running') return;
        showScanError('⚠ Scan appears stalled — no progress for 2 minutes. You can Force Stop or wait.');
        showToast('Scan stalled — no progress detected.', 'warn');
    }, STALL_TIMEOUT_MS);
}

// ── Start Scan ────────────────────────────────────────────────────────────────
async function startScan() {
    if (scanStatus === 'completed') {
        // Archive completed scan before resetting — preserves its data in history
        archiveCurrentScan('completed');
        scanProgress = 0;
        liveStats = { requestsSent: 0, urlsDiscovered: 0, vulnerabilitiesFound: 0, criticalIssues: 0, highIssues: 0, mediumIssues: 0, lowIssues: 0 };
        allVulns = [];
        _vulnBuffer = [];
        _pollErrors = 0;
        _lastSeenVulnId = 0;
        if (_vulnFlushTimer) { clearTimeout(_vulnFlushTimer); _vulnFlushTimer = null; }
        document.getElementById('vulnTableBody').innerHTML = '<tr><td colspan="6"><div class="empty-state"><div class="empty-icon">🛡️</div>No vulnerabilities detected yet.</div></td></tr>';
        document.getElementById('recentVulns').innerHTML = '<div class="empty-state"><div class="empty-icon">🔍</div>No findings yet.</div>';
        document.getElementById('vulnBadge').style.display = 'none';
        ['requestsSent', 'urlsDiscovered', 'vulnerabilitiesFound', 'criticalIssues', 'criticalCount', 'highCount', 'mediumCount', 'lowCount'].forEach(id => {
            const el = document.getElementById(id); if (el) el.textContent = '0';
        });
    }

    clearScanError();
    // Exit view mode if browsing a past scan
    if (_viewingScanId) exitViewMode();
    scanStatus = 'running'; setStatus('running');
    document.getElementById('startBtn').style.display = 'none';
    document.getElementById('pauseBtn').style.display = 'flex';
    document.getElementById('pauseLabel').textContent = 'Pause';
    document.getElementById('progressSection').style.display = 'block';
    document.getElementById('progressPlaceholder').style.display = 'none';

    // Show kill switch button
    let killBtn = document.getElementById('killBtn');
    if (!killBtn) {
        killBtn = document.createElement('button');
        killBtn.id = 'killBtn';
        killBtn.onclick = forceStopScan;
        killBtn.style.cssText = `
            display:inline-flex;align-items:center;gap:6px;
            background:rgba(240,80,80,.1);color:#f05050;
            border:1px solid rgba(240,80,80,.25);border-radius:8px;
            padding:7px 14px;font-size:12px;font-weight:700;
            font-family:inherit;cursor:pointer;transition:all .2s;
        `;
        killBtn.innerHTML = '⏹ Force Stop';
        document.getElementById('pauseBtn').insertAdjacentElement('afterend', killBtn);
    }
    killBtn.style.display = 'inline-flex';

    showToast('Starting scan…', 'info');

    activeScanId = null;
    activeScanLogId = null;
    const id = await createFreshScan();
    if (!id) { showToast('Could not create scan record', 'error'); return; }

    const allTargetUrls = getActiveTargetUrls();
    const targetUrl = allTargetUrls[0] || 'http://localhost:8000';

    try {
        // /start creates the ScanLog AND dispatches the job — send ALL targets
        const startRes = await apiFetch(`/api/scans/${id}/start`, {
            method: 'POST',
            body: JSON.stringify({ target_url: targetUrl, all_target_urls: allTargetUrls })
        });

        // Use the scan_log_id the backend created — this is the ONLY log row
        activeScanLogId = startRes.scan_log_id || null;

        _scanStartTime = Date.now();
        _lastProgressTime = Date.now();
        _lastProgressValue = 0;
        _pollErrors = 0;
        _lastSeenVulnId = 0;

        archiveCurrentScan('running');

        // Init multi-target live monitor
        renderTargetMonitor(allTargetUrls);

        showToast('Scan started — ' + allTargetUrls.length + ' target' + (allTargetUrls.length > 1 ? 's' : '') + ' queued', 'success');

        // Hard timeout kill switch (10 min)
        _killTimer = setTimeout(() => {
            if (scanStatus !== 'running') return;
            showScanError('⏱ Scan exceeded maximum time limit (10 min) and was automatically stopped.');
            showToast('Scan timed out after 10 minutes.', 'error');
            forceStopScan();
        }, SCAN_TIMEOUT_MS);

        // Stall detector
        _resetStallTimer();

        // Start live rate ticker and elapsed timer
        const elapsedDisplay = document.getElementById('elapsedDisplay');
        if (elapsedDisplay) elapsedDisplay.style.display = 'inline';
        _updateScanTarget('SCAN', targetUrl);
        const _sf = document.getElementById('scanFeed'); if (_sf) { _sf.innerHTML = ''; _sf.style.display = 'block'; }
        _startRateTicker();

        // Poll DB every 2 seconds for progress + new vulns
        scanInterval = setInterval(scanPoll, 2000);

    } catch (e) {
        console.error('Scan start failed:', e.message);
        showScanError(`Scan failed to start: ${e.message}`);
        showToast('Scan failed to start — check logs', 'error');
        scanStatus = 'idle'; setStatus('idle');
        document.getElementById('startBtn').style.display = 'flex';
        document.getElementById('pauseBtn').style.display = 'none';
        killBtn.style.display = 'none';
        document.getElementById('progressSection').style.display = 'none';
        document.getElementById('progressPlaceholder').style.display = 'block';
    }
}

function pauseOrResume() {
    if (scanStatus === 'running') {
        clearInterval(scanInterval);
        _clearScanTimers();
        _stopRateTicker();
        scanStatus = 'paused'; setStatus('paused');
        document.getElementById('pauseLabel').textContent = 'Resume';
        showToast('Scan paused', 'warn');
        if (_vulnFlushTimer) { clearTimeout(_vulnFlushTimer); _vulnFlushTimer = null; }
        flushVulnBuffer().finally(() => {
            if (activeScanId) apiFetch(`/api/scans/${activeScanId}`, {
                method: 'PATCH', body: JSON.stringify({ status: 'paused' })
            }).catch(() => { });
        });
    } else if (scanStatus === 'paused') {
        scanStatus = 'running'; setStatus('running');
        document.getElementById('pauseLabel').textContent = 'Pause';
        _resetStallTimer();
        _startRateTicker();
        scanInterval = setInterval(scanPoll, 2000);
        showToast('Scan resumed', 'success');
        if (activeScanId) apiFetch(`/api/scans/${activeScanId}`, {
            method: 'PATCH', body: JSON.stringify({ status: 'running' })
        }).catch(() => { });
    }
}

function setStatus(s) {
    document.getElementById('statusDot').className = 'status-dot ' + s;
    document.getElementById('statusText').textContent = s;
}

// ── Scan Poller — polls DB via /api/scan-logs/{id} ───────────────────────────
async function scanPoll() {
    if (scanStatus !== 'running' || !activeScanLogId) return;
    try {
        const res = await apiFetch(`/api/scan-logs/${activeScanLogId}`);

        _pollErrors = 0;
        clearScanError();

        const pct = res.progress || 0;
        const displayPct = Math.max(scanProgress, pct, 2);
        scanProgress = displayPct;
        document.getElementById('progressPercent').textContent = displayPct + '%';
        document.getElementById('progressBar').style.width = displayPct + '%';

        // Phase label + live scan target indicator
        const phaseLabel = res.current_phase
            || PHASES[Math.min(Math.floor((displayPct / 100) * PHASES.length), PHASES.length - 1)];

        // Extract URL from phase label if backend embedded it
        // Backend sends labels like "[http://localhost:8001] Running Nikto…"
        const bracketMatch = phaseLabel ? phaseLabel.match(/^\[([^\]]+)\]\s*(.*)$/) : null;
        const urlInPhase = phaseLabel ? phaseLabel.match(/https?:\/\/[^\s\]]+/) : null;
        const liveUrl = bracketMatch ? bracketMatch[1] : (urlInPhase ? urlInPhase[0] : (res.target_url || (savedTargets[0] && savedTargets[0].url) || ''));
        const cleanLabel = bracketMatch ? bracketMatch[2].trim() : (phaseLabel ? phaseLabel.replace(/https?:\/\/[^\s]+/, '').trim() : phaseLabel);

        // Show target host + phase label so user sees which target is being scanned
        const targetHost = liveUrl ? (() => { try { return new URL(liveUrl).host; } catch(_) { return liveUrl; } })() : '';
        const displayLabel = targetHost ? '[' + targetHost + '] ' + cleanLabel : cleanLabel;
        document.getElementById('progressPhase').textContent = displayLabel;

        // Update multi-target live monitor
        updateTargetMonitor(liveUrl, cleanLabel, displayPct);

        // Show live URL being scanned
        const liveScanUrlEl = document.getElementById('liveScanUrl');
        if (liveScanUrlEl) {
            liveScanUrlEl.textContent = liveUrl ? '↳ ' + liveUrl : '';
            liveScanUrlEl.style.display = liveUrl ? 'block' : 'none';
        }

        // Track scanned URLs and show clean/vuln status per endpoint
        const scanFeedEl = document.getElementById('scanFeed');
        if (scanFeedEl && liveUrl && liveUrl !== _lastFeedUrl) {
            _lastFeedUrl = liveUrl;
            const row = document.createElement('div');
            row.style.cssText = 'display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.04);font-size:11px;font-family:"DM Mono",monospace;';
            row.innerHTML = '<span style="color:var(--neon);flex-shrink:0;">→</span>'
                + '<code style="color:white;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + liveUrl + '">' + liveUrl + '</code>'
                + '<span id="feed_' + btoa(liveUrl).replace(/[^a-zA-Z0-9]/g, '').slice(0, 12) + '" style="flex-shrink:0;color:var(--muted);">scanning…</span>';
            scanFeedEl.insertBefore(row, scanFeedEl.firstChild);
            // Keep feed to last 20 entries
            while (scanFeedEl.children.length > 20) scanFeedEl.removeChild(scanFeedEl.lastChild);
        }

        // Map phase → badge key
        const _phaseKey = (function (p) {
            if (!p) return 'SCAN';
            p = p.toLowerCase();
            if (p.includes('path')) return 'PATHS';
            if (p.includes('header')) return 'HEADERS';
            if (p.includes('nikto')) return 'NIKTO';
            if (p.includes('nuclei')) return 'NUCLEI';
            if (p.includes('depend')) return 'DEPS';
            return 'SCAN';
        })(res.current_phase);
        _updateScanTarget(_phaseKey, liveUrl);

        // Stats
        if (res.stats) {
            liveStats.requestsSent = res.stats.requestsSent || liveStats.requestsSent;
            liveStats.urlsDiscovered = res.stats.urlsDiscovered || liveStats.urlsDiscovered;
        }
        updateStatDOM();

        // Stall detection
        _resetStallTimer();
        if (displayPct > _lastProgressValue) {
            _lastProgressValue = displayPct;
            _lastProgressTime = Date.now();
        }

        // New vulns — compare against what we've already rendered
        const vulns = res.vulns || [];
        vulns.forEach(v => {
            if (!allVulns.find(x => x.id === v.id)) {
                const vuln = {
                    id: v.id,
                    name: v.name,
                    url: v.url,
                    sev: v.sev || v.severity,
                    badge: v.badge || ('badge-' + (v.sev || v.severity || 'low')),
                    cve: v.cve || null,
                    evidence: v.evidence || null,
                    description: v.description || null,
                    solution: v.solution || null,
                    // Prefer the timestamp the scanner/backend recorded; never use
                    // the frontend poll-receipt time as it reflects queue delay.
                    detected_at: v.detected_at || v.time || null,
                    time: v.detected_at || v.time || null,
                };
                allVulns.unshift(vuln);
                liveStats.vulnerabilitiesFound++;
                if (vuln.sev === 'critical') liveStats.criticalIssues++;
                else if (vuln.sev === 'high') liveStats.highIssues++;
                else if (vuln.sev === 'medium') liveStats.mediumIssues++;
                else liveStats.lowIssues++;
                pushRecentVuln(vuln);
                pushVulnRow(vuln);
                lsSaveVulns(allVulns);
                archiveCurrentScan('running');
                if (v.id > _lastSeenVulnId) _lastSeenVulnId = v.id;
            }
        });
        updateStatDOM();

        // Update feed: mark previous URL as clean if no new vulns found for it
        if (_lastFeedUrl) {
            const feedKey = 'feed_' + btoa(_lastFeedUrl).replace(/[^a-zA-Z0-9]/g, '').slice(0, 12);
            const feedStatus = document.getElementById(feedKey);
            if (feedStatus && feedStatus.textContent === 'scanning…') {
                const hadVuln = vulns.some(v => v.url === _lastFeedUrl);
                if (hadVuln) {
                    feedStatus.textContent = '⚠ vuln';
                    feedStatus.style.color = 'var(--red)';
                } else {
                    feedStatus.textContent = '✓ clean';
                    feedStatus.style.color = 'var(--neon)';
                }
            }
        }

        // Stop polling when completed
        if (res.status === 'completed' || pct >= 100) {
            clearInterval(scanInterval);
            scanInterval = null;
            completeScan();
        }

    } catch (e) {
        _pollErrors++;
        console.warn(`Scan poll error (${_pollErrors}/${MAX_POLL_ERRORS}):`, e.message);

        if (_pollErrors >= MAX_POLL_ERRORS) {
            showScanError(`Scanner stopped responding after ${_pollErrors} failed attempts: ${e.message}`);
            showToast('Scanner unreachable — scan aborted.', 'error');
            _clearScanTimers();
            clearInterval(scanInterval);
            scanInterval = null;
            scanStatus = 'idle'; setStatus('idle');
            document.getElementById('startBtn').style.display = 'flex';
            document.getElementById('pauseBtn').style.display = 'none';
            document.getElementById('killBtn') && (document.getElementById('killBtn').style.display = 'none');
        } else {
            showScanError(`Poll error (${_pollErrors}/${MAX_POLL_ERRORS}): ${e.message} — retrying\u2026`);
        }
    }
}


// ── Flush buffered vulns — saves to scans AND scan_logs ─────────────────────
async function flushVulnBuffer() {
    if (!activeScanLogId || !_vulnBuffer.length) return;
    const toSave = _vulnBuffer.splice(0);
    try {
        await dbFlushVulns(toSave);
    } catch (e) {
        _vulnBuffer.unshift(...toSave);
        console.warn('Vuln flush failed, will retry:', e.message);
    }
}

// ── Complete ──────────────────────────────────────────────────────────────────
function completeScan() {
    _clearScanTimers();
    clearInterval(scanInterval);
    scanInterval = null;
    _stopRateTicker();
    _updateScanTarget(null, null);
    const _sfHide = document.getElementById('scanFeed'); if (_sfHide) _sfHide.style.display = 'none';
    const elapsedDisplay = document.getElementById('elapsedDisplay');
    if (elapsedDisplay) elapsedDisplay.style.display = 'none';
    if (_pollSyncTimer) { clearTimeout(_pollSyncTimer); _pollSyncTimer = null; }
    scanStatus = 'completed'; setStatus('completed');
    finalizeTargetMonitor();
    document.getElementById('pauseBtn').style.display = 'none';
    document.getElementById('killBtn') && (document.getElementById('killBtn').style.display = 'none');
    document.getElementById('startBtn').style.display = 'flex';
    document.getElementById('startLabel').textContent = 'New Scan';
    document.getElementById('startIcon').outerHTML = `<svg id="startIcon" width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5"><path d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>`;
    document.getElementById('progressPhase').textContent = '✓ Complete — ' + liveStats.vulnerabilitiesFound + ' vulnerabilities found';
    archiveCurrentScan('completed');
    showToast('Scan done! ' + liveStats.vulnerabilitiesFound + ' findings.', 'success');
    clearScanError();
    if (document.getElementById('autoExport') && document.getElementById('autoExport').checked) exportReport();
    if (activeScanId) {
        if (_vulnFlushTimer) { clearTimeout(_vulnFlushTimer); _vulnFlushTimer = null; }
        flushVulnBuffer().finally(() => {
            // Mark scan completed in scans table
            apiFetch(`/api/scans/${activeScanId}`, {
                method: 'PATCH',
                body: JSON.stringify({ status: 'completed', progress: 100 })
            }).catch(() => { });
            // Mark scan log completed in DB
            dbUpdateScanLog({
                status: 'completed',
                progress: 100,
                requests_sent: liveStats.requestsSent,
                urls_discovered: liveStats.urlsDiscovered,
            });
            _lastSyncedProgress = -1;
        });
    }
}

// ── Rate tracking — +N/s badges, elapsed timer, current scan target ─────────
let _prevReqSnapshot = 0;
let _prevUrlSnapshot = 0;
let _rateInterval = null;

function _startRateTicker() {
    _stopRateTicker();
    _prevReqSnapshot = liveStats.requestsSent;
    _prevUrlSnapshot = liveStats.urlsDiscovered;
    _rateInterval = setInterval(() => {
        const reqDelta = Math.max(0, liveStats.requestsSent - _prevReqSnapshot);
        const urlDelta = Math.max(0, liveStats.urlsDiscovered - _prevUrlSnapshot);
        _prevReqSnapshot = liveStats.requestsSent;
        _prevUrlSnapshot = liveStats.urlsDiscovered;
        const reqRateEl = document.getElementById('reqRate');
        const urlRateEl = document.getElementById('urlRate');
        if (reqRateEl) reqRateEl.textContent = reqDelta;
        if (urlRateEl) urlRateEl.textContent = urlDelta;
        if (_scanStartTime) {
            const secs = Math.floor((Date.now() - _scanStartTime) / 1000);
            const m = Math.floor(secs / 60), s = secs % 60;
            const elapsedEl = document.getElementById('elapsedTime');
            if (elapsedEl) elapsedEl.textContent = m > 0 ? m + 'm ' + s + 's' : s + 's';
        }
    }, 1000);
}

function _stopRateTicker() {
    if (_rateInterval) { clearInterval(_rateInterval); _rateInterval = null; }
    const reqRateEl = document.getElementById('reqRate');
    const urlRateEl = document.getElementById('urlRate');
    if (reqRateEl) reqRateEl.textContent = '0';
    if (urlRateEl) urlRateEl.textContent = '0';
}

// Phase label → display config
const PHASE_DISPLAY = {
    'PATHS': { label: 'PATHS', bg: 'rgba(0,245,196,.08)', fg: 'var(--neon)', border: 'rgba(0,245,196,.15)' },
    'HEADERS': { label: 'HEADERS', bg: 'rgba(99,102,241,.08)', fg: '#818cf8', border: 'rgba(99,102,241,.15)' },
    'NIKTO': { label: 'NIKTO', bg: 'rgba(245,158,11,.08)', fg: 'var(--orange)', border: 'rgba(245,158,11,.15)' },
    'NUCLEI': { label: 'NUCLEI', bg: 'rgba(240,80,80,.08)', fg: 'var(--red)', border: 'rgba(240,80,80,.15)' },
    'DEPS': { label: 'DEPS', bg: 'rgba(16,185,129,.08)', fg: '#34d399', border: 'rgba(16,185,129,.15)' },
    'SCAN': { label: 'SCAN', bg: 'rgba(245,158,11,.08)', fg: 'var(--orange)', border: 'rgba(245,158,11,.15)' },
};

function _updateScanTarget(phase, url) {
    const wrap = document.getElementById('currentScanTarget');
    const phaseEl = document.getElementById('currentScanPhaseIcon');
    const urlEl = document.getElementById('currentScanUrl');
    if (!wrap) return;
    if (!url) { wrap.style.display = 'none'; return; }
    wrap.style.display = 'block';
    if (phaseEl) {
        const cfg = PHASE_DISPLAY[phase] || PHASE_DISPLAY['SCAN'];
        phaseEl.textContent = cfg.label;
        phaseEl.style.background = cfg.bg;
        phaseEl.style.color = cfg.fg;
        phaseEl.style.borderColor = cfg.border;
    }
    if (urlEl) {
        urlEl.textContent = url;
        urlEl.title = url;
    }
}

function updateStatDOM() {
    document.getElementById('requestsSent').textContent = liveStats.requestsSent.toLocaleString();
    document.getElementById('urlsDiscovered').textContent = liveStats.urlsDiscovered;
    document.getElementById('vulnerabilitiesFound').textContent = liveStats.vulnerabilitiesFound;
    document.getElementById('criticalIssues').textContent = liveStats.criticalIssues;
    // Severity breakdown in the SEVERITY panel
    const ce = document.getElementById('criticalCount'); if (ce) ce.textContent = liveStats.criticalIssues;
    const he = document.getElementById('highCount'); if (he) he.textContent = liveStats.highIssues;
    const me = document.getElementById('mediumCount'); if (me) me.textContent = liveStats.mediumIssues;
    const le = document.getElementById('lowCount'); if (le) le.textContent = liveStats.lowIssues;
}

function pushRecentVuln(v) {
    const c = document.getElementById('recentVulns');
    if (c.querySelector('.empty-state')) c.innerHTML = '';
    const sevColor = { critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)', low: 'var(--neon)' };
    const d = document.createElement('div');
    d.className = 'list-row';
    d.innerHTML = `
        <div style="display:flex;align-items:center;gap:10px;flex:1;min-width:0;">
            <div style="width:6px;height:6px;border-radius:50%;flex-shrink:0;background:${sevColor[v.sev] || 'var(--muted)'};box-shadow:0 0 6px ${sevColor[v.sev] || 'transparent'};"></div>
            <div style="min-width:0;">
                <p style="font-size:14px;font-weight:600;">${v.name}</p>
                <p style="font-size:12px;color:white;font-family:'DM Mono',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${v.url}</p>
            </div>
        </div>
        <div style="display:flex;align-items:center;gap:8px;flex-shrink:0;margin-left:12px;">
            <span style="font-family:'DM Mono',monospace;font-size:12px;color:white;">${(v.detected_at || v.time) ? (() => { try { const d = new Date(v.detected_at || v.time); if (isNaN(d)) return v.detected_at || v.time; const pad = n => String(n).padStart(2,'0'); const mo = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][d.getMonth()]; return mo+' '+d.getDate()+' '+pad(d.getHours())+':'+pad(d.getMinutes()); } catch (_) { return v.detected_at || v.time; } })() : '—'}</span>
            <span class="badge ${v.badge}">${v.sev}</span>
            <button style="font-size:14px;font-weight:600;color:var(--neon);background:none;border:none;cursor:pointer;font-family:'DM Sans',sans-serif;" data-action="open-vuln-modal" data-vuln="${btoa(unescape(encodeURIComponent(JSON.stringify(v))))}">Fix →</button>
        </div>`;
    c.insertBefore(d, c.firstChild);
    while (c.children.length > 8) c.removeChild(c.lastChild);
}

function pushVulnRow(v) {
    const tb = document.getElementById('vulnTableBody');
    if (tb.querySelector('.empty-state')) tb.innerHTML = '';
    const row = document.createElement('tr');
    row.setAttribute('data-severity', v.sev);
    const vB64 = btoa(unescape(encodeURIComponent(JSON.stringify(v))));
    row.innerHTML = `
        <td style="font-weight:600;">${v.name}</td>
        <td><code style="font-size:12px;color:var(--neon);font-family:'DM Mono',monospace;">${v.url}</code></td>
        <td><span class="badge ${v.badge}">${v.sev}</span></td>
        <td style="font-size:12px;color:var(--neon);">● Confirmed</td>
        <td style="font-family:'DM Mono',monospace;font-size:12px;color:white;">${(v.detected_at || v.time) ? (() => { try { const d = new Date(v.detected_at || v.time); if (isNaN(d)) return v.detected_at || v.time; const pad = n => String(n).padStart(2,'0'); const mo = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][d.getMonth()]; return mo+' '+d.getDate()+' '+pad(d.getHours())+':'+pad(d.getMinutes())+':'+pad(d.getSeconds()); } catch (_) { return v.detected_at || v.time; } })() : '—'}</td>
        <td><button style="font-size:11px;font-weight:600;color:var(--neon);background:none;border:none;cursor:pointer;font-family:'DM Sans',sans-serif;" data-action="open-vuln-modal" data-v="${vB64}">Details →</button></td>`;
    tb.insertBefore(row, tb.firstChild);
}

// ════════════════════════════════════════
// API HELPERS
// ════════════════════════════════════════
let activeScanId = null;
let savedTargets = [];
let savedCredentials = [];

function userKey(k) { return 'wavs_' + (currentUser ? currentUser.email : 'guest') + '_' + k; }
function lsGetTargets() { try { return JSON.parse(localStorage.getItem(userKey('targets')) || '[]'); } catch (e) { return []; } }
function lsSaveTargets(arr) { try { localStorage.setItem(userKey('targets'), JSON.stringify(arr)); } catch (e) { } }
function lsGetCreds() { try { return JSON.parse(localStorage.getItem(userKey('credentials')) || '[]'); } catch (e) { return []; } }
function lsSaveCreds(arr) { try { localStorage.setItem(userKey('credentials'), JSON.stringify(arr)); } catch (e) { } }
// Vulnerability persistence — DB is source of truth, localStorage is removed
// Kept as stubs so existing code paths don't break
function lsGetVulns() { return []; }
function lsSaveVulns(arr) { /* no-op — vulns saved to DB via flushVulnBuffer */ }

// ════════════════════════════════════════
// SCAN HISTORY — DB-backed (no localStorage)
// ════════════════════════════════════════
// activeScanLogId tracks the current scan_log DB row
let activeScanLogId = null;
let _dbHistory = [];  // in-memory cache from DB


// ── Restore active scan after page refresh ───────────────────────────────────
// Called on enterApp() BEFORE dbLoadHistory() so activeScanLogId is set,
// which prevents dbLoadHistory() from wrongly marking the live scan as 'stopped'.
async function tryRestoreActiveScan() {
    try {
        const logs = await apiFetch('/api/scan-logs');
        if (!Array.isArray(logs)) return;

        // Find the most-recent scan that is still running on the server
        const running = logs.find(s => s.status === 'running');
        if (!running) return;

        // Restore IDs so the rest of the app knows a scan is live
        activeScanLogId = running.id;
        activeScanId = running.scan_id || null;

        // Restore progress state
        scanProgress = running.progress || 0;
        _lastProgressValue = scanProgress;
        _lastProgressTime = Date.now();
        _pollErrors = 0;
        _scanStartTime = Date.now(); // approximate — stall timer reset from now

        // Restore vulns already found so the live table isn't blank
        const vulns = running.vulns || [];
        allVulns = [];
        vulns.forEach(v => {
            const vuln = {
                id: v.id,
                name: v.name,
                url: v.url,
                sev: v.sev || v.severity,
                badge: v.badge || ('badge-' + (v.sev || v.severity || 'low')),
                cve: v.cve || null,
                evidence: v.evidence || null,
                description: v.description || null,
                solution: v.solution || null,
                detected_at: v.detected_at || v.time || null,
                time: v.detected_at || v.time || null,
            };
            allVulns.push(vuln);
            if (vuln.sev === 'critical') liveStats.criticalIssues++;
            else if (vuln.sev === 'high') liveStats.highIssues++;
            else if (vuln.sev === 'medium') liveStats.mediumIssues++;
            else liveStats.lowIssues++;
        });
        liveStats.vulnerabilitiesFound = allVulns.length;

        // Rebuild the UI as if the scan is in progress
        scanStatus = 'running';
        setStatus('running');
        document.getElementById('startBtn').style.display = 'none';
        document.getElementById('pauseBtn').style.display = 'flex';
        document.getElementById('pauseLabel').textContent = 'Pause';
        document.getElementById('progressSection').style.display = 'block';
        document.getElementById('progressPlaceholder').style.display = 'none';

        // Show kill switch
        let killBtn = document.getElementById('killBtn');
        if (!killBtn) {
            killBtn = document.createElement('button');
            killBtn.id = 'killBtn';
            killBtn.style.cssText = `
                display:inline-flex;align-items:center;gap:6px;
                background:rgba(240,80,80,.1);color:#f05050;
                border:1px solid rgba(240,80,80,.25);border-radius:8px;
                padding:7px 14px;font-size:12px;font-weight:700;
                font-family:inherit;cursor:pointer;transition:all .2s;
            `;
            killBtn.innerHTML = '⏹ Force Stop';
            killBtn.addEventListener('click', forceStopScan);
            document.getElementById('pauseBtn').insertAdjacentElement('afterend', killBtn);
        }
        killBtn.style.display = 'inline-flex';

        // Render already-found vulns
        if (allVulns.length) {
            document.getElementById('vulnTableBody').innerHTML = '';
            document.getElementById('recentVulns').innerHTML = '';
            allVulns.forEach(v => { pushRecentVuln(v); pushVulnRow(v); });
            const badge = document.getElementById('vulnBadge');
            if (badge) { badge.textContent = allVulns.length; badge.style.display = 'inline-flex'; }
        }

        // Update progress bar
        document.getElementById('progressPercent').textContent = scanProgress + '%';
        document.getElementById('progressBar').style.width = scanProgress + '%';
        document.getElementById('progressPhase').textContent = running.current_phase || 'Resuming scan…';
        updateStatDOM();

        // Re-start the elapsed timer and poll loop
        const elapsedDisplay = document.getElementById('elapsedDisplay');
        if (elapsedDisplay) elapsedDisplay.style.display = 'inline';
        _startRateTicker();
        _resetStallTimer();
        scanInterval = setInterval(scanPoll, 2000);

        // Re-dispatch the scan job on the server — the queue worker may have
        // lost the job when the page refreshed. Safe to call even if already running.
        if (activeScanId) {
            apiFetch(`/api/scans/${activeScanId}/recover`, { method: 'POST' })
                .then(() => console.info('tryRestoreActiveScan: job re-dispatched for scan', activeScanId))
                .catch(e => console.warn('tryRestoreActiveScan: recover failed', e.message));
        }

        renderTargetMonitor(getActiveTargetUrls());
        showToast('Scan resumed after page reload', 'info');
        console.info('tryRestoreActiveScan: resumed scan_log', activeScanLogId);
    } catch (e) {
        console.warn('tryRestoreActiveScan: no active scan to restore', e.message);
    }
}

// Load history from DB
async function dbLoadHistory() {
    try {
        const data = await apiFetch('/api/scan-logs');
        _dbHistory = Array.isArray(data) ? data : [];
        // Fix stale 'running' rows — these are scans that never got marked
        // completed/stopped (crash, refresh, ZAP timeout). Mark them stopped.
        const staleRunning = _dbHistory.filter(s => s.status === 'running' && s.id != activeScanLogId);
        for (const stale of staleRunning) {
            if (activeScanLogId && stale.id === activeScanLogId) continue;
            stale.status = 'stopped';
            apiFetch(`/api/scan-logs/${stale.id}`, {
                method: 'PATCH',
                body: JSON.stringify({ status: 'stopped' })
            }).catch(() => { });
        }
        updateHistoryBadge();
        return _dbHistory;
    } catch (e) {
        console.warn('Could not load scan history from DB:', e.message);
        return [];
    }
}

// Create a new scan log row in DB when scan starts
async function dbCreateScanLog(scanId, targetUrl) {
    try {
        const res = await apiFetch('/api/scan-logs', {
            method: 'POST',
            body: JSON.stringify({ scan_id: scanId, target_url: targetUrl })
        });
        activeScanLogId = res.scan_log_id;
        return activeScanLogId;
    } catch (e) {
        console.warn('Could not create scan log:', e.message);
        return null;
    }
}

// Update scan log progress/status in DB
async function dbUpdateScanLog(updates) {
    if (!activeScanLogId) return;
    try {
        await apiFetch(`/api/scan-logs/${activeScanLogId}`, {
            method: 'PATCH',
            body: JSON.stringify(updates)
        });
    } catch (e) {
        console.warn('Could not update scan log:', e.message);
    }
}

// Save vulns for current scan log to DB
async function dbFlushVulns(vulns) {
    if (!activeScanLogId || !vulns.length) return;
    try {
        await apiFetch(`/api/scan-logs/${activeScanLogId}/vulnerabilities`, {
            method: 'POST',
            body: JSON.stringify({ vulnerabilities: vulns })
        });
    } catch (e) {
        console.warn('Could not save vulns to DB:', e.message);
    }
}

// Delete a scan log from DB
async function dbDeleteScanLog(id) {
    try {
        await apiFetch(`/api/scan-logs/${id}`, { method: 'DELETE' });
        _dbHistory = _dbHistory.filter(s => s.id !== id);
        updateHistoryBadge();
    } catch (e) {
        console.warn('Could not delete scan log:', e.message);
    }
}

// Legacy stubs — kept so nothing breaks, but DB is source of truth
function lsGetHistory() { return _dbHistory; }
function lsSaveHistory(arr) { /* no-op — DB is source of truth */ }

// Viewing state — null = live view, scanId = viewing past scan
let _viewingScanId = null;

// ── Archive current scan to history (DB + in-memory) ────────────────────────
function archiveCurrentScan(status) {
    if (!activeScanId) return;

    // Update in-memory cache — use == (loose) since scan_id may be int vs string
    const existing = _dbHistory.findIndex(s => s.scan_id == activeScanId || s.id == activeScanLogId);
    const scanEndTime = (status === 'completed' || status === 'failed') ? new Date().toISOString() : null;
    // Stamp all vulns with the scan end time when scan finishes
    if (scanEndTime) {
        allVulns = allVulns.map(v => ({ ...v, time: scanEndTime }));
    }
    const record = {
        id: activeScanLogId,
        scan_id: activeScanId,
        name: 'Scan — ' + (savedTargets[0]?.url || 'Unknown'),
        target: savedTargets[0]?.url || '—',
        target_url: savedTargets[0]?.url || '',
        startedAt: existing >= 0 ? _dbHistory[existing].startedAt : (_scanStartTime ? new Date(_scanStartTime).toISOString() : new Date().toISOString()),
        completedAt: scanEndTime,
        status: status || 'running',
        vulns: [...allVulns],
        stats: { ...liveStats },
        progress: scanProgress,
        vuln_total: allVulns.length,
        vuln_critical: liveStats.criticalIssues || 0,
        vuln_high: liveStats.highIssues || 0,
        vuln_medium: liveStats.mediumIssues || 0,
        vuln_low: liveStats.lowIssues || 0,
    };
    if (existing >= 0) {
        _dbHistory[existing] = record;
    } else {
        _dbHistory.unshift(record);
    }
    updateHistoryBadge();

    // Sync to DB
    dbUpdateScanLog({
        status: status,
        progress: Math.floor(scanProgress),
        requests_sent: liveStats.requestsSent,
        urls_discovered: liveStats.urlsDiscovered,
    });
    // Refresh from DB so vuln counts reflect real scanner results, not fake animation
    if (status === 'completed' || status === 'failed') {
        setTimeout(async () => {
            try {
                const fresh = await apiFetch('/api/scan-logs');
                if (Array.isArray(fresh)) {
                    _dbHistory = fresh;
                    updateHistoryBadge();
                    const tab = document.getElementById('scan-history-tab');
                    if (tab && tab.classList.contains('active')) loadScanHistoryTab();
                }
            } catch (e) { }
        }, 2500);
    }
    // Refresh from DB so vuln counts reflect real scanner results
    if (status === 'completed' || status === 'failed') {
        setTimeout(async () => { try { const fresh = await apiFetch('/api/scan-logs'); if (Array.isArray(fresh)) { _dbHistory = fresh; updateHistoryBadge(); if (typeof loadScanHistoryTab === 'function' && document.getElementById('scan-history-tab').classList.contains('active')) loadScanHistoryTab(); } } catch (e) { } }, 2500);
    }
}

// ── Update the sidebar badge (drawer + nav tab) ──────────────────────────────
function updateHistoryBadge() {
    const count = _dbHistory.length;
    const el = document.getElementById('historyCount');
    if (el) el.textContent = count;
    const cnt = document.getElementById('drawerScanCount');
    if (cnt) cnt.textContent = count + ' scan' + (count !== 1 ? 's' : '');
    // Also update the nav tab badge
    const navBadge = document.getElementById('historyNavBadge');
    if (navBadge) {
        navBadge.textContent = count;
        navBadge.style.display = count > 0 ? 'inline-flex' : 'none';
    }
}

// ── Load & render full Scan History tab ─────────────────────────────────────
async function loadScanHistoryTab() {
    const container = document.getElementById('historyTabContent');
    container.innerHTML = '<div style="padding:40px;text-align:center;color:white;">⟳ Loading…</div>';

    const history = await dbLoadHistory();

    // Update summary stats
    const totalVulns = history.reduce((a, s) => a + (s.vuln_total || 0), 0);
    const totalCritical = history.reduce((a, s) => a + (s.vuln_critical || 0), 0);
    const completed = history.filter(s => s.status === 'completed').length;
    const hTotal = document.getElementById('hstat-total');
    const hVulns = document.getElementById('hstat-vulns');
    const hCritical = document.getElementById('hstat-critical');
    const hComp = document.getElementById('hstat-completed');
    if (hTotal) hTotal.textContent = history.length;
    if (hVulns) hVulns.textContent = totalVulns;
    if (hCritical) hCritical.textContent = totalCritical;
    if (hComp) hComp.textContent = completed;

    if (!history.length) {
        container.innerHTML = `<div style="padding:48px 20px;text-align:center;">
            <div style="font-size:28px;margin-bottom:12px;">📋</div>
            <p style="font-size:13px;font-weight:600;color:white;margin-bottom:4px;">No scan history yet</p>
            <p style="font-size:11px;color:white;">Run your first scan and it will appear here.</p>
        </div>`;
        return;
    }

    const statusColor = { completed: 'var(--neon)', running: 'var(--neon)', failed: 'var(--red)', stopped: 'var(--orange)', paused: 'var(--orange)', idle: 'var(--muted)' };

    container.innerHTML = `
    <table class="wavs-table">
        <thead><tr>
            <th>#</th>
            <th>Target</th>
            <th>Status</th>
            <th>Started</th>
            <th>Duration</th>
            <th>Vulns</th>
            <th>C</th><th>H</th><th>M</th><th>L</th>
            <th>URLs Found</th>
            <th></th>
        </tr></thead>
        <tbody>
        ${history.map((scan, idx) => {
        const started = scan.started_at || scan.startedAt
            ? new Date(scan.started_at || scan.startedAt).toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })
            : '—';
        const dur = scan.duration_seconds
            ? (scan.duration_seconds >= 60
                ? Math.floor(scan.duration_seconds / 60) + 'm ' + (scan.duration_seconds % 60) + 's'
                : scan.duration_seconds + 's')
            : '—';
        const isLive = (scan.scan_id == activeScanId || scan.id == activeScanLogId) && _viewingScanId === null && scanStatus === 'running';
        return `<tr>
                <td style="font-family:'DM Mono',monospace;font-size:11px;color:white;">${history.length - idx}</td>
                <td>
                    <code style="font-size:14px;color:var(--neon);font-family:'DM Mono',monospace;">${scan.target || scan.target_url || '—'}</code>
                    ${isLive ? '<span style="font-size:9px;font-weight:700;color:var(--neon);background:rgba(0,245,196,.1);border:1px solid rgba(0,245,196,.2);padding:1px 6px;border-radius:4px;margin-left:6px;">LIVE</span>' : ''}
                </td>
                <td>
                    <span style="display:inline-flex;align-items:center;gap:5px;font-size:14px;font-weight:600;">
                        ${(() => {
                // A 'running' row is only truly live if it's the active scan right now.
                // Stale 'running' rows (crashed/abandoned) show as 'interrupted'.
                const effectiveStatus = (scan.status === 'running' && !isLive) ? 'interrupted' : scan.status;
                const dotColor = effectiveStatus === 'interrupted' ? 'var(--orange)' : (statusColor[effectiveStatus] || 'var(--muted)');
                const dotAnim = isLive ? 'box-shadow:0 0 6px var(--neon);animation:termBlink 1.5s ease-in-out infinite;' : '';
                return '<span style="width:6px;height:6px;border-radius:50%;background:' + dotColor + ';flex-shrink:0;' + dotAnim + '"></span>' + effectiveStatus;
            })()}
                    </span>
                </td>
                <td style="font-size:14px;color:white;">${started}</td>
                <td style="font-family:'DM Mono',monospace;font-size:14px;color:white;">${dur}</td>
                <td style="font-family:'DM Mono',monospace;font-size:14px;font-weight:600;color:white;">${scan.vuln_total || 0}</td>
                <td style="font-family:'DM Mono',monospace;font-size:14px;color:var(--red);">${scan.vuln_critical || 0}</td>
                <td style="font-family:'DM Mono',monospace;font-size:14px;color:var(--orange);">${scan.vuln_high || 0}</td>
                <td style="font-family:'DM Mono',monospace;font-size:14px;color:var(--yellow);">${scan.vuln_medium || 0}</td>
                <td style="font-family:'DM Mono',monospace;font-size:14px;color:var(--neon);">${scan.vuln_low || 0}</td>
                <td style="font-family:'DM Mono',monospace;font-size:14px;color:white;">${scan.urls_discovered || 0}</td>
                <td>
                    <div style="display:flex;gap:5px;justify-content:flex-end;">
                        ${!isLive ? `<button class="btn-ghost" style="padding:4px 10px;font-size:14px;color:white;" data-action="open-scan-detail" data-idx="${idx}">View</button>` : '<span style="font-size:14px;color:var(--neon);padding:0 4px;">Live</span>'}
                        <button class="btn-ghost" style="padding:4px 10px;font-size:14px;color:white;" data-action="export-history-scan" data-idx="${idx}">PDF</button>
                        <button class="btn-ghost" style="padding:4px 8px;font-size:14px;color:white;display:flex;align-items:center;justify-content:center;" data-action="email-history-scan" data-idx="${idx}"><svg width="13" height="13" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg></button>
                        <button class="btn-danger" style="padding:4px 8px;font-size:14px;color:white;display:flex;align-items:center;justify-content:center;" data-action="delete-history-scan-tab" data-idx="${idx}"><svg width="13" height="13" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 011-1h4a1 1 0 011 1v2"/></svg></button>
                    </div>
                </td>
            </tr>`;
    }).join('')}
        </tbody>
    </table>`;
}

// Delete from the history tab (refreshes tab after)
async function deleteHistoryScanFromTab(idx) {
    if (!await customConfirm('Delete this scan record?')) return;
    const scan = _dbHistory[idx];
    if (!scan) return;
    if (scan.id == _viewingScanId) exitViewMode();
    await dbDeleteScanLog(scan.id);
    _dbHistory.splice(idx, 1);
    updateHistoryBadge();
    loadScanHistoryTab();
    showToast('Scan deleted', 'warn');
}

// ── Open / close drawer ───────────────────────────────────────────────────────
function openScanHistory() {
    renderScanHistory();
    document.getElementById('scanHistoryDrawer').classList.add('open');
    document.getElementById('drawerOverlay').classList.add('show');
}
function closeScanHistory() {
    document.getElementById('scanHistoryDrawer').classList.remove('open');
    document.getElementById('drawerOverlay').classList.remove('show');
}

// ── Render history list — loads from DB ─────────────────────────────────────
async function renderScanHistory() {
    const container = document.getElementById('scanHistoryList');
    container.innerHTML = '<div class="drawer-empty"><div class="de-icon" style="animation:radarSpin 1s linear infinite;display:inline-block;">⟳</div><p>Loading scan history…</p></div>';

    const history = await dbLoadHistory();
    const cnt = document.getElementById('drawerScanCount');
    if (cnt) cnt.textContent = history.length + ' scan' + (history.length !== 1 ? 's' : '');

    if (!history.length) {
        container.innerHTML = '<div class="drawer-empty"><div class="de-icon">📋</div><p>No scans recorded yet.</p><p style="margin-top:6px;font-size:11px;">Run your first scan and it will appear here automatically.</p></div>';
        return;
    }

    container.innerHTML = history.map((scan, idx) => {
        const c = scan.vuln_critical || scan.stats?.criticalIssues || scan.vulns?.filter(v => v.sev === 'critical').length || 0;
        const h = scan.vuln_high || scan.stats?.highIssues || scan.vulns?.filter(v => v.sev === 'high').length || 0;
        const m = scan.vuln_medium || scan.stats?.mediumIssues || scan.vulns?.filter(v => v.sev === 'medium').length || 0;
        const l = scan.vuln_low || scan.stats?.lowIssues || scan.vulns?.filter(v => v.sev === 'low').length || 0;
        const total = scan.vuln_total || scan.vulns?.length || 0;
        const isActive = (scan.scan_id == activeScanId || scan.id == activeScanLogId) && _viewingScanId === null && scanStatus === 'running';
        const isViewing = scan.id == _viewingScanId;

        const started = (scan.startedAt || scan.started_at) ? new Date(scan.startedAt || scan.started_at).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—';
        const duration = (scan.startedAt || scan.started_at) && (scan.completedAt || scan.completed_at)
            ? (() => { const ms = new Date(scan.completedAt || scan.completed_at) - new Date(scan.startedAt || scan.started_at); const m = Math.floor(ms / 60000); const s = Math.floor((ms % 60000) / 1000); return m > 0 ? `${m}m ${s}s` : `${s}s`; })()
            : '—';

        const statusColors = { completed: 'var(--neon)', running: 'var(--neon)', failed: 'var(--red)', paused: 'var(--orange)', idle: 'var(--muted)' };

        return `
        <div class="sh-card ${isActive ? 'sh-active' : ''} ${isViewing ? 'sh-active' : ''}" data-scan-idx="${idx}">
            <div class="sh-card-head">
                <div class="sh-dot ${(scan.status === 'running' && !isActive) ? 'paused' : scan.status}"></div>
                <span class="sh-name" title="${scan.target}">${scan.name}</span>
                <span class="sh-time">${started}</span>
                ${isActive ? '<span style="font-size:9px;font-weight:700;color:var(--neon);background:rgba(0,245,196,.1);border:1px solid rgba(0,245,196,.2);padding:1px 6px;border-radius:4px;flex-shrink:0;">LIVE</span>' : ''}
                ${isViewing ? '<span style="font-size:9px;font-weight:700;color:#93c5fd;background:rgba(59,130,246,.12);border:1px solid rgba(59,130,246,.25);padding:1px 6px;border-radius:4px;flex-shrink:0;">VIEWING</span>' : ''}
            </div>
            <div class="sh-card-body">
                <div class="sh-stat">
                    <span class="sh-stat-num" style="color:white;">${total}</span>
                    <span class="sh-stat-lbl" style="color:white;">Vulns</span>
                </div>
                <div class="sh-stat">
                    <span class="sh-stat-num" style="color:white;font-size:16px;">${scan.progress || 0}%</span>
                    <span class="sh-stat-lbl" style="color:white;">Progress</span>
                </div>
                <div class="sh-stat">
                    <span class="sh-stat-num" style="color:white;font-size:16px;">${duration}</span>
                    <span class="sh-stat-lbl" style="color:white;">Duration</span>
                </div>
                <div class="sh-sev-pills">
                    ${c > 0 ? `<span class="sh-pill c">C:${c}</span>` : ''}
                    ${h > 0 ? `<span class="sh-pill h">H:${h}</span>` : ''}
                    ${m > 0 ? `<span class="sh-pill m">M:${m}</span>` : ''}
                    ${l > 0 ? `<span class="sh-pill l">L:${l}</span>` : ''}
                    ${total === 0 ? `<span style="font-size:10px;color:var(--muted);">No findings</span>` : ''}
                </div>
            </div>
            <div class="sh-card-actions">
                ${!isActive && !isViewing ? `<button class="sh-btn primary" data-action="open-scan-detail-drawer" data-idx="${idx}">
                    <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
                    View Results
                </button>` : ''}
                ${isViewing ? `<button class="sh-btn primary" data-action="exit-view-mode-drawer">
                    <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M19 12H5M12 5l-7 7 7 7"/></svg>
                    Back to Live
                </button>` : ''}
                ${isActive ? `<span style="font-size:11px;color:var(--neon);padding:0 4px;align-self:center;">Currently scanning</span>` : ''}
                <button class="sh-btn" data-action="export-history-scan" data-idx="${idx}" title="Export PDF">
                    <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                    PDF
                </button>
                <button class="sh-btn danger" data-action="delete-history-scan" data-idx="${idx}" title="Delete">
                    <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/></svg>
                </button>
            </div>
        </div>`;
    }).join('');
}

// ── Load a past scan into the UI (read-only view) ────────────────────────────
async function loadHistoryScan(idx) {
    // Fetch full details from DB (includes vulns)
    const listItem = _dbHistory[idx];
    if (!listItem) return;

    let scan = listItem;
    // If vulns not loaded yet, fetch full record
    if (!scan.vulns || scan.vulns.length !== (scan.vuln_total || 0)) {
        try {
            scan = await apiFetch(`/api/scan-logs/${listItem.id}`);
            _dbHistory[idx] = scan; // update cache
        } catch (e) {
            console.warn('Could not load scan details:', e.message);
        }
    }

    _viewingScanId = scan.id;

    // Show viewing banner
    const banner = document.getElementById('viewingBanner');
    const bannerText = document.getElementById('viewingBannerText');
    banner.classList.add('show');
    bannerText.textContent = `Viewing: ${scan.name} · ${scan.target} · ${scan.status}`;

    // Populate stats
    const s = scan.stats || {};
    document.getElementById('requestsSent').textContent = (s.requestsSent || 0).toLocaleString();
    document.getElementById('urlsDiscovered').textContent = s.urlsDiscovered || 0;
    document.getElementById('vulnerabilitiesFound').textContent = scan.vulns?.length || 0;
    document.getElementById('criticalIssues').textContent = s.criticalIssues || 0;
    document.getElementById('criticalCount').textContent = scan.vulns?.filter(v => v.sev === 'critical').length || 0;
    document.getElementById('highCount').textContent = scan.vulns?.filter(v => v.sev === 'high').length || 0;
    document.getElementById('mediumCount').textContent = scan.vulns?.filter(v => v.sev === 'medium').length || 0;
    document.getElementById('lowCount').textContent = scan.vulns?.filter(v => v.sev === 'low').length || 0;

    // Progress bar
    document.getElementById('progressPercent').textContent = (scan.progress || 100) + '%';
    document.getElementById('progressBar').style.width = (scan.progress || 100) + '%';
    document.getElementById('progressPhase').textContent = scan.status === 'completed'
        ? '✓ Complete — ' + (scan.vulns?.length || 0) + ' vulnerabilities found'
        : scan.status;
    document.getElementById('progressSection').style.display = 'block';
    document.getElementById('progressPlaceholder').style.display = 'none';

    // Populate vuln table and recent list
    const tb = document.getElementById('vulnTableBody');
    const rv = document.getElementById('recentVulns');
    tb.innerHTML = '';
    rv.innerHTML = '';

    const vulns = scan.vulns || [];
    if (!vulns.length) {
        tb.innerHTML = '<tr><td colspan="6"><div class="empty-state"><div class="empty-icon">🛡️</div>No vulnerabilities in this scan.</div></td></tr>';
        rv.innerHTML = '<div class="empty-state"><div class="empty-icon">🔍</div>No findings in this scan.</div>';
    } else {
        vulns.forEach(v => { pushRecentVuln(v); pushVulnRow(v); });
        const badge = document.getElementById('vulnBadge');
        if (badge) { badge.textContent = vulns.length; badge.style.display = 'inline-flex'; }
    }

    switchTab('dashboard');
    showToast('Viewing: ' + scan.name, 'info');
}

// ── Exit view mode — restore live scan state ─────────────────────────────────
function exitViewMode() {
    _viewingScanId = null;
    document.getElementById('viewingBanner').classList.remove('show');

    // Restore live state
    const tb = document.getElementById('vulnTableBody');
    const rv = document.getElementById('recentVulns');
    tb.innerHTML = '';
    rv.innerHTML = '';

    if (allVulns.length) {
        allVulns.forEach(v => { pushRecentVuln(v); pushVulnRow(v); });
    } else {
        tb.innerHTML = '<tr><td colspan="6"><div class="empty-state"><div class="empty-icon">🛡️</div>No vulnerabilities detected yet.</div></td></tr>';
        rv.innerHTML = '<div class="empty-state"><div class="empty-icon">🔍</div>No findings yet. Start a scan.</div>';
    }

    updateStatDOM();
    const badge = document.getElementById('vulnBadge');
    if (badge) {
        if (allVulns.length) { badge.textContent = allVulns.length; badge.style.display = 'inline-flex'; }
        else badge.style.display = 'none';
    }
    showToast('Back to live view', 'success');
}

// ── Delete a history record — removes from DB ───────────────────────────────
async function deleteHistoryScan(idx) {
    if (!await customConfirm('Delete this scan record?')) return;
    const scan = _dbHistory[idx];
    if (!scan) return;
    if (scan.id === _viewingScanId) exitViewMode();
    await dbDeleteScanLog(scan.id);
    _dbHistory.splice(idx, 1);
    updateHistoryBadge();
    renderScanHistory();
    showToast('Scan deleted', 'warn');
}

// ── Export a past scan as PDF ─────────────────────────────────────────────────
async function exportHistoryScan(idx) {
    let scan = _dbHistory[idx];
    if (!scan) { showToast('Scan not found', 'warn'); return; }
    // Fetch full record if vulns not loaded
    if (!scan.vulns || !scan.vulns.length) {
        try {
            scan = await apiFetch(`/api/scan-logs/${scan.id}`);
            _dbHistory[idx] = scan;
        } catch (e) {
            showToast('Could not load scan data', 'error'); return;
        }
    }
    if (!scan.vulns?.length) { showToast('No vulnerabilities to export', 'warn'); return; }
    const savedAllVulns = allVulns;
    allVulns = scan.vulns;
    exportReportPDF();
    allVulns = savedAllVulns;
}

const API_BASE = (() => {
    // If running inside the uptimebot proxy (port 8000), use proxied path
    if (window.location.port === '8000' || window.location.pathname.startsWith('/vulnsight')) {
        return window.location.protocol + '//' + window.location.hostname + ':8000/vulnsight';
    }
    return 'http://localhost:8001';
})();

async function apiFetch(url, options = {}) {
    const fullUrl = url.startsWith('http') ? url : API_BASE + url;

    // Read CSRF token from cookie first (works through proxy), fallback to meta tag
    const getCsrfFromCookie = () => {
        const match = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]+)/);
        if (!match) return '';
        try { return decodeURIComponent(match[1]); } catch (_) { return match[1]; }
    };
    const csrfToken = getCsrfFromCookie()
        || document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
        || '';

    const bearerToken = localStorage.getItem('token') || '';
    const merged = {
        credentials: 'include',
        ...options,
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'X-CSRF-TOKEN': csrfToken,
            'X-XSRF-TOKEN': csrfToken,
            ...(bearerToken ? { 'Authorization': 'Bearer ' + bearerToken } : {}),
            ...(options.headers || {}),
        },
    };
    const response = await fetch(fullUrl, merged);
    if (!response.ok) {
        if (response.status === 401) { console.error('User is not logged in.'); throw new Error('Unauthenticated'); }
        if (response.status === 403) {
            try {
                const b = await response.clone().json();
                if (b.banned === true) {
                    // Account banned — force immediate logout and redirect to login
                    try { await fetch(API_BASE + '/api/logout', { method: 'POST', credentials: 'include', headers: { 'X-Requested-With': 'XMLHttpRequest' } }); } catch (_) { }
                    alert('Your account has been suspended. Please contact support.');
                    window.location.href = '/';
                    throw new Error('Banned');
                }
            } catch (e) { if (e.message === 'Banned') throw e; }
        }
        let msg = `HTTP ${response.status}: ${response.statusText}`;
        try { const b = await response.clone().json(); if (b.message) msg = b.message; } catch (_) { }
        console.error(`apiFetch ${response.status} on ${url}:`, msg);
        throw new Error(msg);
    }
    if (response.status === 204) return null;
    const text = await response.text();
    if (!text || !text.trim()) return null;
    try { return JSON.parse(text); } catch (_) { return null; }
}

// createFreshScan — always makes a NEW scan record (used by startScan)
async function createFreshScan() {
    try {
        const s = await apiFetch('/api/scans', {
            method: 'POST',
            body: JSON.stringify({ name: 'VulnSight Scan ' + new Date().toLocaleTimeString() })
        });
        activeScanId = s.id;
        return activeScanId;
    } catch (e) {
        console.error('Could not create scan:', e.message);
        return null;
    }
}

// ensureScan — reuses existing scan if one exists (used by targets/credentials/config)
async function ensureScan() {
    if (activeScanId) return activeScanId;
    try {
        const scans = await apiFetch('/api/scans');
        if (scans && scans.length) { activeScanId = scans[0].id; return activeScanId; }
    } catch (e) { console.warn('Could not list scans:', e.message); }
    try {
        const s = await apiFetch('/api/scans', { method: 'POST', body: JSON.stringify({ name: 'VulnSight Scan' }) });
        activeScanId = s.id; return activeScanId;
    } catch (e) { console.error('Could not create scan:', e.message); }
    return null;
}

// Track IDs deleted this session so API re-fetches don't restore them
const _deletedTargetIds = new Set();

async function loadTargets() {
    // FIX: Always load from localStorage first as the primary source of truth
    const local = lsGetTargets();
    if (local.length) { savedTargets = local; renderTargetsList(); }
    const scanId = await ensureScan();
    if (!scanId) return;
    try {
        const targets = await apiFetch(`/api/scans/${scanId}/targets`);
        // Filter out deleted targets
        const apiTargets = targets
            .filter(t => !_deletedTargetIds.has(String(t.id)))
            .map(t => ({ id: t.id, url: t.url, type: 'Web Application' }));

        if (apiTargets.length) {
            // FIX: Merge API targets with local-only targets (those with 'local_' IDs)
            const localOnlyTargets = savedTargets.filter(t => String(t.id).startsWith('local_'));
            // Combine: API targets first, then any local-only ones not in API
            const mergedUrls = new Set(apiTargets.map(t => t.url));
            const uniqueLocalOnly = localOnlyTargets.filter(t => !mergedUrls.has(t.url));
            savedTargets = [...apiTargets, ...uniqueLocalOnly];
        }
        // If API returns empty, keep whatever is in localStorage (don't wipe it)
        lsSaveTargets(savedTargets); renderTargetsList();
    } catch (e) { console.warn('loadTargets API failed, using localStorage:', e.message); }
}

async function loadCredentials() {
    savedCredentials = lsGetCreds();
    const list = document.getElementById('sessionsList');
    const countEl = document.getElementById('credCountLabel');
    const hintEl = document.getElementById('credRevealHint');
    if (countEl) countEl.textContent = savedCredentials.length + ' stored';
    if (hintEl) hintEl.style.display = savedCredentials.length ? 'block' : 'none';

    if (!savedCredentials.length) {
        list.innerHTML = `<div class="empty-state">
            <div style="width:40px;height:40px;border-radius:10px;background:var(--surface2);border:1px solid var(--border);display:flex;align-items:center;justify-content:center;margin:0 auto 12px;font-size:20px;">🔑</div>
            <p style="font-size:18px;font-weight:600;color:var(--text);margin-bottom:4px;">No credentials yet</p>
            <p style="font-size:16px;color:white;">Add a session cookie or API token above to enable authenticated scanning.</p>
        </div>`;
        return;
    }

    const typeColors = { cookie: 'type-cookie', bearer: 'type-bearer', basic: 'type-basic', oauth: 'type-oauth' };
    const typeIcons = {
        cookie: '<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>',
        bearer: '<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>',
        basic: '<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
        oauth: '<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M8.56 2.75c4.37 6.03 6.02 9.42 8.03 17.72m2.54-15.38c-3.72 4.35-8.94 5.66-16.88 5.85m19.5 1.9c-3.5-.93-6.63-.82-8.94 0-2.58.92-5.01 2.86-7.44 6.32"/></svg>',
    };

    list.innerHTML = '<div style="display:flex;flex-direction:column;gap:8px;padding:14px;">' +
        savedCredentials.map((c, idx) => {
            const typeKey = c.type || 'cookie';
            const tc = typeColors[typeKey] || 'type-bearer';
            const ti = typeIcons[typeKey] || typeIcons.bearer;
            const displayName = c.label || c.username || 'Unnamed';
            const displaySub = c.type === 'basic' ? (c.username || '') + ' / ••••••••' : '••••••••••••••••••';
            return `
            <div class="cred-card ${tc}" data-idx="${idx}">
                <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
                    <div style="display:flex;align-items:center;gap:10px;flex:1;min-width:0;">
                        <div style="width:32px;height:32px;border-radius:8px;background:var(--surface);border:1px solid var(--border);display:flex;align-items:center;justify-content:center;flex-shrink:0;color:var(--muted);">${ti}</div>
                        <div style="flex:1;min-width:0;">
                            <div style="display:flex;align-items:center;gap:7px;margin-bottom:3px;">
                                <span style="font-size:13px;font-weight:700;">${displayName}</span>
                                <span class="cred-type-badge ${tc}">${c.method}</span>
                            </div>
                            <div style="display:flex;align-items:center;gap:7px;">
                                <code style="font-size:11px;color:var(--muted);font-family:'DM Mono',monospace;" data-val="${displaySub}" data-revealed="0">${displaySub}</code>
                                <button class="reveal-btn" data-action="reveal-cred">
                                    <svg width="11" height="11" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                                    Reveal
                                </button>
                            </div>
                        </div>
                    </div>
                    <button class="btn-danger" style="display:flex;align-items:center;gap:5px;flex-shrink:0;" data-action="remove-cred" data-idx="${idx}">
                        <svg width="11" height="11" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>
                        Remove
                    </button>
                </div>
            </div>`;
        }).join('') + '</div>';
}

function toggleReveal(btn) {
    const code = btn.previousElementSibling;
    const isRevealed = code.dataset.revealed === '1';
    if (isRevealed) {
        code.textContent = '••••••••••••••••••';
        code.dataset.revealed = '0';
        btn.innerHTML = '<svg width="11" height="11" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg> Reveal';
    } else {
        // In a real app, you'd decrypt or retrieve the actual stored value
        code.textContent = code.dataset.val || '(value hidden)';
        code.dataset.revealed = '1';
        btn.innerHTML = '<svg width="11" height="11" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24M1 1l22 22"/></svg> Hide';
    }
}

function removeCredential(btn, idx) {
    savedCredentials.splice(idx, 1);
    lsSaveCreds(savedCredentials); loadCredentials();
    showToast('Credential removed', 'warn');
}

function renderTargetsList() {
    const list = document.getElementById('targetsList');
    if (!savedTargets.length) {
        list.innerHTML = `<div class="list-row">
            <div style="display:flex;align-items:center;gap:13px;">
                <div class="target-dot"></div>
                <div>
                    <p style="font-family:'DM Mono',monospace;font-size:13px;font-weight:500;">http://localhost:8000</p>
                    <p style="font-size:11px;color:var(--muted);margin-top:2px;">Laravel App · Default target</p>
                </div>
            </div>
            <div style="display:flex;align-items:center;gap:8px;">
                <span class="tag-active">active</span>
                <button class="btn-ghost" data-action="scan-target" data-url="http://localhost:8000" style="padding:5px 11px;font-size:11px;">Scan</button>
            </div>
        </div>`;
        return;
    }
    list.innerHTML = savedTargets.map(t => `
        <div data-target-id="${t.id}" class="list-row">
            <div style="display:flex;align-items:center;gap:13px;">
                <div class="target-dot"></div>
                <div>
                    <p style="font-family:'DM Mono',monospace;font-size:13px;font-weight:500;">${t.url}</p>
                    <p style="font-size:11px;color:var(--muted);margin-top:2px;">${t.type} · Saved</p>
                </div>
            </div>
            <div style="display:flex;align-items:center;gap:8px;">
                <span class="tag-active" >active</span>
                <button class="btn-ghost" data-action="scan-target" data-url="${t.url}" style="padding:5px 11px;font-size:14px;font-weight:600;color:white;">Scan</button>
                <button class="btn-danger" data-remove-id="${t.id}"style="font-size:14px;">Remove</button>
            </div>
        </div>`).join('');

    // Attach remove listeners after render to avoid inline onclick issues
    list.querySelectorAll('[data-remove-id]').forEach(btn => {
        btn.addEventListener('click', function () {
            removeTarget(this, this.getAttribute('data-remove-id'));
        });
    });
}

async function addTarget() {
    const url = document.getElementById('targetUrl').value.trim();
    if (!url) { showToast('Enter a target URL', 'warn'); return; }
    if (!/^https?:\/\/.+/.test(url)) { showToast('URL must start with http:// or https://', 'error'); return; }
    const type = document.getElementById('targetType').value;
    const scanId = await ensureScan();
    if (scanId) {
        try {
            const target = await apiFetch(`/api/scans/${scanId}/targets`, { method: 'POST', body: JSON.stringify({ url }) });
            savedTargets.push({ id: target.id, url: target.url, type });
            lsSaveTargets(savedTargets); renderTargetsList();
            document.getElementById('targetUrl').value = '';
            showToast('Target saved: ' + url, 'success'); return;
        } catch (e) {
            console.warn('API addTarget failed, saving locally:', e.message);
            showToast('Could not reach server — target saved locally only', 'warn');
        }
    }
    const newTarget = { id: 'local_' + Date.now(), url, type };
    savedTargets.push(newTarget); lsSaveTargets(savedTargets); renderTargetsList();
    document.getElementById('targetUrl').value = '';
    showToast('Target saved: ' + url, 'success');
}

async function removeTarget(btn, targetId) {
    if (!targetId) { showToast('Cannot remove this target', 'warn'); return; }

    // Dim immediately for instant visual feedback
    const el = btn.closest('[data-target-id]');
    if (el) { el.style.opacity = '0.4'; el.style.pointerEvents = 'none'; }

    // Sync deletion to the backend FIRST for persisted (non-local) targets
    if (!String(targetId).startsWith('local_')) {
        try {
            const scanId = activeScanId || await ensureScan();
            if (!scanId) throw new Error('No active scan');
            await apiFetch(`/api/scans/${scanId}/targets/${targetId}`, { method: 'DELETE' });
        } catch (e) {
            console.error('DELETE target failed:', e.message);
            // Restore the row visually since DB delete failed
            if (el) { el.style.opacity = ''; el.style.pointerEvents = ''; }
            showToast('Failed to delete target — please try again', 'error');
            return;
        }
    }

    // Track deletion so API re-fetches won't restore this target
    _deletedTargetIds.add(String(targetId));

    // Remove from in-memory state and localStorage
    savedTargets = savedTargets.filter(t => String(t.id) !== String(targetId));
    lsSaveTargets(savedTargets);

    // Full re-render (shows placeholder if list is now empty)
    renderTargetsList();
    showToast('Target removed', 'warn');
}

function getActiveTargetUrls() {
    return savedTargets.length ? savedTargets.map(t => t.url) : ['http://localhost:8000'];
}
function scanTarget(url) { switchTab('dashboard'); showToast('Scanning ' + url, 'info'); setTimeout(startScan, 400); }

// ════════════════════════════════════════
// AUTH VAULT
// ════════════════════════════════════════
let currentAuthType = 'cookie';

const AUTH_TYPE_HINTS = {
    cookie: '💡 Paste a session cookie from DevTools → Application → Cookies after logging in to your target app.',
    bearer: '💡 Used for API auth. Copy the token from DevTools → Network → Authorization header (omit the "Bearer " prefix).',
    basic: '💡 Enter the username and password used for HTTP Basic Authentication on the target.',
    oauth: '💡 Copy the access_token value from your OAuth token response or DevTools → Application → localStorage.',
};

function selectAuthType(btn, type) {
    currentAuthType = type;
    document.querySelectorAll('.auth-type-btn').forEach(b => {
        b.className = 'auth-type-btn';
    });
    btn.classList.add('active-' + type);
    document.getElementById('authHintBox').textContent = AUTH_TYPE_HINTS[type] || '';

    const tokenField = document.getElementById('authTokenField');
    const basicFields = document.getElementById('authBasicFields');
    const tokenLabel = document.getElementById('authTokenLabel');
    const tokenInput = document.getElementById('authPassword');

    if (type === 'basic') {
        tokenField.style.display = 'none';
        basicFields.style.display = 'block';
    } else {
        tokenField.style.display = 'block';
        basicFields.style.display = 'none';
        const labels = { cookie: 'Cookie Value', bearer: 'Token Value', oauth: 'Access Token' };
        const placeholders = { cookie: 'Paste cookie string…', bearer: 'Paste token value…', oauth: 'Paste access_token…' };
        tokenLabel.textContent = labels[type] || 'Token';
        tokenInput.placeholder = placeholders[type] || '••••••••';
    }
}

async function addCredentials() {
    const label = document.getElementById('authLabel').value.trim();
    const type = currentAuthType;
    if (!label) { showToast('Enter a label for this credential', 'warn'); return; }

    let token = '', username = '';
    if (type === 'basic') {
        username = document.getElementById('authUsername').value.trim();
        const bp = document.getElementById('authBasicPass').value;
        if (!username || !bp) { showToast('Enter both username and password', 'warn'); return; }
        token = bp;
    } else {
        token = document.getElementById('authPassword').value.trim();
        if (!token) { showToast('Paste your token / cookie value', 'warn'); return; }
    }

    const typeMap = { cookie: 'Cookie Session', bearer: 'JWT Bearer', basic: 'Basic Auth', oauth: 'OAuth 2.0' };
    const method = typeMap[type] || type;
    const scanId = await ensureScan();
    if (scanId) {
        try { await apiFetch(`/api/scans/${scanId}/credentials`, { method: 'POST', body: JSON.stringify({ name: label, type, token: token || null }) }); }
        catch (e) { console.warn('addCredentials API failed, saving locally:', e.message); }
    }
    const cred = { id: 'local_' + Date.now(), label, username, method, type, token: token ? '••••••' : '' };
    savedCredentials.push(cred); lsSaveCreds(savedCredentials); loadCredentials();
    document.getElementById('authLabel').value = '';
    document.getElementById('authPassword').value = '';
    document.getElementById('authUsername').value = '';
    document.getElementById('authBasicPass') && (document.getElementById('authBasicPass').value = '');
    showToast('Credential saved to Auth Vault', 'success');
}

// ════════════════════════════════════════
// CONFIGURATION
// ════════════════════════════════════════
function setIntensity(level, btn) {
    document.querySelectorAll('.int-card').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    scanIntensity = level;
    showToast('Intensity: ' + level, 'info');
}

function addExclusion() {
    const input = document.getElementById('exclusionInput');
    const val = input.value.trim();
    if (!val) return;
    const tags = document.getElementById('exclusionTags');
    const span = document.createElement('span');
    span.style.cssText = "display:inline-flex;align-items:center;gap:5px;padding:3px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:20px;font-size:11px;font-family:'DM Mono',monospace;";
    span.innerHTML = `${val}<button data-action="remove-exclusion" style="color:var(--red);background:none;border:none;cursor:pointer;padding:0;font-size:13px;line-height:1;margin-left:2px;">&times;</button>`;
    tags.appendChild(span);
    input.value = '';
    showToast('Exclusion added', 'success');
}

async function saveConfiguration() {
    const data = {
        intensity: scanIntensity || 'standard',
        max_requests_per_second: parseInt(document.getElementById('cfgMaxRps')?.value) || 100,
        request_timeout: parseInt(document.getElementById('cfgTimeout')?.value) || 30,
        crawl_depth: parseInt(document.getElementById('cfgDepth')?.value) || 5,
        follow_redirects: document.getElementById('cfgRedirects')?.checked ?? true,
        javascript_execution: document.getElementById('cfgJsExec')?.checked ?? true,
        exclusion_rules: [...document.querySelectorAll('#exclusionTags span')].map(s => s.textContent.replace('×', '').trim()).filter(Boolean),
    };
    const scanId = await ensureScan();
    if (scanId) {
        try { await apiFetch(`/api/scans/${scanId}/config`, { method: 'PUT', body: JSON.stringify(data) }); showToast('Configuration saved ✓', 'success'); return; }
        catch (e) { console.warn('saveConfig error:', e.message); }
    }
    showToast('Configuration saved locally ✓', 'success');
}

// ════════════════════════════════════════
// VULNERABILITIES
// ════════════════════════════════════════
function filterVulns() {
    const val = document.getElementById('sevFilter').value;
    document.querySelectorAll('#vulnTableBody tr[data-severity]').forEach(row => {
        row.style.display = (val === 'all' || row.dataset.severity === val) ? '' : 'none';
    });
}

/* ─── Alias kept for autoExport checkbox ─── */
function exportReport() { exportReportPDF(); }

function exportReportPDF() {
    if (!allVulns.length) { showToast('No vulnerabilities to export', 'warn'); return; }

    /* ── Meta ── */
    const reportId = 'VS-' + Date.now().toString(36).toUpperCase().slice(-6);
    const reportDate = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    const reportTime = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    const assessedBy = (currentUser && currentUser.name) ? currentUser.name : 'VulnSight Scanner';
    const scanTargets = savedTargets.length ? savedTargets.map(t => t.url).join(', ') : 'http://localhost:8000';

    /* ── Sort & count ── */
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    const sorted = [...allVulns].sort((a, b) => (sevOrder[a.sev] ?? 99) - (sevOrder[b.sev] ?? 99));
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    sorted.forEach(v => { if (counts[v.sev] !== undefined) counts[v.sev]++; });

    const riskRating = counts.critical > 0 ? 'CRITICAL' : counts.high > 0 ? 'HIGH' : counts.medium > 0 ? 'MEDIUM' : 'LOW';
    const RISK_THEME = {
        CRITICAL: { text: '#991b1b', bg: '#fef2f2', border: '#fecaca', accent: '#dc2626' },
        HIGH: { text: '#9a3412', bg: '#fff7ed', border: '#fed7aa', accent: '#ea580c' },
        MEDIUM: { text: '#854d0e', bg: '#fefce8', border: '#fef08a', accent: '#ca8a04' },
        LOW: { text: '#166534', bg: '#f0fdf4', border: '#bbf7d0', accent: '#16a34a' },
    };
    const RT = RISK_THEME[riskRating];

    /* ── Severity styling ── */
    const SEV = {
        critical: { bg: '#fff1f2', border: '#fecdd3', text: '#9f1239', dot: '#e11d48', label: 'CRITICAL' },
        high: { bg: '#fff7ed', border: '#fed7aa', text: '#9a3412', dot: '#ea580c', label: 'HIGH' },
        medium: { bg: '#fefce8', border: '#fef08a', text: '#854d0e', dot: '#ca8a04', label: 'MEDIUM' },
        low: { bg: '#f0fdf4', border: '#bbf7d0', text: '#166534', dot: '#16a34a', label: 'LOW' },
    };

    /* ── Severity distribution bar widths ── */
    const total = sorted.length || 1;
    const barC = Math.round(counts.critical / total * 100);
    const barH = Math.round(counts.high / total * 100);
    const barM = Math.round(counts.medium / total * 100);
    const barL = 100 - barC - barH - barM;

    /* ── Per-finding detail blocks ── */
    const findingBlocks = sorted.map((v, i) => {
        const s = SEV[v.sev] || SEV.low;
        const fix = (typeof VULN_FIX_DB !== 'undefined' && VULN_FIX_DB[v.name])
            ? VULN_FIX_DB[v.name]
            : {
                summary: 'Review this endpoint and apply appropriate security controls.',
                steps: ['Validate and sanitize all user-supplied input.',
                    'Apply the principle of least privilege.',
                    'Consult OWASP guidelines for remediation.'],
                ref: 'https://owasp.org/www-project-top-ten/'
            };

        const stepRows = fix.steps.map((step, si) =>
            `<tr>
               <td style="padding:5px 8px;width:22px;font-weight:700;color:${s.text};font-size:11px;vertical-align:top;">${si + 1}.</td>
               <td style="padding:5px 8px;font-size:11px;color:#374151;line-height:1.6;">${step}</td>
             </tr>`
        ).join('');

        return `
<div style="margin-bottom:20px;border:1.5px solid ${s.border};border-radius:10px;overflow:hidden;page-break-inside:avoid;">
  <!-- header -->
  <div style="background:${s.bg};border-bottom:2px solid ${s.border};padding:12px 16px;display:flex;align-items:center;gap:12px;">
    <div style="width:34px;height:34px;border-radius:50%;background:${s.dot};display:flex;align-items:center;justify-content:center;flex-shrink:0;">
      <span style="color:#fff;font-weight:800;font-size:12px;font-family:monospace;">${String(i + 1).padStart(2, '0')}</span>
    </div>
    <div style="flex:1;min-width:0;">
      <div style="font-size:13px;font-weight:700;color:#111827;">${v.name}</div>
      <div style="font-size:10px;color:#6b7280;margin-top:2px;font-family:'Courier New',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${v.url}</div>
    </div>
    <div style="flex-shrink:0;text-align:right;">
      <span style="display:inline-block;padding:3px 10px;border-radius:20px;font-size:9px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;background:${s.bg};color:${s.text};border:1.5px solid ${s.border};">${s.label}</span>
      ${v.cve ? `<div style="font-size:9px;color:#9ca3af;margin-top:3px;font-family:'Courier New',monospace;">${v.cve}</div>` : ''}
    </div>
  </div>
  <!-- meta row -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:0;border-bottom:1px solid #f3f4f6;">
    <div style="padding:8px 16px;border-right:1px solid #f3f4f6;">
      <div style="font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#9ca3af;margin-bottom:3px;">Affected Endpoint</div>
      <div style="font-size:10px;font-family:'Courier New',monospace;color:#374151;word-break:break-all;">${v.url}</div>
    </div>
    <div style="padding:8px 16px;">
      <div style="font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#9ca3af;margin-bottom:3px;">CVE Reference</div>
      <div style="font-size:10px;font-family:'Courier New',monospace;color:#374151;">${v.cve || 'N/A'}</div>
    </div>
  </div>
  <!-- body -->
  <div style="padding:12px 16px;background:#fff;">
    <div style="background:#f9fafb;border:1px solid #f3f4f6;border-radius:6px;padding:10px 13px;margin-bottom:12px;">
      <div style="font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#6b7280;margin-bottom:5px;">Description</div>
      <div style="font-size:11px;color:#374151;line-height:1.65;">${fix.summary}</div>
    </div>
    <div style="font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#6b7280;margin-bottom:6px;">Remediation Steps</div>
    <table style="width:100%;border-collapse:collapse;">${stepRows}</table>
    <div style="margin-top:9px;font-size:9px;color:#9ca3af;">Reference: <span style="color:#2563eb;">${fix.ref}</span></div>
  </div>
</div>`;
    }).join('');

    /* ── Findings summary table rows ── */
    const tableRows = sorted.map((v, i) => {
        const s = SEV[v.sev] || SEV.low;
        return `<tr style="background:${i % 2 === 0 ? '#ffffff' : '#f9fafb'};">
          <td style="padding:8px 12px;font-size:10px;color:#9ca3af;font-family:monospace;border-bottom:1px solid #f3f4f6;">${String(i + 1).padStart(2, '0')}</td>
          <td style="padding:8px 12px;font-size:11px;font-weight:600;color:#111827;border-bottom:1px solid #f3f4f6;">${v.name}</td>
          <td style="padding:8px 12px;font-size:10px;font-family:'Courier New',monospace;color:#4b5563;word-break:break-all;border-bottom:1px solid #f3f4f6;">${v.url}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #f3f4f6;">
            <span style="display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:20px;background:${s.bg};color:${s.text};border:1px solid ${s.border};font-size:9px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;">
              <span style="width:5px;height:5px;border-radius:50%;background:${s.dot};flex-shrink:0;"></span>${s.label}
            </span>
          </td>
          <td style="padding:8px 12px;font-size:10px;font-family:monospace;color:#6b7280;border-bottom:1px solid #f3f4f6;">${v.cve || '—'}</td>
        </tr>`;
    }).join('');

    /* ══════════════════════════ HTML DOCUMENT ══════════════════════════ */
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Vulnerability Assessment Report — ${reportId}</title>
<style>
  @page { margin:14mm 15mm; size:A4; }
  @media print {
    .no-print { display:none!important; }
    body { -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  }
  *,*::before,*::after { box-sizing:border-box; margin:0; padding:0; }
  body { font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,sans-serif; background:#fff; color:#111827; line-height:1.5; }
</style>
</head>
<body>

<!-- ░░░░░░░░░░░░░░░░  COVER  ░░░░░░░░░░░░░░░░ -->
<div style="height:267mm;max-height:267mm;display:flex;flex-direction:column;background:linear-gradient(150deg,#050d1a 0%,#0a1628 45%,#04090f 100%);color:#fff;page-break-after:always;page-break-inside:avoid;position:relative;overflow:hidden;">

  <!-- Dot-grid overlay -->
  <div style="position:absolute;inset:0;opacity:.035;background-image:radial-gradient(circle,rgba(255,255,255,.9) 1px,transparent 1px);background-size:28px 28px;pointer-events:none;"></div>

  <!-- Top rainbow bar -->
  <div style="height:3px;background:linear-gradient(90deg,#00f5c4 0%,#3b82f6 50%,#8b5cf6 100%);flex-shrink:0;"></div>

  <!-- Navbar-style header -->
  <div style="padding:28px 44px;display:flex;align-items:center;justify-content:space-between;flex-shrink:0;border-bottom:1px solid rgba(255,255,255,.06);">
    <div style="display:flex;align-items:center;gap:11px;">
      <div style="width:38px;height:38px;border-radius:9px;background:linear-gradient(135deg,rgba(0,245,196,.18),rgba(59,130,246,.18));border:1px solid rgba(0,245,196,.35);display:flex;align-items:center;justify-content:center;">
        <svg width="18" height="18" fill="none" stroke="#00f5c4" viewBox="0 0 24 24" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      </div>
      <div>
        <div style="font-size:15px;font-weight:700;letter-spacing:-.02em;color:#fff;">VulnSight</div>
        <div style="font-size:8px;color:rgba(255,255,255,.35);letter-spacing:.14em;text-transform:uppercase;margin-top:1px;">Security Platform</div>
      </div>
    </div>
    <div style="text-align:right;">
      <div style="font-size:8px;color:rgba(255,255,255,.3);letter-spacing:.1em;text-transform:uppercase;">Report ID</div>
      <div style="font-size:11px;font-family:'Courier New',monospace;color:rgba(255,255,255,.55);margin-top:2px;">${reportId}</div>
    </div>
  </div>

  <!-- Cover hero -->
  <div style="flex:1;display:flex;flex-direction:column;justify-content:center;padding:44px 44px 32px;">
    <div style="font-size:10px;font-weight:700;letter-spacing:.22em;text-transform:uppercase;color:#00f5c4;margin-bottom:14px;">Confidential Security Document</div>

    <div style="font-size:52px;font-weight:900;line-height:1.02;letter-spacing:-.04em;margin-bottom:10px;">
      Vulnerability<br>Assessment<br>
      <span style="background:linear-gradient(90deg,#00f5c4,#3b82f6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;">Report</span>
    </div>
    <div style="font-size:13px;color:rgba(255,255,255,.45);margin-bottom:36px;">Web Application Penetration Testing — Automated Scan Results</div>

    <!-- Risk rating pill -->
    <div style="display:inline-flex;align-items:center;gap:9px;padding:9px 18px;background:${RT.bg};border:1.5px solid ${RT.border};border-radius:8px;margin-bottom:36px;width:fit-content;">
      <div style="width:9px;height:9px;border-radius:50%;background:${RT.accent};"></div>
      <span style="font-size:10px;font-weight:800;letter-spacing:.16em;text-transform:uppercase;color:${RT.text};">Overall Risk: ${riskRating}</span>
    </div>

    <!-- 4 severity count boxes -->
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:36px;">
      ${[
            { l: 'Critical', n: counts.critical, c: '#dc2626', bg: 'rgba(220,38,38,.1)', b: 'rgba(220,38,38,.22)' },
            { l: 'High', n: counts.high, c: '#ea580c', bg: 'rgba(234,88,12,.1)', b: 'rgba(234,88,12,.22)' },
            { l: 'Medium', n: counts.medium, c: '#ca8a04', bg: 'rgba(202,138,4,.1)', b: 'rgba(202,138,4,.22)' },
            { l: 'Low', n: counts.low, c: '#16a34a', bg: 'rgba(22,163,74,.1)', b: 'rgba(22,163,74,.22)' },
        ].map(s => `
        <div style="background:${s.bg};border:1px solid ${s.b};border-radius:10px;padding:16px 18px;">
          <div style="font-size:38px;font-weight:900;color:${s.c};line-height:1;">${s.n}</div>
          <div style="font-size:9px;color:rgba(255,255,255,.45);text-transform:uppercase;letter-spacing:.1em;margin-top:4px;">${s.l}</div>
        </div>`).join('')}
    </div>

    <!-- Distribution bar -->
    <div>
      <div style="font-size:8.5px;color:rgba(255,255,255,.3);text-transform:uppercase;letter-spacing:.1em;margin-bottom:5px;">Severity Distribution</div>
      <div style="height:5px;border-radius:99px;overflow:hidden;background:rgba(255,255,255,.07);display:flex;">
        ${barC ? `<div style="width:${barC}%;background:#dc2626;"></div>` : ''}
        ${barH ? `<div style="width:${barH}%;background:#ea580c;"></div>` : ''}
        ${barM ? `<div style="width:${barM}%;background:#ca8a04;"></div>` : ''}
        ${barL > 0 ? `<div style="width:${barL}%;background:#16a34a;"></div>` : ''}
      </div>
    </div>
  </div>

  <!-- Cover footer metadata -->
  <div style="padding:20px 44px 28px;border-top:1px solid rgba(255,255,255,.06);flex-shrink:0;">
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:20px;">
      ${[
            { l: 'Report Date', v: reportDate },
            { l: 'Scan Target(s)', v: scanTargets },
            { l: 'Assessed By', v: assessedBy },
            { l: 'Classification', v: 'CONFIDENTIAL' },
        ].map(m => `
        <div>
          <div style="font-size:8px;color:rgba(255,255,255,.28);letter-spacing:.12em;text-transform:uppercase;margin-bottom:4px;">${m.l}</div>
          <div style="font-size:11px;color:rgba(255,255,255,.75);font-weight:500;word-break:break-word;">${m.v}</div>
        </div>`).join('')}
    </div>
  </div>
</div>

<!-- ░░░░░░░░░░░░  EXECUTIVE SUMMARY  ░░░░░░░░░░░░ -->
<div style="padding:40px 44px;">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
    <div style="width:3px;height:18px;background:linear-gradient(180deg,#00f5c4,#3b82f6);border-radius:2px;"></div>
    <div style="font-size:9px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:#9ca3af;">Section 01</div>
  </div>
  <h2 style="font-size:22px;font-weight:800;color:#111827;margin-bottom:3px;letter-spacing:-.03em;">Executive Summary</h2>
  <p style="font-size:12px;color:#6b7280;margin-bottom:24px;">High-level overview of security findings and risk posture.</p>

  <!-- 4 summary stat cards -->
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:11px;margin-bottom:24px;">
    ${[
            { l: 'Total Findings', v: sorted.length, sub: 'vulnerabilities', tc: '#374151', bg: '#f9fafb', bc: '#e5e7eb' },
            { l: 'Critical / High', v: counts.critical + counts.high, sub: 'require immediate action', tc: '#991b1b', bg: '#fef2f2', bc: '#fecaca' },
            { l: 'URLs Discovered', v: liveStats ? liveStats.urlsDiscovered : 0, sub: 'endpoints reached', tc: '#1e40af', bg: '#eff6ff', bc: '#bfdbfe' },
            { l: 'Requests Sent', v: liveStats ? (liveStats.requestsSent || 0).toLocaleString() : 0, sub: 'HTTP probes', tc: '#065f46', bg: '#f0fdf4', bc: '#bbf7d0' },
        ].map(s => `
      <div style="background:${s.bg};border:1px solid ${s.bc};border-radius:9px;padding:14px 16px;">
        <div style="font-size:26px;font-weight:800;color:${s.tc};line-height:1;margin-bottom:4px;">${s.v}</div>
        <div style="font-size:10px;font-weight:700;color:#374151;margin-bottom:2px;">${s.l}</div>
        <div style="font-size:9px;color:#9ca3af;">${s.sub}</div>
      </div>`).join('')}
  </div>

  <!-- Scope / methodology table -->
  <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:9px;padding:18px 22px;margin-bottom:22px;">
    <div style="font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:#6b7280;margin-bottom:12px;">Assessment Scope &amp; Methodology</div>
    <table style="width:100%;border-collapse:collapse;font-size:11px;">
      ${[
            ['Target System(s)', scanTargets],
            ['Assessment Type', 'Automated Web Application Vulnerability Scan'],
            ['Methodology', 'OWASP Top 10 (2021) · CWE/SANS Top 25 · CVE Database Cross-Reference'],
            ['Tools Used', 'VulnSight Scanner — Active &amp; Passive Reconnaissance'],
            ['Assessment Date &amp; Time', `${reportDate} at ${reportTime}`],
            ['Assessed By', assessedBy],
            ['Classification', 'CONFIDENTIAL — For authorized personnel only'],
        ].map(([k, v]) => `
        <tr>
          <td style="padding:6px 0;font-weight:600;color:#374151;width:185px;border-bottom:1px solid #f3f4f6;vertical-align:top;">${k}</td>
          <td style="padding:6px 0 6px 14px;color:#6b7280;border-bottom:1px solid #f3f4f6;">${v}</td>
        </tr>`).join('')}
    </table>
  </div>

  <!-- Overall risk banner -->
  <div style="background:${RT.bg};border:1.5px solid ${RT.border};border-radius:9px;padding:14px 18px;">
    <div style="font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:${RT.text};margin-bottom:6px;">Overall Risk Assessment — ${riskRating}</div>
    <div style="font-size:12px;color:#374151;line-height:1.65;">
      The assessment identified <strong>${sorted.length} vulnerabilit${sorted.length !== 1 ? 'ies' : 'y'}</strong> across the target system(s),
      including <strong style="color:#dc2626;">${counts.critical} critical</strong>,
      <strong style="color:#ea580c;">${counts.high} high</strong>,
      <strong style="color:#ca8a04;">${counts.medium} medium</strong>, and
      <strong style="color:#16a34a;">${counts.low} low</strong> severity finding${sorted.length !== 1 ? 's' : ''}.
      ${counts.critical > 0 ? 'Immediate remediation is required for all critical findings before deployment.' : counts.high > 0 ? 'High-severity findings should be prioritised and remediated promptly.' : 'No critical vulnerabilities were detected during this assessment.'}
    </div>
  </div>
</div>

<!-- ░░░░░░░░░░░░  FINDINGS TABLE  ░░░░░░░░░░░░ -->
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
        <th style="padding:9px 12px;text-align:left;font-size:8.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#94a3b8;width:76px;">Severity</th>
        <th style="padding:9px 12px;text-align:left;font-size:8.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#94a3b8;width:106px;">CVE</th>
      </tr>
    </thead>
    <tbody>${tableRows}</tbody>
  </table>
</div>

<!-- ░░░░░░░░░░░░  DETAILED FINDINGS  ░░░░░░░░░░░░ -->
<div style="padding:0 44px 48px;">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
    <div style="width:3px;height:18px;background:linear-gradient(180deg,#00f5c4,#3b82f6);border-radius:2px;"></div>
    <div style="font-size:9px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:#9ca3af;">Section 03</div>
  </div>
  <h2 style="font-size:22px;font-weight:800;color:#111827;margin-bottom:3px;letter-spacing:-.03em;">Detailed Findings</h2>
  <p style="font-size:12px;color:#6b7280;margin-bottom:24px;">In-depth analysis and remediation guidance for each finding.</p>
  ${findingBlocks}
</div>

<!-- ░░░░░░░░░░░░  FOOTER / DISCLAIMER  ░░░░░░░░░░░░ -->
<div style="padding:18px 44px 24px;border-top:2px solid #f3f4f6;background:#f9fafb;">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
    <div style="font-size:9.5px;color:#9ca3af;">VulnSight — Automated Vulnerability Assessment · ${reportId}</div>
    <div style="font-size:9.5px;color:#9ca3af;">CONFIDENTIAL · ${reportDate}</div>
    <div style="font-size:9.5px;color:#9ca3af;">Prepared by ${assessedBy}</div>
  </div>
  <div style="font-size:9px;color:#d1d5db;line-height:1.6;">
    Disclaimer: This report was produced by an automated scanner. All findings should be reviewed and validated by a qualified security professional prior to remediation.
    Results reflect the security posture of the assessed system at the time of scanning only.
  </div>
</div>

<!-- Floating print / close buttons (hidden when printing) -->
<div class="no-print" style="position:fixed;bottom:22px;right:22px;display:flex;gap:9px;z-index:9999;">
  <button id="printReportBtn" style="padding:11px 22px;background:linear-gradient(135deg,#00f5c4,#3b82f6);color:#000;border:none;border-radius:9px;font-weight:700;font-size:12px;cursor:pointer;box-shadow:0 4px 18px rgba(0,245,196,.35);">
    🖨&nbsp;&nbsp;Save as PDF
  </button>
  <button id="closeReportBtn" style="padding:11px 16px;background:#1f2937;color:#fff;border:none;border-radius:9px;font-weight:600;font-size:12px;cursor:pointer;">
    ✕
  </button>
</div>

</body>
</html>`;

    const win = window.open('', '_blank', 'width=1024,height=860,scrollbars=yes,resizable=yes');
    if (!win) { showToast('Pop-up blocked — please allow pop-ups and try again', 'warn'); return; }
    win.document.open();
    win.document.write(html);
    win.document.close();
    // Bind print/close buttons via addEventListener (CSP compliant)
    win.addEventListener('load', () => {
        win.document.getElementById('printReportBtn')?.addEventListener('click', () => win.print());
        win.document.getElementById('closeReportBtn')?.addEventListener('click', () => win.close());
    });
    // Fallback for already-loaded document
    setTimeout(() => {
        win.document.getElementById('printReportBtn')?.addEventListener('click', () => win.print());
        win.document.getElementById('closeReportBtn')?.addEventListener('click', () => win.close());
    }, 300);
    win.focus();
    showToast('PDF report opened — click "Save as PDF" in the new window', 'success');
}

// ════════════════════════════════════════
// VULN MODAL
// ════════════════════════════════════════
function openVulnModal(v) {
    const fix = VULN_FIX_DB[v.name] || { summary: 'Investigate this endpoint for the reported vulnerability type.', steps: ['Review the affected endpoint carefully.', 'Apply the principle of least privilege.', 'Consult OWASP guidelines for remediation.'], ref: 'https://owasp.org/www-project-top-ten/' };
    const iconBg = { critical: 'rgba(240,80,80,.1)', high: 'rgba(245,158,11,.1)', medium: 'rgba(253,224,71,.08)', low: 'rgba(0,245,196,.08)' };
    const iconStroke = { critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)', low: 'var(--neon)' };
    const icon = document.getElementById('vdIcon');
    icon.style.background = iconBg[v.sev] || 'var(--surface2)';
    icon.querySelector('svg').style.stroke = iconStroke[v.sev] || 'var(--neon)';
    document.getElementById('vdName').textContent = v.name;
    document.getElementById('vdBadge').className = 'badge ' + v.badge;
    document.getElementById('vdBadge').textContent = v.sev;
    document.getElementById('vdCve').textContent = v.cve || '';
    document.getElementById('vdUrl').textContent = v.url;
    document.getElementById('vdSummary').textContent = fix.summary;
    document.getElementById('vdRef').href = fix.ref;
    document.getElementById('vdSteps').innerHTML = fix.steps.map((s, i) => `
        <li style="display:flex;gap:10px;align-items:flex-start;padding:10px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:9px;font-size:12px;line-height:1.6;">
            <span style="flex-shrink:0;width:19px;height:19px;border-radius:50%;background:rgba(0,245,196,.08);border:1px solid rgba(0,245,196,.18);display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:var(--neon);font-family:'DM Mono',monospace;">${i + 1}</span>
            <span style="color:var(--text);">${s}</span>
        </li>`).join('');
    const modal = document.getElementById('vulnModal');
    modal.style.display = 'flex';
    requestAnimationFrame(() => { modal.style.opacity = '1'; });
}

function closeVulnModal() {
    const modal = document.getElementById('vulnModal');
    modal.style.opacity = '0';
    setTimeout(() => { modal.style.display = 'none'; }, 200);
}

document.addEventListener('click', e => { if (e.target === document.getElementById('vulnModal')) closeVulnModal(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeVulnModal(); });

// ════════════════════════════════════════
// UTILITIES
// ════════════════════════════════════════
function dlFile(content, name, type) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([content], { type }));
    a.download = name; a.click();
}
function showEmailModal() {
    const defaultEmail = (currentUser && currentUser.email) ? currentUser.email : '';
    return new Promise(resolve => {
        const overlay = document.createElement('div');
        overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;backdrop-filter:blur(4px);';
        overlay.innerHTML = `<div style='background:#111827;border:1px solid #374151;border-radius:14px;padding:28px 32px;min-width:360px;'><p style='font-size:15px;font-weight:600;color:#f9fafb;margin-bottom:6px;'>Email Scan Report</p><p style='font-size:13px;color:#6b7280;margin-bottom:18px;'>Send this scan report to an email address.</p><label style='font-size:11px;font-weight:700;color:#9ca3af;letter-spacing:.06em;text-transform:uppercase;display:block;margin-bottom:7px;'>Email Address</label><input id='_emailInput' type='email' value='${defaultEmail}' placeholder='you@example.com' style='width:100%;box-sizing:border-box;padding:9px 12px;border-radius:8px;border:1px solid #374151;background:#1f2937;color:#f9fafb;font-size:14px;margin-bottom:8px;outline:none;font-family:inherit;'><div id='_emailMsg' style='font-size:13px;color:#ef4444;margin-bottom:12px;min-height:18px;'></div><div style='display:flex;gap:10px;justify-content:center;'><button id='_emailCancel' style='padding:8px 22px;border-radius:8px;border:1px solid #374151;background:#1f2937;color:#d1d5db;font-size:14px;font-weight:600;cursor:pointer;'>Cancel</button><button id='_emailSend' style='padding:8px 22px;border-radius:8px;border:none;background:#3b82f6;color:#fff;font-size:14px;font-weight:600;cursor:pointer;display:flex;align-items:center;gap:6px;'><svg width='13' height='13' fill='none' stroke='currentColor' viewBox='0 0 24 24' stroke-width='2'><line x1='22' y1='2' x2='11' y2='13'/><polygon points='22 2 15 22 11 13 2 9 22 2'/></svg>Send Report</button></div></div>`;
        document.body.appendChild(overlay);
        overlay.querySelector('#_emailCancel').onclick = () => { document.body.removeChild(overlay); resolve(null); };
        overlay.querySelector('#_emailSend').onclick = () => {
            const email = overlay.querySelector('#_emailInput').value.trim();
            const msgEl = overlay.querySelector('#_emailMsg');
            if (!email || !/^[^@]+@[^@]+\.[^@]+$/.test(email)) { msgEl.textContent = 'Please enter a valid email address.'; return; }
            document.body.removeChild(overlay);
            resolve(email);
        };
    });
}

async function emailHistoryScan(idx) {
    const email = await showEmailModal();
    if (!email) return;
    showToast('Sending report...', 'success');
    try {
        let scan = _dbHistory[idx];
        if (!scan) { showToast('Scan not found', 'warn'); return; }
        if (!scan.vulns || !scan.vulns.length) {
            try { scan = await apiFetch('/api/scan-logs/' + scan.id); _dbHistory[idx] = scan; } catch (e) { showToast('Could not load scan data', 'error'); return; }
        }
        const vulns = scan.vulns || [];
        const targets = (scan.targets || []).map(t => t.url || t).join(', ') || scan.target || 'N/A';
        await apiFetch('/api/email-report', {
            method: 'POST',
            body: JSON.stringify({ email, scan_id: scan.id || idx, vulns, targets, started_at: scan.started_at || scan.startedAt || '' }),
        });
        showToast('Report sent to ' + email, 'success');
    } catch (e) {
        showToast('Failed to send report: ' + e.message, 'error');
    }
}

function customConfirm(msg) {
    return new Promise(resolve => {
        const overlay = document.createElement('div');
        overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;backdrop-filter:blur(4px);';
        overlay.innerHTML = `<div style='background:#111827;border:1px solid #374151;border-radius:14px;padding:28px 32px;min-width:320px;text-align:center;'><p style='font-size:15px;font-weight:600;color:#f9fafb;margin-bottom:20px;'>${msg}</p><div style='display:flex;gap:10px;justify-content:center;'><button id='_cfmNo' style='padding:8px 22px;border-radius:8px;border:1px solid #374151;background:#1f2937;color:#d1d5db;font-size:14px;font-weight:600;cursor:pointer;'>Cancel</button><button id='_cfmYes' style='padding:8px 22px;border-radius:8px;border:none;background:#ef4444;color:#fff;font-size:14px;font-weight:600;cursor:pointer;'>Delete</button></div></div>`;
        document.body.appendChild(overlay);
        overlay.querySelector('#_cfmYes').onclick = () => { document.body.removeChild(overlay); resolve(true); };
        overlay.querySelector('#_cfmNo').onclick = () => { document.body.removeChild(overlay); resolve(false); };
    });
}
function dateStr() { return new Date().toISOString().slice(0, 10); }

let toastTimer;
function showToast(msg, type = 'success') {
    const t = document.getElementById('toast');
    const icons = { success: '✓', info: 'ℹ', warn: '⚠', error: '✕' };
    t.innerHTML = `<span>${icons[type] || '●'}</span><span>${msg}</span>`;
    t.className = 'toast show ' + type;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 3500);
}

//HAMBURGER MENU

/* ═══════════════════════════════════════════════════════════════
   PASTE THIS BLOCK SOMEWHERE NEAR THE BOTTOM OF YOUR wavs.js
   (before the closing of your IIFE if you have one)

   It handles:
     1. Sidebar hamburger — collapse/expand with localStorage memory
     2. History hamburger button — open/close drawer + icon animation
     3. Replaces the old openScanHistory() call wiring
═══════════════════════════════════════════════════════════════ */


// ── Sidebar hamburger ────────────────────────────────────────

function initSidebarHamburger() {
    const sidebar = document.getElementById('sidebar');
    const mainApp = document.getElementById('mainApp');
    const btn = document.getElementById('sidebarHamburgerBtn');
    const logoIcon = sidebar ? sidebar.querySelector('.logo-icon') : null;
    if (!sidebar || !btn) return;

    function applyCollapsed(collapsed) {
        sidebar.classList.toggle('collapsed', collapsed);
        if (mainApp) {
            mainApp.style.transition = 'margin-left .28s cubic-bezier(.22,1,.36,1)';
            mainApp.style.marginLeft = collapsed ? '54px' : 'var(--sw, 232px)';
        }
        btn.title = collapsed ? 'Expand sidebar' : 'Collapse sidebar';
        localStorage.setItem('wavs_sidebar_collapsed', collapsed ? '1' : '0');
    }

    applyCollapsed(localStorage.getItem('wavs_sidebar_collapsed') === '1');

    // Hamburger button collapses/expands normally
    btn.addEventListener('click', () => {
        applyCollapsed(!sidebar.classList.contains('collapsed'));
    });

    // Clicking the logo icon when collapsed → expand
    if (logoIcon) {
        logoIcon.addEventListener('click', () => {
            if (sidebar.classList.contains('collapsed')) {
                applyCollapsed(false);
            }
        });
    }
}


// ── History hamburger button ─────────────────────────────────

function initHistoryHamburger() {
    const btn = document.getElementById('historyHamburgerBtn');
    const closeBtn = document.getElementById('drawerCloseBtn');
    const overlay = document.getElementById('drawerOverlay');
    if (!btn) return;

    // Sync the button's active class whenever the drawer closes
    function syncBtnState() {
        const drawer = document.getElementById('scanHistoryDrawer');
        if (!drawer) return;
        const isOpen = drawer.classList.contains('open');
        btn.classList.toggle('drawer-open', isOpen);
    }

    // Override / wrap closeScanHistory so the button always de-activates
    const _origClose = window.closeScanHistory;
    window.closeScanHistory = function () {
        if (typeof _origClose === 'function') _origClose();
        btn.classList.remove('drawer-open');
    };

    // Also patch openScanHistory so the button always activates
    const _origOpen = window.openScanHistory;
    window.openScanHistory = function () {
        if (typeof _origOpen === 'function') _origOpen();
        btn.classList.add('drawer-open');
    };

    // The button itself toggles the drawer
    btn.addEventListener('click', () => {
        const drawer = document.getElementById('scanHistoryDrawer');
        if (!drawer) return;
        const isOpen = drawer.classList.contains('open');
        if (isOpen) {
            window.closeScanHistory();
        } else {
            window.openScanHistory();
        }
    });

    // Sync if close button or overlay is clicked directly
    if (closeBtn) closeBtn.addEventListener('click', () => btn.classList.remove('drawer-open'));
    if (overlay) overlay.addEventListener('click', () => btn.classList.remove('drawer-open'));
}


// ── toggleScanHistory (used by onclick in the blade) ─────────
// This is the function called by onclick="toggleScanHistory()"
// on the history hamburger button in the HTML.

function toggleScanHistory() {
    const drawer = document.getElementById('scanHistoryDrawer');
    const btn = document.getElementById('historyHamburgerBtn');
    if (!drawer) return;

    const isOpen = drawer.classList.contains('open');
    if (isOpen) {
        if (typeof closeScanHistory === 'function') closeScanHistory();
        if (btn) btn.classList.remove('drawer-open');
    } else {
        if (typeof openScanHistory === 'function') openScanHistory();
        if (btn) btn.classList.add('drawer-open');
    }
}
// ── Current scan detail index ─────────────────────────────────
let _currentScanDetailIdx = null;

async function openScanDetail(idx) {
    const scan = _dbHistory[idx];
    if (!scan) return;
    _currentScanDetailIdx = idx;

    // Show + label the sub-nav item
    const navItem = document.getElementById('navScanDetail');
    const navLabel = document.getElementById('navScanDetailLabel');
    if (navItem) {
        navItem.style.display = 'flex';
        navLabel.textContent = scan.name
            ? scan.name.substring(0, 18) + (scan.name.length > 18 ? '…' : '')
            : 'Scan Details';
    }

    // Breadcrumb + header
    const targetLabel = scan.target || scan.target_url || '—';
    document.getElementById('sdBreadcrumb').textContent = targetLabel;
    document.getElementById('sdTitle').textContent = targetLabel;
    const sdStartTime = scan.started_at || scan.startedAt;
    document.getElementById('sdMeta').textContent =
        (sdStartTime
            ? new Date(sdStartTime).toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })
            : '—');

    // Status badge
    const sColor = {
        completed: 'var(--neon)',
        running: 'var(--blue)',
        failed: 'var(--red)',
        paused: 'var(--orange)',
        stopped: 'var(--orange)'
    }[scan.status] || 'var(--muted)';
    document.getElementById('sdStatusBadge').innerHTML =
        `<span style="font-size:12px;font-weight:700;padding:3px 12px;border-radius:20px;
            background:${sColor}22;border:1px solid ${sColor}44;color:${sColor};
            font-family:'DM Mono',monospace;text-transform:uppercase;">
            ${scan.status || 'unknown'}
        </span>`;

    // Stat cards from summary counts first (instant)
    renderScanDetailStats({
        total: scan.vuln_total || 0,
        critical: scan.vuln_critical || 0,
        high: scan.vuln_high || 0,
        medium: scan.vuln_medium || 0,
        low: scan.vuln_low || 0,
    });

    // Show loading state in table
    document.getElementById('sdVulnBody').innerHTML =
        `<tr><td colspan="6" style="text-align:center;padding:32px;color:var(--muted);">⟳ Loading vulnerabilities…</td></tr>`;

    // Navigate first so user sees the page immediately
    switchTab('scan-detail');

    // Then fetch actual vulnerabilities from API
    try {
        const data = await apiFetch(`/api/scan-logs/${scan.id}/vulnerabilities`);
        const vulns = Array.isArray(data) ? data : (data.vulnerabilities || data.data || []);

        // Update stat cards with real counts now that we have actual vulns
        renderScanDetailStats({
            total: vulns.length,
            critical: vulns.filter(v => v.severity === 'critical').length,
            high: vulns.filter(v => v.severity === 'high').length,
            medium: vulns.filter(v => v.severity === 'medium').length,
            low: vulns.filter(v => v.severity === 'low').length,
        });

        renderScanDetailVulns(vulns);
    } catch (e) {
        console.error('Vuln fetch error:', e);
        document.getElementById('sdVulnBody').innerHTML =
            `<tr><td colspan="6" style="text-align:center;padding:32px;color:var(--red);">${e.message}</td></tr>`;
    }
}
function renderScanDetailStats({ total, critical, high, medium, low }) {
    document.getElementById('sdStatRow').innerHTML = `
        <div class="card" style="padding:14px 16px;text-align:center;">
            <div style="font-family:'DM Mono',monospace;font-size:24px;font-weight:600;color:var(--text);line-height:1;">${total}</div>
            <div style="font-size:12px;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:.06em;">Total</div>
        </div>
        <div class="card" style="padding:14px 16px;text-align:center;">
            <div style="font-family:'DM Mono',monospace;font-size:24px;font-weight:600;color:var(--red);line-height:1;">${critical}</div>
            <div style="font-size:12px;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:.06em;">Critical</div>
        </div>
        <div class="card" style="padding:14px 16px;text-align:center;">
            <div style="font-family:'DM Mono',monospace;font-size:24px;font-weight:600;color:var(--orange);line-height:1;">${high}</div>
            <div style="font-size:12px;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:.06em;">High</div>
        </div>
        <div class="card" style="padding:14px 16px;text-align:center;">
            <div style="font-family:'DM Mono',monospace;font-size:24px;font-weight:600;color:var(--yellow);line-height:1;">${medium}</div>
            <div style="font-size:12px;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:.06em;">Medium</div>
        </div>
        <div class="card" style="padding:14px 16px;text-align:center;">
            <div style="font-family:'DM Mono',monospace;font-size:24px;font-weight:600;color:var(--neon);line-height:1;">${low}</div>
            <div style="font-size:12px;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:.06em;">Low</div>
        </div>`;
}
function renderScanDetailVulns(vulns) {
    const filter = document.getElementById('sdSevFilter')?.value || 'all';
    const filtered = filter === 'all' ? vulns : vulns.filter(v => v.severity === filter);
    const tbody = document.getElementById('sdVulnBody');
    if (!filtered.length) {
        tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state"><div class="empty-icon">🛡️</div>No vulnerabilities found.</div></td></tr>`;
        return;
    }
    tbody.innerHTML = filtered.map(v => `
        <tr>
            <td><span style="font-weight:600;color:var(--text);">${v.name || v.type || '—'}</span></td>
            <td><code style="font-family:'DM Mono',monospace;font-size:14px;color:var(--neon);">${v.url || v.endpoint || '—'}</code></td>
            <td><span class="badge ${v.severity || 'low'}">${v.severity || 'low'}</span></td>
            <td><span style="font-size:14px;color:white;">${v.status || 'open'}</span></td>

            <td><button class="btn-ghost" style="padding:3px 10px;font-size:12px;color:white;" data-action="open-vuln-modal" data-v="${btoa(unescape(encodeURIComponent(JSON.stringify(v))))}">Details</button></td>
        </tr>`).join('');
}

async function filterScanDetail() {
    if (_currentScanDetailIdx === null) return;
    const scan = _dbHistory[_currentScanDetailIdx];
    try {
        const data = await apiFetch(`/api/scan-logs/${scan.id}/vulnerabilities`);
        const vulns = Array.isArray(data) ? data : (data.vulnerabilities || []);
        renderScanDetailVulns(vulns);
    } catch (e) { /* keep current table */ }
}

function exportCurrentScanDetail() {
    if (_currentScanDetailIdx !== null) exportHistoryScan(_currentScanDetailIdx);
}

// ── Init both on DOM ready ───────────────────────────────────

function initHamburgers() {
    initSidebarHamburger();
    initHistoryHamburger();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initHamburgers);
} else {
    initHamburgers();
}

// ════════════════════════════════════════
// CSP-COMPLIANT EVENT DELEGATION
// Handles all data-action buttons generated dynamically via innerHTML
// ════════════════════════════════════════
function initDelegatedListeners() {
    document.body.addEventListener('click', function (e) {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;
        const action = btn.dataset.action;

        switch (action) {

            case 'close-scan-error':
                const banner = document.getElementById('scanErrorBanner');
                if (banner) banner.style.display = 'none';
                break;

            case 'open-vuln-modal':
                try {
                    const raw = btn.dataset.vuln || btn.dataset.v;
                    let v;
                    try {
                        // Try base64 decode first (new format)
                        v = JSON.parse(decodeURIComponent(escape(atob(raw))));
                    } catch (_) {
                        // Fall back to legacy escaped JSON
                        v = JSON.parse(raw.replace(/&#39;/g, "'").replace(/&quot;/g, '"'));
                    }
                    openVulnModal(v);
                } catch (err) { console.error('open-vuln-modal parse error', err); }
                break;

            case 'open-scan-detail':
                openScanDetail(parseInt(btn.dataset.idx));
                break;

            case 'open-scan-detail-drawer':
                openScanDetail(parseInt(btn.dataset.idx));
                closeScanHistory();
                break;

            case 'export-history-scan':
                exportHistoryScan(parseInt(btn.dataset.idx));
                break;
            case 'email-history-scan':
                emailHistoryScan(parseInt(btn.dataset.idx));
                break;

            case 'delete-history-scan-tab':
                deleteHistoryScanFromTab(parseInt(btn.dataset.idx));
                break;

            case 'delete-history-scan':
                deleteHistoryScan(parseInt(btn.dataset.idx));
                break;

            case 'exit-view-mode-drawer':
                exitViewMode();
                closeScanHistory();
                break;

            case 'reveal-cred':
                toggleReveal(btn);
                break;

            case 'remove-cred':
                removeCredential(btn, parseInt(btn.dataset.idx));
                break;

            case 'scan-target':
                scanTarget(btn.dataset.url);
                break;

            case 'remove-exclusion':
                btn.parentElement.remove();
                break;
        }
    });

    // Print/close in PDF report window (injected into new window, need DOMContentLoaded there)
    // These are handled inline via the new window's own document
}


// ════════════════════════════════════════
// MULTI-TARGET LIVE MONITOR
// Shows each target as a card inside Scan Progress while scanning.
// Only visible when 2+ targets are added.
// ════════════════════════════════════════
let _monitorTargets = [];

function renderTargetMonitor(urls) {
    _monitorTargets = (urls || []).map(u => ({ url: u, status: 'queued', phase: 'Waiting…', progress: 0 }));
    _buildMonitorDOM();
}

function _buildMonitorDOM() {
    let wrap = document.getElementById('targetMonitorWrap');
    if (!wrap) {
        const prog = document.getElementById('progressSection');
        if (!prog) return;
        wrap = document.createElement('div');
        wrap.id = 'targetMonitorWrap';
        wrap.style.cssText = 'margin-top:10px;display:flex;flex-direction:column;gap:6px;';
        prog.appendChild(wrap);
    }
    if (!_monitorTargets.length || _monitorTargets.length <= 1) { wrap.style.display = 'none'; return; }
    wrap.style.display = 'flex';
    wrap.innerHTML = '<div style="font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-bottom:2px;">Targets</div>'
        + _monitorTargets.map((t, i) => {
            const host = (() => { try { return new URL(t.url).host; } catch(_) { return t.url; } })();
            const col = t.status === 'scanning' ? 'var(--neon)' : t.status === 'done' ? '#22d3ee' : 'var(--muted)';
            const dotStyle = t.status === 'scanning'
                ? 'width:7px;height:7px;border-radius:50%;background:var(--neon);box-shadow:0 0 6px var(--neon);flex-shrink:0;animation:termBlink 1.2s ease-in-out infinite;display:inline-block;'
                : t.status === 'done'
                    ? 'color:#22d3ee;font-size:12px;flex-shrink:0;'
                    : 'width:7px;height:7px;border-radius:50%;background:var(--muted);flex-shrink:0;display:inline-block;';
            const dotText = t.status === 'done' ? '✓' : '';
            return `<div id="tmon_${i}" style="display:flex;align-items:center;gap:9px;padding:7px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:7px;">
                <span style="${dotStyle}">${dotText}</span>
                <div style="flex:1;min-width:0;">
                    <div style="font-family:'DM Mono',monospace;font-size:12px;font-weight:600;color:${col};overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${t.url}">${host}</div>
                    <div id="tmon_phase_${i}" style="font-size:11px;color:var(--muted);margin-top:1px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${t.phase}</div>
                </div>
                <div style="flex-shrink:0;text-align:right;">
                    <div id="tmon_pct_${i}" style="font-family:'DM Mono',monospace;font-size:12px;color:${col};">${t.progress}%</div>
                    <div style="width:60px;height:3px;background:rgba(255,255,255,.07);border-radius:2px;margin-top:3px;">
                        <div id="tmon_bar_${i}" style="height:100%;border-radius:2px;background:${col};width:${t.progress}%;transition:width .4s;"></div>
                    </div>
                </div>
            </div>`;
        }).join('');
}

function updateTargetMonitor(liveUrl, phase, overallPct) {
    if (!_monitorTargets.length || _monitorTargets.length <= 1) return;
    if (!liveUrl) return;
    let activeIdx = -1;
    _monitorTargets.forEach((t, i) => {
        try {
            const th = new URL(t.url).host;
            const lh = new URL(liveUrl.startsWith('http') ? liveUrl : 'http://' + liveUrl).host;
            if (th === lh) activeIdx = i;
        } catch(_) { if (liveUrl.includes(t.url) || t.url.includes(liveUrl)) activeIdx = i; }
    });
    if (activeIdx === -1) return;
    _monitorTargets.forEach((t, i) => {
        if (i < activeIdx && t.status !== 'done') { t.status = 'done'; t.progress = 100; t.phase = 'Complete'; }
    });
    _monitorTargets[activeIdx].status = 'scanning';
    _monitorTargets[activeIdx].phase = phase || 'Scanning…';
    const perTarget = 100 / _monitorTargets.length;
    _monitorTargets[activeIdx].progress = Math.min(100, Math.max(0,
        Math.round(((overallPct - activeIdx * perTarget) / perTarget) * 100)
    ));
    _monitorTargets.forEach((t, i) => {
        const col = t.status === 'scanning' ? 'var(--neon)' : t.status === 'done' ? '#22d3ee' : 'var(--muted)';
        const p = document.getElementById('tmon_phase_' + i);
        const c = document.getElementById('tmon_pct_' + i);
        const b = document.getElementById('tmon_bar_' + i);
        const row = document.getElementById('tmon_' + i);
        if (p) p.textContent = t.phase;
        if (c) { c.textContent = t.progress + '%'; c.style.color = col; }
        if (b) { b.style.width = t.progress + '%'; b.style.background = col; }
        if (row) {
            const dot = row.querySelector('span');
            if (dot) {
                if (t.status === 'scanning') {
                    dot.style.cssText = 'width:7px;height:7px;border-radius:50%;background:var(--neon);box-shadow:0 0 6px var(--neon);flex-shrink:0;animation:termBlink 1.2s ease-in-out infinite;display:inline-block;';
                    dot.textContent = '';
                } else if (t.status === 'done') {
                    dot.style.cssText = 'color:#22d3ee;font-size:12px;flex-shrink:0;animation:none;';
                    dot.textContent = '✓';
                } else {
                    dot.style.cssText = 'width:7px;height:7px;border-radius:50%;background:var(--muted);flex-shrink:0;display:inline-block;';
                    dot.textContent = '';
                }
            }
        }
    });
}

function finalizeTargetMonitor() {
    _monitorTargets.forEach((_, i) => {
        _monitorTargets[i].status = 'done';
        _monitorTargets[i].progress = 100;
        _monitorTargets[i].phase = 'Complete';
        const p = document.getElementById('tmon_phase_' + i);
        const c = document.getElementById('tmon_pct_' + i);
        const b = document.getElementById('tmon_bar_' + i);
        const row = document.getElementById('tmon_' + i);
        if (p) p.textContent = 'Complete';
        if (c) { c.textContent = '100%'; c.style.color = '#22d3ee'; }
        if (b) { b.style.width = '100%'; b.style.background = '#22d3ee'; }
        if (row) {
            const dot = row.querySelector('span');
            if (dot) { dot.style.cssText = 'color:#22d3ee;font-size:12px;flex-shrink:0;animation:none;'; dot.textContent = '✓'; }
        }
    });
}

// ════════════════════════════════════════
// CSP-COMPLIANT STATIC EVENT LISTENERS
// Replaces all inline onclick/onkeydown/etc. from blade template
// ════════════════════════════════════════
function initEventListeners() {
    const on = (id, evt, fn) => { const el = document.getElementById(id); if (el) el.addEventListener(evt, fn); };

    // ── Auth tabs ──────────────────────────────────────────────
    on('signinTab', 'click', () => switchAuthTab('signin'));
    on('signupTab', 'click', () => switchAuthTab('signup'));
    on('switchToSignup', 'click', () => switchAuthTab('signup'));

    // ── Forgot key hover ───────────────────────────────────────
    const forgotKey = document.getElementById('forgotKeyLink');
    if (forgotKey) {
        forgotKey.addEventListener('mouseover', () => forgotKey.style.color = 'var(--neon)');
        forgotKey.addEventListener('mouseout', () => forgotKey.style.color = 'white');
    }

    // ── Sign in ────────────────────────────────────────────────
    on('siBtn', 'click', doSignIn);
    on('siEmail', 'keydown', e => { if (e.key === 'Enter') doSignIn(); });
    on('siPassword', 'keydown', e => { if (e.key === 'Enter') doSignIn(); });

    // ── Password eye toggles ───────────────────────────────────
    on('siPwEye', 'click', function () { togglePw('siPassword', this); });
    on('suPwEye', 'click', function () { togglePw('suPassword', this); });

    // ── Sign up ────────────────────────────────────────────────
    on('suBtn', 'click', doSignUp);
    on('suPassword', 'input', function () { calcPwStr(this.value); });

    // ── OTP ────────────────────────────────────────────────────
    on('otpBackBtn', 'click', backFromOtp);
    on('otpBtn', 'click', doVerifyOtp);
    on('otpResendBtn', 'click', resendOtp);

    // ── Nav items ──────────────────────────────────────────────
    on('nav-dashboard', 'click', () => switchTab('dashboard'));
    on('nav-vulnerabilities', 'click', () => switchTab('vulnerabilities'));
    on('nav-scan-history', 'click', () => { switchTab('scan-history'); loadScanHistoryTab(); });
    on('navScanDetail', 'click', () => switchTab('scan-detail'));
    on('nav-targets', 'click', () => switchTab('targets'));
    on('nav-authentication', 'click', () => switchTab('authentication'));
    on('nav-configuration', 'click', () => switchTab('configuration'));

    // ── Admin nav hover ────────────────────────────────────────
    const adminNavItem = document.getElementById('adminNavItem');
    if (adminNavItem) {
        adminNavItem.addEventListener('mouseenter', () => { adminNavItem.style.background = 'rgba(245,158,11,.07)'; adminNavItem.style.borderColor = 'rgba(245,158,11,.18)'; });
        adminNavItem.addEventListener('mouseleave', () => { adminNavItem.style.background = ''; adminNavItem.style.borderColor = 'transparent'; });
    }

    // ── Sign out ───────────────────────────────────────────────
    on('signOutChip', 'click', doSignOut);

    // ── Topbar ─────────────────────────────────────────────────
    on('exitViewModeBtn', 'click', exitViewMode);
    on('pauseBtn', 'click', pauseOrResume);
    on('historyTopbarBtn', 'click', openScanHistory);
    on('startBtn', 'click', startScan);

    // ── Dashboard ──────────────────────────────────────────────
    on('quickstartAddTargetBtn', 'click', () => switchTab('targets'));
    on('viewAllVulnsBtn', 'click', () => switchTab('vulnerabilities'));

    // ── Scan history tab ───────────────────────────────────────
    on('refreshHistoryBtn', 'click', loadScanHistoryTab);

    // ── Scan detail ────────────────────────────────────────────
    on('breadcrumbScanHistoryLink', 'click', () => { switchTab('scan-history'); loadScanHistoryTab(); });
    on('exportScanDetailBtn', 'click', exportCurrentScanDetail);
    on('backToScanHistoryBtn', 'click', () => { switchTab('scan-history'); loadScanHistoryTab(); });
    on('sdSevFilter', 'change', filterScanDetail);

    // ── Vulnerabilities ────────────────────────────────────────
    on('sevFilter', 'change', filterVulns);
    on('exportReportBtn', 'click', exportReportPDF);

    // ── Targets ────────────────────────────────────────────────
    on('addTargetBtn', 'click', addTarget);
    on('scanDefaultTargetBtn', 'click', () => scanTarget('http://localhost:8000'));

    // ── Auth vault ─────────────────────────────────────────────
    on('authTypeCookie', 'click', function () { selectAuthType(this, 'cookie'); });
    on('authTypeBearer', 'click', function () { selectAuthType(this, 'bearer'); });
    on('authTypeBasic', 'click', function () { selectAuthType(this, 'basic'); });
    on('authTypeOauth', 'click', function () { selectAuthType(this, 'oauth'); });
    on('addCredentialsBtn', 'click', addCredentials);

    // ── Configuration ──────────────────────────────────────────
    on('saveConfigBtn', 'click', saveConfiguration);
    on('intensityPassive', 'click', function () { setIntensity('passive', this); });
    on('intensityStandard', 'click', function () { setIntensity('standard', this); });
    on('intensityAggressive', 'click', function () { setIntensity('aggressive', this); });

    // ── Exclusions ─────────────────────────────────────────────
    on('addExclusionBtn', 'click', addExclusion);
    on('exclusionInput', 'keydown', e => { if (e.key === 'Enter') addExclusion(); });

    // ── Drawer ─────────────────────────────────────────────────
    on('drawerOverlay', 'click', closeScanHistory);
    on('drawerCloseBtn', 'click', closeScanHistory);

    // ── Vuln modal ─────────────────────────────────────────────
    on('closeVulnModalBtn', 'click', closeVulnModal);
}

// Attach after DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        initEventListeners();
        initDelegatedListeners();
    });
} else {
    initEventListeners();
    initDelegatedListeners();
}
