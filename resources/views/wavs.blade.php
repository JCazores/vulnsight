<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='2 2 20 20' fill='none' stroke='%2300f5c4' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z'/></svg>">
    <title>VulnSight — Web Application Vulnerability Scanner</title>
    <link rel="stylesheet" href="{{ asset('css/wavs.css') }}">
    @vite(['resources/css/app.css', 'resources/js/app.js'])
    <style nonce="{{ csp_nonce() }}">
    /* ══════════════════════════════════════════
       UPTIMEBOT-MATCH THEME — embedded iframe
    ══════════════════════════════════════════ */
        @font-face {
        font-family: 'DM Sans';
        src: url('{{ asset('fonts/DM-Sans-400.woff2') }}') format('woff2');
        font-weight: 400;
        font-display: swap;
    }

    /* Hide auth screen always */
    #authScreen { display: none !important; }

    /* Override VulnSight root layout to column */
    body { background: #030712 !important; }
    #mainApp {
        display: flex !important;
        flex-direction: column !important;
        min-height: 100vh;
        background: #030712;
    }

    /* ── TOP NAV — matches UpTimeBot sidebar style ── */
    #topNav {
        display: flex;
        align-items: center;
        justify-content: space-between;
        height: 52px;
        padding: 0 16px;
        background: #111827;
        border-bottom: 1px solid #1f2937;
        flex-shrink: 0;
        gap: 8px;
    }
    .tn-links {
        display: flex;
        align-items: center;
        gap: 2px;
        flex: 1;
        min-width: 0;
        overflow-x: auto;
        scrollbar-width: none;
    }
    .tn-links::-webkit-scrollbar { display: none; }
    .tn-item {
        display: flex;
        align-items: center;
        gap: 7px;
        padding: 6px 12px;
        border-radius: 8px;
        font-size: 13px;
        font-weight: 500;
        color: #6b7280;
        cursor: pointer;
        white-space: nowrap;
        transition: color .15s, background .15s;
        border: none;
        background: transparent;
        position: relative;
        text-decoration: none;
    }
    .tn-item:hover { color: #f9fafb; background: #1f2937; }
    .tn-item.active {
        color: #f9fafb;
        background: #1f2937;
    }
    .tn-item svg { opacity: .7; flex-shrink: 0; }
    .tn-item.active svg { opacity: 1; }
    .tn-item .nav-badge {
        background: #ef4444;
        color: #fff;
        font-size: 10px;
        font-weight: 700;
        padding: 1px 5px;
        border-radius: 99px;
        min-width: 16px;
        text-align: center;
    }

    /* ── Right action area ── */
    .tn-actions {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-shrink: 0;
    }
    .tn-status {
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 4px 10px;
        border-radius: 6px;
        background: #1f2937;
        border: 1px solid #374151;
    }
    .tn-icon-btn {
        position: relative;
        width: 34px;
        height: 34px;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 8px;
        background: #1f2937;
        border: 1px solid #374151;
        color: #9ca3af;
        cursor: pointer;
        transition: color .15s, background .15s;
    }
    .tn-icon-btn:hover { color: #f9fafb; background: #374151; }
    .tn-start-btn {
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 7px 14px;
        border-radius: 8px;
        background: #22c55e;
        color: #000;
        font-size: 13px;
        font-weight: 700;
        border: none;
        cursor: pointer;
        transition: background .15s;
    }
    .tn-start-btn:hover { background: #16a34a; }
    .tn-start-btn.scanning { background: #ef4444; color: #fff; }
    .tn-start-btn.scanning:hover { background: #dc2626; }

    /* ── Page title bar ── */
    .page-titlebar {
        padding: 14px 24px 0;
    }
    .topbar-title {
        font-size: 20px;
        font-weight: 700;
        color: #f9fafb;
        letter-spacing: -.02em;
    }
    .topbar-title span:first-child {
        color: #6b7280;
        font-weight: 400;
        margin-right: 4px;
        font-size: 14px;
    }

    /* ── Viewing banner ── */
    #viewingBanner {
        margin: 10px 24px 0;
        border-radius: 8px;
    }

    /* ── Content area ── */
    .content {
        padding: 16px 24px 24px;
        background: #030712;
        flex: 1;
    }

    /* ── Section titles ── */
    .section-title {
        font-size: 18px;
        font-weight: 700;
        color: #f9fafb;
        letter-spacing: -.02em;
    }

    /* ── Stat cards — UpTimeBot dark style ── */
    .stat-card {
        background: #111827 !important;
        border: 1px solid #1f2937 !important;
        border-radius: 12px !important;
    }
    .stat-card:hover { border-color: #374151 !important; }

    /* ── Cards ── */
    .card {
        background: #111827 !important;
        border: 1px solid #1f2937 !important;
        border-radius: 12px !important;
    }

    /* ── Tables ── */
    .wavs-table th {
        background: #111827;
        color: #6b7280;
        font-size: 11px;
        letter-spacing: .07em;
        border-bottom: 1px solid #1f2937;
    }
    .wavs-table td {
        border-bottom: 1px solid #111827;
        font-size: 13px;
    }
    .wavs-table tr:hover td { background: #0d1117; }

    /* ── Scan progress bar ── */
    .prog-track {
        background: #1f2937;
        height: 6px;
        border-radius: 3px;
    }
    .prog-bar { border-radius: 3px; }

    /* ── btn-ghost ── */
    .btn-ghost {
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 6px 12px;
        border-radius: 8px;
        border: 1px solid #374151;
        background: #1f2937;
        color: #d1d5db;
        font-size: 13px;
        font-weight: 500;
        cursor: pointer;
        transition: background .15s;
    }
    .btn-ghost:hover { background: #374151; }

    /* ── status dot colours ── */
    #statusDot { width: 8px; height: 8px; border-radius: 50%; background: #6b7280; flex-shrink: 0; }

    /* ── Brand/breadcrumb ── */
    .tn-brand {
        display: flex;
        align-items: center;
        gap: 6px;
        flex-shrink: 0;
        padding-right: 16px;
        border-right: 1px solid #1f2937;
        margin-right: 8px;
    }

    /* ── Kill sidebar offset — sidebar removed ── */
    #sidebar { display: none !important; }
    #mainApp { margin-left: 0 !important; }
    :root { --sw: 0px !important; }
    </style>
</head>
<body>

<!-- ══════════════════════════════════════
     AUTH SCREEN
══════════════════════════════════════ -->
<div id="authScreen" style="display:none;">

    <!-- ── Left brand panel ── -->
    <div class="al">
        <div class="al-grid"></div>
        <div class="al-scanline"></div>
        <div class="al-g1"></div>
        <div class="al-g2"></div>

        <!-- Top header bar -->
        <div class="al-topbar">
            <div class="al-logo">
                <div class="al-icon">
                    <svg width="25" height="25" fill="none" stroke="var(--neon)" viewBox="0 0 24 24" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                    </svg>
                </div>
                <div>
                    <div class="al-wordmark">VulnSight</div>
                    <div class="al-tag">Security Platform</div>
                </div>
            </div>
            <div class="al-status-pill">
                <span class="al-status-dot"></span>
                All systems operational
            </div>
        </div>

        <!-- Hero content -->
        <div class="al-hero">
            <!-- Radar -->
            <div class="al-radar-wrap">
                <div class="al-radar-ring"></div>
                <div class="al-radar-ring"></div>
                <div class="al-radar-ring"></div>
                <div class="al-radar-sweep"></div>
                <div class="al-radar-center"></div>
                <div class="al-blip" style="top:28%;left:62%;"></div>
                <div class="al-blip" style="top:58%;left:35%;opacity:.7;"></div>
                <div class="al-blip" style="top:42%;left:78%;background:var(--red);box-shadow:0 0 6px var(--red);opacity:.9;"></div>
                <div class="al-blip" style="top:70%;left:58%;background:var(--orange);box-shadow:0 0 5px var(--orange);opacity:.6;width:4px;height:4px;"></div>
            </div>

            <div class="al-headline">Find threats<br><em>before they find you.</em></div>
            <div class="al-desc">Enterprise-grade vulnerability scanning with real-time detection, CVSS scoring, and automated remediation guidance.</div>

            <!-- Terminal feed -->
            <div class="al-terminal">
                <div class="al-term-header">
                    <span class="al-term-dot" style="background:#ff5f56;"></span>
                    <span class="al-term-dot" style="background:#ffbd2e;"></span>
                    <span class="al-term-dot" style="background:#27c93f;"></span>
                    <span class="al-term-title">live scan monitor</span>
                </div>
                <div class="al-term-body">
                    <div class="al-term-line"><span class="al-term-ts">09:14:22</span><span class="al-term-sev-c">[CRIT]</span><span class="al-term-msg">SQLi detected — /api/users?id=</span></div>
                    <div class="al-term-line"><span class="al-term-ts">09:14:19</span><span class="al-term-sev-w">[WARN]</span><span class="al-term-msg">Missing CSP header — /dashboard</span></div>
                    <div class="al-term-line"><span class="al-term-ts">09:14:15</span><span class="al-term-sev-i">[INFO]</span><span class="al-term-msg">Crawled 247 endpoints successfully</span></div>
                    <div class="al-term-line"><span class="al-term-ts">09:14:08</span><span class="al-term-sev-c">[CRIT]</span><span class="al-term-msg">Stored XSS — /api/comments</span></div>
                    <div class="al-term-line"><span class="al-term-ts">09:14:02</span><span class="al-term-sev-i">[INFO]</span><span class="al-term-msg">Scan engine initialized<span class="al-term-cursor"></span></span></div>
                </div>
            </div>

            <div class="al-chips">
                <div class="al-chip"><div class="al-chip-num">10K+</div><div class="al-chip-lbl">Vulns Detected</div></div>
                <div class="al-chip"><div class="al-chip-num">OWASP</div><div class="al-chip-lbl">Top 10 Coverage</div></div>
                <div class="al-chip"><div class="al-chip-num">99.9%</div><div class="al-chip-lbl">Uptime SLA</div></div>
                <div class="al-chip"><div class="al-chip-num">&lt;2s</div><div class="al-chip-lbl">First Finding</div></div>
            </div>
        </div>

        <div class="al-footer">
            <span>© 2026 VulnSight</span>
            <span><a href="#">Privacy</a> &nbsp;·&nbsp; <a href="#">Terms</a> &nbsp;·&nbsp; <a href="#">Status</a></span>
        </div>
    </div>

    <!-- ── Right form panel ── -->
    <div class="ar">
        <div class="af">

            <!-- Security badge -->
            <div class="af-badge">
                <span class="af-badge-dot"></span>
                Secure Authentication · TLS 1.3
            </div>

            <!-- Step 1: Sign-in / Sign-up -->
            <div id="authStep1">
                <div class="af-title" id="afTitle">Operator Login</div>
                <div class="af-sub"   id="afSub">Authenticate to access the VulnSight platform.</div>

                <div class="auth-tabs">
                    <button class="auth-tab active" id="signinTab">Sign In</button>
                    <button class="auth-tab"         id="signupTab">Create Account</button>
                </div>

                <!-- SIGN IN -->
                <div id="signinForm">
                    <div class="af-field">
                        <label class="af-label">Operator ID (Email)</label>
                        <div class="af-wrap">
                            <input id="siEmail" class="af-input" type="email" placeholder="operator@company.com" autocomplete="email">
                            <svg class="af-ico" width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
                        </div>
                    </div>
                    <div class="af-field">
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                            <label class="af-label" style="margin:0;">Access Key</label>
                            <a href="#" id="forgotKeyLink" style="font-size:10.5px;color:white;text-decoration:none;font-family:'DM Mono',monospace;letter-spacing:.02em;">Forgot key?</a>
                        </div>
                        <div class="af-wrap">
                            <input id="siPassword" class="af-input" type="password" placeholder="••••••••••••" autocomplete="current-password">
                            <svg class="af-ico" width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                            <button class="af-pw-eye" id="siPwEye" type="button" title="Toggle visibility">
                                <svg id="siEyeIcon" width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                            </button>
                        </div>
                    </div>
                    <div id="siMsg" class="af-msg"></div>
                    <button class="af-btn" id="siBtn">
                        <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5"><path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                        <span id="siBtnTxt">Authenticate</span>
                        <div class="af-spin" id="siSpin"></div>
                    </button>

                    <div class="af-or">or</div>
                    <p style="font-size:11.5px;color:var(--muted);text-align:center;font-family:'DM Mono',monospace;">New operator? <button class="af-link" id="switchToSignup">Request access →</button></p>
                </div>

                <!-- SIGN UP -->
                <div id="signupForm" style="display:none;">
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:11px;">
                        <div class="af-field">
                            <label class="af-label">Full name</label>
                            <div class="af-wrap">
                                <input id="suName" class="af-input" type="text" placeholder="Jane Doe" autocomplete="name">
                                <svg class="af-ico" width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                            </div>
                        </div>
                        <div class="af-field">
                            <label class="af-label">Email address</label>
                            <div class="af-wrap">
                                <input id="suEmail" class="af-input" type="email" placeholder="you@company.com" autocomplete="email">
                                <svg class="af-ico" width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
                            </div>
                        </div>
                    </div>
                    <div class="af-field">
                        <label class="af-label">Password</label>
                        <div class="af-wrap">
                            <input id="suPassword" class="af-input" type="password" placeholder="Min. 8 characters" autocomplete="new-password">
                            <svg class="af-ico" width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                            <button class="af-pw-eye" id="suPwEye" type="button">
                                <svg id="suEyeIcon" width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                            </button>
                        </div>
                        <div class="pw-str" id="pwStr">
                            <div class="pw-str-track"><div class="pw-str-bar" id="pwStrBar"></div></div>
                            <div class="pw-str-lbl" id="pwStrLbl">Weak</div>
                        </div>
                    </div>
                    <div class="af-field">
                        <label class="af-label">Confirm password</label>
                        <div class="af-wrap">
                            <input id="suConfirm" class="af-input" type="password" placeholder="Repeat password" autocomplete="new-password">
                            <svg class="af-ico" width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                        </div>
                    </div>
                    <div id="suMsg" class="af-msg"></div>
                    <button class="af-btn" id="suBtn">
                        <span id="suBtnTxt">Send Verification Code</span>
                        <div class="af-spin" id="suSpin"></div>
                    </button>
                    <div class="af-fine">By continuing you agree to our <a href="#">Terms</a> &amp; <a href="#">Privacy Policy</a>.</div>
                </div>
            </div><!-- /authStep1 -->

            <!-- Step 2: OTP verification -->
            <div id="otpStep">
                <button class="otp-back" id="otpBackBtn">
                    <svg width="13" height="13" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
                    Back
                </button>
                <div class="otp-hd">
                    <div class="otp-ring">
                        <svg width="22" height="22" fill="none" stroke="var(--neon)" viewBox="0 0 24 24" stroke-width="1.8"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
                    </div>
                    <div class="otp-title">Check your inbox</div>
                    <div class="otp-desc">
                        We sent a 6-digit code to<br>
                        <span class="otp-badge" id="otpEmailBadge"></span>
                    </div>
                </div>

                <div class="otp-boxes">
                    <input class="otp-box" id="ob0" type="text" inputmode="numeric" maxlength="1" pattern="[0-9]">
                    <input class="otp-box" id="ob1" type="text" inputmode="numeric" maxlength="1" pattern="[0-9]">
                    <input class="otp-box" id="ob2" type="text" inputmode="numeric" maxlength="1" pattern="[0-9]">
                    <input class="otp-box" id="ob3" type="text" inputmode="numeric" maxlength="1" pattern="[0-9]">
                    <input class="otp-box" id="ob4" type="text" inputmode="numeric" maxlength="1" pattern="[0-9]">
                    <input class="otp-box" id="ob5" type="text" inputmode="numeric" maxlength="1" pattern="[0-9]">
                </div>

                <div id="otpMsg" class="af-msg" style="margin-bottom:12px;"></div>

                <button class="af-btn" id="otpBtn" disabled>
                    <span id="otpBtnTxt">Verify &amp; Create Account</span>
                    <div class="af-spin" id="otpSpin"></div>
                </button>

                <div class="otp-resend">
                    Didn't receive it? &nbsp;
                    <button class="otp-resend-btn" id="otpResendBtn" disabled>Resend code</button>
                    <span class="otp-timer" id="otpTimer"></span>
                </div>
            </div><!-- /otpStep -->

        </div><!-- /af -->
    </div><!-- /ar -->
</div>

<!-- ══════════════════════════════════════
     MAIN APP
══════════════════════════════════════ -->
<div id="mainApp" style="display:none;">

    <!-- TOP NAVIGATION BAR — replaces sidebar -->
    <nav id="topNav">
        <!-- Brand/breadcrumb -->
        <div class="tn-brand">
            <svg width="16" height="16" fill="none" stroke="#22c55e" viewBox="0 0 24 24" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
            <span style="font-size:13px;font-weight:700;color:#f9fafb;">VulnSight</span>
            <span style="color:#374151;margin:0 4px;">|</span>
            <span id="topbarTitle" style="font-size:13px;font-weight:500;color:#9ca3af;">Dashboard</span>
        </div>
        <!-- Nav links -->
        <div class="tn-links">
            <div class="tn-item active" data-tab="dashboard" id="nav-dashboard">
                <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.8"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>
                Dashboard
            </div>
            <div class="tn-item" data-tab="vulnerabilities" id="nav-vulnerabilities">
                <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.8"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                Vulnerabilities
                <span class="nav-badge" id="vulnBadge" style="display:none;">0</span>
            </div>
            <div class="tn-item" data-tab="scan-history" id="nav-scan-history">
                <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.8"><path d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                Scan History
            </div>
            <div class="tn-item" data-tab="targets" id="nav-targets">
                <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.8"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>
                Targets
            </div>
            <div class="tn-item" data-tab="configuration" id="nav-configuration">
                <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.8"><path d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><circle cx="12" cy="12" r="3"/></svg>
                Settings
            </div>
            <!-- Scan Detail sub-nav — hidden until a scan is viewed -->
            <div class="tn-item" id="navScanDetail" data-tab="scan-detail" style="display:none;">
                <svg width="13" height="13" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.8"><path d="M9 17H7A5 5 0 017 7h2M15 7h2a5 5 0 010 10h-2M8 12h8"/></svg>
                <span id="navScanDetailLabel">Scan Details</span>
            </div>
            <!-- Admin link — hidden until role check -->
            <div id="adminNavSection" style="display:none;">
                <a href="/admin" style="text-decoration:none;">
                    <div class="tn-item" id="adminNavItem" style="color:#f59e0b;">
                        <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.8" style="opacity:.8;"><path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                        Admin
                    </div>
                </a>
            </div>
        </div>

        <!-- Hidden elements JS writes user info into -->
        <span id="userAvatar" style="display:none;"></span>
        <span id="userNameDisplay" style="display:none;"></span>
        <!-- Right: scan controls -->
        <div class="tn-actions">
            <div class="tn-status">
                <div class="status-dot" id="statusDot"></div>
                <span id="statusText" style="font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:#9ca3af;">idle</span>
            </div>
            <button id="pauseBtn" style="display:none;" class="btn-ghost">
                <svg id="pauseIcon" width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg>
                <span id="pauseLabel">Pause</span>
            </button>
            <button id="historyTopbarBtn" title="Scan History" class="tn-icon-btn">
                <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.8"><path d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                <span class="history-badge" id="historyCount" style="display:none;">0</span>
            </button>
            <button id="startBtn" class="tn-start-btn">
                <svg id="startIcon" width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5"><polygon points="5,3 19,12 5,21"/></svg>
                <span id="startLabel">Start Scan</span>
            </button>
        </div>
    </nav>

    <!-- CONTENT WRAPPER -->
    <div style="display:flex;flex-direction:column;flex:1;min-width:0;">

        <!-- Viewing past scan banner -->
        <div id="viewingBanner">
            <svg width="14" height="14" fill="none" stroke="#93c5fd" viewBox="0 0 24 24" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
            <span id="viewingBannerText">Viewing past scan</span>
            <button id="exitViewModeBtn" style="margin-left:auto;padding:4px 12px;border-radius:6px;background:rgba(59,130,246,.15);border:1px solid rgba(59,130,246,.3);color:#93c5fd;font-size:12px;font-weight:700;cursor:pointer;font-family:inherit;">
                ← Back to Live
            </button>
        </div>



        <div class="content">

            <!-- ══════ DASHBOARD ══════ -->
            <div id="dashboard-tab" class="tab-content active">

                <div class="stat-grid">
                    <div class="stat-card" style="--clr:var(--neon);--clr-rgb:var(--neon-rgb);">
                        <div class="stat-card-bar"></div>
                        <div class="stat-rate">+<span id="reqRate">0</span>/s</div>
                        <div class="stat-num" id="requestsSent">0</div>
                        <div class="stat-lbl">Requests Sent</div>
                    </div>
                    <div class="stat-card" style="--clr:#60a5fa;--clr-rgb:96,165,250;">
                        <div class="stat-card-bar"></div>
                        <div class="stat-rate">+<span id="urlRate">0</span>/s</div>
                        <div class="stat-num" id="urlsDiscovered">0</div>
                        <div class="stat-lbl">URLs Discovered</div>
                    </div>
                    <div class="stat-card" style="--clr:var(--orange);--clr-rgb:245,158,11;">
                        <div class="stat-card-bar"></div>
                        <div class="stat-rate">live</div>
                        <div class="stat-num" id="vulnerabilitiesFound">0</div>
                        <div class="stat-lbl">Vulnerabilities</div>
                    </div>
                    <div class="stat-card" style="--clr:var(--red);--clr-rgb:240,80,80;">
                        <div class="stat-card-bar"></div>
                        <div class="stat-rate">critical</div>
                        <div class="stat-num" id="criticalIssues">0</div>
                        <div class="stat-lbl">Critical Issues</div>
                    </div>
                </div>

                <!-- Progress + Sev row -->
                <div style="display:grid;grid-template-columns:1fr 240px;gap:12px;margin-bottom:12px;">

                    <div class="card" id="progressSection" style="display:none;">
                        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:13px;">
                            <span class="card-label" style="margin:0;">Scan Progress</span>
                            <span style="display:flex;align-items:center;gap:10px;">
                                <span id="elapsedDisplay" style="font-family:'DM Mono',monospace;font-size:11px;color:white;display:none;">&#9201; <span id="elapsedTime">0s</span></span>
                                <span id="progressPercent" style="font-family:'DM Mono',monospace;font-size:20px;font-weight:500;color:var(--neon);">0%</span>
                            </span>
                        </div>
                        <div class="prog-track"><div id="progressBar" class="prog-bar" style="width:0%"></div></div>
                        <p id="progressPhase" style="font-size:14px;color:white;margin-top:9px;font-family:'DM Mono',monospace;">Waiting...</p>
                        <code id="liveScanUrl" style="display:none;font-size:11px;color:var(--neon);font-family:'DM Mono',monospace;margin-top:5px;padding:3px 8px;background:rgba(0,245,196,.06);border:1px solid rgba(0,245,196,.12);border-radius:5px;word-break:break-all;"></code>
                        <div id="scanFeed" style="margin-top:8px;max-height:140px;overflow-y:auto;padding:4px 8px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;display:none;"></div>
                        <div id="currentScanTarget" style="display:none;margin-top:10px;padding:8px 11px;background:var(--surface2);border:1px solid var(--border);border-radius:7px;">
                            <div style="display:flex;align-items:center;gap:7px;flex-wrap:wrap;">
                                <span style="font-size:9px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:white;flex-shrink:0;">Scanning</span>
                                <span id="currentScanPhaseIcon" style="font-size:9px;padding:2px 7px;border-radius:4px;font-weight:700;font-family:'DM Mono',monospace;background:rgba(0,245,196,.08);color:var(--neon);border:1px solid rgba(0,245,196,.15);flex-shrink:0;">SPIDER</span>
                                <span id="currentScanUrl" style="font-family:'DM Mono',monospace;font-size:11px;color:white;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0;flex:1;" title="">—</span>
                            </div>
                        </div>
                    </div>

                    <div class="quickstart" id="progressPlaceholder">
                        <p style="font-size:20px;font-weight:700;color:var(--neon);margin-bottom:6px;">Quick Start</p>
                        <p style="font-size:16px;color:white;line-height:1.65;">Add a target and press <strong style="color:var(--neon);">Start Scan</strong>. Findings appear in real-time.</p>
                        <button id="quickstartAddTargetBtn" style="margin-top:11px;font-size:16px;font-weight:600;color:var(--neon);background:none;border:none;cursor:pointer;font-family:'DM Sans',sans-serif;padding:0;display:inline-flex;align-items:center;gap:5px;">
                            <svg width="11" height="11" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                            Add Target
                        </button>
                    </div>

                    <!-- Severity breakdown -->
                    <div class="card">
                        <span class="card-label">Severity</span>
                        <div class="sev-grid">
                            <div class="sev-cell" style="background:rgba(240,80,80,.055);border:1px solid rgba(240,80,80,.12);">
                                <div class="sev-num" style="color:var(--red);" id="criticalCount">0</div>
                                <div class="sev-lbl">Critical</div>
                            </div>
                            <div class="sev-cell" style="background:rgba(245,158,11,.05);border:1px solid rgba(245,158,11,.12);">
                                <div class="sev-num" style="color:var(--orange);" id="highCount">0</div>
                                <div class="sev-lbl">High</div>
                            </div>
                            <div class="sev-cell" style="background:rgba(253,224,71,.04);border:1px solid rgba(253,224,71,.1);">
                                <div class="sev-num" style="color:var(--yellow);" id="mediumCount">0</div>
                                <div class="sev-lbl">Medium</div>
                            </div>
                            <div class="sev-cell" style="background:rgba(0,245,196,.045);border:1px solid rgba(0,245,196,.12);">
                                <div class="sev-num" style="color:var(--neon);" id="lowCount">0</div>
                                <div class="sev-lbl">Low</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Recent findings -->
                <div class="card" style="padding:0;overflow:hidden;">
                    <div style="display:flex;align-items:center;justify-content:space-between;padding:13px 18px;border-bottom:1px solid var(--border);">
                        <span class="card-label" style="margin:0;">Recent Findings</span>
                        <button id="viewAllVulnsBtn" style="font-size:14px;font-weight:600;color:var(--neon);background:none;border:none;cursor:pointer;font-family:'DM Sans',sans-serif;display:inline-flex;align-items:center;gap:4px;">
                            View all
                            <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
                        </button>
                    </div>
                    <div id="recentVulns">
                        <div class="empty-state">
                            <div class="empty-icon">🔍</div>
                            No findings yet. Start a scan to detect vulnerabilities.
                        </div>
                    </div>
                </div>
            </div>

            <!-- ══════ SCAN HISTORY TAB ══════ -->
            <div id="scan-history-tab" class="tab-content">
                <div class="section-header">
                    <div>
                        <div class="section-title" style="display:flex;align-items:center;gap:10px;">Scan History</div>
                        <p style="font-size:16px;color:white;margin-top:5px;">All scan runs stored in the database — each scan's vulnerabilities are isolated.</p>
                    </div>
                    <button class="btn-primary" id="refreshHistoryBtn" style="font-size:14px;padding:9px 16px;display:flex;align-items:center;gap:6px;">
                        <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5"><path d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                        Refresh
                    </button>
                </div>

                <!-- Summary stat row -->
                <div id="historyStatRow" style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px;">
                    <div class="card" style="padding:14px 16px;text-align:center;">
                        <div id="hstat-total" style="font-family:'DM Mono',monospace;font-size:26px;font-weight:600;color:var(--text);line-height:1;">0</div>
                        <div style="font-size:14px;color:white;text-transform:uppercase;letter-spacing:.06em;margin-top:4px;">Total Scans</div>
                    </div>
                    <div class="card" style="padding:14px 16px;text-align:center;">
                        <div id="hstat-vulns" style="font-family:'DM Mono',monospace;font-size:26px;font-weight:600;color:var(--neon);line-height:1;">0</div>
                        <div style="font-size:14px;color:white;text-transform:uppercase;letter-spacing:.06em;margin-top:4px;">Total Vulns Found</div>
                    </div>
                    <div class="card" style="padding:14px 16px;text-align:center;">
                        <div id="hstat-critical" style="font-family:'DM Mono',monospace;font-size:26px;font-weight:600;color:var(--red);line-height:1;">0</div>
                        <div style="font-size:14px;color:white;text-transform:uppercase;letter-spacing:.06em;margin-top:4px;">Critical Findings</div>
                    </div>
                    <div class="card" style="padding:14px 16px;text-align:center;">
                        <div id="hstat-completed" style="font-family:'DM Mono',monospace;font-size:26px;font-weight:600;color:#93c5fd;line-height:1;">0</div>
                        <div style="font-size:14px;color:white;text-transform:uppercase;letter-spacing:.06em;margin-top:4px;">Completed Scans</div>
                    </div>
                </div>

                <!-- History table -->
                <div class="card" style="padding:0;overflow:hidden;">
                    <div id="historyTabContent">
                        <div style="padding:48px 20px;text-align:center;">
                            <div style="font-size:28px;margin-bottom:12px;">📋</div>
                            <p style="font-size:16px;font-weight:600;color:white;margin-bottom:4px;">No scan history yet</p>
                            <p style="font-size:14px;color:white;">Run your first scan and it will appear here.</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- ══════ SCAN DETAIL ══════ -->
            <div id="scan-detail-tab" class="tab-content">
                <!-- Breadcrumb header -->
                <div class="section-header" style="align-items:flex-start;flex-direction:column;gap:6px;">
                    <div style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted);font-family:'DM Mono',monospace;">
                        <span id="breadcrumbScanHistoryLink" style="cursor:pointer;transition:color .15s;color:white;font-size:16px;">Scan History</span>
                        <svg width="10" height="10" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5" style="color:white;font-size:14px;"><path d="M9 18l6-6-6-6"/></svg>
                        <span id="sdBreadcrumb" style="color:white;font-size:14px;">Scan Details</span>
                    </div>
                    <div style="display:flex;align-items:center;justify-content:space-between;width:100%;">
                        <div>
                            <div id="sdTitle" class="section-title" style="margin-bottom:2px;"></div>
                            <div id="sdMeta" style="font-size:13px;color:white;font-family:'DM Mono',monospace;"></div>
                        </div>
                        <div style="display:flex;align-items:center;gap:8px;">
                            <div id="sdStatusBadge"></div>
                            <button id="exportScanDetailBtn" class="btn-ghost" style="font-size:13px;display:flex;align-items:center;gap:6px;color:white;">
                                <svg width="13" height="13" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                                Export PDF
                            </button>
                            <button id="backToScanHistoryBtn" class="btn-ghost" style="font-size:13px;display:flex;align-items:center;gap:6px;color:white;">
                                <svg width="13" height="13" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5"><path d="M19 12H5M12 5l-7 7 7 7"/></svg>
                                Back
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Stat cards -->
                <div id="sdStatRow" style="display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:14px;"></div>

                <!-- Severity filter + vuln table -->
                <div class="card" style="padding:0;overflow:hidden;">
                    <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--border);">
                        <span style="font-size:16px;font-weight:700;color:var(--text);">Vulnerabilities</span>
                        <select id="sdSevFilter" class="wavs-input" style="width:140px;padding:6px 10px;font-size:13px;">
                            <option value="all">All Severity</option>
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                        </select>
                    </div>
                    <table class="wavs-table">
                        <thead><tr>
                            <th>Vulnerability</th><th>Endpoint</th><th>Severity</th><th>Status</th><th>Detected</th><th></th>
                        </tr></thead>
                        <tbody id="sdVulnBody">
                            <tr><td colspan="6"><div class="empty-state"><div class="empty-icon">🛡️</div>No vulnerabilities for this scan.</div></td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- ══════ VULNERABILITIES ══════ -->
            <div id="vulnerabilities-tab" class="tab-content">
                <div class="section-header">
                    <div class="section-title">Vulnerability Report</div>
                    <div style="display:flex;gap:8px;align-items:center;">
                        <select id="sevFilter" class="wavs-input" style="width:148px;padding:8px 12px;">
                            <option value="all">All Severity</option>
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                        </select>
                        <button class="btn-primary" id="exportReportBtn" style="font-size:14px;padding:9px 16px;display:flex;align-items:center;gap:6px;">
                            <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                            Export PDF Report
                        </button>
                    </div>
                </div>
                <div class="card" style="padding:0;overflow:hidden;">
                    <table class="wavs-table">
                        <thead><tr>
                            <th>Vulnerability</th><th>Endpoint</th><th>Severity</th><th>Status</th><th>Detected</th><th></th>
                        </tr></thead>
                        <tbody id="vulnTableBody">
                            <tr><td colspan="6"><div class="empty-state"><div class="empty-icon">🛡️</div>No vulnerabilities detected yet.</div></td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- ══════ TARGETS ══════ -->
            <div id="targets-tab" class="tab-content">
                <div class="section-header">
                    <div class="section-title">Target Management</div>
                </div>

                <div class="card" style="margin-bottom:12px;">
                    <span class="card-label">Add New Target</span>
                    <div style="display:grid;grid-template-columns:1fr 155px;gap:10px;margin-bottom:11px;">
                        <div>
                            <label class="field-label">Target URL</label>
                            <input id="targetUrl" class="wavs-input" type="text" placeholder="https://example.com" value="http://localhost:8000">
                        </div>
                        <div>
                            <label class="field-label">Type</label>
                            <select id="targetType" class="wavs-input">
                                <option>Web Application</option>
                                <option>REST API</option>
                                <option>GraphQL</option>
                                <option>Laravel App</option>
                            </select>
                        </div>
                    </div>
                    <div style="display:flex;justify-content:flex-end;">
                        <button class="btn-primary" id="addTargetBtn" style="font-size:14px;padding:9px 18px;">
                            <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                            Add Target
                        </button>
                    </div>
                </div>

                <div class="card" style="padding:0;overflow:hidden;">
                    <div style="padding:13px 18px;border-bottom:1px solid var(--border);">
                        <span class="card-label" style="margin:0;">Active Targets</span>
                    </div>
                    <div id="targetsList">
                        <div class="list-row">
                            <div style="display:flex;align-items:center;gap:13px;">
                                <div class="target-dot"></div>
                                <div>
                                    <p style="font-family:'DM Mono',monospace;font-size:13px;font-weight:500;">http://localhost:8000</p>
                                    <p style="font-size:11px;color:var(--muted);margin-top:2px;">Laravel App · Default target</p>
                                </div>
                            </div>
                            <div style="display:flex;align-items:center;gap:8px;">
                                <span class="tag-active">active</span>
                                <button class="btn-ghost" id="scanDefaultTargetBtn" style="padding:5px 11px;font-size:14px;">Scan</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- ══════ AUTH VAULT ══════ -->
            <div id="authentication-tab" class="tab-content">

                <!-- Header -->
                <div class="section-header">
                    <div>
                        <div class="section-title" style="display:flex;align-items:center;gap:10px;">Auth Vault</div>
                        <p style="font-size:16px;color:white;margin-top:5px;max-width:520px;line-height:1.5;">Store session credentials so the scanner can reach <strong style="color:var(--neon);">authenticated routes</strong> — uncovering vulnerabilities only visible to logged-in users.</p>
                    </div>
                    <div style="display:flex;align-items:center;gap:7px;padding:6px 13px;background:rgba(var(--neon-rgb),.06);border:1px solid rgba(var(--neon-rgb),.18);border-radius:8px;">
                        <div style="width:6px;height:6px;border-radius:50%;background:var(--neon);box-shadow:0 0 6px var(--neon);"></div>
                        <span id="credCountLabel" style="font-size:14px;font-weight:700;color:var(--neon);font-family:'DM Mono',monospace;">0 stored</span>
                    </div>
                </div>

                <!-- How It Works Banner -->
                <div style="background:rgba(var(--blue-rgb),.05);border:1px solid rgba(var(--blue-rgb),.14);border-radius:13px;padding:15px 18px;margin-bottom:12px;">
                    <div style="display:flex;align-items:center;gap:7px;margin-bottom:10px;">
                        <span style="font-size:16px;font-weight:700;color:white;text-transform:uppercase;letter-spacing:.08em;">How It Works</span>
                    </div>
                    <div class="vault-how-grid">
                        <div class="vault-how-step">
                            <div class="vault-step-num">1</div>
                            <div class="vault-step-title">Log in to your app</div>
                            <div class="vault-step-body">Use a real browser to sign into the target application as a normal user.</div>
                        </div>
                        <div class="vault-how-step">
                            <div class="vault-step-num">2</div>
                            <div class="vault-step-title">Copy your credential</div>
                            <div class="vault-step-body">From DevTools → Application → Cookies, or the Network tab → Authorization header.</div>
                        </div>
                        <div class="vault-how-step">
                            <div class="vault-step-num">3</div>
                            <div class="vault-step-title">Save it here</div>
                            <div class="vault-step-body">VulnSight will attach it to every scan request, unlocking access to protected pages.</div>
                        </div>
                        <div class="vault-how-step">
                            <div class="vault-step-num">4</div>
                            <div class="vault-step-title">Run the scan</div>
                            <div class="vault-step-body">Authenticated vulnerabilities — IDOR, auth bypass, broken access control — are now reachable.</div>
                        </div>
                    </div>
                </div>

                <!-- Main grid: Form + Side notes -->
                <div style="display:grid;grid-template-columns:1fr 300px;gap:12px;margin-bottom:14px;">

                    <!-- Add Form -->
                    <div class="card" style="position:relative;overflow:hidden;">
                        <div style="position:absolute;top:-1px;left:10%;right:10%;height:1px;background:linear-gradient(90deg,transparent,var(--neon),transparent);opacity:.45;"></div>
                        <span class="card-label">Add Credential</span>

                        <div class="field">
                            <label class="field-label" style="font-size:16px;">Credential Label</label>
                            <input id="authLabel" class="wavs-input" type="text" placeholder="e.g. Admin Session, API Key – Prod">
                        </div>

                        <div class="field">
                            <label class="field-label" style="font-size:16px;">Auth Type</label>
                            <div class="auth-type-selector">
                                <button class="auth-type-btn active-cookie" data-type="cookie" id="authTypeCookie">
                                    <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>
                                    Cookie
                                </button>
                                <button class="auth-type-btn" data-type="bearer" id="authTypeBearer">
                                    <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                                    Bearer
                                </button>
                                <button class="auth-type-btn" data-type="basic" id="authTypeBasic">
                                    <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                                    Basic
                                </button>
                                <button class="auth-type-btn" data-type="oauth" id="authTypeOauth">
                                    <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M8.56 2.75c4.37 6.03 6.02 9.42 8.03 17.72m2.54-15.38c-3.72 4.35-8.94 5.66-16.88 5.85m19.5 1.9c-3.5-.93-6.63-.82-8.94 0-2.58.92-5.01 2.86-7.44 6.32"/></svg>
                                    OAuth 2.0
                                </button>
                            </div>
                            <div class="auth-hint-box" id="authHintBox">
                                💡 Paste a session cookie from DevTools → Application → Cookies after logging in to your target app.
                            </div>
                        </div>

                        <div id="authTokenField" class="field">
                            <label class="field-label" id="authTokenLabel" style="font-size:16px;">Cookie Value</label>
                            <input id="authPassword" class="wavs-input" type="password" placeholder="Paste cookie string…">
                        </div>

                        <div id="authBasicFields" style="display:none;">
                            <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;" class="field">
                                <div>
                                    <label class="field-label">Username</label>
                                    <input id="authUsername" class="wavs-input" type="text" placeholder="admin">
                                </div>
                                <div>
                                    <label class="field-label">Password</label>
                                    <input id="authBasicPass" class="wavs-input" type="password" placeholder="••••••••">
                                </div>
                            </div>
                        </div>

                        <button class="btn-primary" id="addCredentialsBtn" style="width:100%;justify-content:center;">
                            <svg width="13" height="13" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                            Save to Vault
                        </button>
                    </div>

                    <!-- Side notes -->
                    <div style="display:flex;flex-direction:column;gap:10px;">
                        <div style="background:rgba(245,158,11,.05);border:1px solid rgba(245,158,11,.18);border-radius:12px;padding:14px 16px;">
                            <div style="display:flex;align-items:center;gap:7px;margin-bottom:8px;">
                                <svg width="13" height="13" fill="none" stroke="var(--orange)" viewBox="0 0 24 24" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                                <span style="font-size:14px;font-weight:700;color:var(--orange);text-transform:uppercase;letter-spacing:.06em;">Security Note</span>
                            </div>
                            <p style="font-size:14px;color:white;line-height:1.6;">Credentials are stored <strong style="color:var(--orange);">locally in your browser</strong> and never transmitted to any external server. Only scan targets you own or have explicit permission to test.</p>
                        </div>

                        <div style="background:rgba(var(--neon-rgb),.04);border:1px solid rgba(var(--neon-rgb),.14);border-radius:12px;padding:14px 16px;">
                            <div style="display:flex;align-items:center;gap:7px;margin-bottom:8px;">
                                <svg width="13" height="13" fill="none" stroke="var(--neon)" viewBox="0 0 24 24" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                                <span style="font-size:14px;font-weight:700;color:var(--neon);text-transform:uppercase;letter-spacing:.06em;">Why Auth Matters</span>
                            </div>
                            <p style="font-size:14px;color:var(--white);line-height:1.6;">Up to <strong style="color:var(--neon);">70% of web vulnerabilities</strong> live behind authentication. Without a credential, the scanner only tests public pages — you'd miss IDOR, broken access control, and auth bypass flaws entirely.</p>
                        </div>
                    </div>
                </div>

                <!-- Stored Credentials -->
                <div class="card" style="padding:0;overflow:hidden;">
                    <div style="display:flex;align-items:center;justify-content:space-between;padding:13px 18px;border-bottom:1px solid var(--border);">
                        <span class="card-label" style="margin:0;">Stored Credentials</span>
                        <span style="font-size:11px;color:var(--muted);" id="credRevealHint">Click the eye icon to reveal a token</span>
                    </div>
                    <div id="sessionsList">
                        <div class="empty-state">
                            <div class="empty-icon">🔑</div>
                            No credentials saved yet.<br>
                            <span style="font-size:12px;">Add a session cookie or API token above to enable authenticated scanning.</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- ══════ CONFIGURATION ══════ -->
            <div id="configuration-tab" class="tab-content">
                <div class="section-header">
                    <div class="section-title">Scan Settings</div>
                    <button class="btn-primary" id="saveConfigBtn" style="font-size:14px;padding:9px 18px;">
                        <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5"><path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
                        Save Config
                    </button>
                </div>

                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
                    <div class="card">
                        <span class="card-label">Scan Intensity</span>
                        <div style="display:flex;flex-direction:column;gap:7px;">
                            <button class="int-card" data-intensity="passive" id="intensityPassive">
                                <div class="int-title">🔍 Passive</div>
                                <div class="int-desc">Observe only. No active probing — safe for live sites.</div>
                            </button>
                            <button class="int-card active" data-intensity="standard" id="intensityStandard">
                                <div class="int-title">⚡ Standard</div>
                                <div class="int-desc">Balanced scanning with common vulnerability payloads.</div>
                            </button>
                            <button class="int-card" data-intensity="aggressive" id="intensityAggressive">
                                <div class="int-title">🔥 Aggressive</div>
                                <div class="int-desc">Full exploit coverage. Test environments only.</div>
                            </button>
                        </div>
                    </div>

                    <div style="display:flex;flex-direction:column;gap:12px;">
                        <div class="card">
                            <span class="card-label">Advanced Settings</span>
                            <div style="display:grid;gap:11px;">
                                <div>
                                    <label class="field-label" style="font-size:16px;">Max Requests / sec</label>
                                    <input id="cfgMaxRps" class="wavs-input" type="number" value="100">
                                </div>
                                <div>
                                    <label class="field-label" style="font-size:16px;">Request Timeout (s)</label>
                                    <input id="cfgTimeout" class="wavs-input" type="number" value="30">
                                </div>
                                <div>
                                    <label class="field-label" style="font-size:16px;">Crawl Depth</label>
                                    <input id="cfgDepth" class="wavs-input" type="number" value="5">
                                </div>
                            </div>
                        </div>

                        <div class="card">
                            <span class="card-label">Options</span>
                            <div style="display:flex;flex-direction:column;gap:13px;">
                                <label style="display:flex;align-items:center;justify-content:space-between;cursor:pointer;">
                                    <div>
                                        <p style="font-size:16px;font-weight:600;">Follow Redirects</p>
                                        <p style="font-size:14px;color:white;margin-top:2px;">Track 301/302 chains</p>
                                    </div>
                                    <label class="toggle"><input type="checkbox" id="cfgRedirects" checked><div class="toggle-slider"></div></label>
                                </label>
                                <div class="divider" style="margin:0;"></div>
                                <label style="display:flex;align-items:center;justify-content:space-between;cursor:pointer;">
                                    <div>
                                        <p style="font-size:16px;font-weight:600;">JS Execution</p>
                                        <p style="font-size:14px;color:white;margin-top:2px;">Headless browser crawling</p>
                                    </div>
                                    <label class="toggle"><input type="checkbox" id="cfgJsExec" checked><div class="toggle-slider"></div></label>
                                </label>
                                <div class="divider" style="margin:0;"></div>
                                <label style="display:flex;align-items:center;justify-content:space-between;cursor:pointer;">
                                    <div>
                                        <p style="font-size:16px;font-weight:600;">Auto-Export Report</p>
                                        <p style="font-size:14px;color:white;margin-top:2px;">Download CSV when scan ends</p>
                                    </div>
                                    <label class="toggle"><input type="checkbox" id="autoExport"><div class="toggle-slider"></div></label>
                                </label>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="card" style="margin-top:12px;">
                    <span class="card-label">Exclusion Rules</span>
                    <div style="display:flex;gap:8px;margin-bottom:11px;">
                        <input id="exclusionInput" class="wavs-input" type="text" placeholder="/logout, /admin/delete" style="flex:1;">
                        <button class="btn-ghost" id="addExclusionBtn" style="padding:9px 15px;font-size:16px;white-space:nowrap;color:white;">Add Rule</button>
                    </div>
                    <div id="exclusionTags" style="display:flex;flex-wrap:wrap;gap:6px;"></div>
                </div>
            </div>

        </div><!-- /content -->
    </div>

<!-- ══════════════════════════════════════
     SCAN HISTORY DRAWER
══════════════════════════════════════ -->
<div class="drawer-overlay" id="drawerOverlay"></div>
<div id="scanHistoryDrawer">
    <div class="drawer-head">
        <svg width="18" height="18" fill="none" stroke="var(--neon)" viewBox="0 0 24 24" stroke-width="1.8">
            <path d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
        </svg>
        <span class="drawer-title" style="font-size: 16px;">Scan History</span>
        <span style="font-size:14px;color:white;font-family:'DM Mono',monospace;" id="drawerScanCount">0 scans</span>
        <button class="drawer-close" id="drawerCloseBtn">&#215;</button>
    </div>
    <div class="drawer-body" id="scanHistoryList">
        <div class="drawer-empty">
            <div class="de-icon">📋</div>
            <p>No scans recorded yet.</p>
            <p style="margin-top:6px;font-size:11px;">Run your first scan and it will appear here automatically.</p>
        </div>
    </div>
</div>

</div><!-- /mainApp -->

<!-- ══════════════════════════════════════
     VULN MODAL
══════════════════════════════════════ -->
<div id="vulnModal" style="display:none;position:fixed;inset:0;z-index:2000;background:rgba(2,5,8,.92);backdrop-filter:blur(14px);align-items:center;justify-content:center;opacity:0;transition:opacity .2s;">
    <div class="modal-box">
        <div class="modal-head">
            <div style="display:flex;align-items:center;gap:12px;">
                <div id="vdIcon" style="width:36px;height:36px;border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0;">
                    <svg width="17" height="17" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                </div>
                <div>
                    <p id="vdName" style="font-size:15px;font-weight:700;letter-spacing:-.02em;"></p>
                    <div style="display:flex;align-items:center;gap:8px;margin-top:4px;">
                        <span id="vdBadge" class="badge"></span>
                        <span id="vdCve" style="font-family:'DM Mono',monospace;font-size:10px;color:var(--muted);"></span>
                    </div>
                </div>
            </div>
            <button id="closeVulnModalBtn" class="btn-icon">&times;</button>
        </div>
        <div class="modal-body">
            <div style="margin-bottom:15px;">
                <span style="font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;display:block;margin-bottom:6px;">Affected Endpoint</span>
                <code id="vdUrl" style="font-size:12px;color:var(--neon);background:rgba(var(--neon-rgb),.05);border:1px solid rgba(var(--neon-rgb),.12);padding:8px 11px;border-radius:8px;display:block;word-break:break-all;font-family:'DM Mono',monospace;"></code>
            </div>
            <div style="margin-bottom:15px;">
                <span style="font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;display:block;margin-bottom:6px;">What Was Found</span>
                <p id="vdSummary" style="font-size:13px;line-height:1.65;color:var(--text);background:var(--surface2);border:1px solid var(--border);padding:12px 14px;border-radius:10px;"></p>
            </div>
            <div style="margin-bottom:15px;">
                <span style="font-size:10px;font-weight:700;color:var(--neon);text-transform:uppercase;letter-spacing:.08em;display:flex;align-items:center;gap:5px;margin-bottom:9px;">
                    <svg width="11" height="11" fill="none" stroke="var(--neon)" viewBox="0 0 24 24" stroke-width="2.5"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                    Recommended Fixes
                </span>
                <ol id="vdSteps" style="list-style:none;display:flex;flex-direction:column;gap:6px;padding:0;margin:0;"></ol>
            </div>
            <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 13px;background:rgba(var(--blue-rgb),.06);border:1px solid rgba(var(--blue-rgb),.15);border-radius:9px;">
                <span style="font-size:11px;color:#93c5fd;font-weight:600;">OWASP Reference</span>
                <a id="vdRef" href="#" target="_blank" rel="noopener" style="font-size:11px;font-family:'DM Mono',monospace;color:var(--neon);text-decoration:none;">View →</a>
            </div>
        </div>
    </div>
</div>

<div id="toast"></div>

@verbatim
@endverbatim

{{-- wavs.js must load first (no defer) so its functions exist when listeners are bound --}}
<script src="{{ asset('js/wavs.js') }}" nonce="{{ csp_nonce() }}"></script>


</body>
</html>
