<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='2 2 20 20' fill='none' stroke='%2300f5c4' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z'/></svg>">
    <meta name="csp-nonce" content="{{ csp_nonce() }}">
    <title>VulnSight — Admin Panel</title>

    @vite(['resources/css/app.css', 'resources/js/app.js'])
    <style nonce="{{ csp_nonce() }}">
        @font-face {
    font-family: 'DM Sans';
    src: url('/fonts/DM-Sans-400.woff2') format('woff2');
    font-weight: 400;
    font-display: swap;
}
@font-face {
    font-family: 'DM Mono';
    src: url('/fonts/DM-Mono-400.woff2') format('woff2');
    font-weight: 400;
    font-display: swap;
}
        /* ═══════════════ TOKENS ═══════════════ */
        :root {
            --neon:       #00f5c4;
            --neon-rgb:   0,245,196;
            --blue:       #3b82f6;
            --blue-rgb:   59,130,246;
            --bg:         #020508;
            --bg2:        #050c14;
            --surface:    #0a1628;
            --surface2:   #0f1f35;
            --surface3:   #152642;
            --border:     rgba(255,255,255,.06);
            --border-h:   rgba(255,255,255,.1);
            --text:       #c8dae8;
            --text2:      #6b8fa8;
            --muted:      #374e62;
            --red:        #f05050;
            --orange:     #f59e0b;
            --yellow:     #fde047;
            --green:      #00f5c4;
            --purple:     #a78bfa;
            --pink:       #f472b6;
            --sw:         236px;
        }

        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        html { font-size: 14px; scroll-behavior: smooth; }
        body {
            font-family: 'DM Sans', system-ui, sans-serif;
            background: var(--bg); color: var(--text);
            min-height: 100vh; overflow-x: hidden;
            -webkit-font-smoothing: antialiased;
        }

        /* Atmospheric glow */
        body::before {
            content: ''; position: fixed;
            width: 900px; height: 600px; top: -200px; left: -300px;
            background: radial-gradient(ellipse at center,
                rgba(0,245,196,.035) 0%, rgba(59,130,246,.02) 50%, transparent 70%);
            pointer-events: none; z-index: 0; filter: blur(40px);
        }
        /* Dot grid */
        body::after {
            content: ''; position: fixed; inset: 0;
            pointer-events: none; z-index: 0;
            background-image: radial-gradient(circle, rgba(255,255,255,.035) 1px, transparent 1px);
            background-size: 32px 32px;
        }

        ::-webkit-scrollbar { width: 3px; height: 3px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: var(--surface3); border-radius: 3px; }

        /* ═══════════════ SIDEBAR ═══════════════ */
        #sidebar {
            position: fixed; left: 0; top: 0; bottom: 0; width: var(--sw);
            background: linear-gradient(180deg, var(--bg2) 0%, var(--bg) 100%);
            border-right: 1px solid var(--border);
            display: flex; flex-direction: column; z-index: 100;
        }
        .sidebar-header {
            padding: 18px 14px 15px; border-bottom: 1px solid var(--border);
            display: flex; align-items: center; gap: 10px;
        }
        .logo-icon {
            width: 40px; height: 40px; flex-shrink: 0;
            background: linear-gradient(140deg, rgba(0,245,196,.2), rgba(59,130,246,.2));
            border: 1px solid rgba(0,245,196,.25); border-radius: 8px;
            display: flex; align-items: center; justify-content: center;
            box-shadow: 0 0 12px rgba(var(--neon-rgb),.15);
        }
        .logo-text {
            font-size: 22px; font-weight: 700; letter-spacing: -.03em;
            background: linear-gradient(135deg, #fff 20%, var(--neon) 100%);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }
        .logo-badge {
            font-size: 9px; font-weight: 700; letter-spacing: .08em;
            text-transform: uppercase; color: var(--orange);
            background: rgba(245,158,11,.1); border: 1px solid rgba(245,158,11,.2);
            padding: 2px 6px; border-radius: 4px; margin-left: auto; flex-shrink: 0;
        }

        .nav-section { padding: 10px 8px 0; }
        .nav-label {
            font-size: 12px; font-weight: 600; letter-spacing: .1em;
            color: white; text-transform: uppercase; padding: 0 8px;
            margin-bottom: 3px; display: block;
        }
        .nav-item {
            display: flex; align-items: center; gap: 9px;
            padding: 8px 10px; border-radius: 9px; cursor: pointer;
            color: white; font-size: 16px; font-weight: 500;
            transition: all .14s; margin-bottom: 1px;
            border: 1px solid transparent; user-select: none; position: relative;
        }
        .nav-item svg { opacity: .5; flex-shrink: 0; transition: opacity .14s; }
        .nav-item:hover { background: var(--surface2); color: var(--text2); border-color: var(--border); }
        .nav-item:hover svg { opacity: .85; }
        .nav-item.active {
            background: rgba(var(--neon-rgb),.07);
            border-color: rgba(var(--neon-rgb),.15); color: var(--neon);
        }
        .nav-item.active svg { opacity: 1; }
        .nav-badge {
            margin-left: auto; font-size: 10px; font-weight: 700;
            padding: 1px 6px; border-radius: 10px; min-width: 18px; text-align: center;
            font-family: 'DM Mono', monospace;
        }
        .nav-badge.red    { background: var(--red);    color: #fff; }
        .nav-badge.orange { background: var(--orange); color: #000; }
        .nav-badge.neon   { background: rgba(var(--neon-rgb),.15); color: var(--neon); border: 1px solid rgba(var(--neon-rgb),.25); }

        .sidebar-footer { margin-top: auto; padding: 10px; border-top: 1px solid var(--border); }
        .user-chip {
            display: flex; align-items: center; gap: 9px; padding: 8px 10px;
            background: var(--surface); border-radius: 10px; cursor: pointer;
            border: 1px solid var(--border); transition: all .15s;
        }
        .user-chip:hover { border-color: var(--border-h); background: var(--surface2); }
        .user-avatar {
            width: 28px; height: 28px; border-radius: 50%; flex-shrink: 0;
            background: linear-gradient(135deg, var(--orange), var(--red));
            display: flex; align-items: center; justify-content: center;
            font-size: 11px; font-weight: 700; color: #fff;
        }
        .user-name { font-size: 12px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .user-sub  { font-size: 10px; color: var(--muted); margin-top: 1px; }

        /* ═══════════════ MAIN ═══════════════ */
        #mainContent { margin-left: var(--sw); min-height: 100vh; display: flex; flex-direction: column; position: relative; z-index: 1; }

        .topbar {
            height: 52px; border-bottom: 1px solid var(--border);
            background: rgba(2,5,8,.92); backdrop-filter: blur(24px);
            display: flex; align-items: center; padding: 0 22px; gap: 10px;
            position: sticky; top: 0; z-index: 50;
        }
        .topbar-title { font-weight: 700; font-size: 18px; flex: 1; letter-spacing: -.02em; }
        .topbar-title span { color: white; font-weight: 400; margin-right: 6px; }

        .sys-status {
            display: flex; align-items: center; gap: 6px; padding: 4px 12px;
            background: rgba(0,245,196,.05); border: 1px solid rgba(0,245,196,.14);
            border-radius: 20px; font-size: 12px; font-weight: 600;
            font-family: 'DM Mono', monospace; color: var(--neon); flex-shrink: 0;
        }
        .sys-dot {
            width: 6px; height: 6px; border-radius: 50%;
            background: var(--neon); box-shadow: 0 0 6px var(--neon);
            animation: throb 2s ease-in-out infinite;
        }
        @keyframes throb { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.4;transform:scale(.75)} }

        .content { padding: 22px; flex: 1; }
        .tab-content { display: none; }
        .tab-content.active { display: block; animation: appear .22s ease; }
        @keyframes appear { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:translateY(0)} }

        /* ═══════════════ SECTION HEADER ═══════════════ */
        .section-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; }
        .section-title { font-size: 22px; font-weight: 700; letter-spacing: -.04em; }
        .section-sub { font-size: 14px; color: white; margin-top: 3px; }

        /* ═══════════════ CARDS ═══════════════ */
        .card {
            background: var(--surface); border: 1px solid var(--border);
            border-radius: 14px; padding: 18px 20px;
        }
        .card-label {
            font-size: 14px; font-weight: 700; letter-spacing: .1em;
            text-transform: uppercase; color: white;
            margin-bottom: 14px; display: flex; align-items: center; gap: 6px;
        }
        .card-label::after { content: ''; flex: 1; height: 1px; background: var(--border); }

        /* ═══════════════ STAT CARDS ═══════════════ */
        .stat-grid { display: grid; grid-template-columns: repeat(4,1fr); gap: 10px; margin-bottom: 14px; }
        .stat-card {
            background: var(--surface); border: 1px solid var(--border);
            border-radius: 14px; padding: 16px 18px;
            position: relative; overflow: hidden;
            transition: border-color .2s, transform .18s;
        }
        .stat-card:hover { border-color: var(--border-h); transform: translateY(-1px); }
        .stat-card-bar { position: absolute; top: 0; left: 0; right: 0; height: 2px; background: var(--clr, var(--neon)); opacity: .55; }
        .stat-num { font-family: 'DM Mono', monospace; font-size: 27px; font-weight: 500; line-height: 1.1; margin-bottom: 4px; color: var(--clr, var(--text)); }
        .stat-lbl { font-size: 14px; color: white; font-weight: 500; }
        .stat-delta {
            position: absolute; top: 13px; right: 13px;
            font-family: 'DM Mono', monospace; font-size: 12px; color: var(--clr, var(--neon));
            background: rgba(var(--clr-rgb, var(--neon-rgb)),.08);
            border: 1px solid rgba(var(--clr-rgb, var(--neon-rgb)),.16);
            padding: 2px 7px; border-radius: 20px;
        }

        /* ═══════════════ BUTTONS ═══════════════ */
        .btn-primary {
            background: linear-gradient(135deg, rgba(var(--neon-rgb),.9), rgba(var(--blue-rgb),.9));
            color: #000; font-family: 'DM Sans', sans-serif; font-weight: 700; font-size: 13px;
            padding: 9px 18px; border-radius: 10px; border: none; cursor: pointer;
            transition: all .18s; display: inline-flex; align-items: center; gap: 7px;
            box-shadow: 0 2px 12px rgba(var(--neon-rgb),.18); white-space: nowrap;
        }
        .btn-primary:hover { filter: brightness(1.08); transform: translateY(-1px); box-shadow: 0 6px 24px rgba(var(--neon-rgb),.28); }
        .btn-ghost {
            background: transparent; color: var(--text2); font-family: 'DM Sans', sans-serif;
            font-weight: 500; font-size: 13px; padding: 8px 14px; border-radius: 9px;
            border: 1px solid var(--border); cursor: pointer; transition: all .15s;
            display: inline-flex; align-items: center; gap: 7px; white-space: nowrap;
        }
        .btn-ghost:hover { border-color: var(--border-h); color: var(--text); background: var(--surface2); }
        .btn-danger {
            background: rgba(240,80,80,.08); color: var(--red); border: 1px solid rgba(240,80,80,.2);
            border-radius: 8px; padding: 6px 12px; font-size: 12px;
            font-family: 'DM Sans', sans-serif; font-weight: 600; cursor: pointer; transition: all .15s;
            display: inline-flex; align-items: center; gap: 5px;
        }
        .btn-danger:hover { background: rgba(240,80,80,.15); }
        .btn-warn {
            background: rgba(245,158,11,.08); color: var(--orange); border: 1px solid rgba(245,158,11,.2);
            border-radius: 8px; padding: 6px 12px; font-size: 12px;
            font-family: 'DM Sans', sans-serif; font-weight: 600; cursor: pointer; transition: all .15s;
            display: inline-flex; align-items: center; gap: 5px;
        }
        .btn-warn:hover { background: rgba(245,158,11,.15); }
        .btn-sm {
            padding: 5px 11px; font-size: 11px; border-radius: 7px;
        }

        /* ═══════════════ BADGES ═══════════════ */
        .badge {
            display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 20px;
            font-size: 12px; font-weight: 600; font-family: 'DM Mono', monospace;
            text-transform: uppercase; letter-spacing: .04em;
        }
        .badge-critical { background: rgba(240,80,80,.12);  color: #ff7070; border: 1px solid rgba(240,80,80,.25); }
        .badge-high     { background: rgba(245,158,11,.11); color: #fbbf24; border: 1px solid rgba(245,158,11,.25); }
        .badge-medium   { background: rgba(253,224,71,.09); color: #fde047; border: 1px solid rgba(253,224,71,.2); }
        .badge-low      { background: rgba(0,245,196,.09);  color: var(--neon); border: 1px solid rgba(0,245,196,.2); }
        .badge-admin    { background: rgba(245,158,11,.1);  color: var(--orange); border: 1px solid rgba(245,158,11,.2); }
        .badge-user     { background: rgba(59,130,246,.1);  color: #60a5fa; border: 1px solid rgba(59,130,246,.2); }
        .badge-active   { background: rgba(0,245,196,.1);   color: var(--neon); border: 1px solid rgba(0,245,196,.2); }
        .badge-inactive { background: rgba(55,78,98,.2);    color: var(--muted); border: 1px solid rgba(55,78,98,.3); }
        .badge-banned   { background: rgba(240,80,80,.1);   color: var(--red); border: 1px solid rgba(240,80,80,.2); }
        .badge-running  { background: rgba(0,245,196,.08);  color: var(--neon); border: 1px solid rgba(0,245,196,.18); }
        .badge-completed{ background: rgba(59,130,246,.1);  color: #60a5fa; border: 1px solid rgba(59,130,246,.2); }
        .badge-failed   { background: rgba(240,80,80,.1);   color: var(--red); border: 1px solid rgba(240,80,80,.2); }
        .badge-purple   { background: rgba(167,139,250,.1); color: var(--purple); border: 1px solid rgba(167,139,250,.2); }

        /* ═══════════════ TABLE ═══════════════ */
        .wavs-table { width: 100%; border-collapse: collapse; }
        .wavs-table th {
            text-align: left; padding: 9px 16px; font-size: 14px; font-weight: 700;
            text-transform: uppercase; letter-spacing: .08em; color: white;
            border-bottom: 1px solid var(--border);
        }
        .wavs-table td { padding: 12px 16px; font-size: 13px; border-bottom: 1px solid rgba(255,255,255,.03); vertical-align: middle; }
        .wavs-table tr:hover td { background: rgba(var(--neon-rgb),.012); }
        .wavs-table tr:last-child td { border-bottom: none; }

        /* ═══════════════ FORM FIELDS ═══════════════ */
        .field { margin-bottom: 14px; }
        .field-label {
            display: block; font-size: 14px; font-weight: 600; color: white;
            margin-bottom: 5px; text-transform: uppercase; letter-spacing: .07em;
        }
        .wavs-input {
            width: 100%; background: var(--bg2); border: 1px solid var(--border);
            border-radius: 10px; padding: 10px 13px; color: var(--text);
            font-family: 'DM Mono', monospace; font-size: 14px; outline: none;
            transition: border-color .15s, box-shadow .15s; appearance: none;
        }
        .wavs-input:focus { border-color: rgba(var(--neon-rgb),.3); box-shadow: 0 0 0 3px rgba(var(--neon-rgb),.06); }
        .wavs-input::placeholder { color: white; }
        .wavs-input:hover:not(:focus) { border-color: var(--border-h); }
        select.wavs-input { cursor: pointer; }

        /* ═══════════════ TOGGLE ═══════════════ */
        .toggle { position: relative; width: 38px; height: 21px; flex-shrink: 0; }
        .toggle input { opacity: 0; width: 0; height: 0; }
        .toggle-slider {
            position: absolute; inset: 0; border-radius: 21px;
            background: var(--surface2); border: 1px solid var(--border);
            cursor: pointer; transition: .2s;
        }
        .toggle-slider::before {
            content: ''; position: absolute; height: 15px; width: 15px;
            left: 2px; top: 2px; border-radius: 50%; background: white; transition: .2s;
        }
        .toggle input:checked + .toggle-slider { background: rgba(var(--neon-rgb),.15); border-color: var(--neon); }
        .toggle input:checked + .toggle-slider::before { transform: translateX(17px); background: var(--neon); }

        /* ═══════════════ PROGRESS BAR ═══════════════ */
        .prog-track { background: var(--surface2); border-radius: 99px; height: 4px; overflow: hidden; }
        .prog-bar { height: 100%; border-radius: 99px; background: linear-gradient(90deg, var(--neon), var(--blue)); transition: width .4s; }

        /* ═══════════════ HEALTH METRICS ═══════════════ */
        .health-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
        .health-card {
            background: var(--surface2); border: 1px solid var(--border);
            border-radius: 12px; padding: 14px 16px; transition: border-color .18s;
        }
        .health-card:hover { border-color: var(--border-h); }
        .health-val { font-family: 'DM Mono', monospace; font-size: 22px; font-weight: 500; margin-bottom: 3px; }
        .health-lbl { font-size: 14px; color: white; font-weight: 500; }
        .health-bar-wrap { margin-top: 9px; }

        .scan-row:hover { background: rgba(var(--neon-rgb),.012); }

        /* ═══════════════ LIST ROW ═══════════════ */
        .list-row {
            display: flex; align-items: center; justify-content: space-between;
            padding: 12px 18px; border-bottom: 1px solid rgba(255,255,255,.03);
            transition: background .1s;
        }
        .list-row:hover { background: rgba(var(--neon-rgb),.012); }
        .list-row:last-child { border-bottom: none; }

        /* ═══════════════ USER AVATAR ═══════════════ */
        .u-avatar {
            width: 30px; height: 30px; border-radius: 50%; flex-shrink: 0;
            display: flex; align-items: center; justify-content: center;
            font-size: 11px; font-weight: 700; color: #000;
        }

        /* ═══════════════ AUDIT LOG ═══════════════ */
        .audit-row {
            display: flex; gap: 0; padding: 8px 18px;
            border-bottom: 1px solid rgba(255,255,255,.025);
            transition: background .1s; align-items: baseline;
        }
        .audit-row:hover { background: rgba(var(--neon-rgb),.012); }
        .audit-row:last-child { border-bottom: none; }
        .audit-ts    { font-family: 'DM Mono', monospace; font-size: 14px; color: white; width: 148px; flex-shrink: 0; }
        .audit-actor { font-size: 14px; font-weight: 600; color: var(--neon); width: 200px; min-width: 200px; flex-shrink: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.audit-action{ font-size: 14px; color: var(--text); flex: 1; min-width: 0; padding-left: 16px; }
        .audit-sev   { flex-shrink: 0; margin-left: 10px; }

        /* ═══════════════ MODAL ═══════════════ */
        .modal-overlay {
            display: none; position: fixed; inset: 0; z-index: 2000;
            background: rgba(2,5,8,.88); backdrop-filter: blur(14px);
            align-items: center; justify-content: center;
            opacity: 0; transition: opacity .2s;
        }
        .modal-box {
            width: 480px; max-width: 95vw;
            background: var(--surface); border: 1px solid var(--border-h);
            border-radius: 18px; overflow: hidden;
            box-shadow: 0 40px 120px rgba(0,0,0,.7), 0 0 0 1px rgba(var(--neon-rgb),.06);
            position: relative;
        }
        .modal-box::before {
            content: ''; position: absolute; top: -1px; left: 20%; right: 20%; height: 1px;
            background: linear-gradient(90deg, transparent, var(--neon), transparent);
        }
        .modal-head {
            display: flex; align-items: center; justify-content: space-between;
            padding: 16px 20px; border-bottom: 1px solid var(--border);
        }
        .modal-body { padding: 20px; }
        .modal-foot {
            display: flex; justify-content: flex-end; gap: 8px;
            padding: 14px 20px; border-top: 1px solid var(--border);
        }

        /* ═══════════════ EMPTY STATE ═══════════════ */
        .empty-state { padding: 44px; text-align: center; color: white; font-size: 14px; line-height: 1.7; }
        .empty-icon { font-size: 30px; margin-bottom: 8px; opacity: .4; }

        /* ═══════════════ SEARCH BAR ═══════════════ */
        .search-wrap { position: relative; }
        .search-wrap svg { position: absolute; left: 11px; top: 50%; transform: translateY(-50%); color: var(--muted); pointer-events: none; }
        .search-wrap .wavs-input { padding-left: 34px; }

        /* ═══════════════ INFO NOTE ═══════════════ */
        .info-note {
            padding: 10px 13px; border-radius: 9px;
            display: flex; align-items: flex-start; gap: 9px;
        }
        .info-note.blue { background: rgba(var(--blue-rgb),.06); border: 1px solid rgba(var(--blue-rgb),.15); }
        .info-note.orange { background: rgba(245,158,11,.06); border: 1px solid rgba(245,158,11,.15); }
        .info-note.red  { background: rgba(240,80,80,.06); border: 1px solid rgba(240,80,80,.15); }

        /* ═══════════════ TOAST ═══════════════ */
        #toast {
            position: fixed; bottom: 20px; right: 20px; padding: 10px 14px;
            border-radius: 12px; font-size: 13px; font-weight: 600;
            font-family: 'DM Sans', sans-serif; z-index: 9999;
            transform: translateY(60px); opacity: 0;
            transition: all .28s cubic-bezier(.34,1.56,.64,1);
            display: flex; align-items: center; gap: 8px;
            max-width: 300px; backdrop-filter: blur(20px); box-shadow: 0 8px 32px rgba(0,0,0,.4);
        }
        #toast.show    { transform: translateY(0); opacity: 1; }
        #toast.success { background: rgba(0,245,196,.1); border: 1px solid rgba(0,245,196,.25); color: var(--neon); }
        #toast.info    { background: rgba(59,130,246,.1); border: 1px solid rgba(59,130,246,.25); color: #93c5fd; }
        #toast.warn    { background: rgba(245,158,11,.1); border: 1px solid rgba(245,158,11,.25); color: var(--orange); }
        #toast.error   { background: rgba(240,80,80,.1);  border: 1px solid rgba(240,80,80,.25);  color: var(--red); }

        /* ═══════════════ SPARKLINE ═══════════════ */
        .sparkline { display: flex; align-items: flex-end; gap: 2px; height: 28px; }
        .spark-bar { width: 5px; border-radius: 2px; background: rgba(var(--neon-rgb),.3); transition: background .2s; }
        .spark-bar:hover { background: var(--neon); }

        /* ═══════════════ PLAN BADGE ═══════════════ */
        .plan-free { background: rgba(55,78,98,.25); color: var(--text2); border: 1px solid rgba(55,78,98,.4); }
        .plan-pro  { background: rgba(59,130,246,.1); color: #60a5fa; border: 1px solid rgba(59,130,246,.2); }
        .plan-ent  { background: rgba(245,158,11,.1); color: var(--orange); border: 1px solid rgba(245,158,11,.2); }

        /* ═══════════════ PERMISSION CHIP ═══════════════ */
        .perm-chip {
            display: inline-flex; align-items: center; gap: 4px;
            padding: 2px 8px; border-radius: 6px; font-size: 10px;
            font-family: 'DM Mono', monospace; font-weight: 600;
            background: var(--surface2); border: 1px solid var(--border); color: var(--text2);
            text-transform: uppercase; letter-spacing: .04em;
        }

        /* ═══════════════ DIVIDER ═══════════════ */
        .divider { height: 1px; background: var(--border); margin: 12px 0; }

        /* ═══════════════ ANIMATIONS ═══════════════ */
        @keyframes fadeUp { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:translateY(0)} }
        .fade-up { animation: fadeUp .3s ease both; }
        .delay-1 { animation-delay: .05s; }
        .delay-2 { animation-delay: .1s; }
        .delay-3 { animation-delay: .15s; }
        .delay-4 { animation-delay: .2s; }

        /* ═══════════════ HAMBURGER + SIDEBAR COLLAPSE ═══════════════ */
        #sidebar { transition: width .28s cubic-bezier(.22,1,.36,1); }
        #sidebar.collapsed { width: 54px; }
        #sidebar.collapsed .sidebar-header { justify-content: center; padding: 18px 0 15px; cursor: pointer; }
        #sidebar.collapsed .sidebar-hamburger-btn { display: none !important; }
        #sidebar.collapsed .logo-text,
        #sidebar.collapsed .logo-badge { display: none !important; }
        #sidebar.collapsed .logo-icon { cursor: pointer; }
        #sidebar.collapsed .nav-section { padding-left: 4px; padding-right: 4px; }
        #sidebar.collapsed .nav-item { justify-content: center; padding: 10px 0; gap: 0; font-size: 0; }
        #sidebar.collapsed .nav-item svg { width: 20px; height: 20px; min-width: 20px; opacity: 0.75; }
        #sidebar.collapsed .nav-item.active svg { opacity: 1; }
        #sidebar.collapsed .nav-label,
        #sidebar.collapsed .nav-badge { display: none !important; }
        #sidebar.collapsed .user-chip { justify-content: center; padding: 8px; gap: 0; }
        #sidebar.collapsed .user-name,
        #sidebar.collapsed .user-sub,
        #sidebar.collapsed .user-chip > svg { display: none !important; }
        #sidebar.collapsed .user-avatar { flex-shrink: 0; width: 28px; height: 28px; min-width: 28px; }
        #sidebar.collapsed .sidebar-footer { padding: 10px 4px; }
        #sidebar.collapsed .btn-ghost.back-btn { display: none !important; }

        /* Tooltip when collapsed */
        #sidebar.collapsed [data-tooltip] { position: relative; }
        #sidebar.collapsed [data-tooltip]:hover::after {
            content: attr(data-tooltip);
            position: absolute; left: calc(100% + 12px); top: 50%; transform: translateY(-50%);
            background: var(--surface3); border: 1px solid var(--border-h); color: var(--text);
            font-size: 12px; font-weight: 600; padding: 5px 10px; border-radius: 7px;
            white-space: nowrap; z-index: 600; pointer-events: none;
            box-shadow: 0 4px 16px rgba(0,0,0,.45); font-family: 'DM Sans', sans-serif;
        }

        /* Main content follows sidebar */
        #mainContent { transition: margin-left .28s cubic-bezier(.22,1,.36,1); }
        #sidebar.collapsed ~ #mainContent { margin-left: 54px; }

        /* Hamburger button */
        .sidebar-hamburger-btn {
            display: flex; align-items: center; justify-content: center;
            background: none; border: none; cursor: pointer; padding: 6px;
            border-radius: 7px; color: var(--text2);
            transition: background .15s, color .15s;
            margin-left: auto; flex-shrink: 0;
        }
        .sidebar-hamburger-btn:hover { background: var(--surface2); color: var(--text); }
        .hbg-icon { display: flex; flex-direction: column; gap: 4px; width: 17px; flex-shrink: 0; }
        .hbg-icon span {
            display: block; height: 2px; border-radius: 2px; background: currentColor;
            transform-origin: center;
            transition: transform .25s cubic-bezier(.22,1,.36,1), opacity .2s, width .25s cubic-bezier(.22,1,.36,1);
        }
        .hbg-icon span:nth-child(1) { width: 17px; }
        .hbg-icon span:nth-child(2) { width: 11px; }
        .hbg-icon span:nth-child(3) { width: 17px; }
        #sidebar.collapsed .hbg-icon span:nth-child(1) { transform: translateY(6px) rotate(45deg); width: 17px; }
        #sidebar.collapsed .hbg-icon span:nth-child(2) { opacity: 0; width: 0; }
        #sidebar.collapsed .hbg-icon span:nth-child(3) { transform: translateY(-6px) rotate(-45deg); width: 17px; }

        @media (max-width: 820px) {
            #sidebar { display: none !important; }
            #mainContent { margin-left: 0 !important; }
        }

        /* ══════════════════════════════════════
           TOP NAV — UpTimeBot-matched theme
        ══════════════════════════════════════ */
        #sidebar { display: none !important; }
        #mainContent { margin-left: 0 !important; }
        :root { --sw: 0px !important; }
        body { background: #030712 !important; }

        #topNav {
            display: flex; align-items: center;
            height: 52px; padding: 0 16px;
            background: #111827; border-bottom: 1px solid #1f2937;
            flex-shrink: 0; gap: 8px;
            position: sticky; top: 0; z-index: 100;
        }
        .tn-brand {
            display: flex; align-items: center; gap: 6px;
            flex-shrink: 0; padding-right: 14px;
            border-right: 1px solid #1f2937; margin-right: 4px;
        }
        .tn-links {
            display: flex; align-items: center; gap: 2px;
            flex: 1; overflow-x: auto; scrollbar-width: none;
        }
        .tn-links::-webkit-scrollbar { display: none; }
        .tn-item {
            display: flex; align-items: center; gap: 7px;
            padding: 6px 12px; border-radius: 8px;
            font-size: 13px; font-weight: 500; color: #6b7280;
            cursor: pointer; white-space: nowrap;
            transition: color .15s, background .15s;
            border: none; background: transparent;
        }
        .tn-item:hover { color: #f9fafb; background: #1f2937; }
        .tn-item.active { color: #f9fafb; background: #1f2937; }
        .tn-item svg { opacity: .6; flex-shrink: 0; }
        .tn-item.active svg { opacity: 1; }
        .tn-badge {
            font-size: 10px; font-weight: 700;
            padding: 1px 6px; border-radius: 99px;
            min-width: 16px; text-align: center;
        }
        .tn-badge.neon   { background: rgba(0,245,196,.15); color: #00f5c4; border: 1px solid rgba(0,245,196,.3); }
        .tn-badge.orange { background: rgba(245,158,11,.15); color: #f59e0b; border: 1px solid rgba(245,158,11,.3); }
        .tn-badge.red    { background: rgba(239,68,68,.15);  color: #ef4444; border: 1px solid rgba(239,68,68,.3); }
        .tn-actions { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }

        #mainContent { display: flex; flex-direction: column; min-height: calc(100vh - 52px); background: #030712; }
        .content { padding: 20px 24px; background: #030712; }
        .card, .stat-card { background: #111827 !important; border: 1px solid #1f2937 !important; border-radius: 12px !important; }
        .section-title { font-size: 18px; font-weight: 700; color: #f9fafb; letter-spacing: -.02em; }
        .wavs-table th { background: #111827; color: #6b7280; font-size: 11px; border-bottom: 1px solid #1f2937; }
        .wavs-table td { border-bottom: 1px solid #111827; font-size: 13px; }
        .btn-ghost {
            display: flex; align-items: center; gap: 6px;
            padding: 6px 12px; border-radius: 8px;
            border: 1px solid #374151; background: #1f2937;
            color: #d1d5db; font-size: 13px; font-weight: 500;
            cursor: pointer; transition: background .15s;
        }
        .btn-ghost:hover { background: #374151; }
    </style>
</head>
<body>

<!-- ══════════════════════════════════════════════
     SIDEBAR
══════════════════════════════════════════════ -->
<nav id="topNav">
    <!-- Brand -->
    <div class="tn-brand">
        <svg width="16" height="16" fill="none" stroke="#22c55e" viewBox="0 0 24 24" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
        <span style="font-size:13px;font-weight:700;color:#f9fafb;">VulnSight</span>
    </div>
    <!-- Hidden topbarTitle — kept for JS compatibility -->
    <span id="topbarTitle" style="display:none;">Dashboard</span>

    <!-- Nav links -->
    <div class="tn-links">
        <div class="tn-item active" data-tab="overview">
            <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.8"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>
            Dashboard
        </div>

        <div class="tn-item" data-tab="scans">
            <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.8"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
            Scans
            <span class="tn-badge orange" id="sideScanRunning">2</span>
        </div>
        <div class="tn-item" data-tab="reports">
            <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.8"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
            Vuln Reports
            <span class="tn-badge red" id="sideVulnCount">47</span>
        </div>
        <div class="tn-item" data-tab="audit">
            <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.8"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
            Audit Log
        </div>
        <div class="tn-item" data-tab="settings">
            <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.8"><path d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><circle cx="12" cy="12" r="3"/></svg>
            Settings
        </div>
    </div>

    <!-- Right actions -->
    <div class="tn-actions">
        <div class="sys-status" style="padding:4px 10px;border-radius:6px;background:#1f2937;border:1px solid #374151;font-size:12px;">
            <div class="sys-dot"></div>
            <span style="color:#9ca3af;">Systems OK</span>
        </div>
        <button class="btn-ghost" style="padding:6px 12px;font-size:13px;color:#d1d5db;" id="flushCacheBtn">
            <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
            Flush Cache
        </button>
        <!-- Hidden elements for JS -->
        <span id="adminAvatarDisplay" style="display:none;">SA</span>
        <span id="adminNameDisplay" style="display:none;">Loading…</span>
        <span id="adminEmailDisplay" style="display:none;">Verifying…</span>
        <span id="adminSignOutChip" style="display:none;"></span>
    </div>
</nav>

<!-- ══════════════════════════════════════════════
     MAIN CONTENT
══════════════════════════════════════════════ -->
<div id="mainContent">



    <div class="content">

        <!-- ══════════════════════════════
             OVERVIEW TAB
        ══════════════════════════════ -->
        <div id="overview-tab" class="tab-content active">
            <div class="section-header">
                <div>
                    <div class="section-title">Admin Dashboard</div>
                    <div class="section-sub">Platform-wide metrics and system snapshot</div>
                </div>
                <div style="display:flex;gap:8px;">
                    <button class="btn-primary exportPdfBtn" style="font-size:12px;padding:8px 15px;display:flex;align-items:center;gap:6px;">
                        <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
                        Export PDF Report
                    </button>
                </div>
            </div>

            <!-- Stat cards -->
            <div class="stat-grid fade-up">
                <div class="stat-card" style="--clr:#60a5fa;--clr-rgb:96,165,250;">
                    <div class="stat-card-bar"></div>
                    <div class="stat-delta" style="color:#60a5fa;" id="deltaScans">—</div>
                    <div class="stat-num" style="color:#60a5fa;" id="totalScans">—</div>
                    <div class="stat-lbl">Total Scans</div>
                </div>
                <div class="stat-card" style="--clr:var(--neon);--clr-rgb:var(--neon-rgb);">
                    <div class="stat-card-bar"></div>
                    <div class="stat-delta" id="deltaActive">—</div>
                    <div class="stat-num" id="totalActive">—</div>
                    <div class="stat-lbl">Active Scans</div>
                </div>
                <div class="stat-card" style="--clr:var(--red);--clr-rgb:240,80,80;">
                    <div class="stat-card-bar"></div>
                    <div class="stat-delta" style="color:var(--red);" id="deltaVulns">—</div>
                    <div class="stat-num" style="color:var(--red);" id="totalVulns">—</div>
                    <div class="stat-lbl">Vulns Found</div>
                </div>
                <div class="stat-card" style="--clr:var(--orange);--clr-rgb:245,158,11;">
                    <div class="stat-card-bar"></div>
                    <div class="stat-delta" style="color:var(--orange);" id="deltaCritical">—</div>
                    <div class="stat-num" style="color:var(--orange);" id="totalCritical">—</div>
                    <div class="stat-lbl">Critical Alerts</div>
                </div>
            </div>

            <!-- Middle row -->
            <div style="display:grid;grid-template-columns:1fr 1fr 300px;gap:12px;margin-bottom:12px;">

                <!-- Scan Activity Sparkline -->
                <div class="card fade-up delay-1">
                    <div class="card-label">Scan Activity (Last 14 days)</div>
                    <div style="display:flex;align-items:flex-end;gap:4px;height:48px;margin-bottom:10px;">
                        <div id="activityBars" style="display:flex;align-items:flex-end;gap:3px;height:48px;flex:1;color:white;"></div>
                    </div>
                    <div style="display:flex;justify-content:space-between;font-size:10px;color:white;font-family:'DM Mono',monospace;">
                        <span>14d ago</span><span>7d ago</span><span>Today</span>
                    </div>
                </div>

                <!-- Vulnerability Mix -->
                <div class="card fade-up delay-2">
                    <div class="card-label">Vulnerability Distribution</div>
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
                        <div style="text-align:center;padding:10px;background:rgba(240,80,80,.055);border:1px solid rgba(240,80,80,.12);border-radius:9px;">
                            <div style="font-family:'DM Mono',monospace;font-size:20px;font-weight:500;color:var(--red);" id="distCritical">—</div>
                            <div style="font-size:12px;color:white;font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin-top:2px;">Critical</div>
                        </div>
                        <div style="text-align:center;padding:10px;background:rgba(245,158,11,.05);border:1px solid rgba(245,158,11,.12);border-radius:9px;">
                            <div style="font-family:'DM Mono',monospace;font-size:20px;font-weight:500;color:var(--orange);" id="distHigh">—</div>
                            <div style="font-size:12px;color:white;font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin-top:2px;">High</div>
                        </div>
                        <div style="text-align:center;padding:10px;background:rgba(253,224,71,.04);border:1px solid rgba(253,224,71,.1);border-radius:9px;">
                            <div style="font-family:'DM Mono',monospace;font-size:20px;font-weight:500;color:var(--yellow);" id="distMedium">—</div>
                            <div style="font-size:12px;color:white;font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin-top:2px;">Medium</div>
                        </div>
                        <div style="text-align:center;padding:10px;background:rgba(0,245,196,.04);border:1px solid rgba(0,245,196,.12);border-radius:9px;">
                            <div style="font-family:'DM Mono',monospace;font-size:20px;font-weight:500;color:var(--neon);" id="distLow">—</div>
                            <div style="font-size:12px;color:white;font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin-top:2px;">Low</div>
                        </div>
                    </div>
                </div>

                <!-- Quick actions -->
                <div class="card fade-up delay-3" style="display:flex;flex-direction:column;gap:8px;">
                    <div class="card-label">Quick Actions</div>
                    <button class="btn-primary exportPdfBtn" style="width:100%;justify-content:center;font-size:14px;">
                        <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
                        Export Full Report
                    </button>
                    <button class="btn-ghost" style="width:100%;justify-content:center;font-size:14px;color:white;" data-switchtab="reports">
                        <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                        View Vuln Reports
                    </button>
                    <button class="btn-ghost" style="width:100%;justify-content:center;font-size:14px;color:white;" data-switchtab="system">
                        <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2v-4M9 21H5a2 2 0 01-2-2v-4m0 0h18"/></svg>
                        System Health
                    </button>
                    <button class="btn-ghost" style="width:100%;justify-content:center;font-size:14px;color:white;" data-switchtab="audit">
                        <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                        Audit Log
                    </button>
                </div>
            </div>

            <!-- Recent users + Recent scans -->
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;" class="fade-up delay-4">

                <!-- Recent critical findings -->
                <div class="card" style="padding:0;overflow:hidden;">
                    <div style="display:flex;align-items:center;justify-content:space-between;padding:13px 18px;border-bottom:1px solid var(--border);">
                        <span class="card-label" style="margin:0;">Recent Critical Findings</span>
                        <button data-switchtab="reports" style="font-size:12px;font-weight:600;color:var(--neon);background:none;border:none;cursor:pointer;font-family:'DM Sans',sans-serif;display:flex;align-items:center;gap:4px;">
                            All reports <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
                        </button>
                    </div>
                    <div id="recentCriticalList"></div>
                </div>

                <!-- Live scans -->
                <div class="card" style="padding:0;overflow:hidden;">
                    <div style="display:flex;align-items:center;justify-content:space-between;padding:13px 18px;border-bottom:1px solid var(--border);">
                        <span class="card-label" style="margin:0;">Active Scans</span>
                        <button data-switchtab="scans" style="font-size:12px;font-weight:600;color:var(--neon);background:none;border:none;cursor:pointer;font-family:'DM Sans',sans-serif;display:flex;align-items:center;gap:4px;">
                            All scans <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
                        </button>
                    </div>
                    <div id="liveScansPreview"></div>
                </div>
            </div>
        </div>

        <!-- ══════════════════════════════
             SYSTEM HEALTH TAB
        ══════════════════════════════ -->
        <div id="system-tab" class="tab-content">
            <div class="section-header">
                <div>
                    <div class="section-title">System Health</div>
                    <div class="section-sub">Real-time server metrics and service status</div>
                </div>
                <button class="btn-ghost" style="font-size:14px;color:white" id="refreshHealthBtn">
                    <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                    Refresh
                </button>
            </div>

            <!-- Resource meters -->
            <div class="health-grid" style="margin-bottom:12px;">
                <div class="health-card">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                        <div class="health-lbl">CPU Usage</div>
                        <span style="font-size:12px;color:var(--neon);font-family:'DM Mono',monospace;" id="cpuPct">34%</span>
                    </div>
                    <div class="health-val" style="color:var(--neon);" id="cpuVal">34<span style="font-size:14px;font-weight:400;">%</span></div>
                    <div class="health-bar-wrap"><div class="prog-track"><div class="prog-bar" id="cpuBar" style="width:34%;background:linear-gradient(90deg,var(--neon),var(--blue));"></div></div></div>
                </div>
                <div class="health-card">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                        <div class="health-lbl">Memory Usage</div>
                        <span style="font-size:12px;color:#60a5fa;font-family:'DM Mono',monospace;">5.2 / 16 GB</span>
                    </div>
                    <div class="health-val" style="color:#60a5fa;">52<span style="font-size:14px;font-weight:400;">%</span></div>
                    <div class="health-bar-wrap"><div class="prog-track"><div class="prog-bar" style="width:52%;background:linear-gradient(90deg,#3b82f6,#818cf8);"></div></div></div>
                </div>
                <div class="health-card">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                        <div class="health-lbl">Disk Usage</div>
                        <span style="font-size:12px;color:var(--orange);font-family:'DM Mono',monospace;">187 / 500 GB</span>
                    </div>
                    <div class="health-val" style="color:var(--orange);">37<span style="font-size:14px;font-weight:400;">%</span></div>
                    <div class="health-bar-wrap"><div class="prog-track"><div class="prog-bar" style="width:37%;background:linear-gradient(90deg,var(--orange),var(--yellow));"></div></div></div>
                </div>
            </div>

            <!-- Services grid -->
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;">
                <div class="card" style="padding:0;overflow:hidden;">
                    <div style="padding:13px 18px;border-bottom:1px solid var(--border);">
                        <span class="card-label" style="margin:0;">Service Status</span>
                    </div>
                    <div id="serviceList"></div>
                </div>

                <div class="card">
                    <div class="card-label">Queue & Workers</div>
                    <div style="display:grid;gap:10px;">
                        <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:9px;">
                            <div>
                                <p style="font-size:13px;font-weight:600;">Scan Workers</p>
                                <p style="font-size:12px;color:white;margin-top:2px;">Active / Max capacity</p>
                            </div>
                            <div style="text-align:right;">
                                <div style="font-family:'DM Mono',monospace;font-size:18px;color:var(--neon);" id="workerCount">6 <span style="font-size:12px;color:var(--muted);">/ 16</span></div>
                            </div>
                        </div>
                        <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:9px;">
                            <div>
                                <p style="font-size:13px;font-weight:600;">Queue Depth</p>
                                <p style="font-size:12px;color:white;margin-top:2px;">Jobs waiting to be processed</p>
                            </div>
                            <div style="font-family:'DM Mono',monospace;font-size:18px;color:#60a5fa;" id="queueDepth">14</div>
                        </div>
                        <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:9px;">
                            <div>
                                <p style="font-size:13px;font-weight:600;">Failed Jobs (24h)</p>
                                <p style="font-size:12px;color:white;margin-top:2px;">Jobs that errored out</p>
                            </div>
                            <div style="display:flex;align-items:center;gap:8px;">
                                <div style="font-family:'DM Mono',monospace;font-size:18px;color:var(--red);">3</div>
                                <button class="btn-danger btn-sm" id="retryJobsBtn">Retry All</button>
                            </div>
                        </div>
                        <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:9px;">
                            <div>
                                <p style="font-size:13px;font-weight:600;">Avg Scan Duration</p>
                                <p style="font-size:12px;color:white;margin-top:2px;">Past 7 days</p>
                            </div>
                            <div style="font-family:'DM Mono',monospace;font-size:18px;color:var(--neon);">4m 32s</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- DB + Cache + API -->
            <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;">
                <div class="card">
                    <div class="card-label">Database</div>
                    <div style="display:grid;gap:7px;">
                        <div style="display:flex;justify-content:space-between;align-items:center;">
                            <span style="font-size:12px;color:white;">Connection pool</span>
                            <span style="font-family:'DM Mono',monospace;font-size:12px;">12 / 100</span>
                        </div>
                        <div style="display:flex;justify-content:space-between;align-items:center;">
                            <span style="font-size:12px;color:white;">Query latency (avg)</span>
                            <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--text);">2.4ms</span>
                        </div>
                        <div style="display:flex;justify-content:space-between;align-items:center;">
                            <span style="font-size:12px;color:white;">Slow queries (1h)</span>
                            <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--orange);">1</span>
                        </div>
                        <div style="display:flex;justify-content:space-between;align-items:center;">
                            <span style="font-size:12px;color:white;">Storage used</span>
                            <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--text);">8.3 GB</span>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-label">Cache (Redis)</div>
                    <div style="display:grid;gap:7px;">
                        <div style="display:flex;justify-content:space-between;align-items:center;">
                            <span style="font-size:12px;color:white;">Hit rate</span>
                            <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--neon);">94.2%</span>
                        </div>
                        <div style="display:flex;justify-content:space-between;align-items:center;">
                            <span style="font-size:12px;color:white;">Used memory</span>
                            <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--text);">412 MB</span>
                        </div>
                        <div style="display:flex;justify-content:space-between;align-items:center;">
                            <span style="font-size:12px;color:white">Evicted keys</span>
                            <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--text);">0</span>
                        </div>
                        <div style="margin-top:4px;">
                            <button class="btn-ghost btn-sm" style="width:100%;justify-content:center;font-size:11px;color:white;" id="flushCacheLocalBtn">Flush Cache</button>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-label">API Performance</div>
                    <div style="display:grid;gap:7px;">
                        <div style="display:flex;justify-content:space-between;align-items:center;">
                            <span style="font-size:12px;color:white;">Req/min (now)</span>
                            <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--neon);" id="apiRpm">847</span>
                        </div>
                        <div style="display:flex;justify-content:space-between;align-items:center;">
                            <span style="font-size:12px;color:white;">Avg response time</span>
                            <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--text);">38ms</span>
                        </div>
                        <div style="display:flex;justify-content:space-between;align-items:center;">
                            <span style="font-size:12px;color:white;">Error rate (1h)</span>
                            <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--green);">0.2%</span>
                        </div>
                        <div style="display:flex;justify-content:space-between;align-items:center;">
                            <span style="font-size:12px;color:white;">Uptime (30d)</span>
                            <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--green);">99.97%</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- ══════════════════════════════
             SCANS TAB
        ══════════════════════════════ -->
        <div id="scans-tab" class="tab-content">
            <div class="section-header">
                <div>
                    <div class="section-title">Scan Management</div>
                    <div class="section-sub">Monitor and control all scans across the platform</div>
                </div>
                <div style="display:flex;gap:8px;">
                    <select class="wavs-input" style="width:140px;padding:8px 12px;" id="scanStatusFilter">
                        <option value="all">All Status</option>
                        <option value="running">Running</option>
                        <option value="completed">Completed</option>
                        <option value="failed">Failed</option>
                    </select>
                </div>
            </div>

            <div class="card" style="padding:0;overflow:hidden;">
                <!-- Column header -->
                <div style="display:flex;align-items:center;gap:16px;padding:9px 20px;border-bottom:1px solid var(--border);background:rgba(255,255,255,.018);">
                    <div style="width:155px;flex-shrink:0;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:white;">Owner</div>
                    <div style="flex:1;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:white;">Target</div>
                    <div style="width:130px;flex-shrink:0;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:white;">Progress</div>
                    <div style="width:105px;flex-shrink:0;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:white;">Status</div>
                    <div style="width:56px;flex-shrink:0;text-align:center;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:white;">Vulns</div>
                    <div style="width:120px;flex-shrink:0;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:white;">Actions</div>
                </div>
                <div id="scansListContainer" style="max-height:600px;overflow-y:auto;"></div>
            </div>
        </div>

        <!-- ══════════════════════════════
             REPORTS TAB
        ══════════════════════════════ -->
        <div id="reports-tab" class="tab-content">
            <div class="section-header">
                <div>
                    <div class="section-title">Vulnerability Reports</div>
                    <div class="section-sub" id="reportSubtitle">Platform-wide findings grouped by user</div>
                </div>
                <div style="display:flex;gap:8px;align-items:center;">
                    <div class="search-wrap">
                        <svg width="13" height="13" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
                        <input class="wavs-input" style="width:180px;padding:8px 12px 8px 34px;" type="text" placeholder="Search user…" id="reportUserSearch">
                    </div>
                    <select class="wavs-input" style="width:140px;padding:8px 12px;" id="sevFilterReports">
                        <option value="all">All Severity</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                    <button class="btn-primary exportPdfBtn" style="font-size:12px;padding:8px 16px;display:flex;align-items:center;gap:6px;">
                        <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
                        Export PDF Report
                    </button>
                </div>
            </div>

            <!-- Per-user report cards -->
            <div id="reportsContainer"></div>

            <!-- Hidden flat table for CSV compat (legacy) -->
            <table style="display:none;"><tbody id="reportsTableBody"></tbody></table>
        </div>

        <!-- ══════════════════════════════
             AUDIT LOG TAB
        ══════════════════════════════ -->
        <div id="audit-tab" class="tab-content">
            <div class="section-header">
                <div>
                    <div class="section-title">Audit Log</div>
                    <div class="section-sub">All admin and user actions across the platform</div>
                </div>
                <div style="display:flex;gap:8px;">
                    <div class="search-wrap">
                        <svg width="13" height="13" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
                        <input class="wavs-input" style="width:220px;padding:8px 12px 8px 34px;" type="text" placeholder="Filter by user or action…" id="auditSearchInput">
                    </div>
                    <select class="wavs-input" style="width:130px;padding:8px 12px;" id="auditSevFilter">
                        <option value="all">All Events</option>
                        <option value="critical">Critical</option>
                        <option value="warn">Warning</option>
                        <option value="info">Info</option>
                    </select>
                    <button class="btn-ghost" style="font-size:13px;color:white;" id="exportAuditBtn">
                        <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                        Export PDF
                    </button>
                </div>
            </div>

            <div class="card" style="padding:0;overflow:hidden;">
                <div style="display:flex;align-items:center;padding:9px 25px;border-bottom:1px solid var(--border);font-size:14px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:white;">
                    <span style="width:148px;flex-shrink:0;">Timestamp</span>
<span style="width:200px;min-width:200px;flex-shrink:0;">Actor</span>
<span style="flex:1;padding-left:16px;">Action</span>
                    <span style="width:80px;text-align:right;">Severity</span>
                </div>
                <div id="auditLogBody" style="max-height:520px;overflow-y:auto;"></div>
            </div>
        </div>

        <!-- ══════════════════════════════
             PLATFORM SETTINGS TAB
        ══════════════════════════════ -->
        <div id="settings-tab" class="tab-content">
            <div class="section-header">
                <div>
                    <div class="section-title">Platform Settings</div>
                    <div class="section-sub">Global configuration for the VulnSight platform</div>
                </div>
                <button class="btn-primary" style="font-size:12px;" id="saveSettingsBtn">
                    <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5"><path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
                    Save Settings
                </button>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;">

                <!-- General -->
                <div class="card">
                    <div class="card-label">General</div>
                    <div class="field">
                        <label class="field-label">Platform Name</label>
                        <input class="wavs-input" id="cfg_platform_name" name="platform_name" type="text" value="VulnSight">
                    </div>
                    <div class="field">
                        <label class="field-label">Support Email</label>
                        <input class="wavs-input" id="cfg_support_email" name="support_email" type="email" value="support@vulnsight.io">
                    </div>
                    <div class="field" style="margin-bottom:0;">
                        <label class="field-label">Support Email</label>
                        <input class="wavs-input" id="cfg_support_email" name="support_email" type="email" value="support@vulnsight.io">
                    </div>
                </div>

                <!-- Access Control -->
                <div class="card">
                    <div class="card-label">Access & Registration</div>
                    <div style="display:flex;flex-direction:column;gap:13px;">
                        <div style="display:flex;align-items:center;justify-content:space-between;">
                            <div>
                                <p style="font-size:14px;font-weight:600;">Scan Rate Limiting</p>
                                <p style="font-size:12px;color:white;margin-top:2px;">Throttle users exceeding daily scan limits</p>
                            </div>
                            <label class="toggle"><input type="checkbox" id="cfg_rate_limiting" name="rate_limiting" checked><div class="toggle-slider"></div></label>
                        </div>

                    </div>
                </div>


            </div>
        </div>

    </div><!-- /content -->
</div><!-- /mainContent -->


<!-- View Scan Modal -->
<div id="viewScanModal" class="modal-overlay">
    <div class="modal-box" style="width:520px;">
        <div class="modal-head">
            <div style="display:flex;align-items:center;gap:10px;">
                <div style="width:32px;height:32px;border-radius:9px;background:rgba(0,245,196,.1);border:1px solid rgba(0,245,196,.2);display:flex;align-items:center;justify-content:center;flex-shrink:0;">
                    <svg width="15" height="15" fill="none" stroke="var(--neon)" viewBox="0 0 24 24" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                </div>
                <p style="font-size:15px;font-weight:700;">Scan Details</p>
            </div>
            <button class="btn-ghost btn-sm" data-closemodal="viewScanModal"style="color:white;">✕</button>
        </div>
        <div class="modal-body" id="viewScanContent"></div>
        <div class="modal-foot">
            <button class="btn-ghost btn-sm" data-closemodal="viewScanModal"style="color:white;">Close</button>
        </div>
    </div>
</div>

<!-- Confirm Modal -->
<div id="confirmModal" class="modal-overlay">
    <div class="modal-box" style="width:400px;">
        <div class="modal-head">
            <div style="display:flex;align-items:center;gap:10px;">
                <div style="width:32px;height:32px;border-radius:9px;background:rgba(240,80,80,.1);border:1px solid rgba(240,80,80,.2);display:flex;align-items:center;justify-content:center;flex-shrink:0;">
                    <svg width="15" height="15" fill="none" stroke="var(--red)" viewBox="0 0 24 24" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                </div>
                <p style="font-size:15px;font-weight:700;">Confirm Action</p>
            </div>
            <button class="btn-ghost btn-sm" data-closemodal="confirmModal">✕</button>
        </div>
        <div class="modal-body">
            <p id="confirmMsg" style="font-size:13px;color:var(--text2);line-height:1.6;"></p>
        </div>
        <div class="modal-foot">
            <button class="btn-ghost btn-sm" data-closemodal="confirmModal">Cancel</button>
            <button class="btn-danger btn-sm" id="confirmOkBtn">Confirm</button>
        </div>
    </div>
</div>

<div id="toast"></div>

<script src="{{ asset('js/wavs_admin.js') }}" nonce="{{ csp_nonce() }}"></script>
</body>
</html>
