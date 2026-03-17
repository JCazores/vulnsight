import { useState, useEffect, useRef, useCallback } from "react";

// ─── CSS ──────────────────────────────────────────────────────────────────────
const CSS = `
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Syne:wght@400;600;700;800&display=swap');
  :root {
    --neon:#00ffe0;--neon2:#007aff;--bg:#060910;--surface:#0d1117;
    --surface2:#141b24;--border:#1e2d3d;--text:#cdd9e5;--muted:#4d6475;
    --red:#ff4444;--orange:#ff8c00;--yellow:#ffd700;--green:#00d084;
    --neon-dim:rgba(0,255,224,.07);--neon-border:rgba(0,255,224,.18);
  }
  *{box-sizing:border-box;margin:0;padding:0;}
  body{font-family:'Syne',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden;}
  code,.mono{font-family:'JetBrains Mono',monospace;}
  ::-webkit-scrollbar{width:4px;height:4px;}
  ::-webkit-scrollbar-track{background:var(--surface);}
  ::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px;}
  ::-webkit-scrollbar-thumb:hover{background:var(--muted);}
  .grid-bg{background-image:linear-gradient(rgba(0,255,224,.022) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,224,.022) 1px,transparent 1px);background-size:40px 40px;}
  .wavs-input{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 14px;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:13px;outline:none;transition:border-color .2s,box-shadow .2s;}
  .wavs-input:focus{border-color:var(--neon);box-shadow:0 0 0 3px rgba(0,255,224,.07);}
  .wavs-input::placeholder{color:var(--muted);}
  .wavs-input:hover:not(:focus){border-color:rgba(30,45,61,.8);}
  .btn-primary{background:linear-gradient(135deg,#00ffe0,#007aff);color:#000;font-family:'Syne',sans-serif;font-weight:700;font-size:13px;letter-spacing:.04em;padding:10px 22px;border-radius:8px;border:none;cursor:pointer;transition:opacity .2s,transform .1s,box-shadow .2s;display:inline-flex;align-items:center;gap:7px;}
  .btn-primary:hover{opacity:.88;transform:translateY(-1px);box-shadow:0 6px 20px rgba(0,255,224,.18);}
  .btn-primary:active{transform:translateY(0);}
  .btn-ghost{background:transparent;color:var(--text);font-family:'Syne',sans-serif;font-weight:600;font-size:13px;padding:9px 18px;border-radius:8px;border:1px solid var(--border);cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:7px;}
  .btn-ghost:hover{border-color:var(--neon);color:var(--neon);background:var(--neon-dim);}
  .btn-danger{background:rgba(255,68,68,.08);color:var(--red);border:1px solid rgba(255,68,68,.18);border-radius:6px;padding:5px 12px;font-size:12px;font-family:'Syne',sans-serif;font-weight:600;cursor:pointer;transition:all .2s;}
  .btn-danger:hover{background:rgba(255,68,68,.18);border-color:rgba(255,68,68,.35);}
  .btn-icon{background:transparent;border:1px solid var(--border);border-radius:6px;padding:5px 8px;cursor:pointer;color:var(--muted);transition:all .2s;display:inline-flex;align-items:center;justify-content:center;}
  .btn-icon:hover{border-color:var(--neon-border);color:var(--neon);}
  .badge{display:inline-flex;align-items:center;padding:3px 9px;border-radius:20px;font-size:10px;font-weight:700;font-family:'JetBrains Mono',monospace;text-transform:uppercase;letter-spacing:.04em;}
  .badge-critical{background:rgba(255,68,68,.14);color:#ff6b6b;border:1px solid rgba(255,68,68,.3);}
  .badge-high{background:rgba(255,140,0,.14);color:#ffaa3d;border:1px solid rgba(255,140,0,.3);}
  .badge-medium{background:rgba(255,215,0,.1);color:var(--yellow);border:1px solid rgba(255,215,0,.22);}
  .badge-low{background:rgba(0,208,132,.1);color:var(--green);border:1px solid rgba(0,208,132,.22);}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:18px 20px;}
  .card-title{font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-bottom:14px;display:block;}
  .stat-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:18px 18px 16px;position:relative;overflow:hidden;transition:border-color .25s,transform .2s;}
  .stat-card:hover{border-color:rgba(0,255,224,.2);transform:translateY(-1px);}
  .stat-card::after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(0,255,224,.028),transparent 60%);pointer-events:none;}
  .prog-track{background:var(--surface2);border-radius:99px;height:5px;overflow:hidden;}
  .prog-bar{height:100%;border-radius:99px;background:linear-gradient(90deg,var(--neon),var(--neon2));transition:width .4s ease;}
  .wavs-table{width:100%;border-collapse:collapse;}
  .wavs-table th{text-align:left;padding:10px 14px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);border-bottom:1px solid var(--border);}
  .wavs-table td{padding:12px 14px;font-size:13px;border-bottom:1px solid rgba(30,45,61,.4);vertical-align:middle;}
  .wavs-table tr:hover td{background:rgba(0,255,224,.015);}
  .wavs-table tr:last-child td{border-bottom:none;}
  .status-dot{width:7px;height:7px;border-radius:50%;background:var(--muted);transition:background .3s;flex-shrink:0;}
  .status-dot.running{background:var(--green);box-shadow:0 0 7px var(--green);animation:blink 1s infinite;}
  .status-dot.paused{background:var(--orange);}
  .status-dot.completed{background:var(--neon);}
  @keyframes blink{0%,100%{opacity:1}50%{opacity:.4}}
  .nav-item{display:flex;align-items:center;gap:9px;padding:9px 10px;border-radius:8px;cursor:pointer;color:var(--muted);font-size:13px;font-weight:600;transition:all .15s;margin-bottom:2px;border:1px solid transparent;user-select:none;}
  .nav-item:hover{background:var(--surface2);color:var(--text);}
  .nav-item.active{background:rgba(0,255,224,.07);border-color:rgba(0,255,224,.14);color:var(--neon);}
  .intensity-card{border:1px solid var(--border);border-radius:10px;padding:14px 16px;cursor:pointer;transition:all .2s;text-align:left;background:var(--surface2);width:100%;}
  .intensity-card:hover{border-color:var(--muted);}
  .intensity-card.active{border-color:var(--neon);background:rgba(0,255,224,.05);}
  .toggle{position:relative;width:38px;height:21px;flex-shrink:0;}
  .toggle input{opacity:0;width:0;height:0;}
  .toggle-slider{position:absolute;inset:0;border-radius:21px;background:var(--surface2);border:1px solid var(--border);cursor:pointer;transition:.2s;}
  .toggle-slider:before{content:'';position:absolute;height:15px;width:15px;left:2px;top:2px;border-radius:50%;background:var(--muted);transition:.2s;}
  .toggle input:checked+.toggle-slider{background:rgba(0,255,224,.18);border-color:var(--neon);}
  .toggle input:checked+.toggle-slider:before{transform:translateX(17px);background:var(--neon);}
  .code-block{background:#000;border:1px solid var(--border);border-radius:8px;padding:14px 16px;font-family:'JetBrains Mono',monospace;font-size:11px;line-height:1.65;color:#6ee7b7;overflow-x:auto;position:relative;}
  .auth-tab{padding:8px 20px;border-radius:6px;font-size:13px;font-weight:700;cursor:pointer;transition:all .2s;border:none;background:transparent;color:var(--muted);font-family:'Syne',sans-serif;}
  .auth-tab.active{background:var(--surface2);color:var(--neon);}
  .log-row{display:flex;align-items:baseline;gap:0;padding:3px 16px;border-bottom:1px solid rgba(30,45,61,.3);white-space:nowrap;overflow:hidden;}
  .log-row:hover{background:rgba(0,255,224,.018);}
  .empty-state{padding:36px;text-align:center;color:var(--muted);font-size:13px;}
  .fade-in{animation:fadeUp .3s ease;}
  @keyframes fadeUp{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
  .modal-overlay{position:fixed;inset:0;z-index:2000;background:rgba(6,9,16,.85);backdrop-filter:blur(6px);display:flex;align-items:center;justify-content:center;}
  .toast-wrap{position:fixed;bottom:22px;right:22px;z-index:9999;display:flex;flex-direction:column;gap:8px;pointer-events:none;}
  .toast{padding:11px 16px;border-radius:10px;font-size:13px;font-weight:600;font-family:'Syne',sans-serif;display:flex;align-items:center;gap:9px;max-width:320px;backdrop-filter:blur(10px);animation:slideIn .3s cubic-bezier(.34,1.56,.64,1);}
  @keyframes slideIn{from{transform:translateY(40px);opacity:0}to{transform:translateY(0);opacity:1}}
  .toast.success{background:rgba(0,208,132,.14);border:1px solid rgba(0,208,132,.35);color:#00d084;}
  .toast.info{background:rgba(0,122,255,.14);border:1px solid rgba(0,122,255,.35);color:#60a5fa;}
  .toast.warn{background:rgba(255,140,0,.14);border:1px solid rgba(255,140,0,.35);color:var(--orange);}
  .toast.error{background:rgba(255,68,68,.14);border:1px solid rgba(255,68,68,.35);color:var(--red);}
  .vault-how-step{display:flex;gap:14px;align-items:flex-start;padding:14px 16px;border-radius:10px;background:var(--surface2);border:1px solid var(--border);transition:border-color .2s;}
  .vault-how-step:hover{border-color:var(--neon-border);}
  .vault-step-num{width:26px;height:26px;border-radius:50%;background:linear-gradient(135deg,rgba(0,255,224,.15),rgba(0,122,255,.15));border:1px solid rgba(0,255,224,.25);display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:800;color:var(--neon);font-family:'JetBrains Mono',monospace;flex-shrink:0;}
  .cred-card{border:1px solid var(--border);border-radius:10px;padding:14px 16px;background:var(--surface2);transition:border-color .2s,box-shadow .2s;position:relative;overflow:hidden;}
  .cred-card:hover{border-color:rgba(0,255,224,.2);box-shadow:0 4px 20px rgba(0,0,0,.3);}
  .cred-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;}
  .cred-card.cookie::before{background:linear-gradient(90deg,#007aff,#60a5fa);}
  .cred-card.bearer::before{background:linear-gradient(90deg,#00ffe0,#007aff);}
  .cred-card.basic::before{background:linear-gradient(90deg,#ffd700,#ff8c00);}
  .cred-type-badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:10px;font-weight:700;font-family:'JetBrains Mono',monospace;text-transform:uppercase;letter-spacing:.04em;}
  .cred-type-badge.cookie{background:rgba(0,122,255,.12);color:#60a5fa;border:1px solid rgba(0,122,255,.25);}
  .cred-type-badge.bearer{background:rgba(0,255,224,.1);color:var(--neon);border:1px solid rgba(0,255,224,.2);}
  .cred-type-badge.basic{background:rgba(255,215,0,.1);color:var(--yellow);border:1px solid rgba(255,215,0,.2);}
  .form-label{font-size:11px;font-weight:700;color:var(--muted);display:block;margin-bottom:5px;text-transform:uppercase;letter-spacing:.06em;}
  .type-selector{display:flex;gap:6px;}
  .type-btn{flex:1;padding:9px 10px;border-radius:8px;border:1px solid var(--border);background:var(--surface2);color:var(--muted);font-family:'Syne',sans-serif;font-size:12px;font-weight:700;cursor:pointer;transition:all .2s;display:flex;flex-direction:column;align-items:center;gap:4px;}
  .type-btn:hover{border-color:var(--muted);color:var(--text);}
  .type-btn.active.cookie{border-color:#60a5fa;background:rgba(0,122,255,.08);color:#60a5fa;}
  .type-btn.active.bearer{border-color:var(--neon);background:rgba(0,255,224,.06);color:var(--neon);}
  .type-btn.active.basic{border-color:var(--yellow);background:rgba(255,215,0,.06);color:var(--yellow);}
  /* Admin badge */
  .admin-badge{display:inline-flex;align-items:center;gap:5px;padding:2px 8px;border-radius:20px;font-size:9px;font-weight:700;font-family:'JetBrains Mono',monospace;text-transform:uppercase;letter-spacing:.06em;background:rgba(255,140,0,.12);color:var(--orange);border:1px solid rgba(255,140,0,.25);}
`;

// ─── Constants ────────────────────────────────────────────────────────────────
const VULN_DB = [
  {name:'SQL Injection',sev:'critical',badge:'badge-critical',cve:'CVE-2024-1234'},
  {name:'Stored XSS',sev:'critical',badge:'badge-critical',cve:'CVE-2024-9012'},
  {name:'SSRF',sev:'critical',badge:'badge-critical',cve:'CVE-2024-8901'},
  {name:'Reflected XSS',sev:'high',badge:'badge-high',cve:'CVE-2024-5678'},
  {name:'IDOR',sev:'high',badge:'badge-high',cve:'CVE-2024-7890'},
  {name:'Path Traversal',sev:'high',badge:'badge-high',cve:'CVE-2024-2345'},
  {name:'CSRF',sev:'medium',badge:'badge-medium',cve:'CVE-2024-3456'},
  {name:'Info Disclosure',sev:'medium',badge:'badge-medium',cve:'CVE-2024-4567'},
  {name:'Open Redirect',sev:'low',badge:'badge-low',cve:'CVE-2024-6789'},
  {name:'Insecure Headers',sev:'low',badge:'badge-low',cve:'CVE-2024-0123'},
];
const PATHS = ['/api/users','/api/posts','/login','/admin','/dashboard','/api/v1/auth','/profile','/search','/upload','/api/settings','/api/orders','/api/comments'];
const PHASES = ['Initializing…','Crawling pages…','Enumerating endpoints…','Testing SQL injection…','Testing XSS…','Testing CSRF…','Checking auth…','Testing IDOR…','Analyzing headers…','Fuzzing inputs…','Generating report…','Finalizing…'];
const HTTP_METHODS = ['GET','GET','GET','POST','PUT','DELETE','PATCH'];
const HTTP_STATUSES = [200,200,200,201,301,404,403,200,500];

const VULN_FIX_DB = {
  'SQL Injection':{ summary:'Unsanitized user input is being interpolated directly into SQL queries.',steps:['Use parameterized queries / prepared statements (PDO, Eloquent bindings).','Never concatenate user input into raw SQL strings.','Apply allowlist input validation on all user-supplied values.','Use a WAF rule to block common SQLi patterns as an additional layer.'],ref:'https://owasp.org/www-community/attacks/SQL_Injection'},
  'Stored XSS':{ summary:'Malicious scripts are being persisted in the database and rendered unsanitized.',steps:['HTML-encode all output using e.g. htmlspecialchars() or Blade {{ }} syntax.','Apply a strict Content-Security-Policy (CSP) header.','Sanitize input on the server before storing (strip_tags, HTMLPurifier).','Use HttpOnly and Secure flags on session cookies.'],ref:'https://owasp.org/www-community/attacks/xss/'},
  'Reflected XSS':{ summary:'User-supplied input is echoed back in the HTTP response without encoding.',steps:['Encode all reflected values with htmlspecialchars(ENT_QUOTES).','Implement a Content-Security-Policy (CSP) header.','Validate and reject unexpected characters in URL parameters.','Avoid rendering raw request data in error messages or search results.'],ref:'https://owasp.org/www-community/attacks/xss/'},
  'SSRF':{ summary:'The server is making HTTP requests to attacker-controlled URLs.',steps:['Validate and allowlist all URLs the server is permitted to fetch.','Block internal/private IP ranges (127.0.0.1, 10.x, 169.254.x, etc.).','Disable unused URL schemes (file://, gopher://, ftp://).','Run outbound requests through an egress proxy that enforces the allowlist.'],ref:'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'},
  'IDOR':{ summary:'Object references in URLs/parameters are not validated against the authenticated user.',steps:['Verify ownership/authorization for every resource request server-side.','Replace sequential integer IDs with UUIDs or opaque tokens.','Apply policy-based access control (Gates/Policies in Laravel).','Log and alert on repeated unauthorized access attempts.'],ref:'https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference'},
  'Path Traversal':{ summary:'File paths constructed from user input allow directory traversal.',steps:['Resolve the canonical path and verify it starts within the intended base directory.','Never pass raw user input to file system functions.','Use an allowlist of permitted filenames/extensions.','Serve files through a controller, never directly from public paths.'],ref:'https://owasp.org/www-community/attacks/Path_Traversal'},
  'CSRF':{ summary:'State-changing requests are not protected by a synchronizer token.',steps:['Include a CSRF token in every state-changing form/request (Laravel @csrf).','Validate the token server-side on all POST/PUT/DELETE endpoints.','Use SameSite=Lax or SameSite=Strict on session cookies.','Check the Origin/Referer header as a secondary defense.'],ref:'https://owasp.org/www-community/attacks/csrf'},
  'Info Disclosure':{ summary:'Sensitive application internals (stack traces, config, user data) are exposed.',steps:['Disable debug mode in production (APP_DEBUG=false in Laravel).','Return generic error messages to clients; log details server-side.','Remove X-Powered-By, Server, and version headers.','Audit API responses to ensure they do not leak PII or internal paths.'],ref:'https://owasp.org/www-project-web-security-testing-guide/'},
  'Open Redirect':{ summary:'Redirect targets are taken from user input without validation.',steps:['Only allow redirects to a strict allowlist of trusted URLs.','Reject redirect parameters containing external domains.','Use relative paths for internal redirects instead of full URLs.','Display a warning interstitial when redirecting away from your domain.'],ref:'https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet'},
  'Insecure Headers':{ summary:'Security-relevant HTTP response headers are missing or misconfigured.',steps:['Add Content-Security-Policy, X-Content-Type-Options, X-Frame-Options.','Enable Strict-Transport-Security (HSTS) with a long max-age.','Set Referrer-Policy: no-referrer-when-downgrade.','Use Permissions-Policy to disable unused browser features.'],ref:'https://owasp.org/www-project-secure-headers/'},
};

// ─── API helpers ──────────────────────────────────────────────────────────────
// Determine if current page is the admin view by URL
const IS_ADMIN_ROUTE = window.location.pathname.startsWith('/admin');

async function apiFetch(url, options = {}) {
  const token = localStorage.getItem('token');
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(url, { ...options, headers, credentials: 'include' });
  return res;
}

// ─── SVG Icons ────────────────────────────────────────────────────────────────
function ShieldIcon({ size=20 }){
  return <svg width={size} height={size} fill="none" stroke="#000" viewBox="0 0 24 24" strokeWidth="2.5"><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>;
}
function EyeIcon({ open=true, size=14 }){
  return open
    ? <svg width={size} height={size} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
    : <svg width={size} height={size} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24M1 1l22 22"/></svg>;
}
function CookieIcon({ size=16 }){
  return <svg width={size} height={size} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>;
}
function TokenIcon({ size=16 }){
  return <svg width={size} height={size} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>;
}
function UserPassIcon({ size=16 }){
  return <svg width={size} height={size} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>;
}
function TrashIcon({ size=13 }){
  return <svg width={size} height={size} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>;
}
function AdminIcon({ size=15 }){
  return <svg width={size} height={size} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>;
}

// ─── Toast ────────────────────────────────────────────────────────────────────
function Toast({ toasts }){
  return (
    <div className="toast-wrap">
      {toasts.map(t=>(
        <div key={t.id} className={`toast ${t.type}`}>
          <span>{{success:'✓',info:'ℹ',warn:'⚠',error:'✕'}[t.type]||'●'}</span>
          <span>{t.msg}</span>
        </div>
      ))}
    </div>
  );
}

function Badge({ sev }){
  return <span className={`badge badge-${sev}`}>{sev}</span>;
}

// ─── Auth Screen ──────────────────────────────────────────────────────────────
function AuthScreen({ onLogin }){
  const [tab, setTab]     = useState('signin');
  const [siEmail, setSiEmail] = useState('');
  const [siPass, setSiPass]   = useState('');
  const [suName, setSuName]   = useState('');
  const [suEmail, setSuEmail] = useState('');
  const [suPass, setSuPass]   = useState('');
  const [suConf, setSuConf]   = useState('');
  const [err, setErr]         = useState('');
  const [loading, setLoading] = useState(false);

  async function signIn(e){
    e.preventDefault(); setErr(''); setLoading(true);
    try {
      // Get CSRF cookie first
      await fetch('/sanctum/csrf-cookie', { credentials: 'include' });
      const res = await apiFetch('/api/login', {
        method: 'POST',
        body: JSON.stringify({ email: siEmail, password: siPass }),
      });
      const data = await res.json();
      if (!res.ok) { setErr(data.message || data.errors?.email?.[0] || 'Login failed.'); return; }
      // Store token if returned (Sanctum token auth)
      if (data.token) localStorage.setItem('token', data.token);
      onLogin(data);
    } catch(ex) {
      setErr('Network error. Is the server running?');
    } finally { setLoading(false); }
  }

  async function signUp(e){
    e.preventDefault(); setErr('');
    if(!suName||!suEmail||!suPass){ setErr('Please fill in all fields.'); return; }
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(suEmail)){ setErr('Enter a valid email.'); return; }
    if(suPass.length<8){ setErr('Password must be at least 8 characters.'); return; }
    if(suPass!==suConf){ setErr('Passwords do not match.'); return; }
    setLoading(true);
    try {
      await fetch('/sanctum/csrf-cookie', { credentials: 'include' });
      const res = await apiFetch('/api/register', {
        method: 'POST',
        body: JSON.stringify({ name: suName, email: suEmail, password: suPass, password_confirmation: suConf }),
      });
      const data = await res.json();
      if (!res.ok) { setErr(data.message || 'Registration failed.'); return; }
      if (data.token) localStorage.setItem('token', data.token);
      onLogin(data);
    } catch(ex) {
      setErr('Network error. Is the server running?');
    } finally { setLoading(false); }
  }

  return (
    <div style={{position:'fixed',inset:0,background:'var(--bg)',display:'flex',alignItems:'center',justifyContent:'center',flexDirection:'column',zIndex:1000}}>
      <div style={{position:'absolute',inset:0,overflow:'hidden',pointerEvents:'none'}}>
        <div style={{position:'absolute',top:'5%',left:'10%',width:600,height:600,background:'radial-gradient(circle,rgba(0,255,224,.05) 0%,transparent 70%)'}}/>
        <div style={{position:'absolute',bottom:'5%',right:'5%',width:500,height:500,background:'radial-gradient(circle,rgba(0,122,255,.05) 0%,transparent 70%)'}}/>
      </div>

      <div style={{textAlign:'center',marginBottom:28,position:'relative'}}>
        <div style={{display:'inline-flex',alignItems:'center',gap:10,fontWeight:800,fontSize:22,letterSpacing:'-.02em'}}>
          <div style={{width:38,height:38,background:'linear-gradient(135deg,var(--neon),var(--neon2))',borderRadius:9,display:'flex',alignItems:'center',justifyContent:'center'}}>
            <ShieldIcon size={20}/>
          </div>
          VulnSight
        </div>
        <p style={{color:'var(--muted)',fontSize:12,marginTop:6,fontFamily:'JetBrains Mono,monospace'}}>Web Application Vulnerability Scanner</p>
      </div>

      <div style={{width:400,background:'var(--surface)',border:'1px solid var(--border)',borderRadius:16,padding:36,position:'relative',overflow:'hidden'}}>
        <div style={{position:'absolute',top:-1,left:'15%',right:'15%',height:2,background:'linear-gradient(90deg,transparent,var(--neon),transparent)'}}/>
        <div style={{position:'absolute',top:-120,left:'50%',transform:'translateX(-50%)',width:280,height:280,background:'radial-gradient(circle,rgba(0,255,224,.07) 0%,transparent 70%)',pointerEvents:'none'}}/>

        <div style={{display:'flex',gap:3,background:'var(--bg)',borderRadius:8,padding:3,marginBottom:26}}>
          {['signin','signup'].map(t=>(
            <button key={t} className={`auth-tab${tab===t?' active':''}`} style={{flex:1}} onClick={()=>{setTab(t);setErr('');}}>
              {t==='signin'?'Sign In':'Sign Up'}
            </button>
          ))}
        </div>

        {err && <div style={{background:'rgba(255,68,68,.08)',border:'1px solid rgba(255,68,68,.2)',borderRadius:7,padding:'8px 12px',fontSize:12,color:'var(--red)',marginBottom:14}}>{err}</div>}

        {tab==='signin' ? (
          <form onSubmit={signIn} style={{display:'flex',flexDirection:'column',gap:14}}>
            <div><label className="form-label">Email</label>
              <input className="wavs-input" type="email" placeholder="you@example.com" value={siEmail} onChange={e=>setSiEmail(e.target.value)} autoComplete="email"/></div>
            <div><label className="form-label">Password</label>
              <input className="wavs-input" type="password" placeholder="••••••••" value={siPass} onChange={e=>setSiPass(e.target.value)} autoComplete="current-password"/></div>
            <button type="submit" className="btn-primary" style={{width:'100%',justifyContent:'center',marginTop:4}} disabled={loading}>
              {loading ? 'Signing in…' : 'Sign In'}
            </button>
          </form>
        ):(
          <form onSubmit={signUp} style={{display:'flex',flexDirection:'column',gap:14}}>
            <div><label className="form-label">Full Name</label>
              <input className="wavs-input" placeholder="John Doe" value={suName} onChange={e=>setSuName(e.target.value)} autoComplete="name"/></div>
            <div><label className="form-label">Email</label>
              <input className="wavs-input" type="email" placeholder="you@example.com" value={suEmail} onChange={e=>setSuEmail(e.target.value)} autoComplete="email"/></div>
            <div><label className="form-label">Password</label>
              <input className="wavs-input" type="password" placeholder="Min 8 chars" value={suPass} onChange={e=>setSuPass(e.target.value)} autoComplete="new-password"/></div>
            <div><label className="form-label">Confirm Password</label>
              <input className="wavs-input" type="password" placeholder="••••••••" value={suConf} onChange={e=>setSuConf(e.target.value)} autoComplete="new-password"/></div>
            <button type="submit" className="btn-primary" style={{width:'100%',justifyContent:'center',marginTop:4}} disabled={loading}>
              {loading ? 'Creating…' : 'Create Account'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

// ─── Sidebar ──────────────────────────────────────────────────────────────────
// User nav items
const USER_NAV = [
  {id:'dashboard',label:'Dashboard',icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>},
  {id:'activity',label:'Live Activity',icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>},
  {id:'vulnerabilities',label:'Vulnerabilities',icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>},
  {id:'targets',label:'Targets',icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>},
  {id:'authentication',label:'Auth Vault',icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>},
  {id:'configuration',label:'Scan Settings',icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93l-1.41 1.41M4.93 4.93l1.41 1.41M12 2v2M12 20v2M2 12h2M20 12h2M19.07 19.07l-1.41-1.41M4.93 19.07l1.41-1.41"/></svg>},
];

// Admin-only extra nav items
const ADMIN_NAV = [
  {id:'dashboard',label:'Dashboard',icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>},
  {id:'activity',label:'Live Activity',icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>},
  {id:'vulnerabilities',label:'Vulnerabilities',icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>},
  {id:'targets',label:'Targets',icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>},
  {id:'authentication',label:'Auth Vault',icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>},
  {id:'configuration',label:'Scan Settings',icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93l-1.41 1.41M4.93 4.93l1.41 1.41M12 2v2M12 20v2M2 12h2M20 12h2M19.07 19.07l-1.41-1.41M4.93 19.07l1.41-1.41"/></svg>},
  // ── Admin-only section ──
  {id:'admin-users',   label:'Users',        admin:true, icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>},
  {id:'admin-scans',   label:'All Scans',    admin:true, icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>},
  {id:'admin-health',  label:'System Health',admin:true, icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>},
  {id:'admin-settings',label:'Platform',     admin:true, icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93l-1.41 1.41M4.93 4.93l1.41 1.41M12 2v2M12 20v2M2 12h2M20 12h2M19.07 19.07l-1.41-1.41M4.93 19.07l1.41-1.41"/></svg>},
];


function Sidebar({ activeTab, setTab, user, isAdmin, onSignOut, vulnCount }){
  const [collapsed, setCollapsed] = React.useState(false);

  const USER_SECTIONS = [
    {
      label: 'Overview',
      items: [
        {id:'dashboard',label:'Dashboard',icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="1.8"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>},
        {id:'activity', label:'Live Activity',icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="1.8"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>},
      ]
    },
    {
      label: 'Scanner',
      items: [
        {id:'vulnerabilities',label:'Vulnerabilities',icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="1.8"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>, badge: vulnCount > 0 ? {val:vulnCount,cls:'red'} : null},
        {id:'targets',    label:'Targets',     icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="1.8"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>},
        {id:'authentication',label:'Auth Vault',icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="1.8"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>},
      ]
    },
    {
      label: 'Configuration',
      items: [
        {id:'configuration',label:'Scan Settings',icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="1.8"><path d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><circle cx="12" cy="12" r="3"/></svg>},
      ]
    },
  ];

  const ADMIN_SECTIONS = [
    {
      label: 'Overview',
      items: [
        {id:'dashboard',  label:'Dashboard',   icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="1.8"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>},
        {id:'activity',   label:'Live Activity',icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="1.8"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>},
      ]
    },
    {
      label: 'Scanner',
      items: [
        {id:'vulnerabilities',label:'Vulnerabilities',icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="1.8"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>, badge: vulnCount > 0 ? {val:vulnCount,cls:'red'} : null},
        {id:'targets',    label:'Targets',     icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="1.8"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>},
        {id:'authentication',label:'Auth Vault',icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="1.8"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>},
        {id:'configuration',label:'Scan Settings',icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="1.8"><path d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><circle cx="12" cy="12" r="3"/></svg>},
      ]
    },
    {
      label: 'Administration',
      adminOnly: true,
      items: [
        {id:'admin-users',  label:'Users',        icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="1.8"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>},
        {id:'admin-scans',  label:'All Scans',    icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="1.8"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>},
        {id:'admin-health', label:'System Health', icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="1.8"><path d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2v-4M9 21H5a2 2 0 01-2-2v-4m0 0h18"/></svg>},
        {id:'admin-settings',label:'Platform',    icon:<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="1.8"><path d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><circle cx="12" cy="12" r="3"/></svg>},
      ]
    },
  ];

  const sections = isAdmin ? ADMIN_SECTIONS : USER_SECTIONS;
  const sideW = collapsed ? 54 : 236;

  const badgeStyle = (cls) => {
    if (cls === 'red')    return {background:'#f05050',color:'#fff'};
    if (cls === 'orange') return {background:'#f59e0b',color:'#000'};
    return {background:'rgba(0,245,196,.15)',color:'var(--neon)',border:'1px solid rgba(0,245,196,.25)'};
  };

  return (
    <nav style={{
      position:'fixed',left:0,top:0,bottom:0,width:sideW,
      background:'linear-gradient(180deg,var(--surface) 0%,var(--bg) 100%)',
      borderRight:'1px solid var(--border)',
      display:'flex',flexDirection:'column',zIndex:100,
      transition:'width .28s cubic-bezier(.22,1,.36,1)',overflow:'hidden'
    }}>
      {/* Header */}
      <div style={{padding:'18px 14px 15px',borderBottom:'1px solid var(--border)',display:'flex',alignItems:'center',gap:10,flexShrink:0}}>
        <div style={{
          width:40,height:40,flexShrink:0,
          background:'linear-gradient(140deg,rgba(0,245,196,.2),rgba(59,130,246,.2))',
          border:'1px solid rgba(0,245,196,.25)',borderRadius:8,
          display:'flex',alignItems:'center',justifyContent:'center',
          boxShadow:'0 0 12px rgba(0,245,196,.15)',cursor: collapsed ? 'pointer' : 'default'
        }} onClick={()=>{ if(collapsed) setCollapsed(false); }}>
          <ShieldIcon size={20}/>
        </div>
        {!collapsed && <>
          <span style={{
            fontSize:20,fontWeight:700,letterSpacing:'-.03em',
            background:'linear-gradient(135deg,#fff 20%,var(--neon) 100%)',
            WebkitBackgroundClip:'text',WebkitTextFillColor:'transparent',
            whiteSpace:'nowrap'
          }}>VulnSight</span>
          <span style={{
            fontSize:9,fontWeight:700,letterSpacing:'.08em',textTransform:'uppercase',
            color:isAdmin ? 'var(--orange)' : 'var(--neon)',
            background: isAdmin ? 'rgba(245,158,11,.1)' : 'rgba(0,245,196,.1)',
            border: isAdmin ? '1px solid rgba(245,158,11,.2)' : '1px solid rgba(0,245,196,.2)',
            padding:'2px 6px',borderRadius:4,marginLeft:'auto',flexShrink:0,whiteSpace:'nowrap'
          }}>{isAdmin ? 'ADMIN' : 'USER'}</span>
          <button onClick={()=>setCollapsed(true)} style={{
            background:'none',border:'none',cursor:'pointer',padding:6,
            borderRadius:7,color:'var(--muted)',display:'flex',flexDirection:'column',
            gap:4,width:17,flexShrink:0,transition:'color .15s'
          }} title="Collapse sidebar"
            onMouseEnter={e=>e.currentTarget.style.color='var(--text)'}
            onMouseLeave={e=>e.currentTarget.style.color='var(--muted)'}>
            <span style={{display:'block',height:2,borderRadius:2,background:'currentColor',width:17}}/>
            <span style={{display:'block',height:2,borderRadius:2,background:'currentColor',width:11}}/>
            <span style={{display:'block',height:2,borderRadius:2,background:'currentColor',width:17}}/>
          </button>
        </>}
      </div>

      {/* Nav sections */}
      <div style={{flex:1,overflowY:'auto',overflowX:'hidden',padding: collapsed ? '10px 4px 0' : '10px 8px 0'}}>
        {sections.map((section, si) => (
          <div key={si} style={{marginTop: si > 0 ? 4 : 12}}>
            {!collapsed && (
              <span style={{
                fontSize:12,fontWeight:600,letterSpacing:'.1em',
                color: section.adminOnly ? 'var(--orange)' : 'white',
                textTransform:'uppercase',padding:'0 8px',
                marginBottom:3,display:'block',opacity: section.adminOnly ? .85 : 1
              }}>{section.label}</span>
            )}
            {section.items.map(item => (
              <div key={item.id}
                className={`nav-item${activeTab===item.id?' active':''}`}
                onClick={()=>setTab(item.id)}
                title={collapsed ? item.label : undefined}
                style={collapsed ? {justifyContent:'center',padding:'10px 0',gap:0,fontSize:0} : {}}
              >
                {item.icon}
                {!collapsed && <span style={{flex:1}}>{item.label}</span>}
                {!collapsed && item.badge && (
                  <span style={{
                    marginLeft:'auto',fontSize:10,fontWeight:700,
                    padding:'1px 6px',borderRadius:10,minWidth:18,textAlign:'center',
                    fontFamily:'DM Mono,monospace',...badgeStyle(item.badge.cls)
                  }}>{item.badge.val}</span>
                )}
              </div>
            ))}
          </div>
        ))}
      </div>

      {/* Footer user chip */}
      <div style={{padding: collapsed ? '10px 4px' : 10, borderTop:'1px solid var(--border)',flexShrink:0}}>
        <div style={{
          display:'flex',alignItems:'center',gap:9,
          padding: collapsed ? 8 : '8px 10px',
          background:'var(--surface2)',borderRadius:10,cursor:'pointer',
          border:'1px solid var(--border)',transition:'all .15s',
          justifyContent: collapsed ? 'center' : 'flex-start'
        }}
          onClick={onSignOut} title={collapsed ? 'Sign out' : undefined}
          onMouseEnter={e=>{e.currentTarget.style.borderColor='var(--border-h)';e.currentTarget.style.background='var(--surface3);';}}
          onMouseLeave={e=>{e.currentTarget.style.borderColor='var(--border)';e.currentTarget.style.background='var(--surface2)';}}>
          <div style={{
            width:28,height:28,borderRadius:'50%',flexShrink:0,
            background: isAdmin ? 'linear-gradient(135deg,var(--orange),var(--red))' : 'linear-gradient(135deg,var(--neon),#3b82f6)',
            display:'flex',alignItems:'center',justifyContent:'center',
            fontSize:11,fontWeight:700,color: isAdmin ? '#fff' : '#000'
          }}>{user.name.slice(0,2).toUpperCase()}</div>
          {!collapsed && <>
            <div style={{flex:1,minWidth:0}}>
              <p style={{fontSize:12,fontWeight:600,whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>{user.name}</p>
              <p style={{fontSize:10,color:'var(--muted)',marginTop:1}}>{user.email}</p>
            </div>
            <svg width="11" height="11" fill="none" stroke="var(--muted)" viewBox="0 0 24 24" strokeWidth="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9"/></svg>
          </>}
        </div>
      </div>
    </nav>
  );
}


// ─── Vuln Modal ───────────────────────────────────────────────────────────────
function VulnModal({ vuln, onClose }){
  useEffect(()=>{
    function onKey(e){ if(e.key==='Escape') onClose(); }
    window.addEventListener('keydown',onKey);
    return()=>window.removeEventListener('keydown',onKey);
  },[onClose]);

  if(!vuln) return null;
  const fix = VULN_FIX_DB[vuln.name]||{summary:'Investigate this endpoint for the reported vulnerability.',steps:['Review the affected endpoint carefully.','Apply the principle of least privilege.','Consult OWASP guidelines for remediation.'],ref:'https://owasp.org/www-project-top-ten/'};
  const iconBg={critical:'rgba(255,68,68,.12)',high:'rgba(255,140,0,.12)',medium:'rgba(255,215,0,.08)',low:'rgba(0,208,132,.08)'};
  const iconStroke={critical:'var(--red)',high:'var(--orange)',medium:'var(--yellow)',low:'var(--green)'};

  return (
    <div className="modal-overlay" onClick={e=>{ if(e.target===e.currentTarget) onClose(); }}>
      <div style={{width:560,maxWidth:'95vw',background:'var(--surface)',border:'1px solid var(--border)',borderRadius:16,position:'relative',overflow:'hidden',maxHeight:'90vh',display:'flex',flexDirection:'column'}}>
        <div style={{position:'absolute',top:-1,left:'10%',right:'10%',height:2,background:'linear-gradient(90deg,transparent,var(--red),transparent)'}}/>
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'18px 22px',borderBottom:'1px solid var(--border)'}}>
          <div style={{display:'flex',alignItems:'center',gap:12}}>
            <div style={{width:34,height:34,borderRadius:8,background:iconBg[vuln.sev]||'var(--surface2)',display:'flex',alignItems:'center',justifyContent:'center',flexShrink:0}}>
              <svg width="16" height="16" fill="none" stroke={iconStroke[vuln.sev]||'var(--neon)'} viewBox="0 0 24 24" strokeWidth="2.5"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
            </div>
            <div>
              <p style={{fontSize:15,fontWeight:800}}>{vuln.name}</p>
              <div style={{display:'flex',alignItems:'center',gap:8,marginTop:3}}>
                <Badge sev={vuln.sev}/>
                <span style={{fontFamily:'JetBrains Mono,monospace',fontSize:10,color:'var(--muted)'}}>{vuln.cve}</span>
              </div>
            </div>
          </div>
          <button onClick={onClose} style={{background:'var(--surface2)',border:'1px solid var(--border)',borderRadius:7,width:30,height:30,cursor:'pointer',color:'var(--muted)',fontSize:16,display:'flex',alignItems:'center',justifyContent:'center',flexShrink:0}}>×</button>
        </div>
        <div style={{padding:'20px 22px',overflowY:'auto'}}>
          <div style={{marginBottom:16}}>
            <span style={{fontSize:10,fontWeight:700,color:'var(--muted)',textTransform:'uppercase',letterSpacing:'.07em',display:'block',marginBottom:5}}>Affected Endpoint</span>
            <code style={{fontSize:12,color:'var(--neon)',background:'rgba(0,255,224,.05)',border:'1px solid rgba(0,255,224,.1)',padding:'7px 12px',borderRadius:6,display:'block',wordBreak:'break-all'}}>{vuln.url}</code>
          </div>
          <div style={{marginBottom:16}}>
            <span style={{fontSize:10,fontWeight:700,color:'var(--muted)',textTransform:'uppercase',letterSpacing:'.07em',display:'block',marginBottom:5}}>What Was Found</span>
            <p style={{fontSize:13,lineHeight:1.65,color:'var(--text)',background:'var(--surface2)',border:'1px solid var(--border)',padding:'11px 14px',borderRadius:8}}>{fix.summary}</p>
          </div>
          <div style={{marginBottom:16}}>
            <span style={{fontSize:10,fontWeight:700,color:'var(--neon)',textTransform:'uppercase',letterSpacing:'.07em',display:'block',marginBottom:8}}>✓ Recommended Fixes</span>
            <ol style={{listStyle:'none',display:'flex',flexDirection:'column',gap:7,padding:0,margin:0}}>
              {fix.steps.map((s,i)=>(
                <li key={i} style={{display:'flex',gap:10,alignItems:'flex-start',padding:'9px 12px',background:'var(--surface2)',border:'1px solid var(--border)',borderRadius:8,fontSize:12,lineHeight:1.55}}>
                  <span style={{flexShrink:0,width:20,height:20,borderRadius:'50%',background:'rgba(0,255,224,.1)',border:'1px solid rgba(0,255,224,.2)',display:'flex',alignItems:'center',justifyContent:'center',fontSize:10,fontWeight:700,color:'var(--neon)',fontFamily:'JetBrains Mono,monospace'}}>{i+1}</span>
                  <span style={{color:'var(--text)'}}>{s}</span>
                </li>
              ))}
            </ol>
          </div>
          <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'10px 13px',background:'rgba(0,122,255,.05)',border:'1px solid rgba(0,122,255,.14)',borderRadius:8}}>
            <span style={{fontSize:11,color:'#93c5fd',fontWeight:600}}>OWASP Reference</span>
            <a href={fix.ref} target="_blank" rel="noopener noreferrer" style={{fontSize:11,fontFamily:'JetBrains Mono,monospace',color:'var(--neon)',textDecoration:'none'}}>View →</a>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Dashboard Tab ────────────────────────────────────────────────────────────
function DashboardTab({ stats, vulns, scanStatus, progress, phase, setTab, onOpenVuln, isAdmin }){
  const counts = {critical:0,high:0,medium:0,low:0};
  vulns.forEach(v=>{ if(counts[v.sev]!==undefined) counts[v.sev]++; });

  return (
    <div className="fade-in">
      {/* Admin banner */}
      {isAdmin && (
        <div style={{marginBottom:14,padding:'10px 16px',background:'rgba(255,140,0,.06)',border:'1px solid rgba(255,140,0,.2)',borderRadius:10,display:'flex',alignItems:'center',gap:10}}>
          <AdminIcon size={14}/>
          <span style={{fontSize:12,color:'var(--orange)',fontWeight:600}}>Admin view — you can see all scans and manage users from the Administration section.</span>
        </div>
      )}

      <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:10,marginBottom:16}}>
        {[
          {label:'Requests Sent',val:stats.requestsSent.toLocaleString(),delta:`+${stats.reqRate}/s`,color:'var(--neon)'},
          {label:'URLs Discovered',val:stats.urlsDiscovered,delta:`+${stats.urlRate}/s`,color:'var(--neon2)'},
          {label:'Vulnerabilities',val:stats.vulnCount,delta:'live',color:'var(--orange)'},
          {label:'Critical Issues',val:counts.critical,delta:'critical',color:'var(--red)'},
        ].map((s,i)=>(
          <div key={i} className="stat-card">
            <div style={{position:'absolute',top:14,right:14,fontFamily:'JetBrains Mono,monospace',fontSize:10,color:s.color,opacity:.85}}>{s.delta}</div>
            <div style={{fontFamily:'JetBrains Mono,monospace',fontSize:28,fontWeight:700,lineHeight:1.1,marginBottom:6,background:`linear-gradient(135deg,#fff,${s.color})`,WebkitBackgroundClip:'text',WebkitTextFillColor:'transparent'}}>{s.val}</div>
            <div style={{fontSize:11,color:'var(--muted)',fontWeight:600,textTransform:'uppercase',letterSpacing:'.04em'}}>{s.label}</div>
          </div>
        ))}
      </div>

      <div style={{display:'grid',gridTemplateColumns:'1fr 260px',gap:12,marginBottom:16}}>
        {scanStatus!=='idle' ? (
          <div className="card">
            <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:12}}>
              <span className="card-title" style={{margin:0}}>Scan Progress</span>
              <span style={{fontFamily:'JetBrains Mono,monospace',fontSize:22,fontWeight:700,color:'var(--neon)'}}>{Math.floor(progress)}%</span>
            </div>
            <div className="prog-track"><div className="prog-bar" style={{width:`${progress}%`}}/></div>
            <p style={{fontSize:11,color:'var(--muted)',marginTop:8,fontFamily:'JetBrains Mono,monospace'}}>{phase}</p>
          </div>
        ):(
          <div className="card">
            <span className="card-title">Quick Start</span>
            <p style={{fontSize:12,color:'var(--muted)',lineHeight:1.65}}>Add a target and press <strong style={{color:'var(--neon)'}}>Start Scan</strong> to begin. Findings appear in real-time.</p>
            <button onClick={()=>setTab('targets')} style={{marginTop:10,fontSize:12,fontWeight:700,color:'var(--neon)',background:'none',border:'none',cursor:'pointer',fontFamily:'Syne,sans-serif'}}>+ Add Target →</button>
          </div>
        )}

        <div className="card">
          <span className="card-title">Severity Breakdown</span>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:8}}>
            {[{k:'critical',color:'var(--red)',rgb:'255,68,68'},{k:'high',color:'var(--orange)',rgb:'255,140,0'},{k:'medium',color:'var(--yellow)',rgb:'255,215,0'},{k:'low',color:'var(--green)',rgb:'0,208,132'}].map(({k,color,rgb})=>(
              <div key={k} style={{textAlign:'center',padding:10,background:`rgba(${rgb},.05)`,border:`1px solid rgba(${rgb},.14)`,borderRadius:8}}>
                <div style={{fontFamily:'JetBrains Mono,monospace',fontSize:20,fontWeight:700,color}}>{counts[k]}</div>
                <div style={{fontSize:10,color:'var(--muted)',fontWeight:700,textTransform:'uppercase',marginTop:2}}>{k}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card">
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:12}}>
          <span className="card-title" style={{margin:0}}>Recent Findings</span>
          <button onClick={()=>setTab('vulnerabilities')} style={{fontSize:11,fontWeight:700,color:'var(--neon)',background:'none',border:'none',cursor:'pointer',fontFamily:'Syne,sans-serif'}}>View all →</button>
        </div>
        {vulns.length===0 ? (
          <div className="empty-state">No findings yet. Start a scan to detect vulnerabilities.</div>
        ):(
          vulns.slice(0,8).map(v=>(
            <div key={v.id} style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'11px 14px',borderBottom:'1px solid rgba(30,45,61,.4)'}}>
              <div style={{display:'flex',alignItems:'center',gap:10,flex:1,minWidth:0}}>
                <div style={{width:6,height:6,borderRadius:'50%',flexShrink:0,background:{critical:'var(--red)',high:'var(--orange)',medium:'var(--yellow)',low:'var(--green)'}[v.sev]}}/>
                <div style={{minWidth:0}}>
                  <p style={{fontSize:13,fontWeight:700}}>{v.name}</p>
                  <p style={{fontSize:11,color:'var(--muted)',fontFamily:'JetBrains Mono,monospace',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{v.url}</p>
                </div>
              </div>
              <div style={{display:'flex',alignItems:'center',gap:8,flexShrink:0}}>
                <span style={{fontFamily:'JetBrains Mono,monospace',fontSize:10,color:'var(--muted)'}}>{v.time}</span>
                <Badge sev={v.sev}/>
                <button style={{fontSize:11,fontWeight:700,color:'var(--neon)',background:'none',border:'none',cursor:'pointer',fontFamily:'Syne,sans-serif'}} onClick={()=>onOpenVuln(v)}>Fix →</button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// ─── Vulnerabilities Tab ──────────────────────────────────────────────────────
function VulnerabilitiesTab({ vulns, onOpenVuln }){
  const [filter, setFilter] = useState('all');
  const filtered = filter==='all' ? vulns : vulns.filter(v=>v.sev===filter);

  function exportCsv(){
    if(!vulns.length) return;
    const csv=[['Type','URL','Severity','CVE','Detected'],...vulns.map(v=>[v.name,v.url,v.sev,v.cve||'',v.time])].map(r=>r.map(c=>'"'+String(c).replace(/"/g,'""')+'"').join(',')).join('\n');
    const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'})); a.download=`wavs-report-${new Date().toISOString().slice(0,10)}.csv`; a.click();
  }

  return (
    <div className="fade-in">
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:18}}>
        <div><div style={{fontSize:20,fontWeight:800,letterSpacing:'-.02em'}}>Vulnerability Report</div>
        <p style={{fontSize:12,color:'var(--muted)',marginTop:2}}>{vulns.length} findings detected</p></div>
        <div style={{display:'flex',gap:8}}>
          <select className="wavs-input" style={{width:'auto',minWidth:140}} value={filter} onChange={e=>setFilter(e.target.value)}>
            <option value="all">All Severity</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <button className="btn-primary" onClick={exportCsv} style={{padding:'8px 16px'}}>
            <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><path d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
            Export CSV
          </button>
        </div>
      </div>
      <div className="card" style={{padding:0,overflow:'hidden'}}>
        <table className="wavs-table">
          <thead><tr><th>Type</th><th>URL</th><th>Severity</th><th>Status</th><th>Detected</th><th></th></tr></thead>
          <tbody>
            {filtered.length===0 ? (
              <tr><td colSpan={6} className="empty-state">No vulnerabilities detected yet.</td></tr>
            ):filtered.map(v=>(
              <tr key={v.id}>
                <td style={{fontWeight:700}}>{v.name}</td>
                <td><code style={{fontSize:11,color:'var(--neon)'}}>{v.url}</code></td>
                <td><Badge sev={v.sev}/></td>
                <td style={{fontSize:12,color:'var(--green)'}}>● Confirmed</td>
                <td style={{fontFamily:'JetBrains Mono,monospace',fontSize:11,color:'var(--muted)'}}>{v.time}</td>
                <td><button style={{fontSize:11,fontWeight:700,color:'var(--neon)',background:'none',border:'none',cursor:'pointer',fontFamily:'Syne,sans-serif'}} onClick={()=>onOpenVuln(v)}>Details / Fix →</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Targets Tab ──────────────────────────────────────────────────────────────
function TargetsTab({ targets, setTargets, userEmail, showToast }){
  const [url, setUrl]   = useState('');
  const [type, setType] = useState('Web Application');

  function addTarget(){
    const trimmed = url.trim();
    if(!trimmed){ showToast('Enter a URL','warn'); return; }
    try{ new URL(trimmed); }catch{ showToast('Enter a valid URL (include https://)','warn'); return; }
    if(targets.find(t=>t.url===trimmed)){ showToast('Target already added','warn'); return; }
    const t={id:'local_'+Date.now(),url:trimmed,type};
    const next=[...targets,t];
    setTargets(next);
    localStorage.setItem(`wavs_${userEmail}_targets`, JSON.stringify(next));
    setUrl('');
    showToast('Target added','success');
  }

  function removeTarget(id){
    const next=targets.filter(t=>t.id!==id);
    setTargets(next);
    localStorage.setItem(`wavs_${userEmail}_targets`, JSON.stringify(next));
    showToast('Target removed','info');
  }

  return (
    <div className="fade-in">
      <div style={{fontSize:20,fontWeight:800,letterSpacing:'-.02em',marginBottom:18}}>Target Management</div>
      <div className="card" style={{marginBottom:14}}>
        <span className="card-title">Add Target</span>
        <div style={{display:'flex',gap:8,flexWrap:'wrap'}}>
          <input className="wavs-input" style={{flex:1,minWidth:200}} placeholder="https://target.example.com" value={url} onChange={e=>setUrl(e.target.value)} onKeyDown={e=>e.key==='Enter'&&addTarget()}/>
          <select className="wavs-input" style={{width:160}} value={type} onChange={e=>setType(e.target.value)}>
            <option>Web Application</option><option>API Endpoint</option><option>Admin Panel</option><option>REST API</option>
          </select>
          <button className="btn-primary" onClick={addTarget}>+ Add Target</button>
        </div>
      </div>
      <div className="card" style={{padding:0,overflow:'hidden'}}>
        <table className="wavs-table">
          <thead><tr><th>URL</th><th>Type</th><th>Status</th><th></th></tr></thead>
          <tbody>
            {targets.length===0 ? (
              <tr><td colSpan={4} className="empty-state">No targets added. Add a URL above to get started.</td></tr>
            ):targets.map(t=>(
              <tr key={t.id}>
                <td><code style={{fontSize:12,color:'var(--neon)'}}>{t.url}</code></td>
                <td style={{fontSize:12,color:'var(--muted)'}}>{t.type}</td>
                <td><span style={{fontSize:11,color:'var(--muted)',fontFamily:'JetBrains Mono,monospace'}}>● Pending</span></td>
                <td><button className="btn-danger" onClick={()=>removeTarget(t.id)}>Remove</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Auth Vault Tab ───────────────────────────────────────────────────────────
const CRED_TYPES = [
  { id:'cookie',  label:'Cookie',       icon:<CookieIcon size={18}/>,  desc:'Paste a session cookie from your browser DevTools after logging in.' },
  { id:'bearer',  label:'Bearer Token', icon:<TokenIcon size={18}/>,   desc:'Used for API auth. Copy the Authorization header value (without "Bearer ").' },
  { id:'basic',   label:'Basic Auth',   desc:'Username + password for HTTP Basic Authentication protected routes.', icon:<UserPassIcon size={18}/> },
];
const HOW_IT_WORKS = [
  { num:'1', title:'Log in to your target app', body:'Use a real browser, log in to the application you want to scan.' },
  { num:'2', title:'Copy your session credential', body:'From DevTools → Application → Cookies, or the Network tab → copy the Authorization header.' },
  { num:'3', title:'Save it here in Auth Vault', body:'VulnSight will attach it to every scan request, letting it reach protected pages & APIs.' },
  { num:'4', title:'Run a scan', body:'Vulnerabilities behind login walls — IDOR, broken access control, auth bypass — are now reachable.' },
];

function AuthTab({ creds, setCreds, userEmail, showToast }){
  const [name,  setName]  = useState('');
  const [type,  setType]  = useState('cookie');
  const [token, setToken] = useState('');
  const [user,  setUser]  = useState('');
  const [pass,  setPass]  = useState('');
  const [revealed, setRevealed] = useState({});
  const typeInfo = CRED_TYPES.find(t=>t.id===type);

  function addCred(){
    if(!name.trim()){ showToast('Enter a name for this credential','warn'); return; }
    if(type!=='basic' && !token.trim()){ showToast('Paste your token / cookie value','warn'); return; }
    if(type==='basic' && (!user.trim()||!pass.trim())){ showToast('Enter both username and password','warn'); return; }
    const c={id:'local_'+Date.now(),name:name.trim(),type,token:type!=='basic'?token.trim():'',username:type==='basic'?user.trim():''};
    const next=[...creds,c];
    setCreds(next);
    localStorage.setItem(`wavs_${userEmail}_credentials`, JSON.stringify(next));
    setName(''); setToken(''); setUser(''); setPass('');
    showToast('Credential saved to Auth Vault','success');
  }

  function removeCred(id){
    const next=creds.filter(c=>c.id!==id);
    setCreds(next);
    localStorage.setItem(`wavs_${userEmail}_credentials`, JSON.stringify(next));
    setRevealed(p=>{ const n={...p}; delete n[id]; return n; });
    showToast('Credential removed','info');
  }

  function toggleReveal(id){ setRevealed(p=>({...p,[id]:!p[id]})); }

  return (
    <div className="fade-in">
      <div style={{display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:18,gap:12,flexWrap:'wrap'}}>
        <div>
          <div style={{fontSize:20,fontWeight:800,letterSpacing:'-.02em',display:'flex',alignItems:'center',gap:10}}>
            <div style={{width:32,height:32,borderRadius:8,background:'linear-gradient(135deg,rgba(0,255,224,.15),rgba(0,122,255,.15))',border:'1px solid rgba(0,255,224,.2)',display:'flex',alignItems:'center',justifyContent:'center'}}>
              <TokenIcon size={16}/>
            </div>
            Auth Vault
          </div>
          <p style={{fontSize:12,color:'var(--muted)',marginTop:4,lineHeight:1.5,maxWidth:480}}>
            Store session credentials so the scanner can access <strong style={{color:'var(--text)'}}>authenticated routes</strong>.
          </p>
        </div>
        <div style={{display:'flex',alignItems:'center',gap:6,padding:'6px 12px',background:'rgba(0,255,224,.06)',border:'1px solid rgba(0,255,224,.18)',borderRadius:8}}>
          <div style={{width:6,height:6,borderRadius:'50%',background:'var(--neon)',boxShadow:'0 0 6px var(--neon)'}}/>
          <span style={{fontSize:11,fontWeight:700,color:'var(--neon)',fontFamily:'JetBrains Mono,monospace'}}>{creds.length} stored</span>
        </div>
      </div>
      <div style={{marginBottom:14,background:'rgba(0,122,255,.05)',border:'1px solid rgba(0,122,255,.16)',borderRadius:12,padding:'16px 18px'}}>
        <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:12}}>
          <svg width="14" height="14" fill="none" stroke="#60a5fa" viewBox="0 0 24 24" strokeWidth="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
          <span style={{fontSize:11,fontWeight:700,color:'#60a5fa',textTransform:'uppercase',letterSpacing:'.07em'}}>How It Works</span>
        </div>
        <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:8}}>
          {HOW_IT_WORKS.map((s)=>(
            <div key={s.num} className="vault-how-step" style={{flexDirection:'column',gap:8}}>
              <div style={{display:'flex',alignItems:'center',gap:8}}>
                <div className="vault-step-num">{s.num}</div>
                <span style={{fontSize:12,fontWeight:700,color:'var(--text)'}}>{s.title}</span>
              </div>
              <p style={{fontSize:11,color:'var(--muted)',lineHeight:1.5}}>{s.body}</p>
            </div>
          ))}
        </div>
      </div>
      <div style={{display:'grid',gridTemplateColumns:'1fr 320px',gap:14,alignItems:'start'}}>
        <div className="card" style={{position:'relative',overflow:'hidden'}}>
          <div style={{position:'absolute',top:-1,left:'5%',right:'5%',height:2,background:'linear-gradient(90deg,transparent,var(--neon),transparent)',opacity:.5}}/>
          <span className="card-title">Add Credential</span>
          <div style={{marginBottom:14}}>
            <label className="form-label">Credential Label</label>
            <input className="wavs-input" placeholder="e.g. Admin Session, API Key – Prod" value={name} onChange={e=>setName(e.target.value)}/>
          </div>
          <div style={{marginBottom:14}}>
            <label className="form-label">Auth Type</label>
            <div className="type-selector">
              {CRED_TYPES.map(t=>(
                <button key={t.id} className={`type-btn${type===t.id?' active '+t.id:''}`} onClick={()=>setType(t.id)}>
                  <span style={{opacity:.85}}>{t.icon}</span>
                  <span style={{fontSize:11}}>{t.label}</span>
                </button>
              ))}
            </div>
            <div style={{marginTop:8,padding:'7px 10px',background:'var(--surface2)',border:'1px solid var(--border)',borderRadius:7,fontSize:11,color:'var(--muted)',lineHeight:1.5}}>
              💡 {typeInfo?.desc}
            </div>
          </div>
          {(type==='cookie'||type==='bearer') && (
            <div style={{marginBottom:14}}>
              <label className="form-label">{type==='cookie' ? 'Cookie Value' : 'Token Value'}</label>
              <input className="wavs-input" type="password" placeholder={type==='cookie' ? 'Paste cookie string…' : 'Paste token value…'} value={token} onChange={e=>setToken(e.target.value)}/>
            </div>
          )}
          {type==='basic' && (
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10,marginBottom:14}}>
              <div><label className="form-label">Username</label><input className="wavs-input" placeholder="admin" value={user} onChange={e=>setUser(e.target.value)}/></div>
              <div><label className="form-label">Password</label><input className="wavs-input" type="password" placeholder="••••••••" value={pass} onChange={e=>setPass(e.target.value)}/></div>
            </div>
          )}
          <button className="btn-primary" style={{width:'100%',justifyContent:'center'}} onClick={addCred}>
            <svg width="13" height="13" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
            Save to Vault
          </button>
        </div>
        <div style={{display:'flex',flexDirection:'column',gap:10}}>
          <div style={{background:'rgba(255,140,0,.05)',border:'1px solid rgba(255,140,0,.18)',borderRadius:12,padding:'14px 16px'}}>
            <div style={{display:'flex',alignItems:'center',gap:7,marginBottom:8}}>
              <svg width="13" height="13" fill="none" stroke="var(--orange)" viewBox="0 0 24 24" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
              <span style={{fontSize:11,fontWeight:700,color:'var(--orange)',textTransform:'uppercase',letterSpacing:'.06em'}}>Security Note</span>
            </div>
            <p style={{fontSize:11,color:'var(--muted)',lineHeight:1.6}}>Credentials are stored locally in your browser and <strong style={{color:'var(--text)'}}>never sent to any server</strong>. Only scan targets you own or have explicit permission to test.</p>
          </div>
          <div style={{background:'rgba(0,208,132,.05)',border:'1px solid rgba(0,208,132,.18)',borderRadius:12,padding:'14px 16px'}}>
            <div style={{display:'flex',alignItems:'center',gap:7,marginBottom:8}}>
              <svg width="13" height="13" fill="none" stroke="var(--green)" viewBox="0 0 24 24" strokeWidth="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
              <span style={{fontSize:11,fontWeight:700,color:'var(--green)',textTransform:'uppercase',letterSpacing:'.06em'}}>Why Auth Matters</span>
            </div>
            <p style={{fontSize:11,color:'var(--muted)',lineHeight:1.6}}>Up to <strong style={{color:'var(--green)'}}>70% of web vulnerabilities</strong> live behind authentication. Storing auth here unlocks full coverage.</p>
          </div>
        </div>
      </div>
      <div style={{marginTop:18}}>
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:12}}>
          <span style={{fontSize:13,fontWeight:700}}>Stored Credentials</span>
          {creds.length>0&&<span style={{fontSize:11,color:'var(--muted)'}}>Click the eye icon to reveal a token</span>}
        </div>
        {creds.length===0 ? (
          <div style={{border:'1px dashed var(--border)',borderRadius:12,padding:'32px',textAlign:'center'}}>
            <div style={{width:40,height:40,borderRadius:10,background:'var(--surface2)',border:'1px solid var(--border)',display:'flex',alignItems:'center',justifyContent:'center',margin:'0 auto 12px'}}><TokenIcon size={18}/></div>
            <p style={{fontSize:13,fontWeight:600,color:'var(--text)',marginBottom:4}}>No credentials yet</p>
            <p style={{fontSize:11,color:'var(--muted)'}}>Add a session cookie or API token above to enable authenticated scanning.</p>
          </div>
        ):(
          <div style={{display:'flex',flexDirection:'column',gap:8}}>
            {creds.map(c=>{
              const tDef=CRED_TYPES.find(t=>t.id===c.type);
              const isRevealed=revealed[c.id];
              const displayVal=c.token?(isRevealed?c.token:'••••••••••••••••••'):(c.username?`${c.username} / ••••••••`:'(no value stored)');
              return (
                <div key={c.id} className={`cred-card ${c.type}`}>
                  <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',gap:12}}>
                    <div style={{display:'flex',alignItems:'center',gap:10,flex:1,minWidth:0}}>
                      <div style={{width:32,height:32,borderRadius:8,background:'var(--surface)',border:'1px solid var(--border)',display:'flex',alignItems:'center',justifyContent:'center',flexShrink:0,color:'var(--muted)'}}>{tDef?.icon}</div>
                      <div style={{flex:1,minWidth:0}}>
                        <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:3}}>
                          <span style={{fontSize:13,fontWeight:700}}>{c.name}</span>
                          <span className={`cred-type-badge ${c.type}`}>{tDef?.label}</span>
                        </div>
                        <div style={{display:'flex',alignItems:'center',gap:6}}>
                          <code style={{fontSize:11,color:'var(--muted)',fontFamily:'JetBrains Mono,monospace',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',maxWidth:260}}>{displayVal}</code>
                          {c.token&&(<button className="btn-icon" onClick={()=>toggleReveal(c.id)} title={isRevealed?'Hide':'Reveal'} style={{padding:'2px 5px'}}><EyeIcon open={!isRevealed} size={12}/></button>)}
                        </div>
                      </div>
                    </div>
                    <button className="btn-danger" style={{display:'flex',alignItems:'center',gap:5,flexShrink:0}} onClick={()=>removeCred(c.id)}><TrashIcon size={11}/> Remove</button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Activity Tab ─────────────────────────────────────────────────────────────
function ActivityTab({ logs, totals, onClear }){
  const logRef = useRef(null);
  const mColors={GET:'#6ee7b7',POST:'#93c5fd',PUT:'#fcd34d',DELETE:'#fca5a5',PATCH:'#c4b5fd'};
  return (
    <div className="fade-in">
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:18}}>
        <div>
          <div style={{fontSize:20,fontWeight:800,letterSpacing:'-.02em'}}>Live Activity Monitor</div>
          <p style={{fontSize:12,color:'var(--muted)',marginTop:3}}>Real-time HTTP traffic from your target</p>
        </div>
        <button className="btn-ghost" onClick={onClear} style={{fontSize:12,padding:'7px 14px'}}>Clear</button>
      </div>
      <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:10,marginBottom:14}}>
        {[['Total',totals.total],['2xx',totals.success],['4xx/5xx',totals.errors],['Avg Time',totals.avgMs?`${totals.avgMs}ms`:'—']].map(([l,v])=>(
          <div key={l} className="card" style={{textAlign:'center',padding:'12px 14px'}}>
            <div style={{fontFamily:'JetBrains Mono,monospace',fontSize:18,fontWeight:700,color:'var(--neon)'}}>{v}</div>
            <div style={{fontSize:10,color:'var(--muted)',fontWeight:700,textTransform:'uppercase',marginTop:2}}>{l}</div>
          </div>
        ))}
      </div>
      <div className="card" style={{padding:0,overflow:'hidden'}}>
        <div style={{fontFamily:'JetBrains Mono,monospace',fontSize:11,maxHeight:480,overflowY:'auto'}} ref={logRef}>
          {logs.length===0 ? (
            <div className="empty-state" style={{fontFamily:'JetBrains Mono,monospace',fontSize:11}}>Waiting for activity…</div>
          ):logs.map((e,i)=>{
            const sColor=e.status>=500?'var(--red)':e.status>=400?'var(--orange)':e.status>=300?'#93c5fd':'var(--green)';
            const mColor=mColors[e.method]||'var(--text)';
            const rowBg=e.status>=500?'rgba(255,68,68,.04)':e.status>=400?'rgba(255,140,0,.03)':'';
            return (
              <div key={i} className="log-row" style={{background:rowBg,fontSize:11}}>
                <span style={{color:'var(--muted)',flexShrink:0,marginRight:10,fontSize:10}}>{e.ts||new Date().toISOString().slice(0,19).replace('T',' ')}</span>
                <span style={{color:mColor,flexShrink:0,width:52,marginRight:4}}>{e.method}</span>
                <span style={{color:'var(--neon)',flex:1,overflow:'hidden',textOverflow:'ellipsis'}}>{e.url}{e.query||''}</span>
                <span style={{color:sColor,flexShrink:0,marginRight:10}}>{e.status}</span>
                <span style={{color:'var(--muted)',flexShrink:0}}>{e.ms?`~${e.ms}ms`:'—'}</span>
                {e.alert && <span className={`badge badge-${e.alert}`} style={{fontSize:9,padding:'1px 6px',marginLeft:6}}>{e.alert}</span>}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ─── Configuration Tab ────────────────────────────────────────────────────────
function ConfigTab({ showToast }){
  const [intensity, setIntensity] = useState('standard');
  const [maxRps, setMaxRps]       = useState(100);
  const [timeout, setTimeout_]    = useState(30);
  const [depth, setDepth]         = useState(5);
  const [exclusions, setExclusions] = useState(['/logout','/delete-account']);
  const [excInput, setExcInput]   = useState('');

  function addExclusion(){
    if(!excInput.trim()) return;
    setExclusions(p=>[...p,excInput.trim()]);
    setExcInput('');
    showToast('Exclusion added','success');
  }

  return (
    <div className="fade-in">
      <div style={{fontSize:20,fontWeight:800,letterSpacing:'-.02em',marginBottom:18}}>Scan Settings</div>
      <div style={{display:'grid',gridTemplateColumns:'1fr 280px',gap:14}}>
        <div>
          <div className="card" style={{marginBottom:14}}>
            <span className="card-title">Scan Intensity</span>
            <div style={{display:'flex',flex:1,gap:10}}>
              {[{id:'passive',emoji:'🌿',label:'Passive',desc:'Read-only. Zero active probing.'},
                {id:'standard',emoji:'⚡',label:'Standard',desc:'Balanced coverage and speed.'},
                {id:'aggressive',emoji:'🔥',label:'Aggressive',desc:'Full exploit coverage. Test envs only.'}].map(x=>(
                <button key={x.id} className={`intensity-card${intensity===x.id?' active':''}`} style={{flex:1}} onClick={()=>setIntensity(x.id)}>
                  <div style={{fontSize:13,fontWeight:700,marginBottom:2}}>{x.emoji} {x.label}</div>
                  <div style={{fontSize:11,color:'var(--muted)'}}>{x.desc}</div>
                </button>
              ))}
            </div>
          </div>
          <div className="card">
            <span className="card-title">Exclusion Rules</span>
            <div style={{display:'flex',gap:8,marginBottom:10}}>
              <input className="wavs-input" style={{flex:1}} placeholder="/logout, /admin/delete" value={excInput} onChange={e=>setExcInput(e.target.value)} onKeyDown={e=>e.key==='Enter'&&addExclusion()}/>
              <button className="btn-ghost" onClick={addExclusion} style={{padding:'8px 14px',fontSize:12}}>Add Rule</button>
            </div>
            <div style={{display:'flex',flexWrap:'wrap',gap:6}}>
              {exclusions.map((ex,i)=>(
                <span key={i} style={{display:'inline-flex',alignItems:'center',gap:5,padding:'3px 10px',background:'var(--surface2)',border:'1px solid var(--border)',borderRadius:20,fontSize:11,fontFamily:'JetBrains Mono,monospace'}}>
                  {ex}
                  <button onClick={()=>setExclusions(p=>p.filter((_,j)=>j!==i))} style={{color:'var(--red)',background:'none',border:'none',cursor:'pointer',padding:0,fontSize:13,lineHeight:1}}>×</button>
                </span>
              ))}
            </div>
          </div>
        </div>
        <div>
          <div className="card" style={{marginBottom:12}}>
            <span className="card-title">Advanced Settings</span>
            <div style={{display:'grid',gap:10}}>
              {[['Max Requests/sec',maxRps,setMaxRps,'number'],['Request Timeout (s)',timeout,setTimeout_,'number'],['Crawl Depth',depth,setDepth,'number']].map(([l,v,s,t])=>(
                <div key={l}><label className="form-label">{l}</label>
                  <input className="wavs-input" type={t} value={v} onChange={e=>s(e.target.value)}/></div>
              ))}
            </div>
          </div>
          <div className="card">
            <span className="card-title">Options</span>
            <div style={{display:'flex',flexDirection:'column',gap:12}}>
              {[['Follow Redirects','Track 301/302 chains'],['JS Execution','Headless browser crawling'],['Auto-Export Report','Download CSV when scan ends']].map(([l,d])=>(
                <div key={l} style={{display:'flex',alignItems:'center',justifyContent:'space-between'}}>
                  <div><p style={{fontSize:13,fontWeight:600}}>{l}</p><p style={{fontSize:11,color:'var(--muted)'}}>{d}</p></div>
                  <label className="toggle"><input type="checkbox" defaultChecked/><div className="toggle-slider"/></label>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Admin-only tabs (placeholders that call real API) ────────────────────────
function AdminUsersTab({ showToast }){
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(()=>{
    apiFetch('/api/admin/users').then(r=>r.json()).then(d=>{ setUsers(d); setLoading(false); }).catch(()=>setLoading(false));
  },[]);

  async function banUser(id){
    await apiFetch(`/api/admin/users/${id}/ban`, {method:'POST'});
    setUsers(p=>p.map(u=>u.id===id?{...u,status:'banned'}:u));
    showToast('User banned','warn');
  }
  async function unbanUser(id){
    await apiFetch(`/api/admin/users/${id}/unban`, {method:'POST'});
    setUsers(p=>p.map(u=>u.id===id?{...u,status:'active'}:u));
    showToast('User unbanned','success');
  }
  async function deleteUser(id){
    if(!window.confirm('Delete this user?')) return;
    await apiFetch(`/api/admin/users/${id}`, {method:'DELETE'});
    setUsers(p=>p.filter(u=>u.id!==id));
    showToast('User deleted','info');
  }

  return (
    <div className="fade-in">
      <div style={{fontSize:20,fontWeight:800,letterSpacing:'-.02em',marginBottom:18}}>User Management</div>
      <div className="card" style={{padding:0,overflow:'hidden'}}>
        {loading ? <div className="empty-state">Loading…</div> : (
          <table className="wavs-table">
            <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Scans</th><th>Last Active</th><th></th></tr></thead>
            <tbody>
              {users.length===0
                ? <tr><td colSpan={7} className="empty-state">No users found.</td></tr>
                : users.map(u=>(
                  <tr key={u.id}>
                    <td style={{fontWeight:700}}>{u.name}</td>
                    <td style={{fontFamily:'JetBrains Mono,monospace',fontSize:11,color:'var(--muted)'}}>{u.email}</td>
                    <td><span className={u.role==='admin'?'admin-badge':''}>{u.role}</span></td>
                    <td><span style={{fontSize:11,color:u.status==='banned'?'var(--red)':'var(--green)'}}>● {u.status}</span></td>
                    <td style={{fontFamily:'JetBrains Mono,monospace',fontSize:12}}>{u.scans_count}</td>
                    <td style={{fontSize:11,color:'var(--muted)'}}>{u.last_active_human}</td>
                    <td style={{display:'flex',gap:6}}>
                      {u.status==='banned'
                        ? <button className="btn-ghost" style={{fontSize:11,padding:'4px 10px'}} onClick={()=>unbanUser(u.id)}>Unban</button>
                        : <button className="btn-danger" onClick={()=>banUser(u.id)}>Ban</button>
                      }
                      <button className="btn-danger" onClick={()=>deleteUser(u.id)}>Delete</button>
                    </td>
                  </tr>
                ))
              }
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function AdminScansTab({ showToast }){
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(()=>{
    apiFetch('/api/admin/scans').then(r=>r.json()).then(d=>{ setScans(d); setLoading(false); }).catch(()=>setLoading(false));
  },[]);

  return (
    <div className="fade-in">
      <div style={{fontSize:20,fontWeight:800,letterSpacing:'-.02em',marginBottom:18}}>All Scans</div>
      <div className="card" style={{padding:0,overflow:'hidden'}}>
        {loading ? <div className="empty-state">Loading…</div> : (
          <table className="wavs-table">
            <thead><tr><th>Target</th><th>Owner</th><th>Status</th><th>Vulns</th><th>Started</th></tr></thead>
            <tbody>
              {scans.length===0
                ? <tr><td colSpan={5} className="empty-state">No scans yet.</td></tr>
                : scans.map(s=>(
                  <tr key={s.id}>
                    <td><code style={{fontSize:11,color:'var(--neon)'}}>{s.target_url}</code></td>
                    <td style={{fontSize:11,color:'var(--muted)'}}>{s.owner_name} <span style={{color:'var(--border)'}}>({s.owner_email})</span></td>
                    <td><span style={{fontSize:11,color:s.status==='completed'?'var(--green)':s.status==='running'?'var(--neon)':'var(--muted)'}}>● {s.status}</span></td>
                    <td style={{fontFamily:'JetBrains Mono,monospace',fontSize:12,color:'var(--orange)'}}>{s.vuln_count}</td>
                    <td style={{fontSize:11,color:'var(--muted)'}}>{s.created_at ? new Date(s.created_at).toLocaleString() : '—'}</td>
                  </tr>
                ))
              }
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function AdminHealthTab(){
  const [services, setServices] = useState([]);
  const [loading, setLoading]   = useState(true);

  useEffect(()=>{
    apiFetch('/api/admin/health').then(r=>r.json()).then(d=>{ setServices(d); setLoading(false); }).catch(()=>setLoading(false));
  },[]);

  const statusColor = s => s==='operational'?'var(--green)':s==='degraded'?'var(--orange)':'var(--red)';

  return (
    <div className="fade-in">
      <div style={{fontSize:20,fontWeight:800,letterSpacing:'-.02em',marginBottom:18}}>System Health</div>
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(220px,1fr))',gap:12}}>
        {loading ? <div className="empty-state">Loading…</div> : services.map(s=>(
          <div key={s.name} className="stat-card">
            <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:8}}>
              <div style={{width:8,height:8,borderRadius:'50%',background:statusColor(s.status),boxShadow:`0 0 6px ${statusColor(s.status)}`}}/>
              <span style={{fontSize:13,fontWeight:700}}>{s.name}</span>
            </div>
            <div style={{fontSize:11,color:'var(--muted)',fontFamily:'JetBrains Mono,monospace'}}>{s.latency}</div>
            <div style={{fontSize:10,color:statusColor(s.status),fontWeight:700,textTransform:'uppercase',marginTop:4}}>{s.status}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function AdminSettingsTab({ showToast }){
  const [settings, setSettings] = useState(null);

  useEffect(()=>{
    apiFetch('/api/admin/settings').then(r=>r.json()).then(d=>setSettings(d));
  },[]);

  async function save(){
    await apiFetch('/api/admin/settings', {method:'PUT', body: JSON.stringify(settings)});
    showToast('Settings saved','success');
  }

  if(!settings) return <div className="empty-state">Loading…</div>;

  return (
    <div className="fade-in">
      <div style={{fontSize:20,fontWeight:800,letterSpacing:'-.02em',marginBottom:18}}>Platform Settings</div>
      <div className="card" style={{maxWidth:500}}>
        <div style={{display:'flex',flexDirection:'column',gap:14}}>
          {[['Platform Name','platform_name','text'],['Support Email','support_email','email']].map(([label,key,type])=>(
            <div key={key}>
              <label className="form-label">{label}</label>
              <input className="wavs-input" type={type} value={settings[key]||''} onChange={e=>setSettings(p=>({...p,[key]:e.target.value}))}/>
            </div>
          ))}
          {[['Open Registration','open_registration'],['Rate Limiting','rate_limiting'],['Maintenance Mode','maintenance_mode']].map(([label,key])=>(
            <div key={key} style={{display:'flex',alignItems:'center',justifyContent:'space-between'}}>
              <span style={{fontSize:13,fontWeight:600}}>{label}</span>
              <label className="toggle">
                <input type="checkbox" checked={!!settings[key]} onChange={e=>setSettings(p=>({...p,[key]:e.target.checked}))}/>
                <div className="toggle-slider"/>
              </label>
            </div>
          ))}
          <button className="btn-primary" onClick={save} style={{marginTop:6}}>Save Settings</button>
        </div>
      </div>
    </div>
  );
}

// ─── Loading Screen ───────────────────────────────────────────────────────────
function LoadingScreen(){
  return (
    <div style={{position:'fixed',inset:0,background:'var(--bg)',display:'flex',alignItems:'center',justifyContent:'center',flexDirection:'column',gap:16}}>
      <div style={{width:36,height:36,background:'linear-gradient(135deg,var(--neon),var(--neon2))',borderRadius:9,display:'flex',alignItems:'center',justifyContent:'center'}}>
        <ShieldIcon size={18}/>
      </div>
      <div style={{fontFamily:'JetBrains Mono,monospace',fontSize:11,color:'var(--muted)'}}>Authenticating…</div>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function VulnSight(){
  const [user, setUser]             = useState(null);
  const [isAdmin, setIsAdmin]       = useState(false);
  const [authLoading, setAuthLoading] = useState(true); // check session on mount
  const [activeTab, setActiveTab]   = useState('dashboard');
  const [scanStatus, setScanStatus] = useState('idle');
  const [progress, setProgress]     = useState(0);
  const [phase, setPhase]           = useState('Waiting…');
  const [vulns, setVulns]           = useState([]);
  const [actLogs, setActLogs]       = useState([]);
  const [actTotals, setActTotals]   = useState({total:0,success:0,errors:0,avgMs:0,times:[]});
  const [stats, setStats]           = useState({requestsSent:0,urlsDiscovered:0,vulnCount:0,reqRate:0,urlRate:0});
  const scanRef = useRef(null);
  const progRef = useRef(0);
  const [targets, setTargets]       = useState([]);
  const [creds, setCreds]           = useState([]);
  const [vulnModal, setVulnModal]   = useState(null);
  const [toasts, setToasts]         = useState([]);

  const showToast = useCallback((msg, type='success')=>{
    const id = Date.now();
    setToasts(p=>[...p,{id,msg,type}]);
    setTimeout(()=>setToasts(p=>p.filter(t=>t.id!==id)),3500);
  },[]);

  // ── On mount: check real session from Laravel ────────────────────────────
  useEffect(()=>{
    (async ()=>{
      try {
        const res = await apiFetch('/api/me');
        if(res.ok){
          const data = await res.json();
          handleLogin(data, true);
        }
      } catch(e) {
        // not logged in
      } finally {
        setAuthLoading(false);
      }
    })();
  },[]);

  function resolveIsAdmin(data){
    return data.role === 'admin' || data.is_admin === true;
  }

  function handleLogin(data, silent=false){
    const admin = resolveIsAdmin(data);
    setUser(data);
    setIsAdmin(admin);

    // ── Route enforcement ──────────────────────────────────────────────────
    // Admin logged in but on user route → redirect to /admin
    if(admin && !IS_ADMIN_ROUTE){
      window.location.replace('/admin');
      return;
    }
    // Regular user on admin route → redirect to /
    if(!admin && IS_ADMIN_ROUTE){
      window.location.replace('/');
      return;
    }

    // Load per-user persisted data
    const t = JSON.parse(localStorage.getItem(`wavs_${data.email}_targets`) || '[]');
    const c = JSON.parse(localStorage.getItem(`wavs_${data.email}_credentials`) || '[]');
    setTargets(t);
    setCreds(c);
    if(!silent) showToast(`Welcome${admin?' back, Admin':''}, ${data.name}!`,'success');
  }

  async function handleSignOut(){
    if(!window.confirm('Sign out?')) return;
    try {
      await apiFetch('/api/logout', { method: 'POST' });
    } catch(e) {}
    localStorage.removeItem('token');
    setUser(null); setIsAdmin(false);
    clearInterval(scanRef.current);
    setScanStatus('idle'); setProgress(0); setVulns([]); setActLogs([]);
    setStats({requestsSent:0,urlsDiscovered:0,vulnCount:0,reqRate:0,urlRate:0});
    window.location.replace('/');
  }

  function getTargetUrls(){ return targets.length ? targets.map(t=>t.url) : ['https://example.com']; }

  function startScan(){
    if(scanStatus==='completed'){
      setVulns([]); setProgress(0); progRef.current=0;
      setStats({requestsSent:0,urlsDiscovered:0,vulnCount:0,reqRate:0,urlRate:0});
    }
    setScanStatus('running');
    scanRef.current = setInterval(tick, 420);
    showToast('Scan started','success');
  }

  function pauseOrResume(){
    if(scanStatus==='running'){
      clearInterval(scanRef.current);
      setScanStatus('paused');
      showToast('Scan paused','warn');
    } else if(scanStatus==='paused'){
      setScanStatus('running');
      scanRef.current = setInterval(tick, 420);
      showToast('Scan resumed','success');
    }
  }

  function tick(){
    progRef.current = Math.min(progRef.current + Math.random()*3+0.4, 100);
    const pct = progRef.current;
    const pi  = Math.min(Math.floor((pct/100)*PHASES.length),PHASES.length-1);
    setProgress(pct);
    setPhase(PHASES[pi]);
    const reqAdd = Math.floor(Math.random()*10+2);
    const urlAdd = Math.random()>.65 ? 1 : 0;
    const isVuln = Math.random()>0.88;
    const path   = PATHS[Math.floor(Math.random()*PATHS.length)];
    const tUrls  = getTargetUrls();
    const base   = tUrls[Math.floor(Math.random()*tUrls.length)].replace(/\/$/,'');
    const fullUrl= base + path + (Math.random()>.5 ? '?id='+Math.floor(Math.random()*999) : '');
    const timeStr= new Date().toTimeString().slice(0,8);
    if(isVuln){
      const vt = VULN_DB[Math.floor(Math.random()*VULN_DB.length)];
      const v  = {...vt, url:fullUrl, time:timeStr, id:Date.now()};
      setVulns(p=>[v,...p]);
      setStats(p=>({...p,requestsSent:p.requestsSent+reqAdd,urlsDiscovered:p.urlsDiscovered+urlAdd,vulnCount:p.vulnCount+1,reqRate:Math.floor(Math.random()*18+4),urlRate:Math.floor(Math.random()*4+1)}));
      addLog({method:'GET',url:fullUrl,status:vt.sev==='critical'?500:200,ms:Math.floor(Math.random()*800+50),alert:vt.sev,ts:timeStr});
    } else {
      const method = HTTP_METHODS[Math.floor(Math.random()*HTTP_METHODS.length)];
      const status = HTTP_STATUSES[Math.floor(Math.random()*HTTP_STATUSES.length)];
      setStats(p=>({...p,requestsSent:p.requestsSent+reqAdd,urlsDiscovered:p.urlsDiscovered+urlAdd,reqRate:Math.floor(Math.random()*18+4),urlRate:Math.floor(Math.random()*4+1)}));
      addLog({method,url:fullUrl,status,ms:Math.floor(Math.random()*500+20),alert:null,ts:timeStr});
    }
    if(pct>=100){
      clearInterval(scanRef.current);
      setScanStatus('completed');
      setPhase('✓ Complete');
      showToast('Scan complete!','success');
    }
  }

  function addLog(e){
    setActLogs(p=>[e,...p].slice(0,300));
    setActTotals(p=>{
      const times = e.ms ? [...p.times,e.ms].slice(-60) : p.times;
      const avgMs = times.length ? Math.round(times.reduce((a,b)=>a+b,0)/times.length) : 0;
      return {total:p.total+1,success:e.status>=200&&e.status<300?p.success+1:p.success,errors:e.status>=400?p.errors+1:p.errors,avgMs,times};
    });
  }

  const TAB_TITLES = {
    dashboard:'Dashboard', activity:'Live Activity', vulnerabilities:'Vulnerabilities',
    targets:'Target Management', authentication:'Auth Vault', configuration:'Scan Settings',
    'admin-users':'User Management', 'admin-scans':'All Scans',
    'admin-health':'System Health', 'admin-settings':'Platform Settings',
  };

  // Show loading spinner while checking session
  if(authLoading) return (
    <>
      <style>{CSS}</style>
      <LoadingScreen/>
    </>
  );

  if(!user) return (
    <>
      <style>{CSS}</style>
      <AuthScreen onLogin={u=>handleLogin(u)}/>
      <Toast toasts={toasts}/>
    </>
  );

  return (
    <>
      <style>{CSS}</style>
      <div className="grid-bg" style={{minHeight:'100vh'}}>
        <Sidebar
          activeTab={activeTab}
          setTab={setActiveTab}
          user={user}
          isAdmin={isAdmin}
          onSignOut={handleSignOut}
          vulnCount={vulns.length}
        />
        <div style={{marginLeft:236,minHeight:'100vh',display:'flex',flexDirection:'column'}}>
          {/* Topbar */}
          <div style={{height:58,borderBottom:'1px solid var(--border)',background:'rgba(13,17,23,.9)',backdropFilter:'blur(12px)',display:'flex',alignItems:'center',padding:'0 22px',gap:14,position:'sticky',top:0,zIndex:50}}>
            <h2 style={{fontWeight:700,fontSize:15,flex:1}}>{TAB_TITLES[activeTab]||activeTab}</h2>
            {/* Role pill in topbar */}
            <div style={{fontSize:10,fontFamily:'JetBrains Mono,monospace',padding:'3px 10px',borderRadius:20,background: isAdmin ? 'rgba(255,140,0,.1)' : 'rgba(0,255,224,.07)', color: isAdmin ? 'var(--orange)' : 'var(--neon)', border: `1px solid ${isAdmin ? 'rgba(255,140,0,.2)' : 'rgba(0,255,224,.14)'}`, fontWeight:700}}>
              {isAdmin ? '⬡ Admin' : '◎ User'}
            </div>
            <div style={{display:'flex',alignItems:'center',gap:6,padding:'5px 12px',background:'var(--surface2)',border:'1px solid var(--border)',borderRadius:20,fontSize:11,fontWeight:600,fontFamily:'JetBrains Mono,monospace',flexShrink:0}}>
              <div className={`status-dot ${scanStatus}`}/>
              <span>{scanStatus}</span>
            </div>
            <div style={{display:'flex',gap:8}}>
              {scanStatus==='running'&&(<button className="btn-ghost" onClick={pauseOrResume} style={{padding:'7px 14px'}}>⏸ Pause</button>)}
              {scanStatus==='paused'&&(<button className="btn-ghost" onClick={pauseOrResume} style={{padding:'7px 14px'}}>▶ Resume</button>)}
              {(scanStatus==='idle'||scanStatus==='completed')&&(
                <button className="btn-primary" onClick={startScan} style={{padding:'8px 16px'}}>
                  {scanStatus==='completed'?'↺ New Scan':'▶ Start Scan'}
                </button>
              )}
            </div>
          </div>

          {/* Tab content */}
          <div style={{padding:22,flex:1}}>
            {activeTab==='dashboard'        && <DashboardTab stats={stats} vulns={vulns} scanStatus={scanStatus} progress={progress} phase={phase} setTab={setActiveTab} onOpenVuln={setVulnModal} isAdmin={isAdmin}/>}
            {activeTab==='vulnerabilities'  && <VulnerabilitiesTab vulns={vulns} onOpenVuln={setVulnModal}/>}
            {activeTab==='activity'         && <ActivityTab logs={actLogs} totals={actTotals} onClear={()=>{ setActLogs([]); setActTotals({total:0,success:0,errors:0,avgMs:0,times:[]}); }}/>}
            {activeTab==='targets'          && <TargetsTab targets={targets} setTargets={setTargets} userEmail={user.email} showToast={showToast}/>}
            {activeTab==='authentication'   && <AuthTab creds={creds} setCreds={setCreds} userEmail={user.email} showToast={showToast}/>}
            {activeTab==='configuration'    && <ConfigTab showToast={showToast}/>}
            {/* Admin-only tabs — blocked for non-admins */}
            {activeTab==='admin-users'    && (isAdmin ? <AdminUsersTab showToast={showToast}/> : <div className="empty-state">Access denied.</div>)}
            {activeTab==='admin-scans'    && (isAdmin ? <AdminScansTab showToast={showToast}/> : <div className="empty-state">Access denied.</div>)}
            {activeTab==='admin-health'   && (isAdmin ? <AdminHealthTab/> : <div className="empty-state">Access denied.</div>)}
            {activeTab==='admin-settings' && (isAdmin ? <AdminSettingsTab showToast={showToast}/> : <div className="empty-state">Access denied.</div>)}
          </div>
        </div>
      </div>
      {vulnModal && <VulnModal vuln={vulnModal} onClose={()=>setVulnModal(null)}/>}
      <Toast toasts={toasts}/>
    </>
  );
}
