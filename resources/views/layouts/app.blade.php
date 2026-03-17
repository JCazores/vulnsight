<script>
(function(){
  /* WAVS 2026 Tracker - paste into your blade layout */

  function report(m,u,s,ms){
    try{ navigator.sendBeacon(WAVS, JSON.stringify({method:m,url:u,status:s,ms:ms,ts:Date.now()})); }
    catch(e){ try{fetch(WAVS,{method:'POST',body:JSON.stringify({method:m,url:u,status:s,ms:ms,ts:Date.now()}),headers:{'Content-Type':'application/json'},mode:'no-cors'});}catch(ex){} }
  }
  /* fetch intercept */
  const _fetch = window.fetch;
  window.fetch = function(input,init){
    const url=typeof input==='string'?input:(input&&input.url)||String(input);
    const method=((init&&init.method)||'GET').toUpperCase();
    const t=Date.now();
    return _fetch.apply(this,arguments)
      .then(r=>{ report(method,url,r.status,Date.now()-t); return r; })
      .catch(e=>{ report(method,url,0,Date.now()-t); throw e; });
  };
  /* XHR intercept */
  const _open=XMLHttpRequest.prototype.open, _send=XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open=function(m,u){ this._m=m; this._u=u; _open.apply(this,arguments); };
  XMLHttpRequest.prototype.send=function(){ const t=Date.now(); this.addEventListener('loadend',()=>report(this._m,this._u,this.status,Date.now()-t)); _send.apply(this,arguments); };
  /* navigation */
  const _push=history.pushState, _replace=history.replaceState;
  history.pushState=function(){ _push.apply(this,arguments); report('NAV',location.pathname,200,0); };
  history.replaceState=function(){ _replace.apply(this,arguments); report('NAV',location.pathname,200,0); };
  window.addEventListener('popstate',()=>report('NAV',location.pathname,200,0));
  report('NAV',location.pathname,200,0);
  console.log('%c[WAVS] Tracker active','color:#00ffe0;font-weight:bold;');
})();
</script>
