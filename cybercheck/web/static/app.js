/* CyberCheck dashboard script. Progressive enhancement only: every page and action works without it.
   No frameworks, no external requests. CSP: script-src 'self', so page scripts are files in /static/ too.
   Public API: window.CC (documented in docs/UI.md). Build DOM with CC.el (text only, never innerHTML with data). */
(function () {
  'use strict';

  var CC = window.CC = window.CC || {};
  var doc = document;

  // ---- small utilities --------------------------------------------------------------------------------

  CC.$ = function (sel, root) { return (root || doc).querySelector(sel); };
  CC.$$ = function (sel, root) { return Array.prototype.slice.call((root || doc).querySelectorAll(sel)); };
  CC.ready = function (fn) {
    if (doc.readyState !== 'loading') { fn(); } else { doc.addEventListener('DOMContentLoaded', fn); }
  };
  CC.on = function (name, fn) {
    var h = function (e) { fn(e.detail, e); };
    doc.addEventListener('cc:' + name, h);
    return function () { doc.removeEventListener('cc:' + name, h); };
  };
  CC.emit = function (name, detail) { doc.dispatchEvent(new CustomEvent('cc:' + name, { detail: detail })); };

  /* CC.el('a', {class: 'dom', href: '/domain/5', text: host}, child, 'text', ...)
     Strings become text nodes. Attributes named on* are refused (CSP and XSS); listeners go in {on: {click: fn}}.
     href/src must be same-origin relative paths: attacker-controlled URLs are shown as text, never linked. */
  CC.el = function (tag, attrs) {
    var node = doc.createElement(tag);
    var a = attrs || {};
    Object.keys(a).forEach(function (k) {
      var v = a[k];
      if (v === null || v === undefined || v === false) { return; }
      if (k === 'class') { node.className = v; }
      else if (k === 'text') { node.textContent = String(v); }
      else if (k === 'dataset') { Object.keys(v).forEach(function (d) { node.dataset[d] = v[d]; }); }
      else if (k === 'on') { Object.keys(v).forEach(function (t) { node.addEventListener(t, v[t]); }); }
      else if (/^on/i.test(k)) { throw new Error('CC.el: use {on: {...}} for listeners, not ' + k); }
      else if ((k === 'href' || k === 'src' || k === 'action' || k === 'formaction') && !CC.isLocalPath(String(v))) {
        throw new Error('CC.el: ' + k + ' must be a same-origin path');
      }
      else { node.setAttribute(k, v === true ? '' : String(v)); }
    });
    for (var i = 2; i < arguments.length; i++) {
      var c = arguments[i];
      if (c === null || c === undefined || c === false) { continue; }
      node.appendChild(typeof c === 'object' ? c : doc.createTextNode(String(c)));
    }
    return node;
  };

  // A path on this dashboard: "/x", "?q", "#id". Not "//host", not "javascript:", not absolute URLs.
  CC.isLocalPath = function (u) {
    return /^(\/(?!\/)|\?|#)/.test(u) && !/[\\\u0000-\u001f]/.test(u);
  };

  CC.fmtInt = function (n) { return n === null || n === undefined ? '-' : Number(n).toLocaleString('en-AU'); };

  CC.data = function (id) {
    // JSON a template put in <script type="application/json" id="..."> {{ value | tojson }} </script>
    var node = doc.getElementById(id);
    if (!node) { return null; }
    try { return JSON.parse(node.textContent); } catch (e) { return null; }
  };

  // ---- relative times ---------------------------------------------------------------------------------

  CC.formatAgo = function (date, now) {
    var t = date instanceof Date ? date.getTime() : Date.parse(date);
    if (isNaN(t)) { return ''; }
    var s = Math.round(((now || Date.now()) - t) / 1000);
    var future = s < 0;
    s = Math.abs(s);
    var out;
    if (s < 60) { out = s + 's'; }
    else if (s < 3600) { out = Math.floor(s / 60) + 'm'; }
    else if (s < 86400) { out = Math.floor(s / 3600) + 'h'; }
    else { out = Math.floor(s / 86400) + 'd'; }
    return future ? 'in ' + out : out + ' ago';
  };

  // Every <time datetime> except [data-abs] shows a live relative time; the absolute time stays in title.
  CC.relTime = function (root) {
    var now = Date.now();
    CC.$$('time[datetime]:not([data-abs])', root).forEach(function (el) {
      var txt = CC.formatAgo(el.getAttribute('datetime'), now);
      if (!txt) { return; }
      if (!el.title) {
        var d = new Date(el.getAttribute('datetime'));
        el.title = d.toLocaleString('en-AU', { dateStyle: 'medium', timeStyle: 'short' });
      }
      if (el.textContent !== txt) { el.textContent = txt; }
    });
  };

  // ---- same-origin fetch helpers ----------------------------------------------------------------------

  function checkUrl(url) {
    if (!CC.isLocalPath(String(url))) { throw new Error('CC: only same-origin paths may be fetched'); }
    return url;
  }

  CC.getJSON = function (url) {
    return fetch(checkUrl(url), {
      credentials: 'same-origin', cache: 'no-store', headers: { 'Accept': 'application/json' }
    }).then(function (r) {
      if (!r.ok) { var e = new Error('HTTP ' + r.status); e.status = r.status; throw e; }
      return r.json();
    });
  };

  /* CC.post('/domain/5/status', {status: 'confirmed', note: ''}) -> Promise<Response>
     data: a plain object, URLSearchParams, a <form> element, or FormData (sent url-encoded, files are not
     supported). The browser adds Origin and Sec-Fetch-Site: same-origin, which same_origin() checks on the
     server; nothing else is needed. Redirects are followed (the POST routes answer 303 to a page). A non-2xx
     answer rejects with err.status and err.detail (FastAPI's {"detail": ...} when there is one). */
  CC.post = function (url, data, opts) {
    var o = opts || {};
    var body;
    if (data instanceof HTMLFormElement) { body = new URLSearchParams(new FormData(data, o.submitter || undefined)); }
    else if (data instanceof FormData) { body = new URLSearchParams(data); }
    else if (data instanceof URLSearchParams) { body = data; }
    else {
      body = new URLSearchParams();
      Object.keys(data || {}).forEach(function (k) { if (data[k] !== undefined && data[k] !== null) { body.append(k, data[k]); } });
    }
    return fetch(checkUrl(url), {
      method: 'POST', body: body, credentials: 'same-origin', redirect: 'follow', cache: 'no-store',
      headers: { 'Accept': o.accept || 'text/html,application/json;q=0.9', 'X-Requested-With': 'cybercheck' }
    }).then(function (r) {
      if (r.ok) { return r; }
      return r.text().then(function (t) {
        var detail = t;
        try { var j = JSON.parse(t); if (j && j.detail) { detail = typeof j.detail === 'string' ? j.detail : JSON.stringify(j.detail); } } catch (e) { /* text */ }
        var err = new Error(detail || ('HTTP ' + r.status));
        err.status = r.status; err.detail = detail;
        throw err;
      });
    });
  };

  /* CC.poll('/api/recent?after_id=5', 5000, function (data) {...}) -> {stop(), now()}
     Pauses while the tab is hidden, backs off (up to 4x) after failures, never overlaps requests.
     url may be a function returning the url, so it can carry the latest id. */
  CC.poll = function (url, ms, onData, opts) {
    var o = opts || {};
    var timer = null, stopped = false, fails = 0, inflight = false;
    function schedule() {
      if (stopped) { return; }
      clearTimeout(timer);
      timer = setTimeout(tick, ms * Math.min(4, 1 + fails));
    }
    function tick() {
      if (stopped) { return; }
      if (doc.hidden || inflight) { schedule(); return; }
      inflight = true;
      CC.getJSON(typeof url === 'function' ? url() : url).then(function (d) {
        fails = 0; onData(d);
      }, function (e) {
        fails += 1;
        if (o.onError) { o.onError(e, fails); }
      }).then(function () { inflight = false; schedule(); });
    }
    doc.addEventListener('visibilitychange', function () { if (!doc.hidden && !stopped) { clearTimeout(timer); timer = setTimeout(tick, 300); } });
    if (o.immediate) { tick(); } else { schedule(); }
    return { stop: function () { stopped = true; clearTimeout(timer); }, now: function () { clearTimeout(timer); tick(); } };
  };

  // ---- toasts -----------------------------------------------------------------------------------------

  // CC.toast('Saved', 'ok' | 'warn' | 'error', ms). Text only. Announced politely (aria-live region).
  CC.toast = function (message, tone, ms) {
    var box = doc.getElementById('cc-toasts');
    if (!box) { return null; }
    var t = CC.el('div', { class: 'toast toast--' + (tone || 'ok'), role: tone === 'error' ? 'alert' : null },
      CC.el('span', { text: message }),
      CC.el('button', { type: 'button', class: 'toast-close', 'aria-label': 'Dismiss', text: '×',
        on: { click: function () { t.remove(); } } }));
    box.appendChild(t);
    if (ms !== 0) { setTimeout(function () { t.remove(); }, ms || (tone === 'error' ? 9000 : 5000)); }
    return t;
  };

  // ---- dialogs ----------------------------------------------------------------------------------------

  function dialogShell(cls, title) {
    var dlg = CC.el('dialog', { class: 'cc-dialog ' + (cls || '') });
    var h = CC.el('h2', { text: title || '' });
    var close = CC.el('button', { type: 'button', class: 'btn btn--quiet btn--sm dialog-x', 'aria-label': 'Close', text: 'Close',
      on: { click: function () { dlg.close('cancel'); } } });
    var head = CC.el('div', { class: 'dialog-head' }, h, close);
    var body = CC.el('div', { class: 'dialog-body' });
    var foot = CC.el('div', { class: 'dialog-foot' });
    dlg.appendChild(head); dlg.appendChild(body); dlg.appendChild(foot);
    dlg.addEventListener('click', function (e) { if (e.target === dlg) { dlg.close('cancel'); } });
    dlg.addEventListener('close', function () { setTimeout(function () { dlg.remove(); }, 0); });
    doc.body.appendChild(dlg);
    return { dlg: dlg, title: h, body: body, foot: foot };
  }

  /* CC.confirm({title, message, detail, ok, cancel, tone: 'danger' | 'primary'}) -> Promise<boolean>
     Focus starts on Cancel for danger, on the confirm button otherwise. Esc and the backdrop cancel. */
  CC.confirm = function (o) {
    o = o || {};
    return new Promise(function (resolve) {
      var tone = o.tone === 'danger' ? 'danger' : 'primary';
      var d = dialogShell('dialog--' + tone, o.title || (tone === 'danger' ? 'Are you sure?' : 'Confirm'));
      d.dlg.setAttribute('aria-describedby', 'cc-confirm-msg');
      d.body.appendChild(CC.el('p', { id: 'cc-confirm-msg', text: o.message || '' }));
      if (o.detail) { d.body.appendChild(CC.el('p', { class: 'dialog-detail', text: o.detail })); }
      var cancel = CC.el('button', { type: 'button', class: 'btn', text: o.cancel || 'Cancel',
        on: { click: function () { d.dlg.close('cancel'); } } });
      var ok = CC.el('button', { type: 'button', class: 'btn btn--' + tone, text: o.ok || 'Confirm',
        on: { click: function () { d.dlg.close('ok'); } } });
      d.foot.appendChild(cancel); d.foot.appendChild(ok);
      var opener = doc.activeElement;
      d.dlg.addEventListener('close', function () {
        resolve(d.dlg.returnValue === 'ok');
        if (opener && opener.focus && doc.contains(opener)) { opener.focus(); }
      });
      d.dlg.showModal();
      (tone === 'danger' ? cancel : ok).focus();
    });
  };

  /* Forms: a submit button (or the form) with data-confirm="..." asks first (data-confirm-ok, -detail, -tone,
     -title). Without JS the same button just posts. After the answer the form is submitted with the same
     submitter, so name="status" value="confirmed" still reaches the server. */
  doc.addEventListener('submit', function (e) {
    var form = e.target;
    if (!(form instanceof HTMLFormElement)) { return; }
    var sub = e.submitter || null;
    var src = (sub && sub.hasAttribute('data-confirm')) ? sub : (form.hasAttribute('data-confirm') ? form : null);
    if (!src) { return; }
    if (form._ccConfirmed) { form._ccConfirmed = false; return; }
    e.preventDefault();
    e.stopImmediatePropagation();
    CC.confirm({
      title: src.getAttribute('data-confirm-title'),
      message: src.getAttribute('data-confirm'),
      detail: src.getAttribute('data-confirm-detail'),
      ok: src.getAttribute('data-confirm-ok') || (sub ? sub.textContent.trim() : 'Confirm'),
      tone: src.getAttribute('data-confirm-tone') || 'danger'
    }).then(function (yes) {
      if (!yes) { return; }
      form._ccConfirmed = true;
      if (form.requestSubmit) { form.requestSubmit(sub || undefined); }
      else {
        if (sub && sub.name) { form.appendChild(CC.el('input', { type: 'hidden', name: sub.name, value: sub.value })); }
        form.submit();
      }
    });
  }, true);

  // Loading state and double-submit guard for ordinary form posts. A page script that handles the submit
  // itself (preventDefault) is left alone.
  doc.addEventListener('submit', function (e) {
    var form = e.target;
    if (e.defaultPrevented || !(form instanceof HTMLFormElement) || form.hasAttribute('data-no-busy')) { return; }
    if (form._ccBusy) { e.preventDefault(); return; }
    form._ccBusy = true;
    form.setAttribute('aria-busy', 'true');
    var sub = e.submitter;
    if (sub && sub.classList) { sub.classList.add('is-loading'); sub.setAttribute('aria-disabled', 'true'); }
  });
  CC.busy = function (btn, on) {
    if (!btn) { return; }
    btn.classList.toggle('is-loading', !!on);
    if (on) { btn.setAttribute('aria-disabled', 'true'); btn.disabled = true; }
    else { btn.removeAttribute('aria-disabled'); btn.disabled = false; }
  };
  window.addEventListener('pageshow', function () {
    CC.$$('form[aria-busy="true"]').forEach(function (f) { f._ccBusy = false; f.removeAttribute('aria-busy'); });
    CC.$$('.is-loading').forEach(function (b) { b.classList.remove('is-loading'); b.removeAttribute('aria-disabled'); });
  });

  // ---- lightbox ---------------------------------------------------------------------------------------

  CC.lightbox = function (src, caption, list) {
    if (!CC.isLocalPath(src)) { return; }
    var d = dialogShell('cc-lightbox', caption || 'Screenshot');
    var img = CC.el('img', { src: src, alt: caption || 'Screenshot' });
    d.body.appendChild(img);
    var idx = 0;
    var count = CC.el('span', { class: 'muted' });
    function show(i) {
      idx = (i + list.length) % list.length;
      img.src = list[idx].src; img.alt = list[idx].caption || 'Screenshot'; d.title.textContent = list[idx].caption || 'Screenshot';
      count.textContent = (idx + 1) + ' of ' + list.length;
    }
    if (list && list.length > 1) {
      list = list.map(function (x) { return typeof x === 'string' ? { src: x } : x; });
      idx = list.findIndex(function (x) { return x.src === src; });
      d.foot.appendChild(count);
      d.foot.appendChild(CC.el('button', { type: 'button', class: 'btn', text: 'Previous', 'aria-keyshortcuts': 'ArrowLeft',
        on: { click: function () { show(idx - 1); } } }));
      d.foot.appendChild(CC.el('button', { type: 'button', class: 'btn', text: 'Next', 'aria-keyshortcuts': 'ArrowRight',
        on: { click: function () { show(idx + 1); } } }));
      count.textContent = (idx + 1) + ' of ' + list.length;
      d.dlg.addEventListener('keydown', function (e) {
        if (e.key === 'ArrowLeft') { e.preventDefault(); show(idx - 1); }
        if (e.key === 'ArrowRight') { e.preventDefault(); show(idx + 1); }
      });
    }
    d.foot.appendChild(CC.el('a', { class: 'btn btn--quiet', href: src, text: 'Open full size' }));
    var opener = doc.activeElement;
    d.dlg.addEventListener('close', function () { if (opener && opener.focus) { opener.focus(); } });
    d.dlg.showModal();
  };

  doc.addEventListener('click', function (e) {
    var a = e.target.closest && e.target.closest('a[data-lightbox]');
    if (!a || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) { return; }
    var src = a.getAttribute('href');
    if (!CC.isLocalPath(src)) { return; }
    e.preventDefault();
    var list = CC.$$('a[data-lightbox]').map(function (x) { return { src: x.getAttribute('href'), caption: x.getAttribute('data-caption') }; });
    CC.lightbox(src, a.getAttribute('data-caption'), list);
  });

  // ---- keyboard shortcuts -----------------------------------------------------------------------------

  var registry = [];
  var pending = null, pendingTimer = null;

  /* CC.shortcut('j', 'Next row', fn, {group: 'This page'}) -> unregister function.
     keys: one key ("j", "?", "/", "Escape") or a two-key chord ("g r"). Ignored while typing in a field,
     with Ctrl/Cmd/Alt held, and while a dialog is open. */
  CC.shortcut = function (keys, label, handler, opts) {
    var entry = { keys: keys, label: label, handler: handler, group: (opts && opts.group) || 'This page' };
    registry = registry.filter(function (r) { return r.keys !== keys; });
    registry.push(entry);
    return function () { registry = registry.filter(function (r) { return r !== entry; }); };
  };
  CC.shortcuts = function () { return registry.slice(); };

  function editable(el) {
    if (!el) { return false; }
    var t = el.tagName;
    return t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT' || el.isContentEditable;
  }
  function visible(el) { return !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length)); }

  doc.addEventListener('keydown', function (e) {
    if (e.defaultPrevented || e.ctrlKey || e.metaKey || e.altKey || e.isComposing) { return; }
    if (doc.querySelector('dialog[open]')) { return; }
    var t = e.target;
    if (editable(t)) {
      if (e.key === 'Escape' && t.blur) { t.blur(); }
      return;
    }
    var key = e.key;
    if (key === 'Shift') { return; }
    if (key === 'Escape') {
      CC.tooltip.hide();
      var more = CC.$('details[data-nav-more][open]');
      var sheet = doc.getElementById('cc-nav');
      if (more && !(sheet && sheet.classList.contains('is-open'))) {
        e.preventDefault(); more.open = false; CC.$('summary', more).focus(); return;
      }
      if (sheet && sheet.classList.contains('is-open')) { e.preventDefault(); openMenu(false); }
      return;
    }
    var match = null;
    if (pending) {
      var combo = pending + ' ' + key;
      pending = null; clearTimeout(pendingTimer);
      match = registry.find(function (r) { return r.keys === combo; });
      if (!match) { return; }
    } else if (registry.some(function (r) { return r.keys.indexOf(key + ' ') === 0; })) {
      pending = key;
      pendingTimer = setTimeout(function () { pending = null; }, 1500);
      e.preventDefault();
      return;
    } else {
      match = registry.find(function (r) { return r.keys === key; });
    }
    if (match) {
      e.preventDefault();
      match.handler(e);
    }
  });

  CC.openHelp = function () {
    var d = dialogShell('dialog--help', 'Keyboard shortcuts');
    var groups = {};
    var order = ['Global', 'Go to', 'This page'];
    registry.forEach(function (r) { (groups[r.group] = groups[r.group] || []).push(r); });
    Object.keys(groups).forEach(function (g) { if (order.indexOf(g) < 0) { order.push(g); } });
    order.forEach(function (g) {
      if (!groups[g]) { return; }
      var dl = CC.el('dl', { class: 'help-list' });
      groups[g].forEach(function (r) {
        var dt = CC.el('dt');
        r.keys.split(' ').forEach(function (k, i) {
          if (i) { dt.appendChild(doc.createTextNode(' then ')); }
          dt.appendChild(CC.el('kbd', { text: k === ' ' ? 'Space' : k }));
        });
        dl.appendChild(dt);
        dl.appendChild(CC.el('dd', { text: r.label }));
      });
      d.body.appendChild(CC.el('section', { class: 'help-group' }, CC.el('h3', { text: g }), dl));
    });
    d.body.appendChild(CC.el('p', { class: 'muted', text: 'Shortcuts are off while you type in a field. Esc leaves the field.' }));
    d.dlg.showModal();
  };

  function focusSearch() {
    var s = CC.$('main [data-search]') || CC.$('main input[type=search]') || CC.$('[data-global-search]');
    if (!s) { return; }
    if (!visible(s)) { openMenu(true); }
    s.focus();
    if (s.select) { s.select(); }
  }

  // ---- row cursor (j / k) for tables with <tbody data-rows> -------------------------------------------

  var cursor = -1;
  function rows() {
    return CC.$$('[data-rows] > tr').filter(function (tr) { return visible(tr) && (tr.dataset.href || tr.querySelector('a[href]')); });
  }
  function moveCursor(step) {
    var list = rows();
    if (!list.length) { return; }
    CC.$$('tr.is-cursor').forEach(function (tr) { tr.classList.remove('is-cursor'); });
    var current = list.indexOf(doc.activeElement && doc.activeElement.closest ? doc.activeElement.closest('tr') : null);
    if (current >= 0) { cursor = current; }
    cursor = Math.max(0, Math.min(list.length - 1, cursor + step));
    var tr = list[cursor];
    tr.classList.add('is-cursor');
    var link = tr.querySelector('a[href]');
    if (link) { link.focus({ preventScroll: true }); }
    tr.scrollIntoView({ block: 'nearest' });
  }
  function openCursor() {
    var tr = CC.$('tr.is-cursor');
    if (!tr) { return; }
    var href = tr.dataset.href || (tr.querySelector('a[href]') || {}).getAttribute('href');
    if (href && CC.isLocalPath(href)) { location.href = href; }
  }
  CC.rows = { next: function () { moveCursor(1); }, prev: function () { moveCursor(-1); }, open: openCursor };

  // ---- mobile menu ------------------------------------------------------------------------------------

  // The phone sheet (#cc-nav). Without JS the menu button is a #cc-nav link and :target opens the sheet.
  function openMenu(force) {
    var sheet = doc.getElementById('cc-nav');
    var btn = CC.$('[data-menu-toggle]');
    if (!sheet || !btn) { return; }
    var open = force === undefined ? !sheet.classList.contains('is-open') : force;
    sheet.classList.toggle('is-open', open);
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    var txt = CC.$('.menu-btn-text', btn);
    if (txt) { txt.textContent = open ? 'Close menu' : 'Menu'; } else { btn.textContent = open ? 'Close menu' : 'Menu'; }
    var use = CC.$('use', btn);
    if (use) { use.setAttribute('href', open ? '#i-close' : '#i-menu'); }
    if (open) {
      // in the sheet, show the "More" sections when the current page is one of them
      var more = CC.$('details[data-nav-more]', sheet);
      if (more && CC.$('.nav-menu-link.is-active', more)) { more.open = true; }
    }
  }
  CC.menu = { open: function () { openMenu(true); }, close: function () { openMenu(false); }, toggle: function () { openMenu(); } };

  // ---- in-page tabs -----------------------------------------------------------------------------------

  function initTabs(nav) {
    var links = CC.$$('a[href^="#"]', nav);
    var panels = links.map(function (a) { return doc.getElementById(a.getAttribute('href').slice(1)); });
    if (!links.length || panels.some(function (p) { return !p; })) { return; }
    nav.setAttribute('role', 'tablist');
    function activate(i, focus) {
      links.forEach(function (a, j) {
        var on = i === j;
        a.setAttribute('aria-selected', on ? 'true' : 'false');
        a.setAttribute('tabindex', on ? '0' : '-1');
        a.classList.toggle('is-active', on);
        if (on) { a.setAttribute('aria-current', 'true'); } else { a.removeAttribute('aria-current'); }
        panels[j].hidden = !on;
      });
      if (focus) { links[i].focus(); }
    }
    links.forEach(function (a, i) {
      a.setAttribute('role', 'tab');
      a.setAttribute('aria-controls', panels[i].id);
      if (!a.id) { a.id = 'tab-' + panels[i].id; }
      panels[i].setAttribute('role', 'tabpanel');
      panels[i].setAttribute('aria-labelledby', a.id);
      a.addEventListener('click', function (e) {
        e.preventDefault(); activate(i);
        if (history.replaceState) { history.replaceState(null, '', a.getAttribute('href')); }
      });
      a.addEventListener('keydown', function (e) {
        if (e.key === 'ArrowRight') { e.preventDefault(); activate((i + 1) % links.length, true); }
        if (e.key === 'ArrowLeft') { e.preventDefault(); activate((i - 1 + links.length) % links.length, true); }
      });
    });
    var start = links.findIndex(function (a) { return a.getAttribute('href') === location.hash; });
    if (start < 0) { start = links.findIndex(function (a) { return a.classList.contains('is-active'); }); }
    activate(Math.max(0, start));
  }

  // ---- copy buttons -----------------------------------------------------------------------------------

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) { return navigator.clipboard.writeText(text); }
    return new Promise(function (resolve, reject) {
      var ta = CC.el('textarea', { class: 'visually-hidden', readonly: true });
      ta.value = text; doc.body.appendChild(ta); ta.select();
      var ok = false;
      try { ok = doc.execCommand('copy'); } catch (e) { ok = false; }
      ta.remove();
      if (ok) { resolve(); } else { reject(new Error('copy failed')); }
    });
  }
  CC.copy = function (text) {
    return copyText(text).then(function () { CC.toast('Copied to the clipboard'); },
      function () { CC.toast('Could not copy. Select the text and copy it by hand.', 'warn'); });
  };
  doc.addEventListener('click', function (e) {
    var b = e.target.closest && e.target.closest('[data-copy], [data-copy-target]');
    if (!b) { return; }
    e.preventDefault();
    var text = b.getAttribute('data-copy');
    if (text === null) {
      var t = doc.querySelector(b.getAttribute('data-copy-target'));
      text = t ? ('value' in t ? t.value : t.textContent) : '';
    }
    CC.copy(text);
  });

  // ---- status line ------------------------------------------------------------------------------------

  CC.status = null;
  function applyStatus(data) {
    if (!data || !data.segments) { return; }
    CC.status = data;
    data.segments.forEach(function (s) {
      var li = CC.$('#cc-status [data-status-key="' + s.key + '"]');
      if (!li) { return; }
      li.className = 'seg seg--' + s.tone;
      li.title = s.title || '';
      var g = CC.$('.seg-glyph', li), v = CC.$('.seg-value', li);
      if (g) { g.textContent = s.glyph; }
      if (v && v.textContent !== s.value) {
        v.textContent = s.value;
        li.classList.add('is-updated');
        setTimeout(function () { li.classList.remove('is-updated'); }, 1000);
      }
    });
    CC.$$('.nav-link[href="/review"]').forEach(function (link) {
      var badge = CC.$('[data-status-badge="queue"]', link);
      var n = data.open_review;
      if (n && !badge) {
        badge = CC.el('span', { class: 'nav-badge', 'data-status-badge': 'queue' });
        link.appendChild(badge);
      }
      if (badge) {
        badge.hidden = !n;
        badge.textContent = n ? String(n) : '';
        badge.title = n ? n + ' waiting for review' : '';
        badge.classList.toggle('nav-badge--high', !!data.open_high);
      }
    });
    CC.emit('status', data);
  }

  // ---- icons ------------------------------------------------------------------------------------------

  // CC.icon('shield', 'tile-ico') -> <svg class="ico tile-ico" aria-hidden="true"><use href="#i-shield"/></svg>
  // (the sprite is in base.html; names are listed in docs/UI.md).
  var SVGNS = 'http://www.w3.org/2000/svg';
  CC.icon = function (name, cls) {
    var svg = doc.createElementNS(SVGNS, 'svg');
    svg.setAttribute('class', 'ico' + (cls ? ' ' + cls : ''));
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    var use = doc.createElementNS(SVGNS, 'use');
    use.setAttribute('href', '#i-' + String(name).replace(/[^a-z0-9-]/g, ''));
    svg.appendChild(use);
    return svg;
  };
  // kind -> [icon, tone], the same table as KIND in _ui.html
  CC.KIND = { protected: ['shield', 'green'], danger: ['danger', 'red'], alert: ['alert', 'amber'], unknown: ['unknown', 'grey'],
    ai: ['ai', 'violet'], live: ['live', 'teal'], done: ['done', 'teal'], report: ['report', 'violet'] };

  /* CC.badge('danger', 'login-commbank.top, AI phishing', {href: '/domain/5', tip: [...lines], size: 'sm'})
     -> the same markup as ui.badge(): a round glass badge (a link when href is a local path). */
  CC.badge = function (kind, label, o) {
    o = o || {};
    var k = CC.KIND[kind] || CC.KIND.unknown;
    var cls = 'badge badge--' + k[1] + (o.size ? ' badge--' + o.size : '') + (o['class'] ? ' ' + o['class'] : '');
    var b = o.href
      ? CC.el('a', { class: cls, href: o.href, 'aria-label': label })
      : CC.el('span', { class: cls, role: 'img', 'aria-label': label, tabindex: o.tip ? '0' : null });
    b.appendChild(CC.icon(k[0]));
    b._ccTip = o.tip || label;
    if (typeof b._ccTip === 'string') { b.setAttribute('data-tip', b._ccTip); }
    return b;
  };

  // ---- tooltips ---------------------------------------------------------------------------------------

  /* One floating pill (#cc-tip, role=tooltip), text only.
     CC.tooltip.show(anchor, content, {kind}) where anchor is an element or a viewport point {x, y}, and content
     is a string, a Node, or an array of lines (the first line is the title, the rest muted).
     CC.tooltip.hide(). Declarative: any element with data-tip="text" (and optional data-tip-sub, data-tip-kind)
     shows it on hover and keyboard focus; ui.badge and ui.icon_button set data-tip for you. */
  var tipEl = null, tipAnchor = null;
  function tipNode() {
    if (!tipEl) {
      tipEl = CC.el('div', { class: 'tip', id: 'cc-tip', role: 'tooltip', hidden: true });
      doc.body.appendChild(tipEl);
    }
    return tipEl;
  }
  function placeTip(anchor) {
    var t = tipNode();
    var vw = doc.documentElement.clientWidth, vh = doc.documentElement.clientHeight;
    var r = anchor && anchor.getBoundingClientRect ? anchor.getBoundingClientRect()
      : { left: anchor.x, right: anchor.x, top: anchor.y, bottom: anchor.y, width: 0 };
    var tw = t.offsetWidth, th = t.offsetHeight;
    var x = Math.max(8, Math.min(vw - tw - 8, r.left + r.width / 2 - tw / 2));
    var y = r.top - th - 10;
    if (y < 8) { y = Math.min(vh - th - 8, r.bottom + 10); }
    t.style.transform = 'translate(' + Math.round(x) + 'px,' + Math.round(y) + 'px)';   // CSSOM: allowed by the CSP
  }
  CC.tooltip = {
    show: function (anchor, content, opts) {
      var o = opts || {};
      var t = tipNode();
      while (t.firstChild) { t.removeChild(t.firstChild); }
      var lines = Array.isArray(content) ? content.filter(function (x) { return x !== null && x !== undefined && x !== ''; }) : [content];
      t.className = 'tip' + (lines.length > 1 ? ' is-multi' : '');
      var first = CC.el('span', { class: 'tip-row' });
      if (o.kind && CC.KIND[o.kind]) { first.appendChild(CC.icon(CC.KIND[o.kind][0], 'tip-ico tip-ico--' + CC.KIND[o.kind][1])); }
      lines.forEach(function (line, i) {
        var node = (line && typeof line === 'object') ? line : CC.el('span', { class: i ? 'tip-text tip-sub' : 'tip-text', text: line });
        if (i === 0) { first.appendChild(node); t.appendChild(first); } else { t.appendChild(node); }
      });
      t.hidden = false;
      if (tipAnchor && tipAnchor !== anchor && tipAnchor.removeAttribute) { tipAnchor.removeAttribute('aria-describedby'); }
      tipAnchor = anchor;
      if (anchor && anchor.setAttribute && t.textContent !== (anchor.getAttribute('aria-label') || '')) {
        anchor.setAttribute('aria-describedby', 'cc-tip');
      }
      placeTip(anchor);
    },
    hide: function () {
      if (tipEl) { tipEl.hidden = true; }
      if (tipAnchor && tipAnchor.removeAttribute) { tipAnchor.removeAttribute('aria-describedby'); }
      tipAnchor = null;
    },
    get anchor() { return tipAnchor; }
  };
  function tipContent(el) {
    if (el._ccTip) { return el._ccTip; }
    var sub = el.getAttribute('data-tip-sub');
    return sub ? [el.getAttribute('data-tip'), sub] : el.getAttribute('data-tip');
  }
  function initTips() {
    function over(e) {
      var el = e.target.closest && e.target.closest('[data-tip], .badge');
      if (!el || (!el.hasAttribute('data-tip') && !el._ccTip)) { return; }
      if (el === tipAnchor) { return; }
      CC.tooltip.show(el, tipContent(el), { kind: el.getAttribute('data-tip-kind') });
    }
    function out(e) {
      if (!tipAnchor) { return; }
      var to = e.relatedTarget;
      if (to && tipAnchor.contains && tipAnchor.contains(to)) { return; }
      if (e.target === tipAnchor || (tipAnchor.contains && tipAnchor.contains(e.target))) { CC.tooltip.hide(); }
    }
    doc.addEventListener('mouseover', over);
    doc.addEventListener('mouseout', out);
    doc.addEventListener('focusin', function (e) {
      // keyboard focus only: a tap focuses too, and the hover handler already covers it
      var kb = true;
      try { kb = e.target.matches(':focus-visible'); } catch (err) { kb = true; }
      if (kb) { over(e); }
    });
    doc.addEventListener('focusout', out);
    window.addEventListener('scroll', function () { CC.tooltip.hide(); }, { passive: true, capture: true });
  }

  // ---- canvas and motion helpers ------------------------------------------------------------------------

  /* CC.canvasDPR(canvas, cssWidth?, cssHeight?, maxDpr = 2) -> {ctx, w, h, dpr}
     Sizes the backing store to the CSS size times devicePixelRatio (capped, so a phone stays smooth) and
     scales the context, so drawing code works in CSS pixels. Call it again after a resize. */
  CC.canvasDPR = function (canvas, cssW, cssH, maxDpr) {
    var rect = canvas.getBoundingClientRect();
    var w = cssW || rect.width || canvas.clientWidth || 300;
    var h = cssH || rect.height || canvas.clientHeight || 150;
    var dpr = Math.max(1, Math.min(window.devicePixelRatio || 1, maxDpr || 2));
    var bw = Math.max(1, Math.round(w * dpr)), bh = Math.max(1, Math.round(h * dpr));
    if (canvas.width !== bw) { canvas.width = bw; }
    if (canvas.height !== bh) { canvas.height = bh; }
    var ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return { ctx: ctx, w: w, h: h, dpr: dpr };
  };

  // CC.observeSize(el, fn) calls fn({width, height}) once per frame at most when el's box changes. Returns stop().
  CC.observeSize = function (el, fn) {
    var raf = 0;
    function fire() {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(function () { var r = el.getBoundingClientRect(); fn({ width: r.width, height: r.height }); });
    }
    if (window.ResizeObserver) {
      var ro = new ResizeObserver(fire);
      ro.observe(el);
      return function () { ro.disconnect(); cancelAnimationFrame(raf); };
    }
    window.addEventListener('resize', fire);
    return function () { window.removeEventListener('resize', fire); cancelAnimationFrame(raf); };
  };

  // CC.reducedMotion() -> true when the viewer asked for less motion (no glow animation then).
  var rmq = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;
  CC.reducedMotion = function () { return !!(rmq && rmq.matches); };
  CC.onMotionChange = function (fn) {
    if (!rmq) { return function () {}; }
    var h = function () { fn(rmq.matches); };
    if (rmq.addEventListener) { rmq.addEventListener('change', h); } else { rmq.addListener(h); }
    return function () { if (rmq.removeEventListener) { rmq.removeEventListener('change', h); } else { rmq.removeListener(h); } };
  };

  /* CC.loop(fn) -> {start(), stop(), running()}: requestAnimationFrame loop, fn(timeMs, dtMs). It skips frames
     while the tab is hidden. The caller decides whether to start it at all under CC.reducedMotion(). */
  CC.loop = function (fn) {
    var id = 0, on = false, last = 0;
    function tick(t) {
      if (!on) { return; }
      if (!doc.hidden) { fn(t, last ? t - last : 16); }
      last = t;
      id = requestAnimationFrame(tick);
    }
    return {
      start: function () { if (!on) { on = true; last = 0; id = requestAnimationFrame(tick); } },
      stop: function () { on = false; cancelAnimationFrame(id); },
      running: function () { return on; }
    };
  };

  // CC.token('--teal') -> '#2fd3a7': a design token from app.css, for canvas colours.
  CC.token = function (name) {
    return getComputedStyle(doc.documentElement).getPropertyValue(name).trim();
  };

  // CC.compact(882000) -> '882k', 1234 -> '1.2k', 2400000 -> '2.4M' (the same as the Jinja |compact filter).
  CC.compact = function (n, digits) {
    if (n === null || n === undefined || n === '' || isNaN(Number(n))) { return '-'; }
    var v = Number(n), d = digits === undefined ? 1 : digits;
    var sign = v < 0 ? '-' : '';
    v = Math.abs(v);
    var units = [[1e9, 'B'], [1e6, 'M'], [1e3, 'k']];
    for (var i = 0; i < units.length; i++) {
      if (v >= units[i][0] * 0.99995) {
        var x = v / units[i][0];
        var txt = x >= 100 ? x.toFixed(0) : String(Number(x.toFixed(d)));
        return sign + txt + units[i][1];
      }
    }
    return sign + (v === Math.round(v) ? v.toLocaleString('en-AU') : v.toLocaleString('en-AU', { maximumFractionDigits: d }));
  };

  // ---- start ------------------------------------------------------------------------------------------

  CC.ready(function () {
    doc.documentElement.classList.add('js');
    CC.$$('.js-only[hidden]').forEach(function (el) { el.hidden = false; });

    CC.relTime();
    setInterval(function () { CC.relTime(); }, 30000);

    CC.shortcut('?', 'Show keyboard shortcuts', CC.openHelp, { group: 'Global' });
    CC.shortcut('/', 'Search domains', focusSearch, { group: 'Global' });
    CC.$$('[data-chord]').forEach(function (a) {
      var href = a.getAttribute('href');
      CC.shortcut(a.getAttribute('data-chord'), a.getAttribute('data-chord-label') || a.textContent.trim(),
        function () { location.href = href; }, { group: 'Go to' });
    });
    CC.$$('[data-shortcut]').forEach(function (el) {
      var label = el.getAttribute('data-shortcut-label') || el.getAttribute('aria-label') ||
        (el.tagName === 'INPUT' || el.tagName === 'SELECT' || el.tagName === 'TEXTAREA'
          ? ((el.labels && el.labels[0] && el.labels[0].textContent) || el.name) : '') ||
        (el.childNodes[0] && el.childNodes[0].textContent) || el.textContent;
      CC.shortcut(el.getAttribute('data-shortcut'), String(label).trim(), function () {
        if (el.disabled || el.getAttribute('aria-disabled') === 'true' || !visible(el)) {
          CC.toast('That action is not available right now.', 'warn'); return;
        }
        if (editable(el)) { el.focus(); } else { el.click(); }
      });
    });
    if (CC.$('[data-rows]')) {
      CC.shortcut('j', 'Next row', function () { moveCursor(1); });
      CC.shortcut('k', 'Previous row', function () { moveCursor(-1); });
      CC.shortcut('o', 'Open the selected row', openCursor);
    }

    CC.$$('[data-help-open]').forEach(function (b) { b.addEventListener('click', CC.openHelp); });

    var toggle = CC.$('[data-menu-toggle]');
    if (toggle) {
      toggle.setAttribute('role', 'button');
      toggle.setAttribute('aria-expanded', 'false');
      toggle.addEventListener('click', function (e) { e.preventDefault(); openMenu(); });
      toggle.addEventListener('keydown', function (e) { if (e.key === ' ') { e.preventDefault(); openMenu(); } });
      if (location.hash === '#cc-nav') { openMenu(true); }
    }
    // a click outside closes the "More" dropdown and the phone sheet
    doc.addEventListener('click', function (e) {
      var t = e.target;
      CC.$$('details[data-nav-more][open]').forEach(function (d) {
        var sheet = doc.getElementById('cc-nav');
        if (!d.contains(t) && !(sheet && sheet.classList.contains('is-open'))) { d.open = false; }
      });
      var sheet = doc.getElementById('cc-nav');
      if (sheet && sheet.classList.contains('is-open') && !sheet.contains(t) && !(toggle && toggle.contains(t))) { openMenu(false); }
    });
    CC.$$('details[data-nav-more]').forEach(function (d) {
      d.addEventListener('focusout', function (e) {
        var sheet = doc.getElementById('cc-nav');
        if (e.relatedTarget && !d.contains(e.relatedTarget) && !(sheet && sheet.classList.contains('is-open'))) { d.open = false; }
      });
    });
    initTips();

    CC.$$('[data-tabs]').forEach(initTabs);

    var bar = doc.getElementById('cc-status');
    if (bar && bar.getAttribute('data-status-url')) {
      CC.statusPoll = CC.poll(bar.getAttribute('data-status-url'), 15000, applyStatus);
    }
  });
})();
