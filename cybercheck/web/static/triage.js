/* Triage screen (/review): keyboard-driven review of the queue. Progressive enhancement only: without this file
   the queue links open /domain/<id> and the decision buttons are plain POST forms to /domain/<id>/status.

   With it: clicking a queue row (or j / k) loads that domain's evidence into the right pane from
   GET /review/evidence/<id> (server-rendered, autoescaped markup; parsed with DOMParser and sanitised again here,
   never innerHTML). c / f / b decide (c asks first, through app.js's data-confirm dialog), the decision is posted
   to the same form action with the same field names, the next domain loads, and a toast offers Undo (which posts
   status=open). Uses window.CC from app.js (docs/UI.md). */
(function () {
  'use strict';

  var CC = window.CC;
  if (!CC || !window.fetch || !window.DOMParser) { return; }
  var doc = document;

  var DONE = {
    confirmed: function (d) { return 'Confirmed ' + d + ' as phishing. Report drafts are being created.'; },
    false_positive: function (d) { return 'Marked ' + d + ' as a false positive.'; },
    benign: function (d) { return 'Marked ' + d + ' as benign or parked.'; },
    open: function (d) { return 'Reopened ' + d + '. It is back in the queue.'; }
  };

  // ---- requests -----------------------------------------------------------------------------------------

  // POST a decision without following the 303 (the redirect target is a full page we do not need).
  // The browser sends Origin and Sec-Fetch-Site: same-origin, which same_origin() checks.
  function send(path, data) {
    if (!CC.isLocalPath(path)) { return Promise.reject(new Error('not a dashboard path')); }
    var body = new URLSearchParams();
    Object.keys(data).forEach(function (k) { body.append(k, data[k]); });
    return fetch(path, {
      method: 'POST', body: body, credentials: 'same-origin', redirect: 'manual', cache: 'no-store',
      headers: { 'Accept': 'application/json' }
    }).then(function (r) {
      if (r.type === 'opaqueredirect' || (r.status >= 200 && r.status < 400)) { return r; }
      return r.text().then(function (t) {
        var detail = '';
        try { var j = JSON.parse(t); if (j && typeof j.detail === 'string') { detail = j.detail; } } catch (e) { /* not JSON */ }
        var err = new Error(detail || ('HTTP ' + r.status));
        err.status = r.status; err.detail = detail;
        throw err;
      });
    });
  }

  // Our own markup, but it carries attacker text: keep only what the pane needs (no scripts, no handlers,
  // only same-origin links). Belt and braces: Jinja escapes everything and the CSP blocks inline script.
  var DROP = 'script,style,iframe,frame,object,embed,link,meta,base,template,svg foreignObject';
  var URL_ATTRS = ['href', 'src', 'action', 'formaction', 'xlink:href', 'srcset', 'poster'];
  function sanitize(root) {
    CC.$$(DROP, root).forEach(function (n) { n.remove(); });
    [root].concat(CC.$$('*', root)).forEach(function (el) {
      Array.prototype.slice.call(el.attributes).forEach(function (a) {
        var name = a.name.toLowerCase();
        if (name.indexOf('on') === 0 || name === 'style') { el.removeAttribute(a.name); return; }
        if (URL_ATTRS.indexOf(name) >= 0 && !CC.isLocalPath(a.value)) { el.removeAttribute(a.name); }
      });
    });
    return root;
  }

  function fetchPane(id) {
    return fetch('/review/evidence/' + encodeURIComponent(id), {
      credentials: 'same-origin', cache: 'no-store', headers: { 'Accept': 'text/html' }
    }).then(function (r) {
      if (!r.ok) { var e = new Error('HTTP ' + r.status); e.status = r.status; throw e; }
      return r.text();
    }).then(function (html) {
      var parsed = new DOMParser().parseFromString(html, 'text/html');
      var pane = parsed.getElementById('evidence');
      if (!pane) { throw new Error('no evidence pane in the answer'); }
      return doc.importNode(sanitize(pane), true);
    });
  }

  // ---- the review screen --------------------------------------------------------------------------------

  function initReview() {
    var root = CC.$('[data-triage]');
    var paneBox = CC.$('[data-pane]');
    if (!root || !paneBox) { return; }
    var narrow = window.matchMedia ? window.matchMedia('(max-width: 899.98px)') : { matches: false };
    var total = parseInt(root.getAttribute('data-total'), 10) || 0;
    var current = null;
    var loadSeq = 0, loadTimer = null;
    var lastUndo = null;

    function queue() { return CC.$('[data-queue]', root); }
    function rows() { var q = queue(); return q ? CC.$$('tr[data-id]', q) : []; }
    function rowFor(id) { return rows().filter(function (tr) { return tr.getAttribute('data-id') === String(id); })[0] || null; }
    function linkOf(tr) { return tr ? CC.$('a.q-link', tr) : null; }
    function pane() { return CC.$('#evidence', paneBox); }

    function markSelected(id) {
      rows().forEach(function (tr) {
        var a = linkOf(tr);
        if (!a) { return; }
        if (tr.getAttribute('data-id') === String(id)) { a.setAttribute('aria-current', 'true'); }
        else { a.removeAttribute('aria-current'); }
      });
    }

    function updateUrl(id) {
      if (!history.replaceState) { return; }
      var a = linkOf(rowFor(id));
      var target = a && a.getAttribute('data-select');
      if (!target) {
        var params = new URLSearchParams(location.search);
        params.set('id', String(id));
        target = '?' + params.toString();
      }
      if (CC.isLocalPath(target)) { history.replaceState(null, '', target); }
    }

    function updateCount(delta) {
      total = Math.max(0, total + delta);
      root.setAttribute('data-total', String(total));
      var el = CC.$('[data-queue-count]');
      var shown = rows().length;
      if (el) {
        el.textContent = total === 0 ? '' : (total > shown
          ? 'Showing the first ' + shown + ' of ' + CC.fmtInt(total) + '.'
          : CC.fmtInt(total) + ' in the queue.');
      }
    }

    function enhancePane(p) {
      CC.relTime(p);
      CC.$$('.js-only[hidden]', p).forEach(function (el) { el.hidden = false; });
      CC.$$('form[data-decision]', p).forEach(function (f) { f.addEventListener('submit', onSubmit); });
    }

    function showPane(fresh, opts) {
      var old = pane();
      if (old) { old.replaceWith(fresh); } else { paneBox.appendChild(fresh); }
      enhancePane(fresh);
      fresh.classList.add('is-in');
      setTimeout(function () { fresh.classList.remove('is-in'); }, 300);
      if (opts && opts.focus) {
        if (narrow.matches) { fresh.scrollIntoView({ block: 'start' }); }
        fresh.focus({ preventScroll: !narrow.matches });
      }
    }

    function load(id, opts) {
      var seq = ++loadSeq;
      var p = pane();
      if (p) { p.classList.add('is-loading'); p.setAttribute('aria-busy', 'true'); }
      return fetchPane(id).then(function (fresh) {
        if (seq !== loadSeq) { return; }               // a newer selection won
        current = String(id);
        markSelected(current);
        updateUrl(current);
        showPane(fresh, opts);
      }, function (err) {
        if (seq !== loadSeq) { return; }
        if (p) { p.classList.remove('is-loading'); p.removeAttribute('aria-busy'); }
        if (err.status === 404) {
          CC.toast('That domain no longer exists. Pick another one from the queue.', 'warn');
        } else {
          CC.toast('Could not load the evidence (' + (err.status ? 'HTTP ' + err.status : 'network error') +
                   '). Open the domain page with o, or try again.', 'error');
        }
        current = String(id);
        markSelected(current);
      });
    }

    function loadSoon(id) {
      clearTimeout(loadTimer);
      loadTimer = setTimeout(function () { load(id); }, 140);
    }

    function showEmpty() {
      current = null;
      var q = CC.$('.queue-wrap', root);
      var none = CC.el('div', { class: 'empty' },
        CC.el('p', { class: 'empty-title' }, CC.el('span', { class: 'empty-glyph', 'aria-hidden': 'true', text: '○' }), ' Nothing here.'),
        CC.el('p', { class: 'empty-text', text: 'You have cleared the queue. New hits from the certificate stream land here within minutes.' }),
        CC.el('p', {}, CC.el('a', { class: 'btn btn--quiet', href: '/domains?status=open', text: 'Browse open domains' })));
      if (q) { q.replaceWith(none); }
      var box = CC.el('section', { class: 'evidence evidence--empty', id: 'evidence', tabindex: '-1', 'aria-label': 'Evidence' },
        CC.el('div', { class: 'empty' },
          CC.el('p', { class: 'empty-title' }, CC.el('span', { class: 'empty-glyph', 'aria-hidden': 'true', text: '○' }), ' Queue cleared.'),
          CC.el('p', { class: 'empty-text', text: 'Every domain in this view has a decision. Undo is still available from the last message for a few seconds.' })));
      var old = pane();
      if (old) { old.replaceWith(box); } else { paneBox.appendChild(box); }
      box.focus();
    }

    // the queue row after the one being removed (or before it, at the end)
    function neighbour(id) {
      var list = rows();
      var i = list.indexOf(rowFor(id));
      if (i < 0) { return list[0] ? list[0].getAttribute('data-id') : null; }
      var n = list[i + 1] || list[i - 1];
      return n ? n.getAttribute('data-id') : null;
    }

    function flash(p, text, tone) {
      var box = p && CC.$('[data-ev-flash]', p);
      if (!box) { return; }
      box.textContent = '';
      box.appendChild(CC.el('div', { class: 'flash flash--' + (tone || 'warn'), role: tone === 'error' ? 'alert' : 'status' },
        CC.el('span', { class: 'flash-glyph', 'aria-hidden': 'true', text: tone === 'error' ? '■' : '▲' }),
        CC.el('span', { class: 'flash-text', text: text })));
    }

    function toastWithUndo(text, undo) {
      var t = CC.toast(text, 'ok', 12000);
      if (!t) { return; }
      var btn = CC.el('button', { type: 'button', class: 'btn btn--sm', text: 'Undo', 'aria-keyshortcuts': 'u',
        on: { click: function () { t.remove(); undo(); } } });
      t.insertBefore(btn, t.lastChild);
      // u works while the message is on screen; later, reopen from the domain page
      lastUndo = function () {
        if (!doc.contains(t)) { lastUndo = null; CC.toast('Nothing to undo.', 'warn'); return; }
        t.remove(); undo();
      };
    }

    function decide(form, sub) {
      var p = form.closest('#evidence');
      var id = p ? p.getAttribute('data-domain-id') : null;
      var domain = form.getAttribute('data-domain') || 'this domain';
      var status = sub.value;
      var noteEl = CC.$('[data-note]', form);
      var note = noteEl ? noteEl.value : '';
      if (!id || form._ccSending) { return; }
      form._ccSending = true;
      CC.busy(sub, true);
      send(form.getAttribute('action'), { status: status, note: note }).then(function () {
        var tr = rowFor(id);
        var removed = null;
        if (status === 'open') {
          CC.toast(DONE.open(domain));
          load(id, { focus: true });
          return;
        }
        var next = neighbour(id);
        if (tr) {
          var list = rows();
          removed = { tr: tr, before: list[list.indexOf(tr) + 1] || null };
          tr.remove();
          updateCount(-1);
        }
        toastWithUndo((DONE[status] || DONE.open)(domain), function () { undo(id, domain, removed); });
        if (CC.statusPoll) { CC.statusPoll.now(); }
        if (next) { load(next, { focus: true }); } else { showEmpty(); }
      }, function (err) {
        form._ccSending = false;
        CC.busy(sub, false);
        if (err.status === 400 && err.detail) {
          // e.g. an official brand domain: the server refuses to call it phishing
          flash(p, err.detail, 'warn');
          CC.toast('Not saved: ' + err.detail, 'error');
        } else if (err.status === 403) {
          CC.toast('Not saved: the dashboard refused the request (' + (err.detail || 'cross-site check') + '). Reload the page and try again.', 'error');
        } else {
          CC.toast('Could not save the decision' + (err.status ? ' (HTTP ' + err.status + ')' : ' (network error)') + '. Nothing changed. Try again.', 'error');
        }
      });
    }

    function undo(id, domain, removed) {
      lastUndo = null;
      send('/domain/' + encodeURIComponent(id) + '/status', { status: 'open', note: '' }).then(function () {
        var q = queue();
        if (removed && q && !rowFor(id)) {
          removed.tr.classList.remove('is-leaving');
          if (removed.before && removed.before.parentNode === q) { q.insertBefore(removed.tr, removed.before); }
          else { q.appendChild(removed.tr); }
          updateCount(1);
        }
        CC.toast(DONE.open(domain));
        if (CC.statusPoll) { CC.statusPoll.now(); }
        if (q) { load(id, { focus: true }); } else { location.href = '/review?id=' + encodeURIComponent(id); }
      }, function (err) {
        CC.toast('Could not undo: ' + (err.detail || (err.status ? 'HTTP ' + err.status : 'network error')) +
                 '. Reopen it from its domain page.', 'error');
      });
    }

    function onSubmit(e) {
      var sub = e.submitter;
      if (!sub || sub.name !== 'status') { return; }     // not a decision button: leave it to the browser
      e.preventDefault();
      decide(e.currentTarget, sub);
    }

    // ---- selection: click, j / k, Enter ---------------------------------------------------------------

    root.addEventListener('click', function (e) {
      var a = e.target.closest && e.target.closest('a.q-link');
      if (!a || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) { return; }
      var tr = a.closest('tr[data-id]');
      if (!tr) { return; }
      e.preventDefault();
      clearTimeout(loadTimer);
      load(tr.getAttribute('data-id'), { focus: true });
    });

    function move(step) {
      var list = rows();
      if (!list.length) { return; }
      var i = list.indexOf(rowFor(current));
      i = i < 0 ? 0 : Math.max(0, Math.min(list.length - 1, i + step));
      var tr = list[i];
      var id = tr.getAttribute('data-id');
      markSelected(id);
      var a = linkOf(tr);
      if (a) { a.focus({ preventScroll: true }); }
      tr.scrollIntoView({ block: 'nearest' });
      if (id !== current) { current = id; loadSoon(id); }
    }

    function press(status) {
      var p = pane();
      var b = p && CC.$('button[name="status"][value="' + status + '"]', p);
      if (!b) { CC.toast('Select a domain in the queue first.', 'warn'); return; }
      if (b.disabled || b.getAttribute('aria-disabled') === 'true') {
        var why = status === 'confirmed' && CC.$('.decision-official', p)
          ? 'This is an official brand domain, so it cannot be confirmed as phishing.'
          : 'That is already the decision for this domain.';
        CC.toast(why, 'warn');
        return;
      }
      b.click();
    }

    var G = 'Review queue';
    CC.shortcut('j', 'Next domain in the queue', function () { move(1); }, { group: G });
    CC.shortcut('k', 'Previous domain in the queue', function () { move(-1); }, { group: G });
    CC.shortcut(']', 'Next domain in the queue', function () { move(1); }, { group: G });
    CC.shortcut('[', 'Previous domain in the queue', function () { move(-1); }, { group: G });
    CC.shortcut('c', 'Confirm phishing (asks first)', function () { press('confirmed'); }, { group: G });
    CC.shortcut('f', 'Mark false positive', function () { press('false_positive'); }, { group: G });
    CC.shortcut('b', 'Mark benign / parked', function () { press('benign'); }, { group: G });
    CC.shortcut('n', 'Write a note for the decision', function () {
      var n = CC.$('#evidence [data-note]');
      if (n) { n.focus(); } else { CC.toast('Select a domain in the queue first.', 'warn'); }
    }, { group: G });
    CC.shortcut('o', 'Open the domain page', function () {
      var p = pane();
      var id = p && p.getAttribute('data-domain-id');
      if (id) { location.href = '/domain/' + encodeURIComponent(id); }
    }, { group: G });
    CC.shortcut('u', 'Undo the last decision', function () {
      if (lastUndo) { lastUndo(); } else { CC.toast('Nothing to undo.', 'warn'); }
    }, { group: G });

    // start: the server already rendered the selected domain's evidence
    var first = pane();
    if (first) {
      current = first.getAttribute('data-domain-id');
      enhancePane(first);
      // a domain picked further down the queue (?id=): bring its row into the queue's own scroll box
      var sel = rowFor(current), wrap = CC.$('.queue-wrap', root);
      if (sel && wrap && !narrow.matches) {
        var top = sel.getBoundingClientRect().top - wrap.getBoundingClientRect().top;
        if (top < 0 || top > wrap.clientHeight - 40) { wrap.scrollTop += top - wrap.clientHeight / 3; }
      }
    }
  }

  CC.ready(function () {
    if (doc.body.getAttribute('data-page') === 'review') { initReview(); }
  });
})();
