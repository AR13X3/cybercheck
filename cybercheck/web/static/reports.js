/* /reports and /reports/<id>. Conveniences only: every action is a plain form POST that works without this.
   - Arriving on #r<id> (after an action) or following an in-page link opens the right tab and item.
   - Email drafts track unsaved edits: the mail-client link uses the saved text, so it asks you to save first,
     and leaving the page with unsaved edits asks first.
   - "Copy all fields" on manual web-form items; readonly fields select their text on focus (phones).
   Uses window.CC from app.js. No innerHTML; text only. */
(function () {
  'use strict';
  var CC = window.CC;
  if (!CC || !CC.ready) { return; }
  var doc = document;

  // ---- reveal an element: switch to its tab, open its <details>, scroll and flash it -------------------
  function reveal(id, opts) {
    var el = id && doc.getElementById(id);
    if (!el || !CC.$('main').contains(el)) { return false; }
    var panel = el.closest('[role="tabpanel"]');
    if (panel && panel.hidden) {
      var tab = CC.$('a[role="tab"][aria-controls="' + panel.id + '"]');
      if (tab) { tab.click(); }
    }
    for (var d = el.closest('details'); d; d = d.parentElement ? d.parentElement.closest('details') : null) {
      d.open = true;
    }
    if (history.replaceState) { history.replaceState(null, '', '#' + id); }
    el.classList.add('rq-flash');
    setTimeout(function () { el.classList.remove('rq-flash'); }, 2600);
    el.scrollIntoView({ block: 'start' });
    if (opts && opts.focus) {
      var f = el.matches('details') ? CC.$('summary', el) : (el.matches('tr') ? CC.$('a[href], button', el) : el);
      if (f && f.focus) { f.focus({ preventScroll: true }); }
    }
    return true;
  }

  function initReveal() {
    var hash = location.hash ? decodeURIComponent(location.hash.slice(1)) : '';
    if (hash && !CC.$('a[role="tab"][href="#' + hash.replace(/["\\]/g, '') + '"]')) { reveal(hash); }
    doc.addEventListener('click', function (e) {
      var a = e.target.closest && e.target.closest('main a[href^="#"]');
      if (!a || a.getAttribute('role') === 'tab' || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey) { return; }
      var id = a.getAttribute('href').slice(1);
      if (id && reveal(id, { focus: true })) { e.preventDefault(); }
    });
  }

  // ---- email drafts: unsaved edits ----------------------------------------------------------------------
  function snapshot(form) {
    return ['to', 'subject', 'body'].map(function (n) {
      var f = form.elements[n];
      return f ? f.value : '';
    }).join('\u0000');
  }

  function initDrafts() {
    var forms = CC.$$('form[data-rq-draft]');
    forms.forEach(function (form) {
      var saved = snapshot(form);
      var note = CC.$('[data-rq-dirty-note]', form);
      form.addEventListener('input', function () {
        form._rqDirty = snapshot(form) !== saved;
        if (note) { note.hidden = !form._rqDirty; }
        CC.$$('a[data-rq-mailto="' + form.id + '"]').forEach(function (a) {
          a.classList.toggle('is-stale', !!form._rqDirty);
          a.setAttribute('title', form._rqDirty ? 'Save the draft first: this link still has the saved text' : '');
        });
      });
      // a real submit (after any confirm dialog) leaves the page on purpose
      form.addEventListener('submit', function (e) {
        if (!e.defaultPrevented) { form._rqDirty = false; }
      });
    });
    doc.addEventListener('click', function (e) {
      var a = e.target.closest && e.target.closest('a[data-rq-mailto]');
      if (!a) { return; }
      var form = doc.getElementById(a.getAttribute('data-rq-mailto'));
      if (form && form._rqDirty) {
        e.preventDefault();
        CC.toast('Save the draft first: the mail-client link still has the saved text.', 'warn');
        var save = CC.$('button:not([formaction]):not([disabled])', form) ||
          CC.$('button[form="' + form.id + '"]:not([formaction]):not([disabled])');
        if (save) { save.focus(); }
      }
    });
    if (forms.length) {
      window.addEventListener('beforeunload', function (e) {
        if (forms.some(function (f) { return f._rqDirty; })) { e.preventDefault(); e.returnValue = ''; }
      });
    }
  }

  // ---- manual web forms ------------------------------------------------------------------------------------
  function initManual() {
    CC.$$('[data-rq-copy-all]').forEach(function (b) {
      var root = doc.getElementById(b.getAttribute('data-rq-copy-all'));
      if (!root) { return; }
      b.hidden = false;
      b.addEventListener('click', function () {
        var parts = CC.$$('.rq-field', root).map(function (li) {
          var label = CC.$('label', li);
          var name = label ? label.textContent.replace(/^\s*\d+/, '').trim() : '';
          var field = CC.$('textarea', li);
          return name + '\n' + (field ? field.value : '');
        });
        CC.copy(parts.join('\n\n'));
      });
    });
    // readonly prefilled fields: one tap selects the whole value, for copying by hand
    doc.addEventListener('focusin', function (e) {
      var t = e.target;
      if (t && t.matches && t.matches('textarea[data-rq-field][readonly]')) {
        setTimeout(function () { try { t.select(); } catch (err) { /* ignore */ } }, 0);
      }
    });
  }

  CC.ready(function () {
    initDrafts();
    initManual();
    initReveal();
  });
})();
