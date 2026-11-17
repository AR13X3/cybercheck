/* Operations pages (AI, blocklist, CZDS, bot, takedowns). Conveniences only: every page and every action works
   without this file. Uses window.CC from app.js (loaded first, both deferred). DOM is built with CC.el, text only. */
(function () {
  'use strict';

  var CC = window.CC;
  if (!CC || !CC.ready) { return; }

  /* Filter box for one table body:
       <input data-filter-for="rows-id">                 hides rows that do not contain every word typed
       <input type="checkbox" data-filter-problems="rows-id">  keeps only <tr data-problem> rows
       <span data-filter-count="rows-id" aria-live="polite">   "Showing 3 of 120"
     Rows keep their markup; hidden ones get .ops-hidden, so j/k skips them. */
  function setupFilter(id) {
    var body = document.getElementById(id);
    if (!body) { return; }
    var input = CC.$('[data-filter-for="' + id + '"]');
    var toggle = CC.$('[data-filter-problems="' + id + '"]');
    var count = CC.$('[data-filter-count="' + id + '"]');
    var rows = CC.$$('tr', body).filter(function (tr) { return tr.parentNode === body && !tr.classList.contains('empty-row'); });
    if (!rows.length) { return; }
    var texts = rows.map(function (tr) { return tr.textContent.toLowerCase().replace(/\s+/g, ' '); });
    var table = body.closest('table');
    var cols = table ? CC.$$('thead th', table).length || 1 : 1;
    var none = null;

    function apply() {
      var words = (input ? input.value : '').toLowerCase().split(/\s+/).filter(Boolean);
      var onlyProblems = !!(toggle && toggle.checked);
      var shown = 0;
      rows.forEach(function (tr, i) {
        var ok = (!onlyProblems || tr.hasAttribute('data-problem')) &&
          words.every(function (w) { return texts[i].indexOf(w) >= 0; });
        tr.classList.toggle('ops-hidden', !ok);
        if (!ok) { tr.classList.remove('is-cursor'); }
        if (ok) { shown += 1; }
      });
      if (!shown && !none) {
        none = CC.el('tr', { class: 'empty-row' },
          CC.el('td', { colspan: String(cols) }, 'No rows match. Clear the filter to see all ' + rows.length + '.'));
        body.appendChild(none);
      } else if (shown && none) {
        none.remove();
        none = null;
      }
      if (count) {
        count.textContent = (words.length || onlyProblems) ? 'Showing ' + shown + ' of ' + rows.length : '';
      }
    }

    if (input) {
      input.addEventListener('input', apply);
      // Esc clears a filled box first; a second Esc leaves the field (app.js)
      input.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && input.value) { input.value = ''; apply(); e.stopPropagation(); }
      });
    }
    if (toggle) { toggle.addEventListener('change', apply); }
    apply();     // the browser may restore a typed filter on back/forward
  }

  // "Copy link" for blocklist files: the full URL another device on your private network can subscribe to.
  function setupCopyPath() {
    document.addEventListener('click', function (e) {
      var b = e.target.closest && e.target.closest('[data-copy-path]');
      if (!b) { return; }
      var path = b.getAttribute('data-copy-path');
      if (!CC.isLocalPath(path)) { return; }
      e.preventDefault();
      CC.copy(location.origin + path);
    });
  }

  CC.ready(function () {
    var ids = {};
    CC.$$('[data-filter-for], [data-filter-problems]').forEach(function (el) {
      ids[el.getAttribute('data-filter-for') || el.getAttribute('data-filter-problems')] = true;
    });
    Object.keys(ids).forEach(setupFilter);
    setupCopyPath();
  });
})();
