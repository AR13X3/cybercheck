/* Overview page ("/"): the threat terrain on a canvas, its pinned domains and controls, live gauges, the live hit
   feed and page shortcuts. Progressive enhancement over overview.html: without this file the terrain is a coarser
   SVG whose notable domains are links, every number is a link and the feed is a static list.
   Data comes from /api/live/terrain (polled every minute), /api/live/summary (30 s) and /api/recent (10 s).
   Hostnames and brands are attacker-controlled: they reach the page only as text (CC.el, CC.tooltip, CC.badge),
   and links are built from numeric ids. */
(function () {
  'use strict';
  var CC = window.CC;
  if (!CC) { return; }
  var doc = document;

  var FEED_MS = 10000, SUMMARY_MS = 30000, TERRAIN_MS = 60000, FEED_MAX = 200;
  var FILTER_KEY = 'cybercheck:overview:feed-filter';

  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function utcTime(d) { return pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds()); }
  function minuteKey(d) {
    return d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) + 'T' +
      pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + 'Z';
  }
  function hourKey(d) { var h = new Date(d.getTime()); h.setUTCMinutes(0, 0, 0); return minuteKey(h); }
  function plural(n, one, many) { return CC.fmtInt(n) + ' ' + (n === 1 ? one : (many || one + 's')); }
  function clamp(v, a, b) { return v < a ? a : (v > b ? b : v); }
  function store(get, value) {
    try {
      if (get) { return window.localStorage.getItem(FILTER_KEY); }
      window.localStorage.setItem(FILTER_KEY, value);
    } catch (e) { /* private window or blocked storage: the default view is fine */ }
    return null;
  }

  // one switch for every live update on the page (the button in the terrain's row and the p key)
  var live = { paused: false };

  // ---- pills, the same markup as _ui.html ----------------------------------------------------------------

  var TIER = { high: ['red', '▲'], review: ['amber', '◆'], watch: ['muted', '○'] };
  var STATUS = { confirmed: ['confirmed phishing', 'red', '✕'], false_positive: ['false positive', 'teal', '✓'],
    benign: ['benign', 'teal', '✓'] };
  var VERDICT = { phishing: '■', suspicious: '▲', benign: '✓', parked: '–', error: '!' };

  function pill(text, tone, glyph, title) {
    return CC.el('span', { class: 'pill pill--' + tone, title: title || null },
      glyph ? CC.el('span', { class: 'pill-glyph', 'aria-hidden': 'true', text: glyph }) : null, text);
  }
  function tierPill(t) { var x = TIER[t] || ['muted', '○']; return pill(t || 'none', x[0], x[1], 'Domain-name tier'); }
  function verdictPill(v) {
    var known = Object.prototype.hasOwnProperty.call(VERDICT, v);
    return CC.el('span', { class: 'pill pill--violet pill--ai-' + (known ? v : 'other'), title: 'AI page verdict' },
      CC.el('span', { class: 'pill-glyph', 'aria-hidden': 'true', text: known ? VERDICT[v] : '◆' }), 'AI ' + v);
  }
  function dom(host, unicode, href) {
    var frag = doc.createDocumentFragment();
    frag.appendChild(CC.el('a', { class: 'dom', href: href, text: host }));
    if (unicode && unicode !== host) {
      frag.appendChild(CC.el('span', { class: 'dom-alt', title: 'How the browser displays this name', text: unicode }));
    }
    return frag;
  }

  // ---- threat terrain -----------------------------------------------------------------------------------

  var LEVEL = {};
  '0123456789abcdefghijklmnopqrstuvwxyz'.split('').forEach(function (ch, i) { LEVEL[ch] = i / 35; });
  var RGB = { teal: [47, 211, 167], amber: [243, 154, 61], red: [255, 107, 107], warm: [205, 118, 52],
    hotAmber: [255, 196, 120], hotRed: [255, 150, 112], base: [120, 196, 176] };

  function mix(a, b, t) { return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t]; }
  function smoothstep(e0, e1, x) { var t = clamp((x - e0) / (e1 - e0), 0, 1); return t * t * (3 - 2 * t); }

  function Terrain(stage) {
    var canvas = CC.$('#terrain-canvas', stage);
    var layer = CC.$('#terrain-layer', stage);
    if (!canvas || !canvas.getContext || !layer) { return null; }
    var src = stage.getAttribute('data-src');
    var self = { data: null };
    var show = { hits: true, certs: true, marks: true };
    var tier = 0;                                         // 0 all, 1 review and high, 2 high
    var grid = null, cpm = null, cellMap = null;          // decoded data
    var dotsCanvas = doc.createElement('canvas'), glowCanvas = doc.createElement('canvas');
    var size = { w: 0, h: 0, dpr: 1 }, plot = null, glowA = 0.4, visible = true, built = false;
    var anim = null;

    function decode(d) {
      var rows = d.rows, cols = d.cols;
      grid = new Float32Array(rows * cols);
      for (var r = 0; r < rows; r++) {
        var line = d.levels[r] || '';
        for (var c = 0; c < cols; c++) { grid[r * cols + c] = LEVEL[line.charAt(c)] || 0; }
      }
      var top = d.cpm_max || 0;
      cpm = new Float32Array(cols);
      for (var i = 0; i < cols; i++) { cpm[i] = top > 0 ? Math.min(1, (d.cpm[i] || 0) / top) : 0; }
      cellMap = {};
      (d.cells || []).forEach(function (x) { cellMap[x[0] * rows + x[1]] = x[2]; });
    }

    // grid sample at a fractional (row, col), bilinear
    function sample(rf, cf) {
      var d = self.data, rows = d.rows, cols = d.cols;
      rf = clamp(rf, 0, rows - 1); cf = clamp(cf, 0, cols - 1);
      var r0 = Math.floor(rf), c0 = Math.floor(cf), r1 = Math.min(rows - 1, r0 + 1), c1 = Math.min(cols - 1, c0 + 1);
      var fr = rf - r0, fc = cf - c0;
      var a = grid[r0 * cols + c0] * (1 - fc) + grid[r0 * cols + c1] * fc;
      var b = grid[r1 * cols + c0] * (1 - fc) + grid[r1 * cols + c1] * fc;
      return a * (1 - fr) + b * fr;
    }
    function cpmAt(cf) {
      var cols = self.data.cols;
      cf = clamp(cf, 0, cols - 1);
      var c0 = Math.floor(cf), c1 = Math.min(cols - 1, c0 + 1), f = cf - c0;
      return cpm[c0] * (1 - f) + cpm[c1] * f;
    }
    function scoreMin() { var d = self.data; return tier === 2 ? d.high_at : (tier === 1 ? d.review_at : 0); }

    // colour of a dot at a score with hit intensity L (0..1): teal (watch), amber (review), red (high), and a warm
    // shift where hits cluster
    function colour(score, L) {
      var d = self.data;
      var toAmber = smoothstep(d.review_at - 3, d.review_at + 1, score);
      var toRed = smoothstep(d.high_at - 3, d.high_at + 1, score);
      var band = mix(mix(RGB.teal, RGB.amber, toAmber), RGB.red, toRed);
      // faint areas stay close to the neutral field colour; the band colour comes through as hits pile up
      var c = mix(RGB.base, band, 0.35 + 0.65 * smoothstep(0, 0.6, L));
      var hot = smoothstep(0.55, 1, L);
      if (hot > 0) {
        var target = toRed > 0.5 ? RGB.hotRed : (toAmber > 0.5 ? RGB.hotAmber : RGB.warm);
        c = mix(c, target, hot * (toAmber > 0.5 ? 0.4 : 0.75));
      }
      return c;
    }

    function layout() {
      var w = size.w, h = size.h;
      var padX = w < 560 ? 6 : 14, padTop = 22, padBottom = w < 900 ? 22 : 48;
      plot = { x0: padX, x1: w - padX, y0: padTop, y1: h - padBottom };
      plot.pitch = w < 560 ? 4.2 : (w < 1000 ? 3.8 : 3.6);
    }
    function xOf(frac) { return plot.x0 + frac * (plot.x1 - plot.x0); }
    function yOfScore(score) {
      var d = self.data, top = d.score_min + (d.rows - 1) * d.score_step;
      return plot.y1 - (clamp(score, d.score_min, top) - d.score_min) / (top - d.score_min) * (plot.y1 - plot.y0);
    }

    // render the dot field (device pixels) and the glow (a small blurred image) once per data or size change
    function build() {
      var d = self.data;
      if (!d || !size.w) { return; }
      layout();
      var dpr = size.dpr, W = Math.max(1, Math.round(size.w * dpr)), H = Math.max(1, Math.round(size.h * dpr));
      dotsCanvas.width = W; dotsCanvas.height = H;
      var dctx = dotsCanvas.getContext('2d');
      var img = dctx.createImageData(W, H), px = img.data;
      var P = plot.pitch, pw = plot.x1 - plot.x0, ph = plot.y1 - plot.y0;
      var nx = Math.floor(pw / P), ny = Math.floor(ph / P);
      var offX = plot.x0 + (pw - nx * P) / 2 + P / 2, offY = plot.y0 + (ph - ny * P) / 2 + P / 2;
      var top = d.score_min + (d.rows - 1) * d.score_step, smin = scoreMin();
      var nowFrac = (d.now_col + 1) / d.cols, fade = Math.min(40, size.w * 0.06);
      // the glow: one cell per 6 css px, box-blurred twice, drawn scaled up
      var gw = Math.max(2, Math.ceil(size.w / 6)), gh = Math.max(2, Math.ceil(size.h / 6));
      var gr = new Float32Array(gw * gh), gg = new Float32Array(gw * gh), gb = new Float32Array(gw * gh), ga = new Float32Array(gw * gh);

      for (var j = 0; j < ny; j++) {
        var cy = offY + j * P;
        var sf = (plot.y1 - cy) / ph, score = d.score_min + sf * (top - d.score_min);
        var rf = sf * (d.rows - 1);
        var fy = Math.min(smoothstep(0, fade, cy - plot.y0), smoothstep(0, fade * 0.6, plot.y1 - cy));
        for (var i = 0; i < nx; i++) {
          var cx = offX + i * P, frac = (cx - plot.x0) / pw, cf = frac * d.cols - 0.5;
          var fx = Math.min(smoothstep(0, fade, cx - plot.x0), smoothstep(0, fade, plot.x1 - cx));
          var edge = fx * fy;
          var future = frac > nowFrac;
          var b = show.certs ? cpmAt(cf) : 0.35;
          var L = (show.hits && !future) ? sample(rf, cf) : 0;
          if (L > 0 && score < smin) { L *= 0.1; }
          var a = (0.07 + 0.2 * b) * (future ? 0.45 : 1), s = 1.0, c = RGB.base;
          if (L > 0.02) {
            c = colour(score, L);
            a = Math.min(1, a + 0.12 + L * 0.78);
            s = 1.0 + 1.3 * L;
            var gx = Math.min(gw - 1, Math.floor(cx / 6)), gy = Math.min(gh - 1, Math.floor(cy / 6)), gk = gy * gw + gx;
            var wgt = L * L * L * edge;
            gr[gk] += c[0] * wgt; gg[gk] += c[1] * wgt; gb[gk] += c[2] * wgt; ga[gk] += wgt;
          }
          a *= edge;
          if (a < 0.01) { continue; }
          var sz = Math.max(1, Math.round(s * dpr)), x0 = Math.round(cx * dpr - sz / 2), y0 = Math.round(cy * dpr - sz / 2);
          var A = Math.round(a * 255), R = c[0] | 0, G = c[1] | 0, B = c[2] | 0;
          for (var yy = 0; yy < sz; yy++) {
            var row = y0 + yy;
            if (row < 0 || row >= H) { continue; }
            for (var xx = 0; xx < sz; xx++) {
              var col = x0 + xx;
              if (col < 0 || col >= W) { continue; }
              var k = (row * W + col) * 4;
              px[k] = R; px[k + 1] = G; px[k + 2] = B; px[k + 3] = A;
            }
          }
        }
      }
      dctx.putImageData(img, 0, 0);

      blur(ga, gw, gh); blur(gr, gw, gh); blur(gg, gw, gh); blur(gb, gw, gh);
      blur(ga, gw, gh); blur(gr, gw, gh); blur(gg, gw, gh); blur(gb, gw, gh);
      var peak = 0;
      for (var q = 0; q < ga.length; q++) { if (ga[q] > peak) { peak = ga[q]; } }
      glowCanvas.width = gw; glowCanvas.height = gh;
      var gctx = glowCanvas.getContext('2d'), gimg = gctx.createImageData(gw, gh), gp = gimg.data;
      for (var t = 0; t < ga.length; t++) {
        if (ga[t] <= 0) { continue; }
        var al = peak > 0 ? Math.pow(ga[t] / peak, 0.85) : 0;
        gp[t * 4] = gr[t] / ga[t]; gp[t * 4 + 1] = gg[t] / ga[t]; gp[t * 4 + 2] = gb[t] / ga[t]; gp[t * 4 + 3] = al * 150;
      }
      gctx.putImageData(gimg, 0, 0);
      built = true;
    }

    // separable box blur (radius 2) in place
    function blur(a, w, h) {
      var tmp = new Float32Array(a.length), x, y, k, s;
      for (y = 0; y < h; y++) {
        for (x = 0; x < w; x++) {
          s = 0;
          for (k = -2; k <= 2; k++) { s += a[y * w + clamp(x + k, 0, w - 1)]; }
          tmp[y * w + x] = s / 5;
        }
      }
      for (x = 0; x < w; x++) {
        for (y = 0; y < h; y++) {
          s = 0;
          for (k = -2; k <= 2; k++) { s += tmp[clamp(y + k, 0, h - 1) * w + x]; }
          a[y * w + x] = s / 5;
        }
      }
    }

    var font = '400 10px ' + (getComputedStyle(doc.body).fontFamily || 'system-ui');
    var muted = CC.token('--muted') || '#a3aba9', faint = CC.token('--faint') || '#7d8583';

    function draw() {
      if (!built) { return; }
      var c = CC.canvasDPR(canvas, size.w, size.h, 2), ctx = c.ctx, d = self.data;
      ctx.clearRect(0, 0, c.w, c.h);
      ctx.save();
      ctx.imageSmoothingEnabled = true;
      if (ctx.imageSmoothingQuality) { ctx.imageSmoothingQuality = 'high'; }
      ctx.globalCompositeOperation = 'lighter';
      ctx.globalAlpha = glowA;
      ctx.drawImage(glowCanvas, 0, 0, c.w, c.h);
      ctx.globalAlpha = glowA * 0.6;
      ctx.drawImage(glowCanvas, -c.w * 0.03, -c.h * 0.03, c.w * 1.06, c.h * 1.06);
      ctx.restore();
      ctx.drawImage(dotsCanvas, 0, 0, c.w, c.h);
      // score bands and the present moment
      ctx.save();
      ctx.strokeStyle = faint; ctx.globalAlpha = 0.55; ctx.lineWidth = 1; ctx.setLineDash([1, 4]);
      [[d.high_at, 'high ' + d.high_at + '+'], [d.review_at, 'review ' + d.review_at + '+']].forEach(function (b) {
        var y = Math.round(yOfScore(b[0] - 0.5)) + 0.5;
        ctx.beginPath(); ctx.moveTo(plot.x0, y); ctx.lineTo(plot.x1, y); ctx.stroke();
        ctx.globalAlpha = 1; ctx.fillStyle = muted; ctx.font = font; ctx.fillText(b[1], plot.x0 + 4, y - 5); ctx.globalAlpha = 0.55;
      });
      var nx = Math.round(xOf((d.now_col + 1) / d.cols)) + 0.5;
      ctx.strokeStyle = 'rgba(47, 211, 167, .55)'; ctx.setLineDash([2, 3]);
      ctx.beginPath(); ctx.moveTo(nx, plot.y0); ctx.lineTo(nx, plot.y1); ctx.stroke();
      ctx.restore();
    }

    // ---- pinned domains ----
    function placeMarks() {
      while (layer.firstChild) { layer.removeChild(layer.firstChild); }
      var d = self.data;
      if (!d || !show.marks) { return; }
      var max = size.w < 600 ? 6 : 12, placed = [], smin = scoreMin(), r = size.w < 600 ? 14 : 18;
      // keep the score-band labels ("high 75+", drawn at the left end of each band line) readable
      var labels = [d.high_at, d.review_at].map(function (s) {
        var ly = yOfScore(s - 0.5);
        return [plot.x0, ly - 18, plot.x0 + 72, ly + 2];
      });
      function clear(x, y) {
        return labels.every(function (q) { return x + r < q[0] || x - r > q[2] || y + r < q[1] || y - r > q[3]; });
      }
      d.marks.forEach(function (m) {
        if (placed.length >= max || m.score < smin) { return; }
        var x = xOf(m.x), y = yOfScore(m.score);
        var ok = false;
        for (var t = 0; t < 5 && !ok; t++) {
          var yy = y + [0, -2.2 * r, 2.2 * r, -4.4 * r, 4.4 * r][t];
          if (yy < plot.y0 || yy > plot.y1) { continue; }
          ok = clear(x, yy) && placed.every(function (p) { return Math.abs(p[0] - x) > 2 * r || Math.abs(p[1] - yy) > 2 * r; });
          if (ok) { y = yy; }
        }
        if (!ok) { return; }
        placed.push([x, y]);
        var lines = [m.host, (m.brand ? m.brand + ', ' : '') + m.what, 'Score ' + m.score +
          (m.final !== null && m.final !== undefined ? ' (final ' + m.final + ')' : '') + ', first seen ' + m.time];
        if (m.unicode && m.unicode !== m.host) { lines.splice(1, 0, 'Displays as ' + m.unicode); }
        var b = CC.badge(m.kind, m.host + ': ' + m.what, { href: '/domain/' + Number(m.id), tip: lines,
          size: size.w < 600 ? 'sm' : '', class: 'pin ov-pin is-new' });
        b.style.left = Math.round(x) + 'px';                 // CSSOM: allowed by the CSP
        b.style.top = Math.round(y) + 'px';
        b.setAttribute('data-tip-kind', m.kind);
        layer.appendChild(b);
      });
    }

    // ---- hover readout ----
    function readout(e) {
      var d = self.data;
      if (!d || !plot) { return; }
      var rect = canvas.getBoundingClientRect(), x = e.clientX - rect.left, y = e.clientY - rect.top;
      if (x < plot.x0 || x > plot.x1 || y < plot.y0 || y > plot.y1) { CC.tooltip.hide(); return null; }
      var frac = (x - plot.x0) / (plot.x1 - plot.x0), col = clamp(Math.floor(frac * d.cols), 0, d.cols - 1);
      var top = d.score_min + (d.rows - 1) * d.score_step;
      var score = d.score_min + (plot.y1 - y) / (plot.y1 - plot.y0) * (top - d.score_min);
      var row = clamp(Math.round((score - d.score_min) / d.score_step), 0, d.rows - 1);
      var n = 0, spread = Math.max(1, Math.round(d.cols / ((plot.x1 - plot.x0) / 8)));
      for (var dc = -spread; dc <= spread; dc++) {
        for (var dr = -1; dr <= 1; dr++) {
          var cc = col + dc, rr = row + dr;
          if (cc >= 0 && cc < d.cols && rr >= 0 && rr < d.rows) { n += cellMap[cc * d.rows + rr] || 0; }
        }
      }
      var start = new Date(new Date(d.start).getTime() + col * d.step * 1000);
      var end = new Date(start.getTime() + d.step * 1000);
      var day = d.step >= 1800 ? ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][start.getUTCDay()] + ' ' : '';
      var when = day + pad(start.getUTCHours()) + ':' + pad(start.getUTCMinutes()) + ' to ' +
        pad(end.getUTCHours()) + ':' + pad(end.getUTCMinutes()) + ' UTC';
      var s0 = Math.max(d.score_min, d.score_min + (row - 1) * d.score_step), s1 = Math.min(top, d.score_min + (row + 1) * d.score_step + 1);
      var future = col > d.now_col;
      var kind = score >= d.high_at ? 'danger' : (score >= d.review_at ? 'alert' : 'live');
      var lines = future ? ['Later in this window', when]
        : [n ? plural(n, 'hit') + ' scored ' + s0 + ' to ' + s1 : 'No stored hits scored ' + s0 + ' to ' + s1,
          when + ', ' + CC.fmtInt(d.cpm[col] || 0) + ' certificates a minute'];
      CC.tooltip.show({ x: e.clientX, y: e.clientY }, lines, { kind: n && !future ? kind : null });
      return { col: col, start: start, n: n, future: future };
    }

    var pending = null;
    canvas.addEventListener('pointermove', function (e) {
      if (e.pointerType === 'touch') { return; }
      if (pending) { return; }
      pending = requestAnimationFrame(function () { pending = null; readout(e); });
    });
    canvas.addEventListener('pointerleave', function () { CC.tooltip.hide(); });
    canvas.addEventListener('click', function (e) {
      var r = readout(e);
      if (r && !r.future && r.n) {
        var href = '/live/list?hour=' + encodeURIComponent(hourKey(r.start)) + (tier === 2 ? '&tier=high' : (tier === 1 ? '&tier=flagged' : ''));
        if (CC.isLocalPath(href)) { location.href = href; }
      }
    });

    // ---- motion: a slow breathing glow, only while visible and when motion is allowed ----
    function startAnim() {
      if (anim) { anim.stop(); anim = null; }
      if (CC.reducedMotion() || !visible) { glowA = 0.4; draw(); return; }
      var last = 0;
      anim = CC.loop(function (t) {
        if (t - last < 66) { return; }                    // about 15 frames a second is plenty for a glow
        last = t;
        glowA = 0.36 + 0.1 * Math.sin(t / 2400);
        draw();
      });
      anim.start();
    }
    CC.onMotionChange(startAnim);
    if (window.IntersectionObserver) {
      new IntersectionObserver(function (entries) {
        visible = entries[0].isIntersecting;
        if (visible) { startAnim(); } else if (anim) { anim.stop(); anim = null; }
      }).observe(stage);
    }

    function resize(box) {
      var w = Math.round(box.width), h = Math.round(box.height), dpr = Math.max(1, Math.min(window.devicePixelRatio || 1, 2));
      if (w === size.w && h === size.h && dpr === size.dpr && built) { return; }
      size.w = w; size.h = h; size.dpr = dpr;
      if (!self.data || !w || !h) { return; }
      build(); draw(); placeMarks();
    }

    self.set = function (d) {
      if (!d || !d.levels || !d.cols) { return; }
      var first = !self.data;
      self.data = d;
      decode(d);
      if (first) {
        canvas.hidden = false;
        stage.classList.add('is-live');
        var r = stage.getBoundingClientRect();
        size.w = Math.round(r.width); size.h = Math.round(r.height);
        size.dpr = Math.max(1, Math.min(window.devicePixelRatio || 1, 2));
      }
      build(); draw(); placeMarks();
      if (first) { startAnim(); }
    };
    self.load = function () {
      return CC.getJSON(src).then(self.set, function () { /* the SVG fallback stays */ });
    };
    self.layer = function (name, on) { show[name] = on; stage.classList.toggle('hide-marks', !show.marks); build(); draw(); placeMarks(); };
    self.tier = function (t) { tier = t; build(); draw(); placeMarks(); };
    self.poll = CC.poll(function () { return src; }, TERRAIN_MS, function (d) { if (!live.paused) { self.set(d); } });
    CC.observeSize(stage, resize);
    return self;
  }

  function initTerrain() {
    var stage = doc.querySelector('[data-terrain]');
    if (!stage) { return null; }
    var t = Terrain(stage);
    if (!t) { return null; }
    t.load();

    CC.$$('[data-layer]', stage).forEach(function (btn) {
      btn.addEventListener('click', function () {
        var on = btn.getAttribute('aria-pressed') !== 'true';
        btn.setAttribute('aria-pressed', on ? 'true' : 'false');
        t.layer(btn.getAttribute('data-layer'), on);
      });
    });
    var tierBtn = CC.$('[data-action="tier"]', stage);
    var TIERS = [['All', 'all hits'], ['Review+', 'review and high tier'], ['High', 'high tier only']];
    var tierIdx = 0;
    if (tierBtn) {
      tierBtn.addEventListener('click', function () {
        tierIdx = (tierIdx + 1) % 3;
        var txt = CC.$('.icon-btn-text', tierBtn);
        if (txt) { txt.textContent = TIERS[tierIdx][0]; }
        var label = 'Tier filter: ' + TIERS[tierIdx][1];
        tierBtn.setAttribute('aria-label', label);
        tierBtn.setAttribute('data-tip', label);
        tierBtn.classList.toggle('is-active', tierIdx > 0);
        t.tier(tierIdx);
        if (CC.tooltip.anchor === tierBtn) { CC.tooltip.show(tierBtn, label); }
      });
    }
    return t;
  }

  // ---- pause every live update ----------------------------------------------------------------------------

  function initPause(feedCtl) {
    var btn = doc.querySelector('[data-action="pause"]');
    function set(p) {
      live.paused = p;
      if (btn) {
        btn.setAttribute('aria-pressed', p ? 'true' : 'false');
        var label = p ? 'Resume live updates' : 'Pause live updates';
        btn.setAttribute('aria-label', label);
        btn.setAttribute('data-tip', label);
        var use = CC.$('use', btn);
        if (use) { use.setAttribute('href', p ? '#i-play' : '#i-pause'); }
        if (CC.tooltip.anchor === btn) { CC.tooltip.show(btn, label); }
      }
      if (feedCtl) { feedCtl.setPaused(p); }
      CC.emit('overview:paused', p);
    }
    if (btn) { btn.addEventListener('click', function () { set(!live.paused); }); }
    CC.shortcut('p', 'Pause or resume live updates', function () { set(!live.paused); });
    return set;
  }

  // ---- gauges -------------------------------------------------------------------------------------------

  // the same geometry as common.gauge_geom: a 270 degree ring in a 100 x 100 viewBox, gap at the bottom
  function gaugeGeom(value, total) {
    var v = Number(value) || 0, t = Number(total) || 0;
    var frac = t <= 0 ? 0 : clamp(v / t, 0, 1), a0 = 135, sweep = 270;
    function pt(r, deg) { var a = deg * Math.PI / 180; return [+(50 + r * Math.cos(a)).toFixed(2), +(50 + r * Math.sin(a)).toFixed(2)]; }
    function arc(r, start, span) {
      if (span <= 0) { return ''; }
      var p0 = pt(r, start), p1 = pt(r, start + Math.min(span, 359.99));
      return 'M' + p0[0] + ' ' + p0[1] + 'A' + r + ' ' + r + ' 0 ' + (span > 180 ? 1 : 0) + ' 1 ' + p1[0] + ' ' + p1[1];
    }
    return { frac: frac, pct: Math.round(frac * 100), arc: arc(40, a0, sweep * frac), n: pt(30, a0 + sweep * frac),
      e: pt(40, a0 + sweep * frac), empty: t <= 0 };
  }

  function setGauge(key, value, total, shown, shownTotal, sub) {
    var box = doc.querySelector('[data-gauge="' + key + '"]');
    if (!box) { return; }
    var svg = CC.$('svg.gauge-ring', box), val = CC.$('.gauge-val', box), of = CC.$('.gauge-n .of', box);
    var label = (CC.$('.gauge-l', box) || {}).textContent || key;
    var g = gaugeGeom(value, total);
    if (svg) {
      var arcEl = CC.$('.gauge-arc', svg);
      if (g.arc && !arcEl) {
        arcEl = doc.createElementNS(svg.namespaceURI, 'path');
        arcEl.setAttribute('class', 'gauge-arc');
        arcEl.setAttribute('fill', 'none');
        arcEl.setAttribute('stroke', 'url(#cc-grad-gauge)');
        arcEl.setAttribute('stroke-width', '3');
        arcEl.setAttribute('stroke-linecap', 'round');
        var track = CC.$('.gauge-track', svg);
        svg.insertBefore(arcEl, track ? track.nextSibling : svg.firstChild);
      }
      if (arcEl) { if (g.arc) { arcEl.setAttribute('d', g.arc); } else { arcEl.remove(); } }
      var needle = CC.$('.gauge-needle', svg), end = CC.$('.gauge-end', svg);
      if (needle) { needle.setAttribute('x2', g.n[0]); needle.setAttribute('y2', g.n[1]); }
      if (end) { end.setAttribute('cx', g.e[0]); end.setAttribute('cy', g.e[1]); }
      svg.setAttribute('aria-label', label + ': ' + shown + ' of ' + shownTotal + (g.empty ? '' : ' (' + g.pct + '%)'));
    }
    if (val && val.textContent !== shown) {
      val.textContent = shown;
      box.classList.remove('is-updated'); void box.offsetWidth; box.classList.add('is-updated');
    }
    if (of) { of.textContent = ' / ' + shownTotal; }
    var subEl = CC.$('.gauge-sub', box);
    if (subEl && sub) { subEl.textContent = sub; }
  }

  function applyAi(st) {
    if (!st || !doc.querySelector('[data-gauge="ai"]')) { return; }
    var spent = st.ai_spent_today, cap = st.ai_daily_cap;
    if (st.ai === 'off' || typeof spent !== 'number') { return; }
    setGauge('ai', spent, cap || 0, '$' + spent.toFixed(2), '$' + (cap || 0).toFixed(2),
      st.ai === 'over' ? 'Cap reached, checks pause until 00:00 UTC' : (st.ai_pct || 0) + '% of the daily cap');
  }

  function chip(key, n, word) {
    var a = doc.querySelector('.ov-chip[data-kpi="' + key + '"]');
    if (!a || typeof n !== 'number') { return; }
    var v = CC.$('.kpi-val', a);
    if (v) { v.textContent = CC.fmtInt(n); }
    var l = CC.$('.ov-chip-l', a);
    if (l && word) { l.textContent = word; }
  }

  function applyQueue(n, high) {
    if (typeof n !== 'number') { return; }
    var a = doc.querySelector('.ov-chip[data-kpi="open_review"]');
    if (a) {
      a.classList.remove('ov-chip--red', 'ov-chip--amber', 'ov-chip--muted');
      a.classList.add(high ? 'ov-chip--red' : (n ? 'ov-chip--amber' : 'ov-chip--muted'));
      var use = CC.$('use', a);
      if (use) { use.setAttribute('href', high ? '#i-danger' : (n ? '#i-alert' : '#i-shield')); }
    }
    chip('open_review', n, (n === 1 ? 'waits for review' : 'wait for review') + (high ? ', ' + high + ' high' : ''));
  }

  function applySummary(d) {
    if (!d || live.paused) { return; }
    var certs = doc.getElementById('s-certs');
    if (certs && typeof d.certs_5m === 'number') { certs.textContent = CC.fmtInt(d.certs_5m); }
    setGauge('live', d.live_phishing, d.judged, CC.fmtInt(d.live_phishing), CC.compact(d.judged));
    var open = d.open_review || 0, decided = d.decided_week || 0;
    setGauge('queue', open, open + decided, CC.fmtInt(open), CC.compact(open + decided), CC.fmtInt(decided) + ' decided in 7 days');
    applyQueue(d.open_review, d.open_high);
    var waiting = d.reports_waiting || 0, failed = d.reports_failed || 0;
    chip('reports_waiting', waiting, (waiting === 1 ? 'report to send' : 'reports to send') + (failed ? ', ' + failed + ' failed to send' : ''));
    applyAi(d);
  }

  // ---- live feed --------------------------------------------------------------------------------------

  function feedLine(r) {
    var d = new Date(r.first_seen);
    var host = r.hostname || r.registered_domain;
    var finalScore = r.final_score === null || r.final_score === undefined ? r.score : r.final_score;
    var meta = CC.el('span', { class: 'fl-meta' }, CC.el('span', { class: 'fl-brand', text: r.brand_id || 'no brand' }));
    if (r.live_state === 'live') { meta.appendChild(pill('live', 'red', '●', 'Page state from the fetcher')); }
    if (r.ai_verdict) { meta.appendChild(verdictPill(r.ai_verdict)); }
    if (r.status && r.status !== 'open' && STATUS[r.status]) {
      var s = STATUS[r.status]; meta.appendChild(pill(s[0], s[1], s[2], 'Review decision'));
    }
    return CC.el('li', { class: 'fl fl--' + (r.tier || 'none') + ' is-new',
        dataset: { id: String(r.id), tier: r.tier || '', t: isNaN(d) ? '' : minuteKey(d) } },
      CC.el('time', { class: 'fl-time', datetime: r.first_seen, 'data-abs': true, title: isNaN(d) ? null : d.toISOString(),
        text: isNaN(d) ? '' : utcTime(d) }),
      CC.el('span', { class: 'fl-tier' }, tierPill(r.tier)),
      CC.el('span', { class: 'fl-score', title: 'Domain-name score ' + r.score +
        (r.final_score === null || r.final_score === undefined ? '' : ', final score ' + r.final_score), text: String(finalScore) }),
      CC.el('span', { class: 'fl-host' }, dom(host, r.unicode_domain, '/domain/' + Number(r.id))),
      meta);
  }

  function initFeed() {
    var feed = doc.getElementById('feed');
    if (!feed) { return null; }
    var state = doc.getElementById('feed-state');
    var pauseBtn = doc.getElementById('feed-pause');
    var filterSel = doc.getElementById('feed-filter');
    var maxId = parseInt(feed.getAttribute('data-max-id'), 10) || 0;
    var src = feed.getAttribute('data-src') || '/api/recent';
    var paused = false, buffer = [], failing = false;

    function setState(text, kind) {
      state.textContent = text;
      state.className = 'feed-state' + (kind ? ' is-' + kind : '') + (kind === 'live' ? ' cursor' : '');
    }
    function liveText() { return 'Live. Checking for new hits every ' + (FEED_MS / 1000) + ' seconds.'; }
    setState(liveText(), 'live');

    var filter = 'all';
    function matches(tier) {
      if (filter === 'high') { return tier === 'high'; }
      if (filter === 'flagged') { return tier === 'high' || tier === 'review'; }
      return true;
    }
    function applyFilter() {
      CC.$$('.fl', feed).forEach(function (li) { li.classList.toggle('is-filtered', !matches(li.getAttribute('data-tier'))); });
    }
    if (filterSel) {
      var saved = store(true);
      if (saved && /^(all|flagged|high)$/.test(saved)) { filterSel.value = saved; filter = saved; applyFilter(); }
      filterSel.addEventListener('change', function () {
        filter = filterSel.value; store(false, filter); applyFilter();
      });
    }

    function summary(rows) {
      var high = rows.filter(function (r) { return r.tier === 'high'; }).length;
      return plural(rows.length, 'new hit') + ' at ' + utcTime(new Date()) + ' UTC' + (high ? ', ' + high + ' high tier' : '') + '.';
    }
    function render(rows) {
      if (!rows.length) { return; }
      var empty = doc.getElementById('feed-empty');
      if (empty) { empty.remove(); }
      rows.slice().reverse().forEach(function (r) {           // rows come newest first; prepend oldest first
        var li = feedLine(r);
        if (!matches(r.tier)) { li.classList.add('is-filtered'); }
        feed.insertBefore(li, feed.firstChild);
        setTimeout(function () { li.classList.remove('is-new'); }, 2000);
      });
      while (feed.children.length > FEED_MAX) { feed.lastElementChild.remove(); }
    }
    function setPauseLabel() {
      if (!pauseBtn) { return; }
      pauseBtn.setAttribute('aria-pressed', paused ? 'true' : 'false');
      pauseBtn.textContent = paused ? (buffer.length ? 'Resume and show ' + plural(buffer.length, 'new hit') : 'Resume') : 'Pause';
    }
    function setPaused(p) {
      if (p === paused) { return; }
      paused = p;
      if (!paused) {
        var n = buffer.length;
        render(buffer); buffer = [];
        setState(n ? 'Resumed. ' + plural(n, 'new hit') + ' added.' : liveText(), 'live');
        poller.now();
      } else {
        setState('Paused. New hits wait here until you resume.', 'paused');
      }
      setPauseLabel();
    }
    if (pauseBtn) { pauseBtn.addEventListener('click', function () { setPaused(!paused); }); }

    function onData(d) {
      if (failing) { failing = false; if (!paused) { setState(liveText(), 'live'); } }
      var rows = (d && d.rows ? d.rows : []).filter(function (r) { return r.id > maxId; });
      rows.forEach(function (r) { if (r.id > maxId) { maxId = r.id; } });
      if (d && d.stats) { CC.emit('overview:stats', d.stats); }
      if (!rows.length) { return; }
      if (paused) {
        buffer = rows.concat(buffer).slice(0, FEED_MAX);
        setState('Paused. ' + plural(buffer.length, 'new hit') + ' waiting.', 'paused');
        setPauseLabel();
        return;
      }
      render(rows);
      setState(summary(rows), 'live');
    }
    var poller = CC.poll(function () { return src + '?after_id=' + maxId; }, FEED_MS, onData, {
      onError: function () { failing = true; setState('Cannot reach the dashboard. Retrying.', 'error'); }
    });

    // keyboard: j/k move through the visible lines, o opens one
    var cursor = -1;
    function lines() { return CC.$$('.fl', feed).filter(function (li) { return !li.classList.contains('is-filtered'); }); }
    function move(step) {
      var list = lines();
      if (!list.length) { return; }
      var cur = list.indexOf(doc.activeElement && doc.activeElement.closest ? doc.activeElement.closest('.fl') : null);
      if (cur >= 0) { cursor = cur; }
      cursor = Math.max(0, Math.min(list.length - 1, cursor + step));
      CC.$$('.fl.is-cursor', feed).forEach(function (li) { li.classList.remove('is-cursor'); });
      var li = list[cursor];
      li.classList.add('is-cursor');
      var a = CC.$('a.dom', li);
      if (a) { a.focus({ preventScroll: true }); }
      li.scrollIntoView({ block: 'nearest' });
    }
    CC.shortcut('j', 'Next hit in the live feed', function () { move(1); });
    CC.shortcut('k', 'Previous hit in the live feed', function () { move(-1); });
    CC.shortcut('o', 'Open the selected hit', function () {
      var a = CC.$('.fl.is-cursor a.dom', feed);
      if (a && CC.isLocalPath(a.getAttribute('href'))) { location.href = a.getAttribute('href'); }
    });
    return { setPaused: setPaused };
  }

  function applyStats(s) {
    if (!s || live.paused) { return; }
    var certs = doc.getElementById('s-certs');
    if (certs && typeof s.certs_5m === 'number') { certs.textContent = CC.fmtInt(s.certs_5m); }
  }

  CC.ready(function () {
    if (!doc.querySelector('[data-overview]')) { return; }
    initTerrain();
    var feedCtl = initFeed();
    initPause(feedCtl);
    CC.on('overview:stats', applyStats);
    CC.on('status', function (st) { if (!live.paused) { applyQueue(st.open_review, st.open_high); applyAi(st); } });
    if (doc.querySelector('[data-gauge]')) {
      CC.poll('/api/live/summary', SUMMARY_MS, applySummary);
    }
  });
})();
