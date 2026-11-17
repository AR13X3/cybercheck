# CyberCheck dashboard UI

The dashboard is calm glass on deep charcoal: a big light headline, translucent panels with faint edges, rounded
pills, thin geometric type, large light numbers with small muted "/ total" suffixes, and glowing dot fields drawn
from CyberCheck's own data (certificates, hits, pages, AI verdicts, reports). Colour is used sparingly and always
means something. A reviewer uses it over a private network (a tailnet, say) from a laptop and a phone. This file is
the contract for anyone building a page: tokens, the shell, components (each with its macro), class names, CSP rules and the JS API.

Files:

| File | What |
|---|---|
| `cybercheck/web/templates/base.html` | the shell: icon sprite, glass top bar (wordmark, segmented nav, search pill, help button), status strip, `<main>`, toast region |
| `cybercheck/web/templates/_ui.html` | Jinja macros for every component: `{% import "_ui.html" as ui %}` |
| `cybercheck/web/static/app.css` | `@font-face`, tokens, glass, shell, components, aliases for the old class names |
| `cybercheck/web/static/app.js` | `window.CC`: shortcuts, relative times, dialogs, lightbox, fetch, polling, status strip, tooltips, canvas helpers |
| `cybercheck/web/static/fonts/Outfit-wght.ttf` | the one bundled font (variable weight, SIL OFL 1.1, licence in `Outfit-OFL.txt`) |
| `cybercheck/web/common.py` | `status_line()`, `refresh_status()`, `nav_groups()`, `compact()`, `gauge_geom()`, `spark_geom()`, `dot_matrix()`, `asset()`, filters `ago`/`iso`/`utc`/`compact` |
| `cybercheck/web/templates/_row.html` | triage macros shared by review, domain and domains (see "Pages" below) |
| `cybercheck/web/templates/ops_macros.html` | tiles and rings for the reports and operations pages: `{% import "ops_macros.html" as ops %}` |
| `overview.css/js`, `triage.css/js`, `reports.css/js`, `ops.css/js` | one stylesheet and script per page group, loaded in `{% block head %}` / `{% block scripts %}` |

Screenshots of the current look (seeded test data) are in `docs/ui-screenshots/`.

## Hard rules

- **CSP** (set on every response by `security_headers` in app.py, `app.CSP`):
  `default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self';
  object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`.
  So templates have **no `style="..."`, no `<style>`, no inline `<script>` and no `on*=` attributes**. The
  browser ignores them silently. Use classes, `data-*` attributes and a JS file in `cybercheck/web/static/`.
  SVG uses **presentation attributes** (`width="42"`, `fill="none"`, `stroke-dasharray="1 3"`, `d="..."`) or
  classes, never `style=`. Scripts may set positions through the CSSOM (`el.style.left = x + 'px'`,
  `el.style.transform = ...`): that is allowed; `setAttribute('style', ...)` is not.
- **No external assets.** No CDN, no remote fonts or images. The font is bundled (`/static/fonts/`). CSS
  `url()` may only point at `data:`, a same-document `#fragment` (SVG gradients) or `fonts/...`
  (`tests/test_web.py` checks this).
- **Autoescape stays on. Never use `|safe` or `Markup`.** Hostnames, page titles, URLs, AI text, CT issuer
  strings and Telegram chat titles all come from attackers. Macro output and `{{ x | tojson }}` are the only
  markup you pass around. In JS, text goes in with `CC.el(..., {text})` or `textContent`, never `innerHTML`.
- **Never turn a reported or phishing URL into a link.** Use `ui.url_text(u)`. Links go only to dashboard
  paths (`/domain/5`, `/screenshot/9`) and to the official report forms that are already linked today.
  `CC.el` and `CC.badge` refuse any `href` that is not a same-origin path.
- **Progressive enhancement.** Every page and every action must work with JS turned off. JS adds shortcuts,
  polling, relative times, dialogs, tooltips, the canvas visuals and copy buttons, nothing that is required. A
  canvas visual needs a server-rendered fallback (a coarser SVG or a summary table) inside it or next to it.
- Keep every route, form action, field name and POST meaning. Every POST still calls `same_origin(request)`.
- Accessibility floor: WCAG AA contrast (the tokens below are checked, including over the hero glow), visible
  `:focus-visible` rings, landmarks and one `<h1>` per page, a `<label>` on every input, usable at 360 px with
  no page-level horizontal scroll (wide tables scroll inside `.table-wrap`), touch targets of 40 px or more on
  narrow screens and touch devices (the CSS handles this for `.btn`, `.icon-btn`, inputs, tabs, nav links,
  filter pills and badges). Every chart has a `role="img"` with an `aria-label` that states the numbers.
- **Glass must degrade.** Floating layers are solid by default and only become translucent and blurred inside
  `@supports (backdrop-filter: ...)`; `prefers-reduced-transparency` makes them solid again. Panels are plain
  translucent fills with no blur (cheap on a phone). Don't put `backdrop-filter` on an element that has
  floating children (it becomes their "backdrop root" and they stop blurring the page): the top bar's glass is
  on its `::before` for that reason.
- **Motion:** `prefers-reduced-motion` turns off every CSS animation; a canvas must not animate its glow then
  (check `CC.reducedMotion()`, listen with `CC.onMotionChange`).
- Copy: sentence case, plain and specific. Buttons say what they do ("Confirm phishing", "Mark false
  positive"). Don't use all-caps labels, decorative "a · b" strings, or arrows in button text. Empty states say
  what to do next.

## Tokens (`:root` in app.css)

Contrast figures are for text on `--glass` over `--bg` unless noted.

| Token | Value | Use |
|---|---|---|
| `--bg` | `#1c1e1f` | page background (with a soft teal radial glow at the top, `background-attachment: fixed`) |
| `--surface`, `--surface-2`, `--surface-3` | `#252728` `#2c2e2f` `#333536` | solid stand-ins for the glass fills: fallbacks, sticky table heads, dialogs |
| `--glass`, `--glass-2`, `--glass-3` | white at 4.5 %, 7 %, 10 % | panels, tiles, pills and their hover states |
| `--glass-overlay` | `rgba(36,39,40,.72)` | floating layers when the browser can blur (bar, tooltips, toasts, button row) |
| `--stroke`, `--stroke-2` | white at 8 %, 14 % | panel edges (decorative), pill and button edges, separators |
| `--control` | `#747879` | input and toggle outlines (3.2:1, the non-text contrast minimum) |
| `--text` | `#e9eceb` | body text (12.5:1) |
| `--muted` | `#a3aba9` | secondary text (6.3:1; 5.3:1 on `--glass-3`; 4.6:1 under the hero glow) |
| `--faint` | `#7d8583` | dotted baselines and ticks only, **never text** |
| `--teal` | `#2fd3a7` | **live data, safe, primary action** (7.8:1) |
| `--green` | `#8bd450` | **protected, benign** (8.2:1) |
| `--amber` | `#f39a3d` | **needs review, alerts** (6.7:1) |
| `--red` | `#ff6b6b` | **phishing, danger, destructive** (5.3:1; `#ef4d4d` failed as text on glass) |
| `--violet` | `#a79bff` | **AI verdicts and AI spend** (6.2:1) |
| `--grey` | `#a3aba9` | unknown, not judged |
| `--focus` | `#8ff0d4` | focus rings, row cursor |
| `--on-accent` | `#16181a` | text on a teal, green, amber, red, violet or light (`--text`) fill (4.9:1 on red, more on the rest) |
| `--teal-bg` … `--violet-bg`, `--green-bg` | tone at 10-13 % | pill and highlight fills (tone text on them is 4.5:1 or more) |
| `--teal-line` … `--violet-line`, `--green-line` | tone at 32-36 % | pill borders |
| `--glow-teal`, `--glow-warm` | | radial glows (hero, `panel(glow=True)`) |
| `--dm-0` … `--dm-4` | | dot-field intensity steps (empty to full teal) |
| `--font` (= `--sans`) | Outfit, system-ui | everything. Weights: **300** for big numbers and the headline, **400** for text, **500** for emphasis and active controls |
| `--mono` | ui-monospace … | only code, report drafts (`textarea`, `pre`), URLs (`.url`), "displays as" IDN text and `ui.dom(..., exact=True)` |
| `--fs-11/12/13/14/15/18/22/28/36/48` | px | type scale. Body 14, labels 12, panel titles 15, `h1` 36 (28 on phones), big numbers 28-48 |
| `--radius-sm` / `--radius` / `--radius-lg` / `--radius-pill` | 10 / 16 / 22 / 999 px | inputs and code / tiles, tables, cards / panels / pills and buttons |
| `--top-h` | 64 px (56 on phones) | height of the sticky top bar: use it for `position: sticky` offsets |
| `--gap`, `--page-w` | 18 px, 1560 px | grid gap, content width |

Old token names still work so page stylesheets keep rendering: `--panel`, `--panel-2`, `--panel-3` (solid
`--surface*`: old CSS uses them for sticky bars and line masks), `--line` (= `--stroke`), `--line-strong`
(= `--control`), `--fs-*`, `--sans`, `--mono`, `--radius`, `--rail-w` (0). New code should use `--glass*` and
`--stroke*`.

The meaning of each colour is fixed. **Colour is never the only signal.** Every tone is paired with an icon or
glyph and text: protected = green shield, danger = red triangle, alert = amber `!` circle, unknown = grey `x`
square, AI = violet spark, live = teal dot. Pills keep their text glyphs (`●` `▲` `■` `◆` `○` `?`, the tests
match them). Gradients appear only on gauge arcs, the warm peak chart and the glows.

## Layout (base.html)

```
<svg class="sprite">           icon symbols (#i-*) and gradients (#cc-grad-gauge, #cc-grad-teal, #cc-grad-warm)
<header class="topbar">        sticky glass bar, --top-h tall
  .brand                       wordmark (ring mark + "CyberCheck"), links to /
  a.menu-btn                   phones only: "Menu" (href="#cc-nav", JS makes it a toggle)
  div.topnav#cc-nav            desktop: a row; phones: a glass sheet under the bar
    nav.nav > .nav-seg         segmented pill control: Overview, Review (+count), Domains, Reports, More v
      a.nav-link[.is-active]   aria-current="page" on the current section, data-chord="g r"
      details.nav-more         "More" dropdown (native <details>, works without JS): Blocklist, Takedowns, AI, CZDS, Bot
    form.search-pill           GET /domains?q=, the field / focuses
    button.icon-btn.topbar-help  round button, opens the keyboard-shortcut help (JS only)
<div class="statusbar">        status strip: small pills (ct, queue, worker, fetcher, vpn, ai) + "Private dashboard" note
<main id="main">               <div class="flash-area">{% block flash %}</div>  {% block body %}
<div class="toasts" id="cc-toasts" aria-live="polite">
```

Under 900 px the bar shows the wordmark and the Menu button. The nav, search and help button move into a glass
sheet. Without JS the Menu button is an `#cc-nav` link and `:target` opens the sheet (a "Close menu" link
appears in it). With JS it toggles `.is-open`, Esc or a click outside closes it, and the More section opens
inside the sheet when the current page is one of its entries. The status strip wraps (every segment stays
visible).

Blocks you can fill:

| Block | For |
|---|---|
| `title` | `CyberCheck · Review queue` style titles (the existing pattern; keep it) |
| `body` | the page |
| `flash` | messages above the page, usually `{{ ui.flash(message) }}` |
| `head` | an extra `<link rel="stylesheet" href="{{ asset('x.css') }}">` if a page really needs one |
| `scripts` | `<script src="{{ asset('review.js') }}" defer></script>`, loaded after app.js |
| `body_class`, `page_id` | a class on `<body>` and `data-page="..."` for page scripts |

`asset("name")` returns `/static/name?v=<content hash>`, so browsers never keep a stale file after a deploy.
Put page files in `cybercheck/web/static/`. They are served at `/static/`, behind the Host allowlist and with
the same headers as every route.

Nav entries are `(path, label)` in `templates.env.globals["nav"]` (core: Overview, Review, All domains; modules
append theirs). `common.nav_groups(current_path)` splits them for the bar: paths in `common.NAV_PRIMARY`
(`/`, `/review`, `/domains`, `/reports`) go in the segmented control, everything else under More.
`common.NAV_SHORT` shortens labels for the control (`All domains` shows as "Domains"). Each item is
`{path, label, full, active, chord, chord_label}`. Two-key shortcuts live in `common.NAV_CHORDS`: `g o`, `g r`,
`g d`, `g p` reports, `g b` blocklist, `g t` takedowns, `g a` AI. `nav_active(current_path, nav_path)` decides
the highlighted entry; `/domain/<id>` belongs to Domains. The current link is
`<a class="nav-link is-active" href="/" aria-current="page" ...>` (the overview test matches this).

## Status strip

`common.status_line()` (a template global) returns the cached status. `StatusLineMiddleware` refreshes it before
each page GET when it is older than 15 s. It sits inside the Host allowlist and skips `/static`, `/api`,
`/healthz`, screenshots and blocklist files. Everything comes from one query, `STATUS_SQL`, with a 2.5 s timeout.
Any failure renders every segment as "unknown". It never causes a 500. `GET /api/status` returns the same dict
as JSON (`Cache-Control: no-store`), and app.js polls it every 15 s and updates the pills and the Review count.

```python
{"ok": bool, "reason": str, "checked_at": iso,
 "certs_per_min": int|None, "stream": "live|stale|unknown", "heartbeat_age_s": int|None,
 "open_review": int|None, "open_high": int|None,
 "worker": "ok|stale|unknown", "worker_age_s": int|None,
 "fetcher": "ok|down|off|error|stale|unknown", "fetcher_detail": str,
 "vpn": "ok|off|unknown", "vpn_country": str|None,
 "ai": "ok|warn|over|off|unknown", "ai_spent_today": float|None, "ai_daily_cap": float|None, "ai_pct": int|None,
 "segments": [{"key", "label", "value", "tone", "glyph", "title", "href"}]}   # keys: ct queue worker fetcher vpn ai
```

Markup (kept for app.js and the tests): `ul#cc-status.statusline > li.seg.seg--<tone>[data-status-key] >
(a|span).seg-in > span.seg-label + span.seg-glyph + span.seg-value`. A red segment gets a red-tinted pill. The
fetcher and VPN state come from the fetch job's last result in `kv['job:fetch']`. The egress IP is never shown.
Pages can listen for updates with `CC.on('status', fn)` instead of polling for the same numbers (`CC.status`
holds the latest; it has `ai_spent_today` and `ai_daily_cap` for an AI gauge).

## Components

Import once per template: `{% import "_ui.html" as ui %}`. Every value is escaped.

### Icons
`{{ ui.icon("shield") }}` renders `<svg class="ico" aria-hidden="true"><use href="#i-shield"/></svg>`
(decorative: put the meaning in nearby text or an `aria-label`). `ui.icon(name, class_)` adds classes.
Badge shapes (solid, `currentColor` with dark cut-outs): `shield`, `danger` (triangle), `alert` (! circle),
`unknown` (x square), `ai` (spark), `live` (dot with ring), `done` (check circle), `report` (sheet), `dot`.
UI icons (1.6 px strokes): `search keyboard sliders menu close chevron-down chevron-up chevron-left
chevron-right clock layers filter pause play refresh plus minus check pulse list grid calendar arrow-up eye copy`.
In JS: `CC.icon('layers', 'extra-class')`. Size with CSS (`svg.ico` is 18 px).

**Kinds** (shared by badges, tiles, dot-grid markers, tooltips; `CC.KIND` in JS):

| kind | icon | tone |
|---|---|---|
| `protected` | shield | green |
| `danger` | danger | red |
| `alert` | alert | amber |
| `unknown` | unknown | grey |
| `ai` | ai | violet |
| `live` | live | teal |
| `done` | done | teal |
| `report` | report | violet |

### Page head
```jinja
{% call ui.page_head("Review queue", sub="7 domains wait for a decision", back="/domains", back_label="all domains") %}
  {{ ui.link_button("Open the next domain", "/domain/5", kind="primary", shortcut="n") }}
{% endcall %}
```
A big light `<h1>` (36 px, weight 300) with a small muted subline, and actions on the right. `back` renders a
glass pill link "← Back to …". Leave out `{% call %}` when there are no actions.

### Panel
```jinja
{% call ui.panel("Why it was flagged", sub="domain score 80", more_href="/domains?brand=commbank", more_label="All commbank domains") %}
  ...
{% endcall %}
```
A glass panel (22 px radius, faint edge, no header rule). Options: `id`, `level=2`, `flush=True` (no padding,
for a table inside), `class_`, `glow=True` (a soft teal glow behind the top of the panel; once or twice a page).
Classes: `.panel > .panel-head > .panel-title, .panel-sub, .panel-more` and `.panel-body`. Lay panels out with
`.grid-2`, `.grid-3`, `.grid-aside` (2:1, stacks under 1100 px) or `.stack`. `.glass` is the bare glass
surface for hand-made boxes.

### Hero stage (for a canvas visual)
```html
<section class="hero" aria-labelledby="...">
  <div class="hero-stage">                       <!-- position: relative; give it a height in your CSS -->
    <canvas ...></canvas>                         <!-- fills the stage; draw with CC.canvasDPR -->
    <div class="hero-layer">                      <!-- absolute overlay; children get pointer events -->
      <a class="badge badge--red pin" ...></a>   <!-- .pin centres on its point; JS sets left/top via CSSOM -->
    </div>
    {% call ui.fab_row("Terrain controls") %}...{% endcall %}   <!-- floats centred on the bottom edge -->
  </div>
</section>
```
`.hero` paints the teal and warm radial glow behind it and has no border. Put the no-JS fallback (an SVG or a
summary table) in the stage and hide it from JS with your page script when the canvas takes over.

### Big numbers
`{{ ui.stat("882k", "992k", "Attacked assets", sub="of 992k stored", id="s-assets", tone=None, size="lg", href=None) }}`
renders a small muted label, then a large light number with a small muted "/ total". Sizes `sm` (22 px), `md`
(28), `lg` (36), `xl` (48). Tones colour the value (teal, amber, red, violet, green). Format numbers first:
`{{ n | compact }}` gives `882k`, `1.2k`, `2.4M` (`common.compact`, `CC.compact` in JS). The `.of` class is
the "/ total" suffix anywhere.

### KPI tile
```jinja
{% call ui.kpis() %}
  {{ ui.kpi("certificates, last 5 min", "{:,}".format(stats.certs_5m), id="s-certs", tone="teal") }}
  {{ ui.kpi("waiting for review", stats.open_review, total=stats.open_all, href="/review", tone="amber", glyph="▲", hint="2 high tier") }}
{% endcall %}
```
The tile is `<div class="kpi"><div class="n">VALUE</div><div class="l">LABEL</div>`. It keeps the old `n`/`l`
class names and order on purpose (integration tests match `<div class="n">2</div><div class="l">label`); CSS
shows the label above the number. `total=` appends `<span class="of"> / total</span>` inside `.n`. Tones: teal,
green, amber, red (these two add a faint tint) and violet. With `href` the whole tile is a link.

### Gauge ring
```jinja
{{ ui.gauge(s.ai_spent_today, s.ai_daily_cap, "AI spend today", shown="$%.2f" % s.ai_spent_today,
            shown_total="$%.0f" % s.ai_daily_cap, sub="resets 00:00 UTC", id="g-ai", href="/ai") }}
{{ ui.gauge(live, judged, "Live phishing pages") }}
{{ ui.gauge(open, decided, "Review queue", tone="amber") }}
```
A thin 270° ring (gap at the bottom) with the green → amber → red gradient up to the value, a dotted inner
ring, a needle and an end dot, then the label, a big light number and "/ total". `value`/`total` are numbers
for the geometry (`common.gauge_geom`: clamps to 0-100 %, a zero total draws an empty ring); `shown`/
`shown_total` are the texts (default: the numbers, compacted). `tone=` draws a flat arc in that colour instead
of the gradient. `size=` `sm` (72 px) / default (96) / `lg` (128). The SVG has `role="img"` and
`aria-label="AI spend today: $1.25 of $5 (25%)"`. To update live, replace the number text (`id`) and re-render
the page fragment, or redraw: the arc is `path.gauge-arc` (`d` from the same formula).

### Sparkline and peak chart
```jinja
{{ ui.sparkline(hits_per_10min, "Hits per 10 minutes, last 24 hours", start="24 h ago", end="now") }}
{{ ui.sparkline(high_per_hour, "High-tier hits per hour", kind="peaks", tone="warm", start="00:00", end="now") }}
{{ ui.sparkline(cpm, "Certificates per minute", kind="line", tone="violet", unit="/min") }}
```
`values` oldest first. Kinds: `bars` (thin bars, the peak bar brighter), `peaks` (a triangle per non-zero
value, like the reference's peak chart) and `line`. Every kind has a dotted baseline, a dotted marker at the
peak, "max N" top right (`show_max=False` hides it) and optional tick labels under the ends. Tones: teal,
amber, red, violet, green, muted, warm (amber gradient). Size: 100 % wide, 44 px tall (36 for peaks); set
`.spark-svg { height }` in page CSS to change. The `aria-label` states points, peak and total.

### Badges and tooltips
```jinja
{{ ui.badge("danger", d.registered_domain ~ ", AI phishing", href="/domain/" ~ d.id) }}
{{ ui.badge("alert", "7 domains wait for review", tip="Review queue: 7") }}
{{ ui.tip("Unsafe connection: login form posts to another host", "danger") }}
```
`badge(kind, label, href=None, tip=None, id=None, size="", class_="", data={})`: a round glass badge (32 px;
`sm` 24, `lg` 40) with the kind's icon in its colour (red and amber glow faintly). `label` is the accessible
name; `tip` (default: label) shows as a pill tooltip on hover and keyboard focus (`data-tip`; without JS a CSS
tooltip shows it). With `href` it is a link (dashboard paths only); without, it is `role="img"` (and focusable
only when it has its own `tip`). A hovered or focused badge grows with the `scale` property, not `transform`, so a
`.pin`'s `translate(-50%, -50%)` centring holds, and a linked badge keeps its tone colour on hover. `ui.tip(text, kind=None)` is a static pill with an icon, for a label that is
always shown. Any element with `data-tip="text"` (plus optional `data-tip-sub` and `data-tip-kind`) gets the
JS tooltip.

### Category tiles
```jinja
<div class="tiles">
  {{ ui.tile("danger", "Phishing", n.phishing, n.judged, "AI verdicts", href="/live/list?verdict=phishing") }}
  {{ ui.tile("alert", "Suspicious", n.suspicious, n.judged, "AI verdicts", href="...") }}
  {{ ui.tile("protected", "Benign or parked", n.benign, n.judged, "AI verdicts", href="...") }}
  {{ ui.tile("unknown", "Not judged", n.unjudged, n.total, "Domains", href="...") }}
</div>
```
`tile(kind, label, value, total=None, caption=None, href=None, id=None)`: icon + label at the top, small muted
caption and a big light "n / total" at the bottom. `.tiles` is an auto-fit grid (150 px minimum).

### Dot grid with labelled rows
```jinja
{{ ui.dot_grid(rows, "Pipeline by stage, last 24 hours: 1,204 seen, 96 scored, ...", cols=["24 h ago", "12 h", "now"]) }}
```
`rows`: `[{"label": "Seen in CT", "total": "1,204", "cells": [{"level": 0-4 or None, "title": "14:00 UTC: 87",
"marker": None or a kind}]}]`. One dot per cell (cells share the width equally), sized and brightened by level
(4 glows); `None` is an empty outline; a `marker` replaces the dot with that kind's icon. Row labels left, totals
right, optional evenly spread tick labels underneath. The whole grid is one `role="img"`, so put the numbers in
`label`; `title`s give hover detail. Compute levels in Python (for example `-(-4 * v // peak)` like
`dot_matrix`).

### Data table
```jinja
{% call ui.table(["Seen", "Tier", ("Score", "num"), "Hostname", "Status"], label="Review queue", id="rows", tall=True, rows=True) %}
  {% for r in rows %}<tr data-href="/domain/{{ r.id }}">...</tr>
  {% else %}{{ ui.empty_row(5, "Nothing waits for review.", "/domains", "Browse all domains") }}{% endfor %}
{% endcall %}
```
This renders `.table-wrap > table.data` in a glass box: a sticky solid header, hairline rows, a row hover.
`label` makes the scroll area a focusable named region. `tall=True` caps the height at 72vh. `rows=True` adds
`data-rows` to the tbody: `j`/`k` move a row cursor (`tr.is-cursor`) and `o` opens the row. Cell classes:
`.num`, `.nowrap`, `.actions`, `.dom`. `table.table--cards` turns rows into cards under 600 px (cells labelled
from `data-label`; `.card-title`, `.card-wide` and `.actions` span the row). A new live row gets
`class="is-new"`: a 1.8 s teal fade.

### Pills
| Macro | Values, tone and glyph |
|---|---|
| `ui.tier_pill(tier)` | high: red ▲, review: amber ◆, watch: muted ○ |
| `ui.status_pill(status)` | open: outline ○, confirmed: red ✕ "confirmed phishing", false_positive: teal ✓ "false positive", benign: teal ✓ |
| `ui.verdict_pill(verdict, confidence=None)` | always violet ("AI phishing 97%"). The glyph shows severity: phishing ■ red, suspicious ▲ amber, benign ✓ green, parked –, error !. No verdict gives muted text |
| `ui.live_pill(state)` | live: red ●, down/no_dns: muted ○, blocked: amber ▲, unknown: "not checked" ? |
| `ui.health_pill(state, text=None)` | ok/live: teal, stale/warn: amber, down/error/over: red, off: muted, unknown: ? |
| `ui.pill(text, tone, glyph=None, title=None)` | generic. Tones: teal, green, amber, red, violet, muted, outline |

Pills are fully rounded, 22 px, with a tinted fill and a tone border.

### Buttons and controls
```jinja
{{ ui.button("Confirm phishing", kind="danger", name="status", value="confirmed", shortcut="c",
             confirm="Confirm " ~ d.registered_domain ~ " as phishing?", confirm_detail="Reports are drafted and the blocklist is rebuilt.") }}
{{ ui.button("Mark false positive", name="status", value="false_positive", shortcut="f") }}
{{ ui.link_button("Open the review queue", "/review", kind="quiet") }}
{{ ui.post_button("/blocklist/rebuild", "Rebuild now", kind="primary") }}
```
Pill buttons. Kinds: `""` (glass), `primary` (teal fill, dark text), `danger` (red fill, dark text), `quiet`
(text only, teal), plus the class `.btn--light` (the light pill used for "View"-style emphasis). `small=True`
for `.btn--sm`. Loading is automatic: on submit, app.js adds `.is-loading` (a spinner) and `aria-disabled` to the
pressed button and ignores a second submit. Opt a form out with `data-no-busy`; in scripts use
`CC.busy(btn, on)`. `shortcut="c"` adds `data-shortcut`, `aria-keyshortcuts` and a small `<kbd>` hint (hidden on
touch devices and without JS).

**Round icon buttons**
```jinja
{{ ui.icon_button("pause", "Pause live updates", pressed=False, data={"action": "pause"}, js_only=True) }}
{{ ui.icon_button("clock", "Window: 24 hours", href="/?window=7d", text="24 h") }}
```
`icon_button(icon, label, href=None, type="button", name=None, value=None, pressed=None, id=None, class_="",
data={}, shortcut=None, js_only=False, size="", tone=None, text=None, disabled=False)`: a 38 px round glass
button (`sm` 32, `lg` 46; 42 on touch). `label` is the `aria-label` and the tooltip. `pressed=True/False` makes
it a toggle (`aria-pressed`; pressed draws a light fill; flip the attribute in your script). `text` adds a short
visible chip label ("24 h"), making it a pill. `data={"k": v}` writes `data-k`. Use `href` for no-JS fallbacks
(a window switch is a link to `?window=7d`); use `js_only=True` for buttons that do nothing without JS.

**Floating button row**: `{% call ui.fab_row("Terrain controls") %}…icon buttons…{% endcall %}` renders
`<div class="fab-row" role="group" aria-label>`: a glass pill holding transparent round buttons. Inside `.hero`
it floats centred on the bottom edge. `<span class="fab-sep" aria-hidden="true"></span>` is a divider.

**Segmented control**: `{{ ui.segmented([("/?w=6h", "6 h"), ("/?w=24h", "24 h"), ("/?w=7d", "7 d")], active="/?w=24h", label="Window") }}`
is `ui.tabs` drawn compact and inline (`nav.tabs.segmented`): a glass track whose active segment is a light
pill. `ui.tabs` itself now has the same look (full size).

**Filter pills** ("Belongs to [War Room v]"):
```jinja
{% call ui.filter_bar(label="Overview filters") %}
  {{ ui.filter_pill("Window", "window", [("6h", "6 h"), ("24h", "24 h"), ("7d", "7 days")], selected=window) }}
  {{ ui.filter_pill("Tier", "tier", ["high", "review", "watch"], selected=tier, any_label="Any tier") }}
{% endcall %}
```
`filter_pill(label, name, options, selected="", id=None, any_label=None)`: a small muted label and a rounded
select with a caret (`id` defaults to `fp-<name>`). `filter_bar(action="", label="Filters", apply="Apply",
class_="")` is the GET form around them with an Apply button. There is no submit-on-change on purpose (it would
reload while a keyboard user arrows through options).

**Search pill**: `{{ ui.search_pill("q", filters.q, label="Search hits", placeholder="Search by domain", action="/live/list") }}`
is its own GET form (don't put it inside another form) with a round search button; the field is the one `/`
focuses.

### Confirm dialog (degrades to a plain POST)
Put `data-confirm="Question?"` on a submit button (or on the `<form>`). Optional: `data-confirm-ok`,
`data-confirm-detail`, `data-confirm-title`, `data-confirm-tone="danger|primary"`. `ui.button(..., confirm=...)`
writes them; `ui.confirm_attrs(message, ok, tone, detail)` writes them on hand-made markup. With JS a glass
`<dialog>` asks first (focus on Cancel for danger), then the form is submitted **with the same submitter**.
Without JS the button posts at once, so only use confirm where a direct post is still acceptable.

### Forms
```jinja
<form method="get" class="filters" role="search">
  {{ ui.field("Search", "q", filters.q, type="search", placeholder="domain or hostname", search=True) }}
  {{ ui.select_field("Tier", "tier", ["high", "review", "watch"], selected=filters.tier, any_label="Any tier") }}
  {{ ui.button("Apply filters") }}
</form>
{{ ui.textarea_field("Body (plain text)", "body", r.body, rows=18, id="bo" ~ r.id) }}
```
Inputs are 10 px-radius fields with a darker fill and a 3:1 outline (`--control`); textareas use the
monospace font (drafts). Signatures unchanged: `field(label, name, value, type, id, placeholder, hint,
maxlength, required, autocomplete, search, shortcut, class_)`, `select_field(label, name, options, selected, id,
hint, any_label, class_)`, `textarea_field(label, name, value, rows, id, hint, maxlength, readonly, class_)`.
Classes: `.field`, `.hint`, `.input`, `.filters`, `.field--inline`, `form.inline`. Reminder for the domain
decision form: keep the disabled, hidden first submit button that stops Enter from submitting a decision.

### Key-value list, empty state, flash, toast, tabs, kbd
- `{% call ui.kv() %}{% call ui.kv_item("Registrar") %}…{% endcall %}{% endcall %}`: `dl.kv`, two columns,
  stacks under 560 px, frameless inside a panel.
- `{{ ui.empty(title, text, href, action) }}` and `ui.empty_row(colspan, text, href, action)`. Keep the existing
  empty-state sentences where tests assert them ("Nothing here.", "No email drafts waiting.", ...).
- `{{ ui.flash(message, tone) }}`: ok ✓ / info ● / warn ▲ / error ■ (role=alert), a glass bar with a tone tint.
  `.msg` and `.warn` still work. Client side: `CC.toast("Copied", "ok")` (a glass pill with a tone dot).
- `{{ ui.tabs(items, active, label) }}`: server links or in-page `#` tabs (JS turns them into a real tablist;
  without JS they are jump links and every section shows).
- `{{ ui.kbd("g r") }}`.

### Domains, URLs, times, copying
- `ui.dom(host, unicode=None, href=None, exact=False)`: a domain in the UI font. When the display form differs
  (an IDN) it adds "displays as …" in amber monospace. `exact=True` renders the name in monospace (`.dom--exact`):
  use it where `rn`/`m` or `l`/`1` look-alikes matter, such as the domain page heading and the evidence pane.
- `ui.url_text(u)`: a URL as monospace text in a glass chip, never a link.
- `ui.ago(ts, fallback="-")`: `<time datetime title="YYYY-MM-DD HH:MM UTC">3m ago</time>`, refreshed live.
  Filters: `ts|ago`, `ts|iso`, `ts|utc`, and `n|compact`.
- `ui.copy_button(text=None, target=None, label="Copy")`: hidden without JS.

### Meter
`{{ ui.meter(s.spent_today, s.daily_cap, "Daily AI cap") }}`: a 5 px rounded SVG bar, `role=img` with the
percentage. Tone automatic (≥ 90 red, ≥ 70 amber, else teal) or `tone="violet"`/`"green"`. Markup kept:
`<svg class="meter meter--red" ...><rect class="meter-track" .../><rect class="meter-fill" ... width="25" height="4"/></svg>`.

### Screenshot frame and lightbox
`{{ ui.shot(p.id, "Screenshot of the page at " ~ (p.final_url or p.url), caption="Desktop, 3m ago", profile=p.user_agent_profile) }}`.
A link to `/screenshot/<id>` around a lazy `<img class="shot">`; with JS it opens a glass lightbox (←/→ step
through every `a[data-lightbox]`).

### Dot-matrix heatmap (unused)
`common.dot_matrix(certs, flags)` and `{{ ui.dot_matrix(m) }}` still work (24 rows × 60 minutes; teal dots that
glow at the top level; review = amber ring, high = red square), but no page uses them since the overview moved
to the canvas terrain. Prefer the terrain pattern or `ui.dot_grid` for new work.

### Live indicator
`class="cursor"` on a caption adds a pulsing teal dot (static under reduced motion); `<span class="live-dot"></span>`
is a still one.

## Old class names (still styled)

`.pill` with `.t-high`, `.t-review`, `.t-watch`, `.t-ok`; `.cards > .card > .n + .l`; `.card`; `.kv`;
`.grid2`; `.muted`; `.dom`; `.num`; `.shot`; `.flex`; `form.inline`; `button.primary`; `.scroll`; `tr.new`;
bare `table`/`th`/`td`; `pre`; `textarea`; `.field`, `.warn`, `.msg`, `.banner`, `details.draft`. The rail
classes (`.rail`, `.rail-link`, `.rail-badge`, `.prompt`) are gone with the rail.

## JavaScript API (`window.CC`)

app.js loads with `defer` on every page. Page scripts go in `{% block scripts %}` and run after it. Plain
ES2017, no frameworks. Build DOM with `CC.el` or `textContent`. **Never** use `innerHTML` with data.

| Call | Does |
|---|---|
| `CC.ready(fn)` | runs fn once the DOM is ready |
| `CC.$(sel, root)`, `CC.$$(sel, root)` | querySelector, and querySelectorAll as an array |
| `CC.el(tag, attrs, ...children)` | creates an element. Strings become text nodes. `attrs`: `class`, `text`, `dataset: {}`, `on: {click: fn}`, others via setAttribute. Throws on `on*` attributes and on `href`/`src`/`action` that is not a same-origin path |
| `CC.icon(name, cls)` | an `<svg class="ico"><use href="#i-name"/></svg>` from the sprite |
| `CC.badge(kind, label, {href, tip, size, class})` | the same markup as `ui.badge()`; `tip` may be a string or an array of lines (title first) |
| `CC.KIND` | kind → `[icon, tone]` (the table above) |
| `CC.tooltip.show(anchor, content, {kind})`, `.hide()`, `.anchor` | the one floating pill tooltip (`#cc-tip`, `role=tooltip`, text only). `anchor` is an element or a viewport point `{x, y}` (for canvas hover). `content` is a string, a Node, or an array of lines (first = title, rest muted). Adds `aria-describedby` to an element anchor when the text differs from its label. Hidden on scroll and Esc |
| `CC.canvasDPR(canvas, cssW?, cssH?, maxDpr=2)` | sizes the backing store to CSS size × devicePixelRatio (capped) and scales the context; returns `{ctx, w, h, dpr}`. Draw in CSS pixels; call again after a resize |
| `CC.observeSize(el, fn)` | `fn({width, height})` at most once per frame when the box changes (ResizeObserver, falls back to window resize). Returns `stop()` |
| `CC.loop(fn)` | rAF loop `fn(timeMs, dtMs)`, skips frames in hidden tabs. `{start(), stop(), running()}`. Don't start it under reduced motion: draw one still frame instead |
| `CC.reducedMotion()`, `CC.onMotionChange(fn)` | the `prefers-reduced-motion` state and its changes |
| `CC.token('--teal')` | a token's value from app.css, for canvas colours |
| `CC.compact(n)` | `882k`, `1.2k`, `2.4M` (same as the `compact` filter) |
| `CC.fmtInt(n)` | `1,234` in en-AU |
| `CC.isLocalPath(u)` | true for `/x`, `?q`, `#id`. False for `//host`, `javascript:` and absolute URLs |
| `CC.data(id)` | parses `<script type="application/json" id="...">{{ value | tojson }}</script>` (allowed by the CSP: data, not script). Use it for a chart payload |
| `CC.getJSON(path)` | same-origin GET with `Accept: application/json` and `no-store`. Rejects on non-2xx with `err.status` |
| `CC.post(path, data, {submitter, accept})` | same-origin POST, url-encoded. Rejects with `err.status` and `err.detail` |
| `CC.poll(pathOrFn, ms, onData, {immediate, onError})` | polls JSON with no overlap, pauses in hidden tabs, backs off up to 4× after errors. Returns `{stop(), now()}` |
| `CC.toast(text, tone='ok'\|'warn'\|'error', ms)` | toast in the polite live region (errors use role=alert). `ms=0` keeps it |
| `CC.confirm({title, message, detail, ok, cancel, tone})` | `Promise<boolean>` from a modal `<dialog>` |
| `CC.busy(button, on)` | sets or clears the loading state |
| `CC.lightbox(src, caption, list)` | opens the lightbox (src must be a local path) |
| `CC.copy(text)` | copies to the clipboard and toasts the result |
| `CC.shortcut(keys, label, handler, {group})` | registers a shortcut (`"j"`, `"?"`, `"/"`, chord `"g r"`). Returns an unregister function. Ignored while typing, with Ctrl/Cmd/Alt, and while a dialog is open |
| `CC.shortcuts()`, `CC.openHelp()` | the registry; the help dialog (also `?` and the round keyboard button in the bar) |
| `CC.rows.next()`, `.prev()`, `.open()` | the `j`/`k`/`o` row cursor for `tbody[data-rows]` |
| `CC.menu.open()`, `.close()`, `.toggle()` | the phone nav sheet |
| `CC.relTime(root)`, `CC.formatAgo(date)` | refreshes `<time datetime>` text (every 30 s on its own) |
| `CC.on(name, fn)`, `CC.emit(name, detail)` | events on `document` named `cc:<name>`. `CC.on('status', fn)` fires after each status poll; `CC.status` holds the latest |
| `CC.statusPoll` | the status poller (`stop()`, `now()`) |

Declarative hooks (no page JS needed):

| Attribute | Effect |
|---|---|
| `data-tip="text"` (+ `data-tip-sub`, `data-tip-kind`) | pill tooltip on hover and keyboard focus |
| `data-shortcut="c"` on a button, link or input | the key clicks it, or focuses an input; listed in `?` help, labelled by `data-shortcut-label`, `aria-label` or the text |
| `data-confirm` and friends on a submit button or form | confirm dialog |
| `tbody[data-rows]` with `tr[data-href]` | `j`/`k`/`o` row navigation |
| `a[data-lightbox][data-caption]` | lightbox |
| `[data-copy="text"]` or `[data-copy-target="#id"]` | copy button (add `class="js-only" hidden`) |
| `.js-only[hidden]` | revealed by app.js |
| `nav.tabs[data-tabs]` with `#` links | in-page tabs |
| `data-search` on an input | the field `/` focuses (before the bar's search pill) |
| `form[data-no-busy]` | no automatic loading state |

Global shortcuts: `?` help, `/` search, `g o` overview, `g r` review, `g d` domains, `g p` reports, `g b`
blocklist, `g t` takedowns, `g a` AI, Esc closes the More menu, the phone sheet and tooltips. Suggested page keys:
on a domain page `c` confirm phishing, `f` false positive, `b` benign, `n` note field, `[`/`]` previous/next
domain in the queue; on lists `j`/`k`/`o`.

### Drawing a canvas visual (pattern)
```js
CC.ready(function () {
  var stage = CC.$('.hero-stage'), canvas = CC.$('canvas', stage);
  if (!canvas.getContext) { return; }                // the server-rendered fallback stays
  // fetch the payload from a JSON route named in data-src (test_it_web allows no <script> without src,
  // not even type="application/json", so CC.data() is for pages outside that test only)
  CC.getJSON(stage.dataset.src).then(function (data) { /* build offscreen layers, then draw() */ });
  var teal = CC.token('--teal');
  function draw() {
    var c = CC.canvasDPR(canvas);                      // c.ctx in CSS pixels, c.w x c.h
    c.ctx.clearRect(0, 0, c.w, c.h);
    // ... radial gradients for the glow, one fillRect/arc per dot; keep it to a few thousand dots on a phone
  }
  CC.observeSize(stage, draw);
  canvas.addEventListener('pointermove', function (e) {
    // hit-test, then CC.tooltip.show({x: e.clientX, y: e.clientY}, [host, brand + ', ' + verdict], {kind: 'danger'})
  });
  canvas.addEventListener('pointerleave', function () { CC.tooltip.hide(); });
});
```
Hosts and brands in the payload are attacker-controlled: they reach the page only through `textContent`
(`CC.tooltip`, `CC.el`), never as markup, and links are built from numeric ids (`'/domain/' + Number(id)`).

## Pages

### Overview (`/`, pages_live.py, overview.html/css/js)
- **Windows**: `?window=6h|24h|7d` (default 24h; unknown values fall back to 24h). The window ends at the next
  bucket boundary so buckets line up with the clock. Terrain columns are 3, 5 or 30 minutes; pipeline buckets
  15 minutes, an hour or 6 hours (6h, 24h, 7d).
- **Threat terrain** (`.hero-stage`, `#terrain-canvas`): x = time over the window, y = domain-name score 40..100.
  Brightness is a Gaussian-smoothed density of stored hits (`smooth()`, absolute scale `1 - exp(-d / 2.5)` so one
  hit always shows) over a faint base that follows certificates a minute; colour runs teal → amber → red by score
  band. Payload: `GET /api/live/terrain?window=` (no-store, cached 20 s per window; levels are encoded one
  character a cell). Pinned glass badges for notable domains (AI phishing, live, confirmed, taken down) come from
  the same payload, at most 12 on desktop and 6 on phones, kept clear of the band labels. The floating button row
  holds the window chip (a link, so it works without JS), the layer toggles, the tier filter, pause (`p`) and a
  list link. Without JS an SVG fallback (`terrain_svg()`) shows the same field more coarsely with linked marks.
  Animation stops under reduced motion, in hidden tabs and off screen.
- **Left column**: certificates and hits, "Hits intensity" (`ui.sparkline` bars, hits per 10 minutes) and
  "High-tier peaks" (peaks, per hour). **Right column**: the window segmented control and three `ui.gauge` rings
  (AI spend today / daily cap, live phishing / judged pages, open review / open + decided in 7 days).
- **Pipeline by stage**: `ui.dot_grid` with rows Seen in CT, Scored, Page live, AI judged, Confirmed, Reported,
  Taken down and one column per pipeline bucket; payload `GET /api/live/pipeline?window=` from
  `domain_events`. A "Show … as a table" details block has the same numbers with `/live/list?hour=` links.
- **Domains by AI verdict**: four `ui.tile`s (Phishing, Suspicious, Benign or parked, Not judged) linking to
  `/live/list?verdict=phishing|suspicious|cleared|unjudged&tier=flagged&window=`, plus one SVG bar with the split.
- **Live hits** (ids `feed`, `feed-state`, `feed-pause`, `feed-filter`, `data-src="/api/recent"`) beside "Hits by
  brand". Side by side the feed takes the brand panel's height and scrolls inside it.
- Polling: terrain 60 s, summary 30 s, feed 10 s; one pause switch stops all three.

### Review, domain and domains (app.py, `_row.html`, triage.css/js)
- `_row.html` macros: `score_ring(value, tone, title)` (small gauge ring in a queue row), `exact_name(name)`
  (the "Exact spelling" monospace chip for rn/m and l/1 look-alikes), `lifecycle(d, ev)` (an `<ol>` of Seen in CT,
  Page fetched, Page live, AI judged, Decided, Reported, Taken down; steps that happened glow and show when),
  plus `queue_row`, `evidence_pane`, `ai_block`, `score_block`, `shots_block`, `why_block`, `blocklist_block`,
  `hostnames_block`.
- Decision buttons: `btn--confirm` (red-tinted glass), `btn--fp`, `btn--benign`, `btn--reopen` (plain glass with a
  small CSS shape before the label); `btn--danger` still works.
- `/domains` adds `by_status` (counts per decision under the other filters) and `status_links` (each tile's link;
  the active tile's link clears the filter) to the context.

### Reports and operations (`ops_macros.html`, ops.css, reports.css)
- `ops.tile(label, value, icon, total=None, tone=None, hint=None, href=None, id=None)`: a category tile that keeps
  `ui.kpi`'s markup start (`<div class="n">V</div><div class="l">L</div>`); the icon and "/ total" are placed by
  ops.css. `ops.tiles(label)` is the container. `ops.ring(value, total, label, tone, size)` is `ui.gauge`'s ring
  alone. The reports pages load ops.css before reports.css.
- AI page: "Last 24 hours" from `ai_calls` (`pages_ai.HOURLY_SQL`, `hourly_view()`): calls per hour, spend per
  hour and a dot grid with one row per purpose, refusals and failures marked.

## Motion

Animate only in response to an action (a dialog opening, a toast, a button's spinner, a status value changing,
the More caret), rows appended to the live feed, and the live indicator's pulse. `prefers-reduced-motion` turns
all of it off. Canvas glow animation must check `CC.reducedMotion()`.
