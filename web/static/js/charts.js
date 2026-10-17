// Hand-drawn SVG charts. Colours come from CSS classes so light and dark mode and
// the colour-blind-safe pairing of colour with text both work; nothing external.
import { svg, h } from './dom.js';

export const LEVELS = [
  { level: 4, name: 'PQ-authenticated', short: 'L4' },
  { level: 3, name: 'Hybrid negotiated', short: 'L3' },
  { level: 2, name: 'Hybrid available', short: 'L2' },
  { level: 1, name: 'Exposed', short: 'L1' },
  { level: 0, name: 'Not ready', short: 'L0' },
  { level: -1, name: 'Undetermined', short: '?' },
];

export const levelName = (l) => (LEVELS.find((x) => x.level === l) || { name: 'Unknown' }).name;
export const levelClass = (l) => (l === null || l === undefined ? 'lv-none' : `lv${l < 0 ? 'u' : l}`);

/** Donut of counts by readiness level, with the total in the centre. */
export function donut(counts, total, size = 160) {
  const r = 58, cx = size / 2, cy = size / 2, sw = 22, C = 2 * Math.PI * r;
  const root = svg('svg', { viewBox: `0 0 ${size} ${size}`, width: size, height: size, role: 'img',
    'aria-label': `Readiness distribution across ${total} scanned assets` });
  root.appendChild(svg('circle', { cx, cy, r, class: 'donut-track', 'stroke-width': sw, fill: 'none' }));
  let offset = 0;
  for (const { level } of LEVELS) {
    const n = counts[level] || 0;
    if (!n || !total) continue;
    const len = (n / total) * C;
    root.appendChild(svg('circle', {
      cx, cy, r, fill: 'none', 'stroke-width': sw, class: `donut-seg ${levelClass(level)}`,
      'stroke-dasharray': `${len} ${C - len}`, 'stroke-dashoffset': -offset,
      transform: `rotate(-90 ${cx} ${cy})`,
    }, svg('title', null, `${levelName(level)}: ${n}`)));
    offset += len;
  }
  root.appendChild(svg('text', { x: cx, y: cy - 2, class: 'donut-num', 'text-anchor': 'middle' }, String(total)));
  root.appendChild(svg('text', { x: cx, y: cy + 16, class: 'donut-lbl', 'text-anchor': 'middle' }, total === 1 ? 'asset' : 'assets'));
  return root;
}

/** Stacked columns: the fleet's readiness distribution per day. */
export function trendBars(points, width = 460, height = 150) {
  const pad = { l: 26, r: 6, t: 8, b: 22 };
  const totals = points.map((p) => Object.values(p.levels).reduce((a, b) => a + b, 0));
  const max = Math.max(1, ...totals);
  const root = svg('svg', { viewBox: `0 0 ${width} ${height}`, class: 'chart', role: 'img',
    'aria-label': 'Fleet readiness by day' });
  const bw = (width - pad.l - pad.r) / Math.max(1, points.length);
  const y = (v) => pad.t + (height - pad.t - pad.b) * (1 - v / max);

  for (const t of [0, Math.ceil(max / 2), max]) {
    root.appendChild(svg('line', { x1: pad.l, x2: width - pad.r, y1: y(t), y2: y(t), class: 'grid' }));
    root.appendChild(svg('text', { x: pad.l - 4, y: y(t) + 3, class: 'axis', 'text-anchor': 'end' }, String(t)));
  }
  points.forEach((p, i) => {
    let acc = 0;
    for (const { level } of [...LEVELS].reverse()) {
      const n = p.levels[level] || 0;
      if (!n) continue;
      const y0 = y(acc + n), y1 = y(acc);
      const rect = svg('rect', {
        x: pad.l + i * bw + bw * 0.14, width: bw * 0.72, y: y0, height: Math.max(0, y1 - y0),
        class: `bar ${levelClass(level)}`,
      }, svg('title', null, `${p.date}: ${n} × ${levelName(level)}`));
      rect.style.setProperty('--i', String(i));
      root.appendChild(rect);
      acc += n;
    }
    // Every third day, counted back from today, so labels never touch and the latest is always shown.
    if ((points.length - 1 - i) % 3 === 0) {
      root.appendChild(svg('text', { x: pad.l + i * bw + bw / 2, y: height - 6, class: 'axis', 'text-anchor': 'middle' },
        p.date.slice(5)));
    }
  });
  return root;
}

/** Horizontal bars for a {label: count} distribution. */
export function barList(entries, classFor) {
  const max = Math.max(1, ...entries.map(([, n]) => n));
  return h('ul', { class: 'barlist' }, entries.map(([label, n]) => h('li', null,
    h('span', { class: 'barlist-label' }, label),
    h('span', { class: 'barlist-track' }, h('span', { class: `barlist-fill ${classFor ? classFor(label) : ''}`, ref: null,
      role: 'presentation', 'data-w': String(Math.round((n / max) * 100)) })),
    h('span', { class: 'barlist-n' }, String(n)))));
}

/** Apply the data-w widths (CSSOM, allowed by the CSP) after insertion. */
export function sizeBars(root) {
  for (const el of root.querySelectorAll('[data-w]')) el.style.width = `${el.getAttribute('data-w')}%`;
}

/** A step line of one asset's readiness level over time, with hygiene score labels. */
// pointMeasure is a history point's own measure (UX-DESIGN-007 §1): the TLS hygiene score, or an
// SSH server's baseline verdict. SSH servers have no score.
function pointMeasure(p, long) {
  if (p.baselineMeets === true) return long ? 'meets the SSH baseline' : '✓';
  if (p.baselineMeets === false) return long ? `${p.baselineChanges} change${p.baselineChanges === 1 ? '' : 's'} to meet the SSH baseline` : String(p.baselineChanges);
  if (p.score < 0) return long ? 'not rated' : '';
  return long ? `TLS hygiene ${p.band} ${p.score}` : String(p.score);
}

// hrefFor, when given, makes each point a mark that opens that scan (PRD-009 REQ-CHT-5).
export function historyChart(points, width = 640, height = 170, hrefFor = null) {
  const pts = points.filter((p) => p.status === 'done' && p.readinessLevel !== null);
  const pad = { l: 132, r: 30, t: 14, b: 26 };
  const root = svg('svg', { viewBox: `0 0 ${width} ${height}`, class: 'chart', role: 'img',
    'aria-label': 'Readiness level of this endpoint over time' });
  const y = (lv) => pad.t + (height - pad.t - pad.b) * (1 - lv / 4);
  for (const lv of [0, 1, 2, 3, 4]) {
    root.appendChild(svg('line', { x1: pad.l, x2: width - pad.r, y1: y(lv), y2: y(lv), class: 'grid' }));
    root.appendChild(svg('text', { x: pad.l - 6, y: y(lv) + 3, class: 'axis', 'text-anchor': 'end' }, `L${lv} ${levelName(lv)}`));
  }
  if (pts.length === 0) {
    root.appendChild(svg('text', { x: width / 2, y: height / 2, class: 'axis', 'text-anchor': 'middle' }, 'No completed scans yet'));
    return root;
  }
  const t0 = new Date(pts[0].at).getTime();
  const t1 = new Date(pts[pts.length - 1].at).getTime();
  const inset = 14; // keep the first and last dots clear of the axis labels
  const x = (t) => (pts.length === 1 || t1 === t0 ? (pad.l + width - pad.r) / 2
    : pad.l + inset + ((new Date(t).getTime() - t0) / (t1 - t0)) * (width - pad.l - pad.r - 2 * inset));

  // Step path.
  let d = '';
  pts.forEach((p, i) => {
    const px = x(p.at), py = y(p.readinessLevel);
    d += i === 0 ? `M ${px} ${py}` : ` H ${px} V ${py}`;
  });
  root.appendChild(svg('path', { d, class: 'stepline', fill: 'none', pathLength: '1' }));
  pts.forEach((p, i) => {
    const words = `${new Date(p.at).toLocaleString()}: L${p.readinessLevel} ${levelName(p.readinessLevel)}, ${pointMeasure(p, true)}`;
    const href = hrefFor ? hrefFor(p) : null;
    const g = svg('g', mark({ class: 'dotmark' }, href, `Scan of ${words}: open its report`,
      { tip: `L${p.readinessLevel} ${levelName(p.readinessLevel)}`, sub: `${stamp(p.at)} · ${pointMeasure(p, true)}` }),
    // A 12px invisible hit area around the 5px dot (WCAG 2.2 target size).
    href ? svg('circle', { cx: x(p.at), cy: y(p.readinessLevel), r: 12, class: 'hit' }) : null,
    svg('circle', { cx: x(p.at), cy: y(p.readinessLevel), r: 5, class: `dot ${levelClass(p.readinessLevel)}` }, svg('title', null, words)));
    g.style.setProperty('--i', String(Math.min(i, 9)));
    root.appendChild(g);
    root.appendChild(svg('text', { x: x(p.at), y: y(p.readinessLevel) - 9, class: 'dotlabel', 'text-anchor': 'middle' }, pointMeasure(p, false)));
  });
  root.appendChild(svg('text', { x: pad.l, y: height - 6, class: 'axis' }, stamp(pts[0].at)));
  if (pts.length > 1) {
    root.appendChild(svg('text', { x: width - pad.r, y: height - 6, class: 'axis', 'text-anchor': 'end' },
      stamp(pts[pts.length - 1].at)));
  }
  return root;
}

const stamp = (iso) => new Date(iso).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' });

/** A tiny sparkline of readiness levels. */
export function spark(points, w = 70, h2 = 20) {
  const pts = points.filter((p) => p.status === 'done' && p.readinessLevel !== null).slice(-12);
  const root = svg('svg', { viewBox: `0 0 ${w} ${h2}`, width: w, height: h2, class: 'spark', 'aria-hidden': 'true' });
  if (pts.length < 2) return root;
  const step = w / (pts.length - 1);
  const d = pts.map((p, i) => `${i === 0 ? 'M' : 'L'} ${i * step} ${h2 - 2 - (p.readinessLevel / 4) * (h2 - 4)}`).join(' ');
  root.appendChild(svg('path', { d, class: 'stepline', fill: 'none' }));
  return root;
}

// ---- marks you can act on (UX-DESIGN-008 §2) -------------------------------------------------
// A mark that counts a set of things opens that set. It is an SVG or HTML element with
// role=link, a name that says what it opens, and data-href; one delegated listener set (wireMarks,
// installed once on the page) gives every mark the same hover, focus, tooltip and keys. A mark
// that counts nothing gets none of this.

/** Attributes that make an element a mark: merge them into its own (class is appended). */
export function mark(attrs, href, label, { tip, sub, key } = {}) {
  if (!href) return attrs;
  return {
    ...attrs,
    class: `${(attrs && attrs.class) || ''} mark`.trim(),
    role: 'link', tabindex: '0', 'aria-label': label, 'data-href': href,
    'data-tip': tip || label, 'data-tip-sub': sub || null, 'data-key': key || null,
  };
}

let tipEl = null;
function tooltip() {
  if (!tipEl) {
    tipEl = h('div', { class: 'charttip', 'aria-hidden': 'true', hidden: true });
    document.body.appendChild(tipEl);
  }
  return tipEl;
}

function showTip(el, at) {
  const tip = tooltip();
  tip.replaceChildren(
    h('b', null, el.getAttribute('data-tip') || ''),
    el.getAttribute('data-tip-sub') ? h('span', null, el.getAttribute('data-tip-sub')) : null,
    el.getAttribute('data-href') ? h('span', { class: 'charttip-hint' }, 'Click to open the list') : null);
  tip.hidden = false;
  const r = el.getBoundingClientRect();
  const w = tip.offsetWidth, ht = tip.offsetHeight;
  // Beside the pointer, or above the mark on keyboard focus; flipped at the viewport's edges.
  let x = at ? at.x + 14 : r.left + r.width / 2 - w / 2;
  let y = at ? at.y + 16 : r.top - ht - 8;
  if (x + w > window.innerWidth - 8) x = (at ? at.x - 14 : r.right) - w;
  if (x < 8) x = 8;
  if (y + ht > window.innerHeight - 8) y = (at ? at.y : r.top) - ht - 10;
  if (y < 8) y = r.bottom + 8;
  tip.style.left = `${Math.round(x + window.scrollX)}px`;
  tip.style.top = `${Math.round(y + window.scrollY)}px`;
}

function hideTip() { if (tipEl) tipEl.hidden = true; }

// The marks of one chart share a container: the nearest [data-chart], else the svg or list.
const chartOf = (el) => el.closest('[data-chart]') || el.closest('svg') || el.parentElement;

function heat(el, on) {
  const chart = chartOf(el);
  if (!chart) return;
  chart.classList.toggle('chart-hot', on);
  const key = el.getAttribute('data-key');
  const same = key ? chart.querySelectorAll(`.mark[data-key="${CSS.escape(key)}"]`) : [el];
  for (const m of chart.querySelectorAll('.mark.is-hot')) m.classList.remove('is-hot');
  if (on) for (const m of same) m.classList.add('is-hot');
}

/** Install the mark behaviour once, on the element that holds every page. */
export function wireMarks(root) {
  if (!root || root._marksWired) return;
  root._marksWired = true;
  const markOf = (e) => (e.target instanceof Element ? e.target.closest('.mark[data-href]') : null);
  const open = (el, e) => {
    e.preventDefault();
    e.stopPropagation();
    hideTip();
    location.hash = el.getAttribute('data-href');
  };
  root.addEventListener('click', (e) => { const el = markOf(e); if (el) open(el, e); });
  root.addEventListener('keydown', (e) => {
    const el = markOf(e);
    if (el && (e.key === 'Enter' || e.key === ' ')) open(el, e);
  });
  root.addEventListener('pointerover', (e) => { const el = markOf(e); if (el) { heat(el, true); showTip(el, { x: e.clientX, y: e.clientY }); } });
  root.addEventListener('pointermove', (e) => { const el = markOf(e); if (el && tipEl && !tipEl.hidden) showTip(el, { x: e.clientX, y: e.clientY }); });
  root.addEventListener('pointerout', (e) => {
    const el = markOf(e);
    if (el && !(e.relatedTarget instanceof Node && el.contains(e.relatedTarget))) { heat(el, false); hideTip(); }
  });
  root.addEventListener('focusin', (e) => { const el = markOf(e); if (el) { heat(el, true); showTip(el, null); } });
  root.addEventListener('focusout', (e) => { const el = markOf(e); if (el) { heat(el, false); hideTip(); } });
  window.addEventListener('hashchange', hideTip);
  // Scrolling moves the pointer off its mark, but focusing a mark by keyboard scrolls it into view:
  // that tooltip stays (it is placed in page coordinates, so it moves with the page).
  window.addEventListener('scroll', () => { if (!document.activeElement?.matches?.('.mark')) hideTip(); }, { passive: true });
}

// ---- filters in the address (UX-DESIGN-008 §1.2) ---------------------------------------------

/** Set (or, with '' / null, remove) query parameters of the current page without a new history
 *  entry and without re-routing, so Back returns to the chart the reader came from. */
export function setQuery(changes) {
  const [path, qs = ''] = (location.hash || '#/').split('?');
  const q = new URLSearchParams(qs);
  for (const [k, v] of Object.entries(changes)) {
    if (v === '' || v === null || v === undefined || v === false) q.delete(k);
    else q.set(k, String(v));
  }
  const s = q.toString();
  history.replaceState(history.state, '', `${path}${s ? `?${s}` : ''}`);
}

/** A removable chip that says why a list is filtered: "Purpose: Key exchange ×". */
export function filterChip(label, onClear) {
  return h('span', { class: 'fchip' }, h('span', null, label),
    h('button', { type: 'button', class: 'fchip-x', 'aria-label': `Remove the filter ${label}`, onclick: onClear }, '×'));
}

/** A row of chips, or nothing when no filter is set. */
export function filterChips(chips) {
  const list = chips.filter(Boolean);
  return list.length ? h('div', { class: 'fchips', role: 'group', 'aria-label': 'Filters from the address' }, list) : null;
}
