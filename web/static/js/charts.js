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
    if (points.length <= 16 || i % 2 === 0) {
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

/** A step line of one asset's readiness level over time, with TLS hygiene score labels. */
export function historyChart(points, width = 640, height = 170) {
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
  pts.forEach((p) => {
    root.appendChild(svg('circle', { cx: x(p.at), cy: y(p.readinessLevel), r: 5, class: `dot ${levelClass(p.readinessLevel)}` },
      svg('title', null, `${new Date(p.at).toLocaleString()}: L${p.readinessLevel} ${levelName(p.readinessLevel)}, TLS hygiene ${p.band} ${p.score}`)));
    root.appendChild(svg('text', { x: x(p.at), y: y(p.readinessLevel) - 9, class: 'dotlabel', 'text-anchor': 'middle' }, String(p.score)));
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
