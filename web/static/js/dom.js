// A tiny, safe DOM builder. Every string is set through textContent or a
// property, never through innerHTML, so data that came from a scanned server
// (certificate subjects, suite names, asset names) can never be interpreted as
// markup or script (PRD AC-11.6).

const SVG_NS = 'http://www.w3.org/2000/svg';

/** h('div', {class: 'x', onclick: fn}, 'text', childNode, [more]) */
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  apply(el, attrs);
  append(el, children);
  return el;
}

/** svg('rect', {x: 0, width: 10}) */
export function svg(tag, attrs, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  apply(el, attrs);
  append(el, children);
  return el;
}

function apply(el, attrs) {
  if (!attrs) return;
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.setAttribute('class', v);
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'text') el.textContent = String(v);
    else if (k === 'value' || k === 'checked' || k === 'disabled' || k === 'selected') el[k] = v;
    else if (k === 'href') el.setAttribute('href', safeHref(v));
    else el.setAttribute(k, v === true ? '' : String(v));
  }
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

/** Only same-page routes and https links may become hrefs. */
export function safeHref(u) {
  const s = String(u);
  if (s.startsWith('#/') || s.startsWith('https://')) return s;
  return '#/';
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

// ---- formatting ---------------------------------------------------------------------------

export function relTime(iso) {
  if (!iso) return '';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '';
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 5) return 'just now';
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  if (s < 86400 * 30) return `${Math.round(s / 86400)} d ago`;
  return new Date(iso).toLocaleDateString();
}

export function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
}

export function fmtDay(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleDateString(undefined, { dateStyle: 'medium' });
}

export function daysUntil(iso) {
  if (!iso) return null;
  return Math.floor((new Date(iso).getTime() - Date.now()) / 86400000);
}

export function duration(startIso, endIso) {
  if (!startIso) return '';
  const end = endIso ? new Date(endIso).getTime() : Date.now();
  const s = Math.max(0, Math.round((end - new Date(startIso).getTime()) / 1000));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
}

export const INTERVALS = [
  [0, 'Off'], [3600, 'Every hour'], [21600, 'Every 6 hours'], [86400, 'Every day'], [604800, 'Every week'],
];

/** Builds a CSV string from rows of plain values, quoting as needed and
 * defusing formula injection (a leading =+-@ or tab/CR gets a leading quote)
 * — the same rule the server's own CSV export uses, since these cells can
 * hold attacker-influenced text from a scanned server (a certificate subject,
 * a finding detail). */
export function toCSV(headers, rows) {
  const safe = (v) => {
    let s = v === null || v === undefined ? '' : String(v);
    if (s !== '' && /^[=+\-@\t\r]/.test(s)) s = `'${s}`;
    if (/[",\n\r]/.test(s)) s = `"${s.replace(/"/g, '""')}"`;
    return s;
  };
  const lines = [headers.map(safe).join(',')];
  for (const row of rows) lines.push(row.map(safe).join(','));
  return lines.join('\r\n');
}

export function intervalLabel(sec) {
  const f = INTERVALS.find(([s]) => s === sec);
  return f ? f[1] : `${sec}s`;
}

/** "4.2 MB" from a byte count. */
export function fmtBytes(n) {
  if (!Number.isFinite(n) || n < 0) return '';
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

/** "Linux" from "linux", "macOS" from "darwin". */
const OS_LABEL = { linux: 'Linux', darwin: 'macOS', windows: 'Windows' };
export function osPlatformLabel(goos) { return OS_LABEL[goos] || goos; }

/** The CipherHorizon mark: a gradient shield (the "horizon", violet into amber) with a keyhole cut
 * from it (the "cipher") and a thin facet line catching the light. idSuffix keeps its <defs> ids
 * unique when more than one copy is on the page at once (the static sidebar mark in index.html is
 * always present); border picks a stroke that reads on the background this copy sits on. */
export function brandMark(idSuffix, border = 'rgba(255,255,255,.16)') {
  const grad = `chGrad${idSuffix}`;
  const cut = `chCut${idSuffix}`;
  return svg('svg', { viewBox: '0 0 32 32', fill: 'none' },
    svg('defs', null,
      svg('linearGradient', { id: grad, x1: '16', y1: '1', x2: '16', y2: '31', gradientUnits: 'userSpaceOnUse' },
        svg('stop', { offset: '0', 'stop-color': '#9C7CFF' }),
        svg('stop', { offset: '.55', 'stop-color': '#7048E8' }),
        svg('stop', { offset: '1', 'stop-color': '#F2A33F' })),
      svg('mask', { id: cut, maskUnits: 'userSpaceOnUse', x: '0', y: '0', width: '32', height: '32' },
        svg('rect', { width: '32', height: '32', fill: '#fff' }),
        svg('circle', { cx: '16', cy: '13.4', r: '3', fill: '#000' }),
        svg('path', { d: 'M14.3 15.3H17.7L16.7 20.4H15.3Z', fill: '#000' }))),
    svg('path', { d: 'M16 1.4 L28.6 8.2 V23.6 L16 30.6 L3.4 23.6 V8.2 Z', fill: `url(#${grad})`, mask: `url(#${cut})` }),
    svg('path', { d: 'M16 1.4 L28.6 8.2 V23.6 L16 30.6 L3.4 23.6 V8.2 Z', fill: 'none', stroke: border, 'stroke-width': '.6' }),
    svg('path', { d: 'M4.6 9.2 L16 15.2 L27.4 9.2', stroke: 'rgba(255,255,255,.4)', 'stroke-width': '.55', fill: 'none' }));
}
