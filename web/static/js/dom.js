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

/** Only same-page routes, in-page anchors (an element id) and https links may become hrefs. */
export function safeHref(u) {
  const s = String(u);
  if (s.startsWith('#/') || s.startsWith('https://') || /^#[A-Za-z][\w.-]*$/.test(s)) return s;
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

/** STARTTLS protocols the scanner speaks, as people name them (PRD-007 REQ-SX). */
export const STARTTLS_NAMES = { smtp: 'SMTP', imap: 'IMAP', pop3: 'POP3', ftp: 'FTP', xmpp: 'XMPP', ldap: 'LDAP', postgres: 'PostgreSQL' };

/** How an endpoint is reached: "via STARTTLS (SMTP)", or '' for direct TLS. */
export function viaStartTLS(a) {
  const used = a && (a.starttlsUsed || (a.target && a.target.starttls));
  return used ? `via STARTTLS (${STARTTLS_NAMES[used] || used})` : '';
}

/** Who started a scan, in words: a person's name, the automation token or the schedule. */
export function startedByWord(s) {
  if (s.startedBy === 'schedule' || (!s.startedBy && s.trigger === 'scheduled')) return 'Schedule';
  if (s.startedBy === 'api-token') return 'Automation token';
  if (s.startedBy === 'local') return 'Anyone (sign-in off)';
  return s.startedBy || 'Not recorded';
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

/** The CipherHorizon icon (DESIGN.md §1): a white padlock on a rounded square. Flat: one colour per
 * shape, no gradient, stroke or glow. tone 'color' (Offset blue) or 'mono' (navy). */
export function brandMark(tone = 'color') {
  const tile = tone === 'mono' ? '#0B1428' : '#2457D6';
  return svg('svg', { viewBox: '0 0 32 32', role: 'img', 'aria-label': 'CipherHorizon' },
    svg('rect', { width: '32', height: '32', rx: '7', fill: tile }),
    svg('path', { d: 'M10.75 15V11.75a5.25 5.25 0 0 1 10.5 0V15h-2.9v-3.25a2.35 2.35 0 0 0-4.7 0V15Z', fill: '#FFFFFF' }),
    svg('rect', { x: '8.5', y: '14.5', width: '15', height: '11', rx: '2.2', fill: '#FFFFFF' }),
    svg('path', { d: 'M16 17.4a1.7 1.7 0 0 1 .85 3.17V22.6h-1.7v-2.03A1.7 1.7 0 0 1 16 17.4Z', fill: tile }));
}
