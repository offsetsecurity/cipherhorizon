// Shared UI components. Everything is built through the safe DOM helper.
import { h, clear, relTime, daysUntil } from './dom.js';
import { levelName, levelClass } from './charts.js';

// ---- badges ---------------------------------------------------------------------------------

export function badge(text, kind = 'neutral', title) {
  return h('span', { class: `badge b-${kind}`, title }, text);
}

/** Readiness: colour + level code + name, never colour alone. */
export function levelBadge(level, withName = true) {
  if (level === null || level === undefined) return badge('Not scanned', 'none');
  const code = level < 0 ? '?' : `L${level}`;
  return h('span', { class: `badge lvbadge ${levelClass(level)}`, title: `PQC readiness: ${levelName(level)}` },
    h('b', null, code), withName ? ` ${levelName(level)}` : '');
}

// TLS hygiene: this product's own 0-100 score of how well an endpoint is configured, shown as a
// band word (never colour alone) and the number.
export const BAND_ORDER = ['Strong', 'Sound', 'Fair', 'Weak', 'Broken', 'Not rated'];
const BAND_TONE = { Strong: 'good', Sound: 'ok', Fair: 'warn', Weak: 'bad', Broken: 'bad', 'Not rated': 'neutral' };
export const bandTone = (band) => BAND_TONE[band] || 'neutral';

export function bandBadge(band, score) {
  if (!band) return badge('–', 'none');
  const rated = typeof score === 'number' && score >= 0;
  return h('span', { class: `badge band tone-${bandTone(band)}`, title: `TLS hygiene: ${band}${rated ? `, ${score} out of 100` : ''}` },
    band, rated ? h('span', { class: 'band-n' }, ` ${score}`) : null);
}

export function sevBadge(sev) {
  const icon = { critical: '⛔', high: '▲', medium: '◆', low: '●', info: 'i' }[sev] || '';
  return h('span', { class: `badge sev s-${sev}` }, h('span', { 'aria-hidden': 'true' }, icon + ' '), sev);
}

export function evidenceBadge(ev) {
  const tips = {
    observed: 'A server reply demonstrated this',
    inferred: 'A consequence of what was observed; not tested directly',
    registry: 'Stated by an authoritative registry',
    'not-measured': 'This product does not measure it',
  };
  return h('span', { class: `badge ev e-${ev}`, title: tips[ev] || '' }, ev);
}

export function statusPill(status) {
  const label = { queued: 'Queued', running: 'Running', done: 'Done', failed: 'Failed', canceled: 'Canceled' }[status] || status;
  return h('span', { class: `pill st-${status}` }, label);
}

export function citations(list) {
  if (!list || !list.length) return null;
  return h('ul', { class: 'cites' }, list.map((c) => h('li', null,
    h('a', { href: c.url, target: '_blank', rel: 'noopener noreferrer' }, c.title))));
}

export function certExpiry(iso) {
  const d = daysUntil(iso);
  if (d === null) return h('span', { class: 'muted' }, '–');
  if (d < 0) return badge(`expired ${-d} d ago`, 'bad');
  if (d <= 30) return badge(`${d} d left`, 'warn');
  return h('span', { class: 'muted' }, `${d} d`);
}

export function progressBar(pct) {
  const fill = h('span', { class: 'progress-fill' });
  fill.style.width = `${Math.max(0, Math.min(100, pct))}%`;
  return h('span', { class: 'progress', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(pct) }, fill);
}

export function empty(title, text, ...actions) {
  return h('div', { class: 'empty' }, h('h3', null, title), text ? h('p', null, text) : null, actions.length ? h('div', { class: 'row' }, actions) : null);
}

export function button(label, onclick, kind = 'secondary', extra = {}) {
  return h('button', { type: 'button', class: `btn btn-${kind}`, onclick, ...extra }, label);
}

// ---- toasts ---------------------------------------------------------------------------------

let toastRoot = null;
export function toast(message, kind = 'info') {
  if (!toastRoot) toastRoot = document.getElementById('toasts');
  const el = h('div', { class: `toast t-${kind}`, role: kind === 'error' ? 'alert' : 'status' }, message);
  toastRoot.appendChild(el);
  setTimeout(() => el.remove(), kind === 'error' ? 8000 : 4000);
}

// ---- modal ------------------------------------------------------------------------------------

/** Opens a dialog. build(close) returns the body; resolves when closed. */
export function modal(title, build, { wide = false } = {}) {
  const root = document.getElementById('modal-root');
  const previous = document.activeElement;
  const overlay = h('div', { class: 'overlay' });
  const box = h('div', { class: `modal${wide ? ' wide' : ''}`, role: 'dialog', 'aria-modal': 'true', 'aria-label': title });
  const close = () => {
    overlay.remove();
    document.removeEventListener('keydown', onKey);
    if (previous && previous.focus) previous.focus();
  };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  box.appendChild(h('div', { class: 'modal-head' }, h('h2', null, title),
    h('button', { type: 'button', class: 'icon-btn', 'aria-label': 'Close', onclick: close }, '×')));
  box.appendChild(build(close));
  overlay.appendChild(box);
  overlay.addEventListener('mousedown', (e) => { if (e.target === overlay) close(); });
  document.addEventListener('keydown', onKey);
  clear(root).appendChild(overlay);
  const first = box.querySelector('input, textarea, select, button.btn-primary');
  if (first) first.focus();
  return close;
}

export function confirmDialog(title, message, confirmLabel = 'Delete') {
  return new Promise((resolve) => {
    modal(title, (close) => h('div', { class: 'modal-body' }, h('p', null, message),
      h('div', { class: 'row end' },
        button('Cancel', () => { close(); resolve(false); }),
        button(confirmLabel, () => { close(); resolve(true); }, 'danger'))));
  });
}

// ---- scan progress tracker -------------------------------------------------------------------

export const STEPS = [
  ['protocols', 'Protocol versions'],
  ['suites', 'Cipher suites'],
  ['keyexchange', 'Key exchange'],
  ['certificates', 'Certificates'],
  ['evaluating', 'Evaluating'],
];

/** The live progress panel for a queued or running scan (AC-02.2). */
export function scanProgress(scan, events, onCancel) {
  const idx = STEPS.findIndex(([k]) => k === scan.stage);
  const steps = h('ol', { class: 'steps' }, STEPS.map(([key, label], i) => {
    let state = 'todo';
    if (scan.status === 'queued') state = 'todo';
    else if (i < idx || scan.status === 'done') state = 'done';
    else if (i === idx) state = 'active';
    return h('li', { class: `step ${state}` }, h('span', { class: 'step-dot', 'aria-hidden': 'true' }, state === 'done' ? '✓' : String(i + 1)),
      h('span', null, label), state === 'active' ? h('span', { class: 'sr-only' }, ' (in progress)') : null);
  }));
  const log = h('ul', { class: 'log', 'aria-label': 'Scan log' }, events.slice(-8).map((e) =>
    h('li', null, h('time', null, new Date(e.at).toLocaleTimeString()), ' ', e.message)));
  return h('section', { class: 'card scanpanel', 'aria-live': 'polite' },
    h('div', { class: 'scanpanel-head' },
      h('h3', null, scan.status === 'queued' ? 'Waiting in the queue…' : 'Scanning…'),
      onCancel ? button('Cancel scan', onCancel, 'secondary') : null),
    progressBar(scan.progressPct),
    h('div', { class: 'scanpanel-meta' },
      h('span', null, `${scan.progressPct}%`),
      h('span', null, `${scan.connections} connections`),
      h('span', { class: 'muted' }, scan.status === 'queued' ? 'queued' : `started ${relTime(scan.startedAt)}`)),
    steps, log);
}
