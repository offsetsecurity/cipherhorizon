// Shared UI components. Everything is built through the safe DOM helper.
import { h, svg, clear, relTime, fmtDay, daysUntil } from './dom.js';
import { levelName, levelClass } from './charts.js';

// ---- small inline icons (no icon font/library: hand-rolled, stroke-based) -------------------

// Every icon carries its own width/height (SVG presentation attributes): an
// icon dropped into a new container must never rely on that container
// remembering to size it in CSS, or it renders at the browser's intrinsic
// (huge) default.
function iconCheck(size = 20) { return svg('svg', { viewBox: '0 0 20 20', width: size, height: size, fill: 'none', 'aria-hidden': 'true' }, svg('path', { d: 'M4 10.5l4 4 8-9', stroke: 'currentColor', 'stroke-width': '2', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' })); }
function iconWarn(size = 20) { return svg('svg', { viewBox: '0 0 20 20', width: size, height: size, fill: 'none', 'aria-hidden': 'true' }, svg('path', { d: 'M10 2.8l8.2 14.4H1.8L10 2.8z', stroke: 'currentColor', 'stroke-width': '1.7', 'stroke-linejoin': 'round' }), svg('path', { d: 'M10 8v4M10 14.2v.1', stroke: 'currentColor', 'stroke-width': '1.8', 'stroke-linecap': 'round' })); }
function iconX(size = 20) { return svg('svg', { viewBox: '0 0 20 20', width: size, height: size, fill: 'none', 'aria-hidden': 'true' }, svg('path', { d: 'M5 5l10 10M15 5L5 15', stroke: 'currentColor', 'stroke-width': '2', 'stroke-linecap': 'round' })); }
function iconShield() { return svg('svg', { viewBox: '0 0 24 24', width: 26, height: 26, fill: 'none', 'aria-hidden': 'true' }, svg('path', { d: 'M12 3l7.5 2.8v5.6c0 4.5-3.1 7.9-7.5 9.1-4.4-1.2-7.5-4.6-7.5-9.1V5.8L12 3z', stroke: 'currentColor', 'stroke-width': '1.6', 'stroke-linejoin': 'round' }), svg('path', { d: 'M8.6 12.2l2.3 2.3 4.5-4.7', stroke: 'currentColor', 'stroke-width': '1.7', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' })); }
function iconCopy() { return svg('svg', { viewBox: '0 0 20 20', width: 14, height: 14, fill: 'none', 'aria-hidden': 'true' }, svg('rect', { x: 7, y: 7, width: 9.5, height: 9.5, rx: 2, stroke: 'currentColor', 'stroke-width': '1.6' }), svg('path', { d: 'M13 7V5.5A1.5 1.5 0 0011.5 4h-6A1.5 1.5 0 004 5.5v6A1.5 1.5 0 005.5 13H7', stroke: 'currentColor', 'stroke-width': '1.6' })); }
function iconChevron() { return svg('svg', { class: 'certcard-chevron', viewBox: '0 0 20 20', fill: 'none', 'aria-hidden': 'true', width: '18', height: '18' }, svg('path', { d: 'M7 4l6 6-6 6', stroke: 'currentColor', 'stroke-width': '2', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' })); }

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

// ---- certificate chain ------------------------------------------------------------------------

function keyDescription(k) {
  if (!k) return 'unknown';
  return `${k.algorithm}${k.bits ? ` ${k.bits}-bit` : ''}${k.curve ? ` (${k.curve})` : ''}`;
}

/** Warnings computed only from fields already observed on this certificate —
 * nothing here is inferred beyond what the scan itself reported. */
function certWarnings(c, isLeafOfSelfSignedChain) {
  const out = [];
  const days = daysUntil(c.notAfter);
  if (days !== null && days < 0) out.push(`Expired ${-days} day(s) ago`);
  else if (days !== null && days <= 30) out.push(`Expires in ${days} day(s)`);
  if (/sha-?1|md5/i.test(c.signatureAlgorithm && c.signatureAlgorithm.name || '')) out.push('Weak signature algorithm (SHA-1/MD5 family)');
  const bits = c.publicKey && c.publicKey.bits;
  if (bits && c.publicKey.algorithm === 'RSA' && bits < 2048) out.push(`Weak key: RSA ${bits}-bit (below 2048)`);
  if (bits && c.publicKey.algorithm === 'ECDSA' && bits < 224) out.push(`Weak key: ECDSA ${bits}-bit (below 224)`);
  if (isLeafOfSelfSignedChain) out.push('Self-signed: no issuing chain was presented');
  return out;
}

function certRole(i, chain) {
  if (i === 0) return 'Leaf certificate';
  if (i === chain.length - 1) return chain[i].selfSigned ? 'Root CA' : 'Intermediate CA (chain incomplete)';
  return 'Intermediate CA';
}

function certCard(c, role, idx, opts) {
  const warnings = certWarnings(c, idx === 0 && chainLenOf(opts) === 1 && c.selfSigned);
  const status = warnings.length ? 'warn' : 'trusted';
  const detail = h('div', { class: 'certcard-detail', hidden: true, onclick: (e) => e.stopPropagation() });
  const field = (label, value) => h('div', { class: 'certfield' }, h('dt', null, label), h('dd', null, value || '–'));
  const fieldCopy = (label, value) => h('div', { class: 'certfield' }, h('dt', null, label), h('dd', { class: 'copyable' }, value || '–', value ? copyButton(value, label.toLowerCase()) : null));
  const fieldProse = (label, value) => h('div', { class: 'certfield' }, h('dt', null, label), h('dd', { class: 'prose' }, value || '–'));
  detail.append(...[
    fieldProse('Subject', c.subject),
    fieldProse('Issuer', c.issuer),
    field('Public key', keyDescription(c.publicKey)),
    field('Key OID', c.publicKey && c.publicKey.oid),
    field('Signature algorithm', c.signatureAlgorithm && c.signatureAlgorithm.name),
    field('Signature OID', c.signatureAlgorithm && c.signatureAlgorithm.oid),
    fieldCopy('Serial number', c.serial),
    field('Valid from', fmtDay(c.notBefore)),
    field('Valid until', `${fmtDay(c.notAfter)}`),
    field('Certificate type', c.isCa ? 'CA (can sign other certificates)' : 'End-entity (leaf)'),
    fieldCopy('SHA-256 fingerprint', c.sha256),
    fieldProse('Subject alternative names', [...(c.dnsNames || []), ...(c.ipAddresses || [])].join(', ') || 'none'),
    c.ocspMustStaple ? field('OCSP must-staple', 'yes') : null,
    c.embeddedScts ? field('Certificate Transparency (SCT)', 'embedded') : null,
  ].filter(Boolean));
  if (warnings.length) {
    detail.appendChild(h('div', { class: 'certwarn' }, iconWarn(), h('div', null, warnings.map((w) => h('div', null, w)))));
  }

  const cardEl = h('div', { class: `certcard ${status === 'warn' ? 'warn' : 'trusted'}`, tabindex: '0', role: 'button', 'aria-expanded': 'false',
    onclick: () => toggleCard(), onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleCard(); } } },
    h('div', { class: 'certcard-head' },
      h('div', null,
        h('div', { class: 'certcard-role' }, role),
        h('div', { class: 'certcard-cn' }, shortSubject(c.subject)),
        h('div', { class: 'certcard-meta' },
          warnings.length ? badge(`${warnings.length} warning${warnings.length > 1 ? 's' : ''}`, 'warn') : badge('no issues observed', 'good'),
          badge(keyDescription(c.publicKey), 'neutral'),
          certExpiry(c.notAfter))),
      iconChevron()),
    detail);

  function toggleCard() {
    const open = detail.hidden;
    detail.hidden = !open;
    cardEl.setAttribute('aria-expanded', String(open));
  }
  return cardEl;
}

function chainLenOf(opts) { return opts && opts.chainLen; }

function shortSubject(subject) {
  if (!subject) return 'Unknown subject';
  const m = /CN=([^,]+)/.exec(subject);
  return m ? m[1] : subject;
}

/** The full certificate chain for one handshake result, drawn leaf-to-root
 * with a connector between each certificate, each one expandable in place. */
export function certChain(c, opts = {}) {
  const chain = c.chain || [];
  const summary = h('div', { class: 'row mt-sm' },
    c.trusted ? badge('chain trusted', 'good') : badge('not trusted', 'bad'),
    c.nameMatches ? badge(`matches ${opts.host || 'the requested host'}`, 'good') : badge('name does not match', 'bad'),
    h('span', { class: 'muted' }, `via ${c.source}`));
  const rail = h('div', { class: 'certchain' },
    ...chain.map((cert, i) => {
      const role = certRole(i, chain);
      const card = certCard(cert, role, i, { chainLen: chain.length });
      const isLast = i === chain.length - 1;
      const nodeStatus = certWarnings(cert, i === 0 && chain.length === 1 && cert.selfSigned).length ? 'warn' : 'trusted';
      return h('div', { class: 'certnode' },
        h('div', { class: 'certnode-rail' },
          h('div', { class: `certnode-dot ${nodeStatus}` }, nodeStatus === 'warn' ? iconWarn() : iconCheck()),
          isLast ? null : h('div', { class: 'certnode-line' })),
        card);
    }));
  const issues = [];
  if (!c.trusted && chain.length === 1 && !chain[0].selfSigned) issues.push('Only one certificate was presented and it is not self-signed — an intermediate certificate may be missing.');
  if (c.trustError) issues.push(c.trustError);
  return h('div', { class: 'mt' }, summary, rail,
    issues.length ? h('div', { class: 'certwarn mt-sm' }, iconWarn(), h('div', null, issues.map((w) => h('div', null, w)))) : null);
}

export function progressBar(pct) {
  const fill = h('span', { class: 'progress-fill' });
  fill.style.width = `${Math.max(0, Math.min(100, pct))}%`;
  return h('span', { class: 'progress', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(pct) }, fill);
}

/** A placeholder shown while a page's first data fetch is still in flight,
 * so a slow load reads as "working" rather than "broken". Callers clear() the
 * container before rendering real content, same as any other paint. */
export function skeleton(lines = 3) {
  return h('div', { class: 'card', 'aria-hidden': 'true' },
    Array.from({ length: lines }, () => h('div', { class: 'skeleton line' })));
}

export function empty(title, text, ...actions) {
  return h('div', { class: 'empty' }, h('div', { class: 'empty-icon', 'aria-hidden': 'true' }, iconShield()), h('h3', null, title), text ? h('p', null, text) : null, actions.length ? h('div', { class: 'row' }, actions) : null);
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
  setTimeout(() => { el.classList.add('leaving'); setTimeout(() => el.remove(), 220); }, kind === 'error' ? 8000 : 4000);
}

// ---- modal ------------------------------------------------------------------------------------

/** Opens a dialog. build(close) returns the body; resolves when closed. */
export function modal(title, build, { wide = false } = {}) {
  const root = document.getElementById('modal-root');
  const previous = document.activeElement;
  const overlay = h('div', { class: 'overlay' });
  const box = h('div', { class: `modal${wide ? ' wide' : ''}`, role: 'dialog', 'aria-modal': 'true', 'aria-label': title });
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    document.removeEventListener('keydown', onKey);
    overlay.classList.add('closing'); // fades out (CSS), and stops taking clicks straight away
    setTimeout(() => overlay.remove(), 160);
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


// ---- motion -----------------------------------------------------------------------------------
// Entrance animation is opt-in and one-shot: a page (or a tab's content) gets the
// `enter` class for a moment, and CSS staggers whatever is inside it. Views that
// repaint on a timer must NOT replay it, so it is applied by the router once per
// navigation and removed again, never by the repaint itself.

const STAGGER = '.grid, .stack, .findings, .priority-list, .cbomtree, .certchain';

export function playEnter(root, ms = 900) {
  if (!root) return;
  const index = (list) => [...list].forEach((el, i) => el.style.setProperty('--i', String(Math.min(i, 9))));
  index(root.children);
  for (const group of root.querySelectorAll(STAGGER)) index(group.children);
  for (const body of root.querySelectorAll('tbody')) index(body.children);
  root.classList.remove('enter');
  void root.offsetWidth; // restart the animation if it is already running
  root.classList.add('enter');
  clearTimeout(root._enterTimer);
  root._enterTimer = setTimeout(() => root.classList.remove('enter'), ms);
}

// A KPI number counts up (or down) to its value once, and again only when the value
// actually changes; a repaint with the same value leaves it alone.
const shownNumbers = new Map();
const reducedMotion = () => window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

export function countUp(el, key, value) {
  const text = String(value);
  const prev = shownNumbers.get(key);
  shownNumbers.set(key, text);
  const parts = (t) => { const m = /^(\d+)(?: \/ (\d+))?$/.exec(t); return m ? [Number(m[1]), m[2] === undefined ? null : Number(m[2])] : null; };
  const to = parts(text);
  if (!to || prev === text || reducedMotion()) return;
  const from = (prev && parts(prev)) || [0, to[1] === null ? null : 0];
  const start = performance.now(), dur = 650;
  const fmt = (a, b) => (b === null ? `${a}` : `${a} / ${b}`);
  el.textContent = fmt(from[0], from[1]);
  const tick = (now) => {
    const t = Math.min(1, (now - start) / dur), e = 1 - Math.pow(1 - t, 3);
    el.textContent = fmt(Math.round(from[0] + (to[0] - from[0]) * e), to[1] === null ? null : Math.round(from[1] + (to[1] - from[1]) * e));
    if (t < 1 && el.isConnected !== false) requestAnimationFrame(tick); else el.textContent = text;
  };
  requestAnimationFrame(tick);
}

/** A small "copy" control that confirms in place. */
export function copyButton(value, label) {
  const btn = h('button', { type: 'button', class: 'copybtn', 'aria-label': `Copy ${label}`, title: `Copy ${label}` }, iconCopy());
  btn.addEventListener('click', async (e) => {
    e.stopPropagation();
    try { await navigator.clipboard.writeText(value); } catch { return; }
    btn.classList.add('done');
    btn.replaceChildren(iconCheck(14));
    setTimeout(() => { btn.classList.remove('done'); btn.replaceChildren(iconCopy()); }, 1400);
  });
  return btn;
}
