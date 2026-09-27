// Pieces shared by the estate views (Estate, System, Certificates, Review, Imports). Every string
// goes through h(), so text a hostile party controls (a certificate subject, an imported tool name,
// a system name) is only ever text.
import { h, fmtDay, fmtDate, daysUntil, relTime } from './dom.js';
import { badge, button, modal, citations } from './ui.js';

const ID_RE = /^[1-9][0-9]{0,15}$/;
const FP_RE = /^[0-9a-f]{64}$/i;

/** True when s can safely be placed in an address as a numeric id. */
export const validId = (s) => ID_RE.test(String(s));
/** True when s is a 64-digit SHA-256 fingerprint. */
export const validFingerprint = (s) => FP_RE.test(String(s));

export const systemHref = (id) => (validId(id) ? `#/systems/${id}` : '#/');
export const certHref = (fp) => (validFingerprint(fp) ? `#/certificates/${String(fp).toLowerCase()}` : '#/certificates');

/** The reasons behind a position: the rule, what it found, and where it is cited. */
export function reasonList(reasons) {
  return h('ol', { class: 'why-list' }, (reasons || []).map((r) => h('li', null,
    h('span', { class: 'why-rule' }, r.rule),
    h('span', { class: 'why-text' }, r.text),
    citations(r.citations))));
}

/** Strength is a word (never a score); the tone only reinforces it. */
export function strengthBadge(strength) {
  const tone = { strong: 'good', medium: 'warn', weak: 'neutral' }[strength] || 'neutral';
  return badge(strength || 'unknown', tone, 'How strongly the matching rules support this join');
}

export function stateBadge(state, stale) {
  const tone = { proposed: 'warn', confirmed: 'good', rejected: 'neutral' }[state] || 'neutral';
  return h('span', null, badge(state, tone), stale ? badge('evidence gone: review', 'bad', 'A confirmed join whose evidence is no longer observed') : null);
}

/** A source class as a person would say it. */
export const CLASS_LABEL = { scanner: 'scan', collector: 'collector', imported: 'imported', operator: 'entered by a person' };
export const classLabel = (c) => CLASS_LABEL[c] || c || '';

/** The wording for a private key at a place. The sensors read a property, never a key. */
export function keyAssociation(v) {
  switch (v) {
    case 'yes': return 'a private key is associated (never read)';
    case 'no': return 'no key associated in this store';
    default: return 'not checked';
  }
}

/** Days to expiry in words, so colour is never the only carrier. */
export function expiryText(c) {
  if (!c.notAfter) return 'no expiry recorded';
  const d = c.daysLeft !== null && c.daysLeft !== undefined ? c.daysLeft : daysUntil(c.notAfter);
  if (d < 0) return `expired ${-d} day${d === -1 ? '' : 's'} ago`;
  if (d === 0) return 'expires today';
  return `${d} day${d === 1 ? '' : 's'} left`;
}

export function expiryBadge(c) {
  if (!c.notAfter) return badge('no expiry', 'none');
  const d = c.daysLeft !== null && c.daysLeft !== undefined ? c.daysLeft : daysUntil(c.notAfter);
  const tone = d < 0 ? 'bad' : d <= 30 ? 'warn' : d <= 90 ? 'ok' : 'good';
  return badge(expiryText(c), tone, `Not after ${fmtDay(c.notAfter)}`);
}

export function keyText(c) {
  if (!c.keyAlgorithm && !c.keyBits) return 'unknown';
  const size = c.keyBits ? ` ${c.keyBits}-bit` : '';
  const curve = c.curve ? ` ${c.curve}` : '';
  return `${c.keyAlgorithm || 'key'}${size}${curve}`;
}

/** A certificate table. showSystem adds the count of systems that hold it. */
export function certTable(certs, { showPlaces = false } = {}) {
  const head = ['Certificate', 'Key', 'Signature', 'Expires', 'Findings'];
  if (showPlaces) head.push('Seen');
  return h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
    h('thead', null, h('tr', null, head.map((c) => h('th', { scope: 'col' }, c)))),
    h('tbody', null, certs.map((c) => h('tr', null,
      h('td', { class: 'namecell' }, h('a', { href: certHref(c.fingerprint) }, c.name || c.subject || c.fingerprint.slice(0, 16)),
        h('div', { class: 'muted small' }, c.subject && c.subject !== c.name ? c.subject : '')),
      h('td', null, keyText(c), c.keyBits ? null : h('div', { class: 'muted small' }, c.keyLengthNote || '')),
      h('td', null, c.signatureAlgorithm || h('span', { class: 'muted' }, 'unknown')),
      h('td', null, expiryBadge(c)),
      h('td', null, c.findings && c.findings.length
        ? c.findings.map((f) => h('div', null, badge(f.severity, f.severity === 'critical' || f.severity === 'high' ? 'bad' : 'warn'), ' ', f.title))
        : h('span', { class: 'muted' }, 'none')),
      showPlaces ? h('td', { class: 'muted' }, `${c.places} place${c.places === 1 ? '' : 's'}, ${c.systems} system${c.systems === 1 ? '' : 's'}`) : null)))));
}

/** One-line summary of the CA certificates on a system or in the estate. */
export function anchorLine(anchors) {
  if (!anchors) return null;
  const r = anchors.root || { count: 0 };
  const i = anchors.intermediate || { count: 0 };
  if (!r.count && !i.count) return null;
  const bits = [];
  if (r.count) bits.push(`${r.count} root${r.count === 1 ? '' : 's'}`);
  if (i.count) bits.push(`${i.count} intermediate${i.count === 1 ? '' : 's'}`);
  const problems = [];
  for (const [name, a] of [['root', r], ['intermediate', i]]) {
    if (a.expired) problems.push(`${a.expired} expired ${name}${a.expired === 1 ? '' : 's'}`);
    if (a.weakKey) problems.push(`${a.weakKey} with a weak key`);
  }
  return h('p', { class: 'hint' }, `Also ${bits.join(' and ')}, summarised rather than listed: a machine trusts hundreds and none is a finding on its own.`,
    problems.length ? ` Of these: ${problems.join(', ')}.` : '');
}

/** Asks for an optional reason. Resolves to the text ('' when left empty) or null when cancelled. */
export function reasonDialog(title, message, confirmLabel) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v, close) => { if (done) return; done = true; close(); resolve(v); };
    modal(title, (closeIt) => {
      const input = h('input', { type: 'text', id: 'reason-input', maxlength: '200', autocomplete: 'off' });
      return h('form', { class: 'modal-body', onsubmit: (e) => { e.preventDefault(); finish(input.value.trim(), closeIt); } },
        h('p', null, message),
        h('label', { for: 'reason-input' }, 'Reason (optional, kept in the audit trail)'), input,
        h('div', { class: 'row end' }, button('Cancel', () => finish(null, closeIt)),
          h('button', { type: 'submit', class: 'btn btn-primary' }, confirmLabel)));
    });
    // Closing the dialog any other way (Escape, the close button) is a cancel.
    const overlay = document.querySelector('#modal-root .overlay');
    if (overlay) new MutationObserver(() => { if (!document.body.contains(overlay)) finish(null, () => {}); }).observe(document.getElementById('modal-root'), { childList: true });
  });
}

export { fmtDate, relTime };
