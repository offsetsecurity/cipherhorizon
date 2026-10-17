// Certificates: every end-entity certificate the estate knows, with its key size, and a summary of
// the CA certificates (PRD-003 REQ-UI-4). Filters are applied here, on data already loaded.
import { h, clear, fmtDate } from '../dom.js';
import { api } from '../api.js';
import { badge, button, skeleton, empty, crossFade } from '../ui.js';
import { setQuery } from '../charts.js';
import { certTable, anchorLine, classLabel } from '../estate-ui.js';

// The Inventory dashboard's expiry buckets open this list with ?expires=…; 31-90 and later are its
// "Within 90 days" and "Later" segments, with the same boundaries (PRD-009 REQ-CHT-2).
const WINDOWS = [['any', 'Any expiry'], ['expired', 'Expired'], ['30', 'Within 30 days'], ['90', 'Within 90 days'],
  ['31-90', 'In 31 to 90 days'], ['later', 'In more than 90 days']];
const PAGE = 500; // rows drawn at once: a whole estate is 50,000 certificates and a browser should not be asked to draw them all
const QUANTUM_VULNERABLE = ['RSA', 'ECDSA', 'EC', 'DSA', 'ED25519', 'ED448'];

function matches(c, f) {
  const d = c.daysLeft;
  if (f.window === 'expired' && !(d !== null && d < 0)) return false;
  if ((f.window === '30' || f.window === '90') && !(d !== null && d >= 0 && d <= Number(f.window))) return false;
  if (f.window === '31-90' && !(d !== null && d > 30 && d <= 90)) return false;
  if (f.window === 'later' && !(d !== null && d > 90)) return false;
  if (f.key === 'weak' && !(c.keyAlgorithm && c.keyAlgorithm.toUpperCase() === 'RSA' && c.keyBits && c.keyBits < 2048)) return false;
  if (f.key === 'unknown' && c.keyBits) return false;
  if (f.key === 'quantum' && !QUANTUM_VULNERABLE.includes((c.keyAlgorithm || '').toUpperCase())) return false;
  if (f.sig && c.signatureAlgorithm !== f.sig) return false;
  if (f.origin && !(c.origins || []).includes(f.origin)) return false;
  if (f.text) {
    const t = f.text.toLowerCase();
    if (!`${c.name} ${c.subject} ${c.dnsNames || ''} ${c.fingerprint}`.toLowerCase().includes(t)) return false;
  }
  return true;
}

export async function render(root, ctx = {}) {
  root.appendChild(skeleton(4));
  const data = await api.certificates();
  clear(root);
  root.appendChild(h('div', { class: 'page-head' },
    ctx.embedded ? h('div') : h('div', null, h('h1', null, 'Certificates'),
      h('div', { class: 'sub' }, 'Every certificate seen by a scan, a collector or an import: its key, when it expires, and where it is'))));

  const certs = data.certificates;
  const changes = data.rootSetChanges || [];
  if (!certs.length && !(data.trustAnchors.root.count || data.trustAnchors.intermediate.count)) {
    root.appendChild(empty('No certificates yet', 'Scan a service or inventory a machine and its certificates appear here, with their key sizes. Only public certificate details are read; private keys are never opened.'));
    return null;
  }

  // The filters start from the address and are written back to it (UX-DESIGN-008 §1.2).
  const query = ctx.query || new URLSearchParams();
  const pick = (v, allowed) => (allowed.includes(v) ? v : '');
  const sigs = [...new Set(certs.map((c) => c.signatureAlgorithm).filter(Boolean))].sort();
  const origins = [...new Set(certs.flatMap((c) => c.origins || []))].sort();
  const f = {
    window: pick(query.get('expires'), WINDOWS.map(([v]) => v)) || 'any',
    key: pick(query.get('key'), ['weak', 'unknown', 'quantum']),
    sig: pick(query.get('sig'), sigs), origin: pick(query.get('origin'), origins), text: query.get('q') || '',
  };
  let limit = PAGE;
  const out = h('div');
  const count = h('p', { class: 'hint', role: 'status' });
  const draw = () => {
    setQuery({ expires: f.window === 'any' ? '' : f.window, key: f.key, sig: f.sig, origin: f.origin, q: f.text });
    clear(out);
    const shown = certs.filter((c) => matches(c, f));
    count.textContent = `${shown.length} of ${certs.length} certificate${certs.length === 1 ? '' : 's'}${shown.length > limit ? `; the first ${limit} are drawn, worst first` : ''}`;
    out.appendChild(shown.length ? certTable(shown.slice(0, limit), { showPlaces: true })
      : empty('No certificate matches', 'Loosen a filter to see more.'));
    if (shown.length > limit) out.appendChild(button(`Show all ${shown.length}`, () => { limit = shown.length; draw(); }));
  };
  const sel = (id, label, options, key) => h('div', null,
    h('label', { for: id }, label),
    h('select', { id, onchange: (e) => { f[key] = e.target.value; limit = PAGE; crossFade(out, draw); } },
      options.map(([v, l]) => h('option', { value: v, selected: v === f[key] }, l))));
  root.appendChild(h('div', { class: 'toolbar' },
    h('div', { class: 'grow' }, h('label', { for: 'cert-q' }, 'Search'),
      h('input', { type: 'search', id: 'cert-q', placeholder: 'Name, subject or fingerprint', value: f.text, oninput: (e) => { f.text = e.target.value.trim(); limit = PAGE; draw(); } })),
    sel('cert-window', 'Expires', WINDOWS, 'window'),
    sel('cert-key', 'Key', [['', 'Any key'], ['weak', 'RSA under 2048 bits'], ['unknown', 'Size not recorded'], ['quantum', 'Quantum-vulnerable algorithm']], 'key'),
    sel('cert-sig', 'Signature', [['', 'Any signature'], ...sigs.map((s) => [s, s])], 'sig'),
    sel('cert-origin', 'Origin', [['', 'Any origin'], ...origins.map((o) => [o, classLabel(o)])], 'origin')));
  root.appendChild(count);
  root.appendChild(out);
  draw();

  root.appendChild(h('section', { class: 'card mt' }, h('h2', null, 'Trust anchors'),
    anchorLine(data.trustAnchors) || h('p', { class: 'hint' }, 'No root or intermediate certificates recorded.')));

  if (changes.length) {
    root.appendChild(h('section', { class: 'card mt' }, h('h2', null, 'Changes to a machine’s trusted roots'),
      h('p', { class: 'hint' }, 'Between the last two uploads from the same machine. A root added outside your usual process is worth asking about.'),
      changes.map((c) => h('div', { class: 'change' },
        h('b', null, c.assetName), ` (${fmtDate(c.previous)} → ${fmtDate(c.latest)})`,
        c.addedNames && c.addedNames.length ? h('div', null, badge(`${c.addedNames.length} added`, 'warn'), ' ', c.addedNames.slice(0, 20).join('; ')) : null,
        c.removedNames && c.removedNames.length ? h('div', null, badge(`${c.removedNames.length} removed`, 'neutral'), ' ', c.removedNames.slice(0, 20).join('; ')) : null))));
  }
  return null;
}
