// Inventory: every algorithm, key, certificate and protocol your scans, your machines and the
// CBOMs you import have seen. The landing page is a dashboard of what matters (how much is
// quantum-vulnerable, what to replace first, what expires); each figure opens its list, one
// click deeper. The lists and the downloads read the same merged CBOM (PRD-005 REQ-INV).
import { h, svg, clear, relTime, fmtDate } from '../dom.js';
import { api } from '../api.js';
import { badge, button, empty, modal, toast, skeleton, crumbs, crossFade, countUp } from '../ui.js';
import { collectSteps } from '../guide.js';
import { mark, setQuery, filterChip, filterChips } from '../charts.js';

const LISTS = [
  ['algorithms', 'Algorithms', 'algorithm', 'Every algorithm in use, with its post-quantum status and where it is used'],
  ['keys', 'Keys', 'key', 'Public keys seen in certificates and machine inventories'],
  ['certificates', 'Certificates', null, 'Every end-entity certificate, worst first'],
  ['protocols', 'Protocols', 'protocol', 'The SSL and TLS versions your endpoints accept'],
  ['software', 'Software', 'software', 'Cryptographic libraries and applications found on your machines'],
  ['sources', 'Sources', null, 'The endpoint scans, machine inventories and imported CBOMs the inventory is made of'],
];

// CycloneDX names an algorithm's primitive with a code; people read words.
const PRIMITIVE = {
  ae: 'authenticated encryption', 'block-cipher': 'block cipher', 'stream-cipher': 'stream cipher', pke: 'public-key encryption',
  signature: 'signature', 'key-agree': 'key agreement', kem: 'key encapsulation', hash: 'hash', mac: 'message authentication',
  combiner: 'hybrid key exchange', drbg: 'random generator', xof: 'extendable output', kdf: 'key derivation',
  'public-key': 'public key', 'private-key': 'private key', 'secret-key': 'secret key', tls: 'TLS',
};
const humanDetail = (d) => (d || '').split(' · ').map((p) => PRIMITIVE[p] || p).join(' · ');

const QUANTUM = {
  'quantum-vulnerable': ['✖ quantum-vulnerable', 'bad'],
  'quantum-safe': ['✔ quantum-safe', 'good'],
  unknown: ['? not classified', 'neutral'],
  'not-applicable': ['·', 'none'],
};
// The classical strength of an algorithm or key (PRD-010): bits from NIST's methods, or broken with
// its cited reason, or why it is not rated. The source is in the tooltip.
function strengthCell(st) {
  if (!st) return h('span', { class: 'muted' }, '·');
  if (st.status === 'broken') return badge('✖ broken', 'bad', st.basis);
  if (st.status === 'disallowed') return h('span', { title: st.basis }, `${st.bits} bits `, badge('disallowed', 'warn', st.basis));
  if (st.status === 'rated') return h('span', { class: st.bits < 112 ? 'text-bad' : '', title: st.basis }, `${st.bits} bits`);
  return h('span', { class: 'muted', title: st.basis }, 'not rated');
}
const quantumBadge = (q) => { const [t, k] = QUANTUM[q] || [q, 'neutral']; return k === 'none' ? h('span', { class: 'muted' }, t) : badge(t, k); };
// Certificates and their keys are named by their subject; people know them by the common name.
const cnOf = (dn) => { const m = /CN=([^,]+)/.exec(dn || ''); return m ? m[1] : dn; };
const shownName = (name) => (/ public key$/.test(name) ? cnOf(name.replace(/ public key$/, '')) : name);
const plural = (n, one, many) => `${n} ${n === 1 ? one : many || `${one}s`}`;

const placeHref = (p) => (p.kind === 'endpoint' ? `#/endpoints/${p.assetId}` : p.kind === 'machine' ? `#/machines/${p.assetId}` : '#/inventory/sources');
const sourceHref = (s) => (s.kind === 'endpoint' ? `#/endpoints/${s.id}` : s.kind === 'machine' ? `#/machines/${s.id}` : '#/inventory/sources');
const KIND_WORD = { endpoint: 'Endpoint scan', machine: 'Machine', import: 'Imported CBOM' };

function seenOn(r) {
  const parts = [];
  if (r.endpoints) parts.push(plural(r.endpoints, 'endpoint'));
  if (r.machines) parts.push(plural(r.machines, 'machine'));
  if (r.imports) parts.push(plural(r.imports, 'imported CBOM'));
  return parts.join(', ') || '·';
}

function placesCell(places) {
  const by = { endpoint: 0, machine: 0, import: 0 };
  for (const p of places) by[p.kind]++;
  if (!places.length) return h('span', { class: 'muted' }, '·');
  return h('details', { class: 'places' }, h('summary', null, seenOn({ endpoints: by.endpoint, machines: by.machine, imports: by.import })),
    h('ul', null, places.map((p) => h('li', null, h('a', { href: placeHref(p) }, p.label), h('span', { class: 'muted' }, ` ${KIND_WORD[p.kind] || p.kind}`)))));
}

/** The one dialog for every way data comes in (REQ-INV-6). */
export function addDataDialog(onDone) {
  modal('Add data', (close) => {
    const body = h('div', { class: 'modal-body' });
    const tile = (title, text, label, action) => h('div', { class: 'adddata-tile' },
      h('h3', null, title), h('p', { class: 'muted' }, text), button(label, action, 'primary'));
    body.append(
      h('div', { class: 'adddata' },
        tile('Scan an endpoint', 'Check a TLS server. Its configuration becomes a report and its cryptography joins the inventory.', 'Scan', () => {
          close(); location.hash = '#/';
        }),
        tile('Inventory a machine', 'Run a short script on a computer (PowerShell or shell, plain text you can read) and upload what it lists: the cryptographic software and certificates inside it.', 'Show me how', () => {
          clear(body).append(collectSteps(() => { close(); if (onDone) onDone(); }), h('div', { class: 'row end' }, button('Close', close)));
        }),
        tile('Import a CBOM', 'Bring a CycloneDX CBOM made by another tool. It joins the inventory as imported, never overwriting what was observed.', 'Import', async () => {
          close();
          const { importDialog } = await import('./imports.js');
          importDialog(onDone || (() => { location.hash = '#/inventory/sources'; }));
        })),
      h('div', { class: 'row end' }, button('Close', close)));
    return body;
  }, { wide: true });
}

/** Download: the inventory as a PDF report, or as one CycloneDX CBOM. */
function downloadMenu() {
  const imported = h('input', { type: 'checkbox', id: 'inv-imported' });
  const spec = h('select', { 'aria-label': 'CycloneDX version' }, h('option', { value: '1.7' }, 'CycloneDX 1.7'), h('option', { value: '1.6' }, 'CycloneDX 1.6'));
  const run = (fn) => async (e) => {
    const b = e.currentTarget;
    const label = b.textContent;
    b.disabled = true; b.textContent = 'Preparing…';
    try { await fn(); toast('Downloaded', 'success'); } catch (err) { toast(err.message, 'error'); }
    b.disabled = false; b.textContent = label;
  };
  return h('details', { class: 'menu download-menu' },
    h('summary', { class: 'btn btn-primary' }, 'Download'),
    h('div', { class: 'menu-panel' },
      h('div', { class: 'dl-option' },
        h('b', null, 'Inventory report (PDF)'),
        h('p', { class: 'hint' }, 'A formatted A4 report: post-quantum status, what to replace first, certificates, every algorithm and key, and the sources.'),
        h('button', { type: 'button', class: 'btn btn-primary', onclick: run(() => api.download('/api/v1/inventory/report.pdf', 'cipherhorizon-inventory-report.pdf')) }, 'Download PDF')),
      h('div', { class: 'dl-option' },
        h('b', null, 'CycloneDX CBOM (JSON)'),
        h('p', { class: 'hint' }, 'The whole inventory as one machine-readable document, with where each item was seen.'),
        spec,
        h('label', { class: 'check' }, imported, ' Include imported CBOMs'),
        h('button', { type: 'button', class: 'btn btn-secondary', onclick: run(() => api.download(`/api/v1/inventory/cbom?spec=${spec.value}&imported=${imported.checked ? 1 : 0}&download=1`, 'cipherhorizon-inventory-cbom.json')) }, 'Download CBOM'))));
}

function pageHead(title, sub, back) {
  return h('div', null,
    back ? crumbs([['Inventory', '#/inventory'], [title]]) : null,
    h('div', { class: 'page-head' },
      h('div', null, h('h1', null, title), h('div', { class: 'sub' }, sub)),
      h('div', { class: 'row' }, button('Add data', () => addDataDialog(), 'secondary'), downloadMenu())));
}

// ---- small SVG charts (the CSP allows no inline styles, so sizes are SVG attributes) -------------

let clipSeq = 0;

/** A horizontal bar of segments [{n, tone, href?, label?, key?}] scaled to max. A segment with an
 *  href is a mark that opens what it counts (UX-DESIGN-008 §3). */
function hbar(segments, max, { width = 240, height = 10, label } = {}) {
  const linked = segments.some((s) => s.href && s.n);
  const root = svg('svg', { viewBox: `0 0 ${width} ${height}`, class: 'hbar', preserveAspectRatio: 'none',
    role: linked ? 'group' : 'img', 'aria-label': label || '' });
  root.appendChild(svg('rect', { x: 0, y: 0, width, height, rx: height / 2, class: 'hbar-track' }));
  const total = segments.reduce((a, s) => a + s.n, 0);
  const id = `hbar-clip-${++clipSeq}`;
  root.appendChild(svg('clipPath', { id }, svg('rect', { x: 0, y: 0, width: (width * total) / Math.max(1, max), height, rx: height / 2 })));
  const g = svg('g', { 'clip-path': `url(#${id})`, class: 'hbar-fill' });
  let x = 0;
  for (const s of segments) {
    if (!s.n) continue;
    const w = (width * s.n) / Math.max(1, max);
    g.appendChild(svg('rect', mark({ x, y: 0, width: w, height, class: `fill-${s.tone}` }, s.href,
      `${s.label || ''}: ${s.n}. Open the list`, { tip: s.label, sub: s.sub || String(s.n), key: s.key })));
    x += w;
  }
  root.appendChild(g);
  return root;
}

/** A ring split by segments [{n, tone, label}], with a figure in the middle. */
function ring(segments, big, small, size = 148) {
  const r = 56, c = size / 2, sw = 18, C = 2 * Math.PI * r;
  const total = segments.reduce((a, s) => a + s.n, 0);
  const root = svg('svg', { viewBox: `0 0 ${size} ${size}`, width: size, height: size, class: 'ring', role: 'img',
    'aria-label': segments.map((s) => `${s.label}: ${s.n}`).join(', ') });
  root.appendChild(svg('circle', { cx: c, cy: c, r, fill: 'none', 'stroke-width': sw, class: 'ring-track' }));
  let off = 0;
  let i = 0;
  for (const s of segments) {
    if (!s.n || !total) continue;
    const len = (s.n / total) * C;
    const seg = svg('circle', mark({ cx: c, cy: c, r, fill: 'none', 'stroke-width': sw, class: `ring-seg stroke-${s.tone}`,
      'stroke-dasharray': `${len} ${C - len}`, 'stroke-dashoffset': -off, transform: `rotate(-90 ${c} ${c})` }, s.href,
    `${s.label}: ${s.n}. Open the list`, { tip: s.label, sub: `${s.n} of ${total}`, key: s.key }), svg('title', null, `${s.label}: ${s.n}`));
    // The sweep starts from nothing and grows to this share (UX-DESIGN-008 §4), one after another.
    seg.style.setProperty('--C', String(C));
    seg.style.setProperty('--i', String(i++));
    root.appendChild(seg);
    off += len;
  }
  root.appendChild(svg('text', { x: c, y: c + 4, class: 'ring-big', 'text-anchor': 'middle' }, big));
  root.appendChild(svg('text', { x: c, y: c + 22, class: 'ring-small', 'text-anchor': 'middle' }, small));
  return root;
}

// A legend row with an href is a mark too: the same as clicking its segment, a bigger target.
function legend(items) {
  return h('ul', { class: 'legend' }, items.map((it) => h('li', it.href && it.n ? mark({}, it.href, `${it.label}: ${it.n}. Open the list`, { tip: it.label, sub: String(it.n), key: it.key }) : null,
    h('span', { class: `swatch sw-${it.tone}`, 'aria-hidden': 'true' }), h('span', null, it.label), it.n === undefined ? null : h('b', null, String(it.n)))));
}

function card(title, sub, content, foot, extra = '') {
  return h('section', { class: `dcard ${extra}`, 'aria-label': title },
    h('div', { class: 'dcard-head' }, h('h2', null, title), sub ? h('span', { class: 'dcard-sub' }, sub) : null),
    content,
    foot ? h('div', { class: 'dcard-foot' }, foot) : null);
}

const daysChip = (n) => (n === null || n === undefined ? h('span', { class: 'muted' }, '·')
  : n < 0 ? badge('expired', 'bad') : badge(`${n} days`, n <= 30 ? 'bad' : n <= 90 ? 'warn' : 'good'));

// ---- the dashboard -------------------------------------------------------------------------------

async function dashboard(root) {
  root.appendChild(pageHead('Inventory', 'Every algorithm, key, certificate and protocol your scans, machines and imported CBOMs have seen'));
  const body = h('div');
  root.appendChild(body);
  body.appendChild(skeleton(4));
  const d = await api.inventoryDashboard();
  clear(body);
  const t = d.totals || {};
  const q = d.quantum || {};
  const classified = (q.vulnerable || 0) + (q.safe || 0) + (q.unknown || 0);
  const c = d.certificates || {};
  const sources = (t.endpoints || 0) + (t.machines || 0) + (t.imports || 0);
  if (!t.algorithm && !c.total && !sources) {
    body.appendChild(empty('Your inventory is empty',
      'Scan an endpoint, run the inventory script on a machine, or import a CBOM from another tool. Everything they find appears here, with its post-quantum status.',
      button('Add data', () => addDataDialog(), 'primary')));
    return;
  }

  const tile = (n, label, sub, cls, href) => {
    const big = h('div', { class: 'sumtile-big' }, String(n));
    countUp(big, `inv:${label}`, n);
    return h('a', { class: `sumtile ${cls || ''}`, href }, big, h('div', { class: 'sumtile-label' }, label), h('div', { class: 'sumtile-sub' }, sub));
  };
  body.appendChild(h('div', { class: 'sumstrip', role: 'group', 'aria-label': 'Inventory summary' },
    tile(t.algorithm || 0, 'Algorithms', `${plural(t.key || 0, 'key')} · ${plural(t.protocol || 0, 'protocol version')}`, '', '#/inventory/algorithms'),
    tile(q.vulnerable || 0, 'Quantum-vulnerable', `of ${classified} algorithms and keys`, q.vulnerable ? 'tile-bad' : 'tile-good', '#/inventory/algorithms?quantum=vulnerable'),
    tile(c.total || 0, 'Certificates', c.expired ? `${c.expired} expired` : c.within30 ? `${c.within30} expire within 30 days` : 'none expire within 30 days',
      c.expired ? 'tile-bad' : c.within30 ? 'tile-warn' : '', '#/inventory/certificates'),
    tile(sources, 'Sources', `${plural(t.endpoints || 0, 'endpoint')} · ${plural(t.machines || 0, 'machine')} · ${t.imports || 0} imported`, '', '#/inventory/sources')));

  const grid = h('div', { class: 'dash-grid' });
  body.appendChild(grid);

  // Post-quantum status.
  const segs = [
    { n: q.vulnerable || 0, tone: 'bad', label: 'Quantum-vulnerable', key: 'vulnerable', href: '#/inventory/algorithms?quantum=vulnerable' },
    { n: q.safe || 0, tone: 'good', label: 'Quantum-safe', key: 'safe', href: '#/inventory/algorithms?quantum=safe' },
    { n: q.unknown || 0, tone: 'neutral', label: 'Not classified', key: 'unknown', href: '#/inventory/algorithms?quantum=unknown' },
  ];
  const pct = classified ? Math.round(((q.vulnerable || 0) * 100) / classified) : 0;
  grid.appendChild(card('Post-quantum status', `${classified} algorithms and keys`,
    h('div', { class: 'pq-split', 'data-chart': 'pq' }, ring(segs, `${pct}%`, 'vulnerable'),
      h('div', { class: 'pq-text' }, legend(segs),
        h('p', { class: 'hint' }, 'Public-key algorithms (RSA, elliptic curves, Diffie-Hellman) can be broken by a large quantum computer; symmetric ciphers and hashes of enough strength stay safe.'))),
    h('a', { href: '#/inventory/algorithms?quantum=vulnerable' }, 'See the quantum-vulnerable algorithms →')));

  // Replace first.
  const rf = d.replaceFirst || [];
  const maxPlaces = Math.max(1, ...rf.map((r) => r.places));
  grid.appendChild(card('Replace first', 'quantum-vulnerable, most used first',
    rf.length
      ? h('ol', { class: 'rank-list', 'data-chart': 'rank' }, rf.map((r, i) => h('li', mark({ class: 'rank-row' },
        `#/inventory/${r.kind === 'key' ? 'keys' : 'algorithms'}?name=${encodeURIComponent(r.name)}&quantum=vulnerable`,
        `${shownName(r.name)}, ${seenOn(r)}: open it in the list`, { tip: shownName(r.name), sub: seenOn(r) }),
        h('span', { class: 'rank-n' }, String(i + 1)),
        h('span', { class: 'rank-name' }, h('b', { title: r.name }, shownName(r.name)), h('small', null, r.purpose || (r.kind === 'key' ? 'certificate key' : humanDetail(r.detail)))),
        hbar([{ n: r.places, tone: 'bad' }], maxPlaces, { label: seenOn(r) }),
        h('span', { class: 'rank-count' }, seenOn(r)))))
      : h('p', { class: 'muted' }, 'Nothing quantum-vulnerable has been found.'),
    h('a', { href: '#/inventory/algorithms' }, 'All algorithms →')));

  // By purpose.
  const bp = d.byPurpose || [];
  if (bp.length) {
    const maxP = Math.max(1, ...bp.map((p) => p.vulnerable + p.safe + p.unknown));
    grid.appendChild(card('Algorithms by purpose', 'algorithms only; keys are counted under Post-quantum status',
      h('div', null,
        h('ul', { class: 'bar-list', 'data-chart': 'purpose' }, bp.map((p) => h('li', { class: 'bar-row' },
          h('span', { class: 'bar-label' }, p.purpose),
          hbar([['vulnerable', 'bad', 'quantum-vulnerable'], ['safe', 'good', 'quantum-safe'], ['unknown', 'neutral', 'not classified']].map(([k, tone, words]) => ({
            n: p[k], tone, key: k, label: `${p.purpose}, ${words}`, sub: plural(p[k], 'algorithm'),
            href: `#/inventory/algorithms?purpose=${encodeURIComponent(p.purpose)}&quantum=${k}` })), maxP,
            { label: `${p.vulnerable} quantum-vulnerable, ${p.safe} quantum-safe, ${p.unknown} not classified` }),
          h('span', { class: 'bar-count' }, String(p.vulnerable + p.safe + p.unknown))))),
        legend([{ tone: 'bad', label: 'quantum-vulnerable' }, { tone: 'good', label: 'quantum-safe' },
          ...(bp.some((p) => p.unknown) ? [{ tone: 'neutral', label: 'not classified' }] : [])])),
      h('a', { href: '#/inventory/algorithms' }, 'All algorithms →')));
  }

  // Protocols.
  const pr = d.protocols || [];
  if (pr.length) {
    const maxE = Math.max(1, ...pr.map((p) => p.places));
    grid.appendChild(card('Protocol versions', 'accepted by your endpoints',
      h('ul', { class: 'bar-list', 'data-chart': 'protocols' }, pr.map((p) => h('li', mark({ class: 'bar-row' },
        `#/inventory/protocols?name=${encodeURIComponent(p.name)}`, `${p.name}, ${seenOn(p)}: open it in the list`, { tip: p.name, sub: seenOn(p) }),
        h('span', { class: 'bar-label' }, h('b', null, p.name), ' ', p.legacy ? badge('deprecated', 'bad') : badge('current', 'good')),
        hbar([{ n: p.places, tone: p.legacy ? 'bad' : 'good' }], maxE, { label: seenOn(p) }),
        h('span', { class: 'bar-count' }, seenOn(p))))),
      h('a', { href: '#/inventory/protocols' }, 'All protocol versions →')));
  }

  // Certificates.
  if (c.total) {
    // The dashboard's buckets (expired; 0 to 30 days; 31 to 90; later) and the list's filter use the
    // same boundaries, so a segment's count is the count of the list it opens.
    const cs = [
      { n: c.expired || 0, tone: 'bad', label: 'Expired', key: 'expired', href: '#/inventory/certificates?expires=expired' },
      { n: c.within30 || 0, tone: 'high', label: 'Within 30 days', key: '30', href: '#/inventory/certificates?expires=30' },
      { n: c.within90 || 0, tone: 'amber', label: 'Within 90 days', key: '31-90', href: '#/inventory/certificates?expires=31-90' },
      { n: c.later || 0, tone: 'good', label: 'Later', key: 'later', href: '#/inventory/certificates?expires=later' },
    ];
    grid.appendChild(card('Certificates', `${plural(c.total, 'certificate')} in use`,
      h('div', null,
        h('div', { 'data-chart': 'certs' },
          hbar(cs, c.total, { width: 400, height: 14, label: cs.map((s) => `${s.label}: ${s.n}`).join(', ') }),
          legend(cs.filter((s) => s.n))),
        h('h3', { class: 'dcard-h3' }, 'Expiring soonest'),
        h('ul', { class: 'mini-list' }, (c.soonest || []).map((x) => h('li', null,
          h('a', { href: `#/certificates/${x.fingerprint}`, title: x.name }, cnOf(x.name)), h('span', { class: 'muted' }, ` ${x.key}`),
          h('span', { class: 'mini-end' }, daysChip(x.daysLeft)))))),
      h('a', { href: '#/inventory/certificates' }, 'All certificates →')));
  }

  // Sources.
  const src = d.sources || [];
  grid.appendChild(card('Sources', 'most recent first',
    src.length
      ? h('ul', { class: 'mini-list' }, src.slice(0, 6).map((s) => h('li', null,
        badge(KIND_WORD[s.kind] || s.kind, 'neutral'), ' ', h('a', { href: sourceHref(s) }, s.label),
        h('span', { class: 'mini-end muted' }, `${plural(s.items, 'item')} · ${relTime(s.when)}`))))
      : h('p', { class: 'muted' }, 'No sources yet.'),
    h('a', { href: '#/inventory/sources' }, `All sources (${src.length}) →`)));

  // Software, when machines reported any.
  const sw = d.software || [];
  if (sw.length) {
    const maxS = Math.max(1, ...sw.map((s) => s.places));
    grid.appendChild(card('Cryptographic software', 'found on your machines',
      h('ul', { class: 'bar-list', 'data-chart': 'software' }, sw.map((s) => h('li', mark({ class: 'bar-row' },
        `#/inventory/software?name=${encodeURIComponent(s.name)}`, `${s.name}, ${seenOn(s)}: open it in the list`, { tip: s.name, sub: seenOn(s) }),
        h('span', { class: 'bar-label' }, h('b', null, s.name), s.detail ? h('span', { class: 'muted' }, ` ${s.detail}`) : null),
        hbar([{ n: s.places, tone: 'primary' }], maxS, { label: seenOn(s) }),
        h('span', { class: 'bar-count' }, seenOn(s))))),
      h('a', { href: '#/inventory/software' }, 'All software →'), 'wide'));
  }
  body.appendChild(h('p', { class: 'hint mt' }, `Updated ${fmtDate(d.generatedAt)}. The inventory merges the latest scan of every endpoint, the latest upload of every machine and the CBOMs you imported.`));
}

// ---- the lists --------------------------------------------------------------------------------

async function itemsList(root, kind, query) {
  // The filters live in the address (UX-DESIGN-008 §1.2): a chart opens this list already filtered,
  // and a change here is written back, so Back returns to the chart. vulnerable=1 is the older
  // spelling of quantum=vulnerable.
  const quantumWords = { vulnerable: 'Quantum-vulnerable', safe: 'Quantum-safe', unknown: 'Not classified' };
  let quantum = query.get('quantum') || (query.get('vulnerable') === '1' ? 'vulnerable' : '');
  if (!quantumWords[quantum]) quantum = '';
  let purpose = query.get('purpose') || '';
  let name = query.get('name') || '';
  const text = h('input', { type: 'search', placeholder: 'Filter by name', value: query.get('q') || '', 'aria-label': 'Filter by name' });
  const vuln = h('input', { type: 'checkbox', id: 'inv-vuln', checked: quantum === 'vulnerable' });
  const source = h('select', { 'aria-label': 'Source' }, [['', 'Any source'], ['endpoint', 'Endpoint scans'], ['machine', 'Machines'], ['import', 'Imported CBOMs']]
    .map(([v, l]) => h('option', { value: v, selected: v === (query.get('source') || '') }, l)));
  const chips = h('div');
  const list = h('div');
  const paintChips = () => {
    clear(chips);
    const c = filterChips([
      quantum && quantum !== 'vulnerable' ? filterChip(quantumWords[quantum], () => { quantum = ''; redraw(); }) : null,
      purpose ? filterChip(`Purpose: ${purpose}`, () => { purpose = ''; redraw(); }) : null,
      name ? filterChip(shownName(name), () => { name = ''; redraw(); }) : null]);
    if (c) chips.appendChild(c);
  };
  const draw = async () => {
    const q = { imported: '1' };
    if (text.value.trim()) q.q = text.value.trim();
    if (quantum) q.quantum = quantum;
    if (purpose) q.purpose = purpose;
    if (name) q.name = name;
    if (source.value) q.source = source.value;
    setQuery({ q: q.q || '', quantum, purpose, name, source: source.value, vulnerable: '' });
    paintChips();
    // The dashboard's post-quantum figures count algorithms and keys together; on the algorithm
    // list, say how many keys share the status, so the two lists add up to the figure clicked.
    const [{ rows }, keys] = await Promise.all([api.inventory(kind, q),
      kind === 'algorithm' && quantum && !purpose && !name ? api.inventory('key', { imported: '1', quantum, ...(q.q ? { q: q.q } : {}), ...(q.source ? { source: q.source } : {}) }).then((r) => r.rows.length).catch(() => 0) : 0]);
    clear(list);
    if (keys) {
      list.appendChild(h('p', { class: 'hint' }, `${plural(keys, 'public key')} ${keys === 1 ? 'is' : 'are'} ${quantumWords[quantum].toLowerCase()} too. `,
        h('a', { href: `#/inventory/keys?quantum=${quantum}` }, 'Open the keys')));
    }
    if (!rows.length) {
      list.appendChild(h('p', { class: 'muted pad' }, Object.keys(q).length > 1 ? 'Nothing matches these filters.' : 'Nothing here yet. Scan an endpoint or add a machine inventory.'));
      return;
    }
    const showQuantum = kind === 'algorithm' || kind === 'key';
    list.appendChild(h('div', { class: 'tablewrap' }, h('table', { class: 'compact invtable' },
      h('thead', null, h('tr', null, ['Name', kind === 'software' ? 'Version' : 'Kind', showQuantum ? 'Classical strength' : null, showQuantum ? 'Post-quantum' : null, 'Seen on', 'Last seen'].filter(Boolean).map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, rows.map((r) => h('tr', null,
        h('td', null, h('b', { title: r.name }, shownName(r.name))),
        h('td', { class: 'muted' }, humanDetail(r.detail) || '·'),
        showQuantum ? h('td', null, strengthCell(r.classicalStrength)) : null,
        showQuantum ? h('td', null, quantumBadge(r.quantum)) : null,
        h('td', null, placesCell(r.places)),
        h('td', { class: 'muted nowrapcell' }, r.lastSeen ? relTime(r.lastSeen) : '·')))))));
    list.appendChild(h('p', { class: 'hint' }, `${plural(rows.length, 'item')}. Post-quantum status uses the cited classification carried in the CBOM.`));
  };
  let timer = null;
  const redraw = () => crossFade(list, draw);
  text.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(draw, 250); });
  vuln.addEventListener('change', () => { quantum = vuln.checked ? 'vulnerable' : (quantum === 'vulnerable' ? '' : quantum); redraw(); });
  source.addEventListener('change', redraw);
  root.append(h('div', { class: 'toolbar' }, text,
    kind === 'algorithm' || kind === 'key' ? h('label', { class: 'check' }, vuln, ' Only quantum-vulnerable') : null, source), chips, list);
  await draw();
}

async function sourcesList(root) {
  const [endpoints, hosts] = await Promise.all([api.assets().catch(() => []), api.hosts().catch(() => [])]);
  const list = (items, href, when) => h('ul', { class: 'source-list' }, items.map((x) => h('li', null, h('a', { href: href(x) }, h('b', null, x.name)),
    x.address && x.address !== x.name ? h('span', { class: 'muted' }, ` ${x.address}`) : null,
    h('span', { class: 'muted source-when' }, when(x)))));
  root.append(
    h('section', { class: 'card mt', 'aria-labelledby': 'src-endpoints' },
      h('div', { class: 'row spread' }, h('h2', { id: 'src-endpoints' }, 'Endpoint scans'), h('a', { href: '#/endpoints' }, 'Endpoints →')),
      endpoints.length ? list(endpoints, (a) => `#/endpoints/${a.id}`, (a) => (a.lastDone ? `scanned ${relTime(a.lastDone.finishedAt)}` : 'not scanned yet'))
        : h('p', { class: 'muted' }, 'No endpoints yet. ', h('a', { href: '#/' }, 'Scan one'), '.')),
    h('section', { class: 'card mt', 'aria-labelledby': 'src-machines' },
      h('div', { class: 'row spread' }, h('h2', { id: 'src-machines' }, 'Machine inventories'), h('a', { href: '#/machines' }, 'Machines →')),
      hosts.length ? list(hosts, (x) => `#/machines/${x.id}`, (x) => (x.snapshotAt ? `uploaded ${relTime(x.snapshotAt)}` : 'nothing uploaded'))
        : h('p', { class: 'muted' }, 'No machines yet. ', h('a', { href: '#/machines' }, 'Add one'), '.')));
  // Imported CBOMs live here: they are a source of the inventory, not a kind of thing of their own.
  const imported = h('div');
  root.append(h('section', { class: 'card mt', 'aria-labelledby': 'src-imports' }, h('h2', { id: 'src-imports' }, 'Imported CBOMs'), imported));
  const { render: renderImports } = await import('./imports.js');
  await renderImports(imported, { embedded: true });
}

async function listPage(root, which, query) {
  const entry = LISTS.find(([k]) => k === which) || LISTS[0];
  root.appendChild(pageHead(entry[1], entry[3], true));
  root.appendChild(h('nav', { class: 'subnav', 'aria-label': 'Inventory lists' }, LISTS.map(([k, label]) =>
    h('a', { href: `#/inventory/${k}`, class: 'subnav-link', 'aria-current': k === entry[0] ? 'page' : null }, label))));
  const body = h('div', { class: 'tabbody' });
  root.appendChild(body);
  if (entry[0] === 'certificates') {
    const mod = await import('./certificates.js');
    return mod.render(body, { embedded: true, query });
  }
  if (entry[0] === 'sources') {
    await sourcesList(body);
    return null;
  }
  await itemsList(body, entry[2], query);
  return null;
}

export async function render(root, { args, query }) {
  if (args && args[0]) return listPage(root, args[0], query);
  await dashboard(root);
  return null;
}
