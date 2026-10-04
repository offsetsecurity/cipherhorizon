// Inventory: every algorithm, key, certificate and protocol your scans, your machines and the
// CBOMs you import have seen. The landing page is a dashboard of what matters (how much is
// quantum-vulnerable, what to replace first, what expires); each figure opens its list, one
// click deeper. The lists and the downloads read the same merged CBOM (PRD-005 REQ-INV).
import { h, svg, clear, relTime, fmtDate } from '../dom.js';
import { api } from '../api.js';
import { badge, button, empty, modal, toast, skeleton, crumbs } from '../ui.js';
import { collectSteps } from '../guide.js';

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
  'not-applicable': ['—', 'none'],
};
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
  return parts.join(', ') || '—';
}

function placesCell(places) {
  const by = { endpoint: 0, machine: 0, import: 0 };
  for (const p of places) by[p.kind]++;
  if (!places.length) return h('span', { class: 'muted' }, '—');
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

/** A horizontal bar of segments [{n, tone}] scaled to max. */
function hbar(segments, max, { width = 240, height = 10, label } = {}) {
  const root = svg('svg', { viewBox: `0 0 ${width} ${height}`, class: 'hbar', preserveAspectRatio: 'none', role: 'img', 'aria-label': label || '' });
  root.appendChild(svg('rect', { x: 0, y: 0, width, height, rx: height / 2, class: 'hbar-track' }));
  const total = segments.reduce((a, s) => a + s.n, 0);
  const id = `hbar-clip-${++clipSeq}`;
  root.appendChild(svg('clipPath', { id }, svg('rect', { x: 0, y: 0, width: (width * total) / Math.max(1, max), height, rx: height / 2 })));
  const g = svg('g', { 'clip-path': `url(#${id})` });
  let x = 0;
  for (const s of segments) {
    if (!s.n) continue;
    const w = (width * s.n) / Math.max(1, max);
    g.appendChild(svg('rect', { x, y: 0, width: w, height, class: `fill-${s.tone}` }));
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
  for (const s of segments) {
    if (!s.n || !total) continue;
    const len = (s.n / total) * C;
    root.appendChild(svg('circle', { cx: c, cy: c, r, fill: 'none', 'stroke-width': sw, class: `stroke-${s.tone}`,
      'stroke-dasharray': `${len} ${C - len}`, 'stroke-dashoffset': -off, transform: `rotate(-90 ${c} ${c})` }, svg('title', null, `${s.label}: ${s.n}`)));
    off += len;
  }
  root.appendChild(svg('text', { x: c, y: c + 4, class: 'ring-big', 'text-anchor': 'middle' }, big));
  root.appendChild(svg('text', { x: c, y: c + 22, class: 'ring-small', 'text-anchor': 'middle' }, small));
  return root;
}

function legend(items) {
  return h('ul', { class: 'legend' }, items.map((it) => h('li', null,
    h('span', { class: `swatch sw-${it.tone}`, 'aria-hidden': 'true' }), h('span', null, it.label), h('b', null, String(it.n)))));
}

function card(title, sub, content, foot, extra = '') {
  return h('section', { class: `dcard ${extra}`, 'aria-label': title },
    h('div', { class: 'dcard-head' }, h('h2', null, title), sub ? h('span', { class: 'dcard-sub' }, sub) : null),
    content,
    foot ? h('div', { class: 'dcard-foot' }, foot) : null);
}

const daysChip = (n) => (n === null || n === undefined ? h('span', { class: 'muted' }, '—')
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

  const tile = (n, label, sub, cls, href) => h('a', { class: `sumtile ${cls || ''}`, href },
    h('div', { class: 'sumtile-big' }, String(n)), h('div', { class: 'sumtile-label' }, label), h('div', { class: 'sumtile-sub' }, sub));
  body.appendChild(h('div', { class: 'sumstrip', role: 'group', 'aria-label': 'Inventory summary' },
    tile(t.algorithm || 0, 'Algorithms', `${plural(t.key || 0, 'key')} · ${plural(t.protocol || 0, 'protocol version')}`, '', '#/inventory/algorithms'),
    tile(q.vulnerable || 0, 'Quantum-vulnerable', `of ${classified} algorithms and keys`, q.vulnerable ? 'tile-bad' : 'tile-good', '#/inventory/algorithms?vulnerable=1'),
    tile(c.total || 0, 'Certificates', c.expired ? `${c.expired} expired` : c.within30 ? `${c.within30} expire within 30 days` : 'none expire within 30 days',
      c.expired ? 'tile-bad' : c.within30 ? 'tile-warn' : '', '#/inventory/certificates'),
    tile(sources, 'Sources', `${plural(t.endpoints || 0, 'endpoint')} · ${plural(t.machines || 0, 'machine')} · ${t.imports || 0} imported`, '', '#/inventory/sources')));

  const grid = h('div', { class: 'dash-grid' });
  body.appendChild(grid);

  // Post-quantum status.
  const segs = [
    { n: q.vulnerable || 0, tone: 'bad', label: 'Quantum-vulnerable' },
    { n: q.safe || 0, tone: 'good', label: 'Quantum-safe' },
    { n: q.unknown || 0, tone: 'neutral', label: 'Not classified' },
  ];
  const pct = classified ? Math.round(((q.vulnerable || 0) * 100) / classified) : 0;
  grid.appendChild(card('Post-quantum status', `${classified} algorithms and keys`,
    h('div', { class: 'pq-split' }, ring(segs, `${pct}%`, 'vulnerable'),
      h('div', { class: 'pq-text' }, legend(segs),
        h('p', { class: 'hint' }, 'Public-key algorithms (RSA, elliptic curves, Diffie-Hellman) can be broken by a large quantum computer; symmetric ciphers and hashes of enough strength stay safe.'))),
    h('a', { href: '#/inventory/algorithms?vulnerable=1' }, 'See the quantum-vulnerable algorithms →')));

  // Replace first.
  const rf = d.replaceFirst || [];
  const maxPlaces = Math.max(1, ...rf.map((r) => r.places));
  grid.appendChild(card('Replace first', 'quantum-vulnerable, most used first',
    rf.length
      ? h('ol', { class: 'rank-list' }, rf.map((r, i) => h('li', { class: 'rank-row' },
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
    grid.appendChild(card('Algorithms by purpose', 'what each algorithm is used for',
      h('div', null,
        h('ul', { class: 'bar-list' }, bp.map((p) => h('li', { class: 'bar-row' },
          h('span', { class: 'bar-label' }, p.purpose),
          hbar([{ n: p.vulnerable, tone: 'bad' }, { n: p.safe, tone: 'good' }, { n: p.unknown, tone: 'neutral' }], maxP,
            { label: `${p.vulnerable} quantum-vulnerable, ${p.safe} quantum-safe, ${p.unknown} not classified` }),
          h('span', { class: 'bar-count' }, String(p.vulnerable + p.safe + p.unknown))))),
        legend([{ tone: 'bad', label: 'quantum-vulnerable', n: bp.reduce((a, p) => a + p.vulnerable, 0) },
          { tone: 'good', label: 'quantum-safe', n: bp.reduce((a, p) => a + p.safe, 0) },
          { tone: 'neutral', label: 'not classified', n: bp.reduce((a, p) => a + p.unknown, 0) }].filter((x) => x.tone !== 'neutral' || x.n))),
      h('a', { href: '#/inventory/algorithms' }, 'All algorithms →')));
  }

  // Protocols.
  const pr = d.protocols || [];
  if (pr.length) {
    const maxE = Math.max(1, ...pr.map((p) => p.places));
    grid.appendChild(card('Protocol versions', 'accepted by your endpoints',
      h('ul', { class: 'bar-list' }, pr.map((p) => h('li', { class: 'bar-row' },
        h('span', { class: 'bar-label' }, h('b', null, p.name), ' ', p.legacy ? badge('deprecated', 'bad') : badge('current', 'good')),
        hbar([{ n: p.places, tone: p.legacy ? 'bad' : 'good' }], maxE, { label: seenOn(p) }),
        h('span', { class: 'bar-count' }, seenOn(p))))),
      h('a', { href: '#/inventory/protocols' }, 'All protocol versions →')));
  }

  // Certificates.
  if (c.total) {
    const cs = [
      { n: c.expired || 0, tone: 'bad', label: 'Expired' },
      { n: c.within30 || 0, tone: 'high', label: 'Within 30 days' },
      { n: c.within90 || 0, tone: 'amber', label: 'Within 90 days' },
      { n: c.later || 0, tone: 'good', label: 'Later' },
    ];
    grid.appendChild(card('Certificates', `${plural(c.total, 'certificate')} in use`,
      h('div', null,
        hbar(cs, c.total, { width: 400, height: 14, label: cs.map((s) => `${s.label}: ${s.n}`).join(', ') }),
        legend(cs.filter((s) => s.n)),
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
      h('ul', { class: 'bar-list' }, sw.map((s) => h('li', { class: 'bar-row' },
        h('span', { class: 'bar-label' }, h('b', null, s.name), s.detail ? h('span', { class: 'muted' }, ` ${s.detail}`) : null),
        hbar([{ n: s.places, tone: 'primary' }], maxS, { label: seenOn(s) }),
        h('span', { class: 'bar-count' }, seenOn(s))))),
      h('a', { href: '#/inventory/software' }, 'All software →'), 'wide'));
  }
  body.appendChild(h('p', { class: 'hint mt' }, `Updated ${fmtDate(d.generatedAt)}. The inventory merges the latest scan of every endpoint, the latest upload of every machine and the CBOMs you imported.`));
}

// ---- the lists --------------------------------------------------------------------------------

async function itemsList(root, kind, query) {
  const params = { q: query.get('q') || '', vulnerable: query.get('vulnerable') === '1' ? '1' : '', source: query.get('source') || '' };
  const text = h('input', { type: 'search', placeholder: 'Filter by name', value: params.q, 'aria-label': 'Filter by name' });
  const vuln = h('input', { type: 'checkbox', id: 'inv-vuln', checked: params.vulnerable === '1' });
  const source = h('select', { 'aria-label': 'Source' }, [['', 'Any source'], ['endpoint', 'Endpoint scans'], ['machine', 'Machines'], ['import', 'Imported CBOMs']]
    .map(([v, l]) => h('option', { value: v, selected: v === params.source }, l)));
  const list = h('div');
  const draw = async () => {
    const q = { imported: '1' };
    if (text.value.trim()) q.q = text.value.trim();
    if (vuln.checked) q.vulnerable = '1';
    if (source.value) q.source = source.value;
    const { rows } = await api.inventory(kind, q);
    clear(list);
    if (!rows.length) {
      list.appendChild(h('p', { class: 'muted pad' }, Object.keys(q).length > 1 ? 'Nothing matches these filters.' : 'Nothing here yet. Scan an endpoint or add a machine inventory.'));
      return;
    }
    const showQuantum = kind === 'algorithm' || kind === 'key';
    list.appendChild(h('div', { class: 'tablewrap' }, h('table', { class: 'compact invtable' },
      h('thead', null, h('tr', null, ['Name', kind === 'software' ? 'Version' : 'Kind', showQuantum ? 'Post-quantum' : null, 'Seen on', 'Last seen'].filter(Boolean).map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, rows.map((r) => h('tr', null,
        h('td', null, h('b', { title: r.name }, shownName(r.name))),
        h('td', { class: 'muted' }, humanDetail(r.detail) || '—'),
        showQuantum ? h('td', null, quantumBadge(r.quantum)) : null,
        h('td', null, placesCell(r.places)),
        h('td', { class: 'muted nowrapcell' }, r.lastSeen ? relTime(r.lastSeen) : '—')))))));
    list.appendChild(h('p', { class: 'hint' }, `${plural(rows.length, 'item')}. Post-quantum status uses the cited classification carried in the CBOM.`));
  };
  let timer = null;
  text.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(draw, 250); });
  vuln.addEventListener('change', draw);
  source.addEventListener('change', draw);
  root.append(h('div', { class: 'toolbar' }, text,
    kind === 'algorithm' || kind === 'key' ? h('label', { class: 'check' }, vuln, ' Only quantum-vulnerable') : null, source), list);
  await draw();
}

async function sourcesList(root) {
  const [endpoints, hosts] = await Promise.all([api.assets('tls-endpoint').catch(() => []), api.hosts().catch(() => [])]);
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
