// CBOM: the cryptographic bill of materials for any asset, shown as a
// human-readable tree (endpoint → protocol / certificate / algorithms), each
// node carrying the evidence that produced it. The same data is one click
// away as a machine-readable CycloneDX export.
import { h, clear } from '../dom.js';
import { api } from '../api.js';
import { badge, button, empty, toast, skeleton } from '../ui.js';

const ASSET_TYPE_LABEL = { protocol: 'Protocol', certificate: 'Certificate', algorithm: 'Algorithm', 'related-crypto-material': 'Key material' };

// Accepted-by-the-server is the default reading of an edge; only what a current client
// actually negotiated carries the flag (see the tls-graph note in the document).
function isNegotiated(c) {
  return (c.properties || []).some((p) => p.name === 'cipherhorizon:negotiated' && p.value === 'true');
}

function evidenceOf(c) {
  const ids = c.evidence && c.evidence.identity;
  const list = Array.isArray(ids) ? ids : ids ? [ids] : [];
  for (const id of list) {
    const m = id.methods && id.methods[0];
    if (m && m.value) return m.value;
  }
  return null;
}

function buildTree(bom) {
  const components = bom.components || [];
  const byRef = new Map(components.map((c) => [c['bom-ref'], c]));
  const dependsOn = new Map();
  for (const c of components) if (c.cryptoProperties) dependsOn.set(c['bom-ref'], []);
  for (const d of bom.dependencies || []) {
    if (byRef.has(d.ref) && d.dependsOn) dependsOn.set(d.ref, d.dependsOn.filter((r) => byRef.has(r)));
  }
  const childOf = new Set();
  for (const kids of dependsOn.values()) for (const k of kids) childOf.add(k);
  const roots = components.filter((c) => c.cryptoProperties && !childOf.has(c['bom-ref']));
  return { byRef, dependsOn, roots };
}

function componentRow(c, depth, dependsOn, byRef) {
  const kind = c.cryptoProperties ? c.cryptoProperties.assetType : '';
  const ev = evidenceOf(c);
  const kids = (dependsOn.get(c['bom-ref']) || []).map((ref) => byRef.get(ref)).filter(Boolean);
  return h('div', { class: kids.length || depth === 0 ? 'cbomnode' + (depth === 0 ? ' cbomnode-root' : '') : '' },
    h('div', { class: 'cbomnode-head' },
      badge(ASSET_TYPE_LABEL[kind] || kind || 'Component', depth === 0 ? 'info' : 'neutral'),
      h('span', { class: 'cbomleaf-name' }, c.name || c['bom-ref']),
      isNegotiated(c) ? h('span', { class: 'evidence-chip negotiated', title: 'Used in the handshake a current client completed with this endpoint' }, '✓ negotiated') : null,
      ev ? h('span', { class: 'evidence-chip' }, '● observed via ', ev) : null),
    kids.length
      ? h('div', { class: 'cbombranch' }, kids.map((k) => componentRow(k, depth + 1, dependsOn, byRef)))
      : null);
}

function treeView(bom, subjectName) {
  const { byRef, dependsOn, roots } = buildTree(bom);
  if (!roots.length) return h('p', { class: 'muted' }, 'This CBOM has no cryptographic components.');
  return h('div', { class: 'cbomtree' },
    h('div', { class: 'cbomnode cbomnode-root' },
      h('div', { class: 'cbomnode-head' }, badge('Endpoint', 'info'), h('span', { class: 'cbomleaf-name' }, subjectName)),
      h('div', { class: 'cbombranch' }, roots.map((r) => componentRow(r, 1, dependsOn, byRef)))));
}

export async function render(root) {
  const head = h('div');
  const body = h('div');
  root.append(head, body);
  body.appendChild(skeleton(4));

  head.appendChild(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'CBOM'), h('div', { class: 'sub' }, 'The cryptographic bill of materials for each asset — what it uses, and how that was observed.'))));

  let assets;
  try {
    const [tls, hosts] = await Promise.all([api.assets(), api.hosts()]);
    assets = [...tls.map((a) => ({ ...a })), ...hosts.map((h2) => ({ ...h2 }))];
  } catch (e) {
    clear(body);
    toast(e.message, 'error');
    return null;
  }

  clear(body);
  if (!assets.length) {
    body.appendChild(empty('No assets yet', 'Add a TLS endpoint or upload a host CBOM to see its cryptographic bill of materials.'));
    return null;
  }

  let openID = null;
  const treeBox = h('div');

  const showTree = async (a) => {
    clear(treeBox);
    let cbomUrl;
    if (a.kind === 'host') {
      const detail = await api.host(a.id);
      const snap = (detail.history || [])[0];
      if (!snap) { treeBox.appendChild(h('p', { class: 'muted' }, 'No CBOM uploaded yet.')); return; }
      cbomUrl = `/api/v1/hosts/${a.id}/snapshots/${snap.id}/cbom`;
    } else {
      cbomUrl = `/api/v1/scans/${a.lastDone.id}/cbom`;
    }
    const res = await fetch(cbomUrl);
    if (!res.ok) throw new Error(`Could not load the CBOM (${res.status})`);
    const bom = await res.json();
    treeBox.appendChild(h('div', { class: 'card mt' },
      h('div', { class: 'row' }, h('h3', null, `CBOM: ${a.name}`),
        button('Download machine-readable CBOM', () => api.download(`${cbomUrl}?download=1`, `${a.kind}-${a.id}-cbom.json`).catch((e) => toast(e.message, 'error')), 'secondary', { class: 'btn btn-sm' })),
      treeView(bom, a.name)));
  };

  const rows = assets.map((a) => {
    const hasResult = a.kind === 'host' ? true : !!a.lastDone;
    const toggle = h('button', { type: 'button', class: 'btn btn-secondary btn-sm', onclick: async () => {
      if (openID === a.id) { openID = null; clear(treeBox); toggle.textContent = 'View CBOM'; return; }
      openID = a.id;
      toggle.textContent = 'Hide CBOM';
      try { await showTree(a); } catch (e) { toast(e.message, 'error'); }
    } }, 'View CBOM');
    return h('div', { class: 'card' },
      h('div', { class: 'row' },
        h('span', { class: 'kind-badge' }, a.kind === 'host' ? 'Host' : 'Endpoint'),
        h('strong', null, a.name),
        a.address !== a.name ? h('span', { class: 'muted' }, a.address) : null,
        hasResult ? toggle : h('span', { class: 'muted' }, 'Not scanned yet')));
  });

  body.append(h('div', { class: 'stack' }, rows), treeBox);
  return null;
}
