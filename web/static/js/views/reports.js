// Reports: the documents the product produces, for people and for tools (UX-DESIGN-005 principle
// 6). Every PDF report, CBOM, spreadsheet and standards export in one place, each one click away.
import { h, clear, relTime, fmtDate } from '../dom.js';
import { api } from '../api.js';
import { button, toast, skeleton, levelBadge, bandBadge } from '../ui.js';
import { protocolOf, reportHref, baselineWords } from './assets.js';

const stemOf = (name) => name.replace(/[^a-z0-9._-]+/gi, '_');

function dl(label, path, filename, kind = 'secondary') {
  return button(label, () => api.download(path, filename).catch((e) => toast(e.message, 'error')), kind, { class: `btn btn-${kind} btn-sm` });
}

function docRow(title, text, ...actions) {
  return h('div', { class: 'docrow' },
    h('div', { class: 'docrow-text' }, h('b', null, title), h('p', { class: 'muted' }, text)),
    h('div', { class: 'docrow-actions' }, actions));
}

export async function render(root) {
  root.appendChild(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Reports'),
      h('div', { class: 'sub' }, 'Documents to share: PDF reports for people, CBOMs for tools, spreadsheets and standards exports. Each downloads in one click.'))));
  const body = h('div', { class: 'reports-docs' }, skeleton(4));
  root.appendChild(body);
  const [assets, hosts, systems] = await Promise.all([
    api.assets().catch(() => []), api.hosts().catch(() => []), api.systems().catch(() => null)]);
  clear(body);

  // The whole inventory.
  body.appendChild(h('section', { class: 'card', 'aria-labelledby': 'doc-inv' },
    h('h2', { id: 'doc-inv' }, 'Your cryptographic inventory'),
    docRow('Inventory report (PDF)', 'Post-quantum status, what to replace first, certificates, every algorithm and key, and where each came from. For managers and auditors.',
      dl('Download PDF', '/api/v1/inventory/report.pdf', 'cipherhorizon-inventory-report.pdf', 'primary')),
    docRow('Inventory CBOM (CycloneDX)', 'Every endpoint and machine merged into one cryptographic bill of materials, for other tools. Imported CBOMs are left out.',
      dl('CycloneDX 1.7', '/api/v1/inventory/cbom?spec=1.7&imported=0&download=1', 'cipherhorizon-inventory-cbom.json'),
      dl('CycloneDX 1.6', '/api/v1/inventory/cbom?spec=1.6&imported=0&download=1', 'cipherhorizon-inventory-cbom-1.6.json'))));

  // One row per scanned endpoint, grouped by protocol (UX-DESIGN-007 §7).
  const byName = (a, b) => a.name.localeCompare(b.name);
  const scanned = assets.filter((a) => a.lastDone && protocolOf(a) === 'tls').sort(byName);
  const servers = assets.filter((a) => a.lastDone && protocolOf(a) === 'ssh').sort(byName);
  body.appendChild(h('section', { class: 'card', 'aria-labelledby': 'doc-ep' },
    h('h2', { id: 'doc-ep' }, 'TLS endpoint reports'),
    h('p', { class: 'muted' }, 'The latest scan of each TLS endpoint. The security report has everything; the TLS and certificate reports are shorter extracts.'),
    scanned.length ? h('div', { class: 'tablewrap' }, h('table', { class: 'compact docs-table' },
      h('thead', null, h('tr', null, ['Endpoint', 'Result', 'Scanned', 'PDF reports', 'CBOM'].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, scanned.map((a) => {
        const d = a.lastDone, stem = stemOf(a.name), pdf = (kind) => `/api/v1/scans/${d.id}/report.pdf?kind=${kind}`;
        return h('tr', null,
          h('td', { class: 'namecell' }, h('a', { href: reportHref(a) }, a.name)),
          h('td', null, levelBadge(d.readinessLevel, false), ' ', bandBadge(d.band, d.score)),
          h('td', { class: 'muted nowrap', title: fmtDate(d.finishedAt) }, relTime(d.finishedAt)),
          h('td', { class: 'nowrap' }, dl('Security', pdf('full'), `${stem}-security-report.pdf`), ' ', dl('TLS', pdf('tls'), `${stem}-tls-report.pdf`), ' ',
            dl('Certificate', pdf('cert'), `${stem}-certificate-report.pdf`)),
          h('td', null, dl('CycloneDX', `/api/v1/scans/${d.id}/cbom?download=1`, `${stem}-cbom.json`)));
      })))) : h('p', { class: 'muted' }, 'No TLS endpoint has been scanned yet. ', h('a', { href: '#/' }, 'Scan one'), '.')));

  body.appendChild(h('section', { class: 'card', 'aria-labelledby': 'doc-ssh' },
    h('h2', { id: 'doc-ssh' }, 'SSH server reports'),
    h('p', { class: 'muted' }, 'The latest scan of each SSH server: readiness, the baseline verdict with the sshd_config lines to meet it, and every check.'),
    servers.length ? h('div', { class: 'tablewrap' }, h('table', { class: 'compact docs-table' },
      h('thead', null, h('tr', null, ['Server', 'Result', 'Scanned', 'PDF report', 'CBOM'].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, servers.map((a) => {
        const d = a.lastDone, stem = stemOf(a.name);
        return h('tr', null,
          h('td', { class: 'namecell' }, h('a', { href: reportHref(a) }, a.name)),
          h('td', null, levelBadge(d.readinessLevel, false), ' ', baselineWords(d)),
          h('td', { class: 'muted nowrap', title: fmtDate(d.finishedAt) }, relTime(d.finishedAt)),
          h('td', { class: 'nowrap' }, dl('SSH security report', `/api/v1/scans/${d.id}/report.pdf`, `${stem}-ssh-report.pdf`)),
          h('td', null, dl('CycloneDX', `/api/v1/scans/${d.id}/cbom?download=1`, `${stem}-cbom.json`)));
      })))) : h('p', { class: 'muted' }, 'No SSH server has been scanned yet. ', h('a', { href: '#/ssh' }, 'Add one'), '.')));

  // One row per machine.
  const withSnap = hosts.filter((x) => x.snapshotId);
  body.appendChild(h('section', { class: 'card', 'aria-labelledby': 'doc-m' },
    h('h2', { id: 'doc-m' }, 'Machine CBOMs'),
    h('p', { class: 'muted' }, 'The CBOM made from each machine\'s latest inventory.'),
    withSnap.length ? h('div', { class: 'tablewrap' }, h('table', { class: 'compact docs-table' },
      h('thead', null, h('tr', null, ['Machine', 'Quantum-vulnerable', 'Uploaded', 'CBOM'].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, withSnap.map((x) => h('tr', null,
        h('td', { class: 'namecell' }, h('a', { href: `#/machines/${x.id}` }, x.name)),
        h('td', null, x.summary ? String(x.summary.vulnerable) : '·'),
        h('td', { class: 'muted nowrap', title: fmtDate(x.snapshotAt) }, relTime(x.snapshotAt)),
        h('td', null, dl('CycloneDX', `/api/v1/hosts/${x.id}/snapshots/${x.snapshotId}/cbom`, `${stemOf(x.name)}-cbom.json`)))))))
      : h('p', { class: 'muted' }, 'No machine inventoried yet. ', h('a', { href: '#/machines' }, 'Add a machine'), '.')));

  // Spreadsheets and standards.
  const sys = systems && systems.systems ? systems.systems : [];
  body.appendChild(h('section', { class: 'card', 'aria-labelledby': 'doc-x' },
    h('h2', { id: 'doc-x' }, 'Spreadsheets and standards exports'),
    docRow('Endpoints (CSV)', 'One row per TLS endpoint and SSH server: post-quantum level, exposure and finding counts, the TLS hygiene score or the SSH baseline verdict.',
      dl('Download CSV', '/api/v1/export/assets.csv', 'cipherhorizon-endpoints.csv')),
    docRow('Systems (CSV)', 'One row per system with its migration rank and owner details.',
      dl('Download CSV', '/api/v1/systems/export.csv', 'cipherhorizon-systems.csv')),
    docRow('OMB M-23-02 inventory', sys.length ? 'The US federal cryptographic inventory format, one file per system.' : 'The US federal cryptographic inventory format, one file per system. Group endpoints and machines into systems first.',
      ...(sys.length ? omb(sys) : [h('a', { href: '#/systems', class: 'btn btn-secondary btn-sm' }, 'Open Systems')]))));
  return null;
}

// One system picker and one button (UX-REVIEW-008 P1): a button per system does not scale.
function omb(sys) {
  const pick = h('select', { 'aria-label': 'System to export' }, sys.map((s) => h('option', { value: String(s.id) }, s.name)));
  return [pick, button('Download CSV', () => {
    const s = sys.find((x) => String(x.id) === pick.value);
    api.download(`/api/v1/systems/${s.id}/m2302.csv`, `${stemOf(s.name)}-m2302.csv`).catch((e) => toast(e.message, 'error'));
  }, 'secondary', { class: 'btn btn-secondary btn-sm' })];
}
