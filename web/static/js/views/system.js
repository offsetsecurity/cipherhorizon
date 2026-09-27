// One system: what it is, why it is where it is in the order, what it relies on, and the record of
// who said what (PRD-003 REQ-UI-3). Sections on one page so nothing is hidden behind a tab.
import { h, clear, fmtDate, relTime } from '../dom.js';
import { api } from '../api.js';
import { badge, button, toast, skeleton, levelBadge, bandBadge } from '../ui.js';
import { collectDialog } from '../guide.js';
import { coverageCard } from './host.js';
import { importDialog, notInterpretedTable } from './imports.js';
import { reasonList, certTable, anchorLine, strengthBadge, stateBadge, reasonDialog, validId } from '../estate-ui.js';

const LABELS = {
  name: 'Name', owner: 'Owner', environment: 'Environment', criticality: 'Criticality (FIPS 199 impact)', exposure: 'Exposure',
  dataLifetimeYears: 'How long the data must stay secret (years) · M-23-02 item 8', fismaId: 'FISMA system identifier · M-23-02 item 1',
  fips199: 'FIPS 199 categorisation · M-23-02 item 2', hvaId: 'High value asset identifier · M-23-02 item 3', hosting: 'Hosting · M-23-02 item 7',
  hostingProvider: 'Hosting provider', notes: 'Notes · M-23-02 item 9',
};
const ENUM_FIELDS = { environment: 'environment', criticality: 'criticality', exposure: 'exposure', fips199: 'fips199', hosting: 'hosting' };
const ORDER = ['name', 'owner', 'environment', 'exposure', 'criticality', 'dataLifetimeYears', 'fismaId', 'fips199', 'hvaId', 'hosting', 'hostingProvider', 'notes'];

function section(id, title, ...body) {
  return h('section', { class: 'card mt', id: `sec-${id}`, 'aria-labelledby': `h-${id}` }, h('h2', { id: `h-${id}`, tabindex: '-1' }, title), ...body);
}

const asText = (v) => (v === null || v === undefined ? '' : String(v));

function editor(sys, enums, onSaved) {
  const inputs = {};
  const fields = ORDER.map((f) => {
    let el;
    if (ENUM_FIELDS[f]) {
      el = h('select', { id: `sys-${f}` }, h('option', { value: '' }, 'not provided'),
        (enums[ENUM_FIELDS[f]] || []).map((v) => h('option', { value: v, selected: sys[f] === v }, v)));
    } else if (f === 'notes') {
      el = h('textarea', { id: `sys-${f}`, maxlength: '4000' });
      el.value = sys[f] || '';
    } else if (f === 'dataLifetimeYears') {
      el = h('input', { type: 'number', id: `sys-${f}`, min: '0', max: '200', step: '1', value: asText(sys[f]) });
    } else {
      el = h('input', { type: 'text', id: `sys-${f}`, maxlength: '200', autocomplete: 'off', value: asText(sys[f]) });
    }
    inputs[f] = el;
    return h('div', { class: 'field' }, h('label', { for: `sys-${f}` }, LABELS[f]), el);
  });
  const reason = h('input', { type: 'text', id: 'sys-reason', maxlength: '200', autocomplete: 'off' });
  const err = h('div', { class: 'callout bad', role: 'alert', hidden: true });
  return h('form', { class: 'system-form', onsubmit: async (e) => {
    e.preventDefault();
    err.hidden = true;
    const patch = {};
    for (const f of ORDER) {
      const v = inputs[f].value.trim();
      if (v === asText(sys[f])) continue;
      if (f === 'dataLifetimeYears') patch[f] = v === '' ? null : Number(v);
      else patch[f] = v === '' ? null : v;
    }
    if (!Object.keys(patch).length) { toast('Nothing changed', 'info'); return; }
    try {
      await api.patchSystem(sys.id, patch, reason.value.trim());
      toast('Saved', 'success');
      onSaved();
    } catch (ex) { err.textContent = ex.message; err.hidden = false; }
  } },
  err,
  h('p', { class: 'hint' }, 'Everything here is optional. Empty means “not provided”, and the system says so wherever it matters. Nothing is filled in for you.'),
  h('div', { class: 'grid two' }, fields),
  h('label', { for: 'sys-reason' }, 'Reason for the change (optional, kept in the audit trail)'), reason,
  h('div', { class: 'row end' }, h('button', { type: 'submit', class: 'btn btn-primary' }, 'Save details')));
}

function servicesTable(sys, endpointRows, hostRows) {
  if (!sys.assets.length) return h('p', { class: 'hint' }, 'No service or machine is attached. Its facts come from imported documents.');
  const dl = (path, name) => api.download(path, name).catch((x) => toast(x.message, 'error'));
  const rows = [];
  for (const a of sys.assets) {
    if (!validId(a.id)) continue;
    const ep = endpointRows.get(a.id);
    const ho = hostRows.get(a.id);
    const d = ep && ep.lastDone;
    const scanId = ep && ep.latest && validId(ep.latest.id) ? ep.latest.id : null;
    rows.push(h('tr', null,
      h('td', { class: 'namecell' }, h('a', { href: a.kind === 'host' ? `#/hosts/${a.id}` : `#/assets/${a.id}` }, a.name || a.address)),
      h('td', null, a.kind === 'host' ? 'machine' : 'service', h('div', { class: 'muted small' }, a.address)),
      h('td', null, d ? [levelBadge(d.readinessLevel), ' ', bandBadge(d.band, d.score)] : ho && ho.summary
        ? `${ho.summary.vulnerable} quantum-vulnerable, ${ho.summary.safe} safe` : h('span', { class: 'muted' }, 'not yet observed')),
      h('td', { class: 'muted' }, ep && ep.latest ? relTime(ep.latest.finishedAt || ep.latest.createdAt) : ho && ho.snapshotAt ? relTime(ho.snapshotAt) : '–'),
      h('td', null, scanId ? [
        button('CycloneDX 1.7', () => dl(`/api/v1/scans/${scanId}/cbom?download=1`, 'endpoint.cbom.json'), 'secondary', { class: 'btn btn-sm btn-secondary' }), ' ',
        button('1.6', () => dl(`/api/v1/scans/${scanId}/cbom?spec=1.6&download=1`, 'endpoint.cbom-1.6.json'), 'secondary', { class: 'btn btn-sm btn-secondary' })] : null)));
  }
  return h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
    h('caption', { class: 'sr-only' }, 'Services and machines in this system'),
    h('thead', null, h('tr', null, ['Name', 'Kind', 'Result', 'Seen', 'CBOM'].map((c) => h('th', { scope: 'col' }, c)))),
    h('tbody', null, rows)));
}

const show = (v) => (v === null || v === undefined || v === '' ? 'not provided' : typeof v === 'object' ? JSON.stringify(v).slice(0, 80) : String(v).slice(0, 120));

function auditList(entries) {
  if (!entries.length) return h('p', { class: 'hint' }, 'No changes recorded yet.');
  const changed = (e) => {
    const b = e.before && typeof e.before === 'object' ? e.before : {};
    const a = e.after && typeof e.after === 'object' ? e.after : {};
    return Object.keys({ ...b, ...a }).filter((k) => JSON.stringify(b[k]) !== JSON.stringify(a[k]) && k !== 'updatedAt' && k !== 'assets');
  };
  return h('ol', { class: 'audit' }, entries.map((e) => h('li', null,
    h('span', { class: 'muted', title: fmtDate(e.at) }, relTime(e.at)), ' ',
    h('b', null, e.action), ` by ${e.actor}`, e.reason ? h('span', null, ` — ${e.reason}`) : null,
    h('ul', null, changed(e).slice(0, 12).map((k) => h('li', null, `${k}: ${show(e.before && e.before[k])} → ${show(e.after && e.after[k])}`))))));
}

export async function render(root, { args }) {
  const id = args[0];
  if (!validId(id)) { location.hash = '#/'; return null; }
  root.appendChild(skeleton(6));
  const [sys, list, est, certs, links, imports, audit, assets, hosts] = await Promise.all([
    api.system(id), api.systems(), api.estate(), api.systemCertificates(id), api.systemLinks(id), api.imports(), api.systemAudit(id), api.assets(), api.hosts(),
  ]);
  clear(root);
  const reload = () => { root.replaceChildren(); return render(root, { args }); };
  const row = est.ranking.find((r) => r.systemId === sys.id);
  const endpointRows = new Map(assets.filter((a) => a.systemId === sys.id).map((a) => [a.id, a]));
  const hostRows = new Map(hosts.filter((x) => x.systemId === sys.id).map((x) => [x.id, x]));

  root.appendChild(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, sys.name),
      h('div', { class: 'sub' }, row ? `Place ${row.rank} of ${est.ranking.length} · ${row.tier}` : 'Not yet ranked'),
      row && row.evidenceOnly ? h('div', { class: 'mt-sm' }, badge('based on evidence only', 'warn', row.basis)) : null),
    h('div', { class: 'row' }, h('a', { class: 'btn btn-secondary', href: '#/' }, 'All systems'))));

  const jump = (k) => (e) => {
    e.preventDefault();
    const el = document.getElementById(`h-${k}`);
    if (el) { el.scrollIntoView({ block: 'start' }); el.focus(); }
  };
  root.appendChild(h('nav', { class: 'toc', 'aria-label': 'On this page' }, [
    ['why', 'Why here'], ['details', 'Details'], ['services', 'Services and machines'], ['certs', 'Certificates'], ['links', 'Matches'],
    ['imports', 'Imported'], ['coverage', 'Coverage'], ['export', 'Export'], ['history', 'History']].map(([k, t]) => h('a', { href: `#/systems/${sys.id}`, onclick: jump(k) }, t))));

  if (row) {
    root.appendChild(section('why', 'Why it is ranked here', reasonList(row.reasons),
      row.missing && row.missing.length ? h('p', { class: 'hint' }, `Would change the order if provided: ${row.missing.join(', ')}.`) : null));
  }
  root.appendChild(section('details', 'Details', editor(sys, list.enums, reload)));
  root.appendChild(section('services', 'Services and machines', servicesTable(sys, endpointRows, hostRows)));

  const ee = certs.certificates || [];
  root.appendChild(section('certs', 'Certificates',
    ee.length ? certTable(ee) : h('p', { class: 'hint' }, 'No end-entity certificate has been observed for this system.'),
    anchorLine(certs.trustAnchors),
    h('p', { class: 'hint' }, 'Only public certificate details are read. Where a machine holds a certificate, the certificate page says whether a key is associated in that store; it never reads the key.')));

  const undo = async (l) => {
    const reason = await reasonDialog('Undo this join', `${l.assetName} will leave “${l.systemName}” and will not be proposed again.`, 'Undo');
    if (reason === null) return;
    try { await api.rejectLink(l.id, reason); toast('Undone', 'success'); reload(); } catch (ex) { toast(ex.message, 'error'); }
  };
  root.appendChild(section('links', 'Matches between services and machines',
    links.length ? h('div', { class: 'stack' }, links.map((l) => h('div', { class: 'link-row' },
      h('div', { class: 'row' }, h('b', null, l.assetName), h('span', { class: 'muted' }, `→ ${l.systemName}`), strengthBadge(l.strength), stateBadge(l.state, l.stale)),
      h('ul', { class: 'why-list plain' }, (l.rules || []).map((r) => h('li', null, h('span', { class: 'why-rule' }, r.id), h('span', { class: 'why-text' }, r.detail)))),
      l.state === 'confirmed' && !l.decidedBy ? h('p', { class: 'hint' }, 'Joined automatically because the rules above matched from this product’s own scans and collectors.') : null,
      l.state === 'proposed' ? h('a', { class: 'btn btn-sm btn-primary', href: '#/review' }, 'Decide in the review queue') : null,
      l.state === 'confirmed' ? button('Undo', () => undo(l), 'secondary', { class: 'btn btn-sm btn-secondary' }) : null)))
      : h('p', { class: 'hint' }, 'No matches proposed or made for this system.')));

  const mine = imports.filter((r) => r.systemId === sys.id);
  root.appendChild(section('imports', 'Imported sources',
    mine.length ? mine.map((r) => h('div', { class: 'import-row' },
      h('div', { class: 'row' }, h('b', null, [r.toolName, r.toolVersion].filter(Boolean).join(' ') || 'unnamed tool'), badge(r.status, r.status === 'active' ? 'good' : 'neutral'),
        h('span', { class: 'muted' }, `${r.specVersion} · ${r.observations} facts · ${relTime(r.receivedAt)} · submitted by ${r.submittedBy || 'unknown'}`)),
      h('p', { class: 'hint' }, `The subject the file claims for itself: ${r.subjectClaim || 'none named'}. It is recorded, and never used to place its data.`),
      notInterpretedTable(r.notInterpreted)))
      : h('p', { class: 'hint' }, 'Nothing imported into this system.'),
    h('div', { class: 'row' }, button('Import a CBOM', () => importDialog(reload)))));

  const hostsWithCoverage = [...hostRows.values()].filter((x) => x.summary && x.summary.coverage);
  const cov = h('div');
  if (hostsWithCoverage.length) {
    for (const x of hostsWithCoverage) cov.appendChild(h('div', null, h('h3', null, x.name), coverageCard(x.summary.coverage, () => collectDialog())));
  } else {
    cov.appendChild(h('p', { class: 'text-2' }, row && row.evidence === 'observed'
      ? 'Only network scans describe this system: they see what a server offers, not the software or files on the machine behind it. Inventory the machine to see inside it.'
      : row && row.evidence === 'imported'
        ? 'Everything known about this system comes from imported documents. Nothing here was observed by this product, so treat it as a lead to verify.'
        : 'Nothing has observed this system yet.'));
  }
  root.appendChild(section('coverage', 'Coverage and blind spots', cov));

  const base = `/api/v1/systems/${sys.id}`;
  const dl = (path, name) => api.download(path, name).catch((x) => toast(x.message, 'error'));
  root.appendChild(section('export', 'Export',
    h('p', { class: 'text-2' }, 'The nine items of OMB M-23-02 Section II for this system, each marked provided or not provided. This supports the structure the memorandum describes; it is not a statement that the system complies with it.'),
    h('div', { class: 'row' },
      button('M-23-02 structure (JSON)', () => dl(`${base}/m2302.json`, `system-${sys.id}-m-23-02.json`)),
      button('M-23-02 structure (CSV)', () => dl(`${base}/m2302.csv`, `system-${sys.id}-m-23-02.csv`)))));

  root.appendChild(section('history', 'History', auditList(audit)));
  return null;
}
