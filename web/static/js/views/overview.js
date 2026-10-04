// Overview: the home page (UX-DESIGN-005). The scan box first, because a URL in and everything about
// it out is the product's promise; then where you stand, one tile per question, each opening its
// list; then the latest results and what to fix first.
import { h, clear, relTime, daysUntil } from '../dom.js';
import { api } from '../api.js';
import { levelBadge, bandBadge, statusPill, sevBadge } from '../ui.js';
import { scanForm } from './scan.js';
import { openAddDialog } from './assets.js';
import { addDataDialog } from './inventory.js';
import { collectDialog } from '../guide.js';
import { uploadDialog } from './hosts.js';
import { groupFindings } from './findings.js';

const plural = (n, one, many) => `${n} ${n === 1 ? one : many || `${one}s`}`;
const problemsOf = (d) => (d ? d.critical + d.high + d.medium + (d.low || 0) : 0);

function tile(href, cls, label, big, ...rest) {
  return h('a', { class: `card kpi fleet-tile ${cls}`, href },
    h('div', { class: 'fleet-label' }, label), h('div', { class: 'n' }, big), ...rest,
    h('span', { class: 'tile-go', 'aria-hidden': 'true' }, '›'));
}

/** Where you stand: endpoints, machines, findings, post-quantum, inventory, certificates. */
function standing(assets, hosts, inv) {
  const done = assets.filter((a) => a.lastDone);
  const failed = assets.filter((a) => !a.lastDone && a.latest?.status === 'failed').length;
  let exposed = 0, hybrid = 0, problems = 0, withProblems = 0, soonest = null;
  const sev = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const a of done) {
    const d = a.lastDone;
    if (d.hndlExposed) exposed++;
    if (d.readinessLevel >= 3) hybrid++;
    for (const k of Object.keys(sev)) sev[k] += d[k] || 0;
    const p = problemsOf(d);
    problems += p;
    if (p) withProblems++;
    const days = daysUntil(d.certNotAfter);
    if (days !== null && (soonest === null || days < soonest.days)) soonest = { days, name: a.name };
  }
  const hostVuln = hosts.reduce((n, x) => n + (x.summary?.vulnerable || 0), 0);
  const sevChips = [['critical', 'bad'], ['high', 'bad'], ['medium', 'warn'], ['low', 'neutral']].filter(([k]) => sev[k]).map(([k, t]) =>
    h('span', { class: `badge b-${t}` }, `${sev[k]} ${k}`));
  const bands = new Map();
  for (const a of done) if (a.lastDone.band) bands.set(a.lastDone.band, (bands.get(a.lastDone.band) || 0) + 1);
  const sound = (bands.get('Strong') || 0) + (bands.get('Sound') || 0);
  return h('section', { class: 'grid kpis fleet-tiles six', 'aria-label': 'Where you stand' },
    tile('#/endpoints', '', 'Endpoints', String(assets.length),
      h('div', { class: 'note' }, done.length ? `${done.length} scanned${failed ? `, ${failed} failed` : ''} · ${sound} of ${done.length} rated Strong or Sound` : 'none scanned yet')),
    tile('#/machines', '', 'Machines', String(hosts.length),
      h('div', { class: 'note' }, hosts.length ? `${plural(hostVuln, 'quantum-vulnerable component')}` : 'run the inventory script to add one')),
    tile('#/findings', problems ? 'alert' : 'good', 'Findings', String(problems),
      h('div', { class: 'note' }, problems ? `problems on ${withProblems} of ${done.length} endpoints` : 'no problems found'),
      sevChips.length ? h('div', { class: 'fleet-chips' }, sevChips) : null),
    tile('#/endpoints', done.length && hybrid === done.length ? 'good' : 'warn', 'Post-quantum', done.length ? `${hybrid} of ${done.length}` : '–',
      h('div', { class: 'note' }, 'endpoints use post-quantum key exchange'),
      exposed ? h('div', { class: 'note fleet-warn' }, `${exposed} exposed to harvest-now-decrypt-later`) : null),
    tile('#/inventory', inv && inv.quantumVulnerable ? 'warn' : '', 'Inventory', inv ? String(inv.algorithm || 0) : '–',
      h('div', { class: 'note' }, inv ? `algorithms · ${inv.quantumVulnerable || 0} quantum-vulnerable · ${plural(inv.certificates || 0, 'certificate')}` : 'nothing yet')),
    tile('#/inventory/certificates', soonest && soonest.days <= 30 ? 'warn' : '', 'Next certificate expiry',
      soonest ? (soonest.days < 0 ? 'expired' : `${soonest.days} days`) : '–',
      h('div', { class: 'note' }, soonest ? soonest.name : 'no certificate seen')));
}

function recentRow(a) {
  const d = a.lastDone;
  const running = a.latest && (a.latest.status === 'queued' || a.latest.status === 'running');
  const p = problemsOf(d);
  return h('a', { class: 'recent-row', href: `#/endpoints/${a.id}` },
    h('span', { class: 'recent-name' }, h('b', null, a.name)),
    h('span', { class: 'recent-verdict' },
      running ? statusPill(a.latest.status) : null,
      d ? levelBadge(d.readinessLevel) : null,
      d ? bandBadge(d.band, d.score) : null,
      d ? h('span', { class: p ? 'muted' : 'ok-text' }, p ? plural(p, 'problem') : 'no problems') : null,
      !d && !running && a.latest ? statusPill(a.latest.status) : null),
    h('span', { class: 'recent-when muted' }, d ? relTime(d.finishedAt) : ''));
}

function fixFirst(findings) {
  const groups = groupFindings(findings.filter((f) => f.severity && f.severity !== 'info')).slice(0, 6);
  return h('section', { class: 'card overview-fix', 'aria-labelledby': 'fixfirst-h' },
    h('div', { class: 'row spread' }, h('h2', { id: 'fixfirst-h' }, 'What to fix first'), groups.length ? h('a', { href: '#/findings' }, 'All findings →') : null),
    groups.length
      ? h('ul', { class: 'firstfix' }, groups.map((fs) => h('li', null,
        h('a', { href: '#/findings', class: 'firstfix-row' }, sevBadge(fs[0].severity), h('span', { class: 'firstfix-title' }, fs[0].title),
          h('span', { class: 'muted' }, fs.length === 1 ? fs[0].assetName : plural(fs.length, 'place'))))))
      : h('p', { class: 'muted' }, 'Nothing to fix. Findings from your scans and machines appear here, worst first.'));
}

export async function render(root) {
  const { input, nodes } = scanForm('scan-target');
  const upload = () => uploadDialog((a) => { location.hash = `#/machines/${a.id}`; });
  root.appendChild(h('section', { class: 'scan-hero overview-hero', 'aria-labelledby': 'scan-h' },
    h('h1', { id: 'scan-h' }, 'Scan a website or endpoint'),
    h('p', { class: 'scan-lede' }, 'Get its TLS configuration, certificate, weaknesses, post-quantum readiness and CBOM in one report.'),
    ...nodes,
    h('p', { class: 'scan-more' },
      h('a', { href: '#', onclick: (e) => { e.preventDefault(); openAddDialog(() => { location.hash = '#/endpoints'; }); } }, 'Scan many endpoints'),
      h('span', { class: 'muted', 'aria-hidden': 'true' }, ' · '),
      h('a', { href: '#', onclick: (e) => { e.preventDefault(); collectDialog(upload); } }, 'Inventory a machine'),
      h('span', { class: 'muted', 'aria-hidden': 'true' }, ' · '),
      h('a', { href: '#', onclick: (e) => { e.preventDefault(); addDataDialog(); } }, 'Import a CBOM'))));
  const tiles = h('div');
  const lower = h('div', { class: 'overview-grid' });
  root.append(tiles, lower);
  input.focus();

  const [assets, hosts, inv, findings] = await Promise.all([
    api.assets('tls-endpoint').catch(() => []), api.hosts().catch(() => []),
    api.inventorySummary().catch(() => null), api.fleetFindings('').catch(() => [])]);
  if (!assets.length && !hosts.length) {
    lower.appendChild(h('p', { class: 'muted overview-empty' }, 'Scan an endpoint above, or inventory a machine, and this page shows where you stand.'));
    return null;
  }
  tiles.appendChild(standing(assets, hosts, inv));
  const shown = assets.filter((a) => a.lastDone || a.latest)
    .sort((a, b) => new Date(b.lastDone?.finishedAt || b.latest?.queuedAt || 0) - new Date(a.lastDone?.finishedAt || a.latest?.queuedAt || 0))
    .slice(0, 6);
  clear(lower).append(
    h('section', { class: 'card recent', 'aria-labelledby': 'recent-h' },
      h('div', { class: 'row spread' }, h('h2', { id: 'recent-h' }, 'Latest results'), h('a', { href: '#/endpoints' }, 'All endpoints →')),
      shown.length ? h('div', { class: 'recent-list' }, shown.map(recentRow)) : h('p', { class: 'muted' }, 'No endpoint scanned yet.'),
      hosts.length ? h('p', { class: 'hint' }, plural(hosts.length, 'machine'), ' inventoried · ', h('a', { href: '#/machines' }, 'Machines →')) : null),
    fixFirst(findings));
  return null;
}
