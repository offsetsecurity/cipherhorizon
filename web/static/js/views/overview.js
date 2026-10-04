// Overview: the home page (UX-DESIGN-005, DESIGN.md §8). The hero says what the product does and
// lets you do it (scan an address), with the readiness scale beside it as the legend for every
// level badge in the product. Below: where you stand as one status band, then the latest results
// and what to fix first.
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

// What each level means, in the words a reader needs to judge an endpoint.
const SCALE = [
  [4, 'L4', 'PQ-authenticated', 'Post-quantum key exchange and post-quantum certificates.'],
  [3, 'L3', 'Hybrid negotiated', 'A current client gets a post-quantum hybrid key exchange.'],
  [2, 'L2', 'Hybrid available', 'Offered, but a current client does not get it by default.'],
  [1, 'L1', 'Exposed', 'TLS 1.3 without post-quantum key exchange.'],
  [0, 'L0', 'Not ready', 'No TLS 1.3, so no post-quantum key exchange is possible.'],
];

function stat(href, tone, label, figure, ...rest) {
  return h('a', { class: `stat ${tone}`, href }, h('span', { class: 'stat-label' }, label), h('span', { class: 'stat-figure' }, figure), ...rest);
}

/** Where you stand, as one band of figures; each opens its place. */
function statusBand(assets, hosts, inv) {
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
  const sound = done.filter((a) => a.lastDone.band === 'Strong' || a.lastDone.band === 'Sound').length;
  return h('section', { class: 'statusband', 'aria-label': 'Where you stand' },
    stat('#/endpoints', '', 'Endpoints', String(assets.length),
      h('span', { class: 'stat-note' }, done.length ? `${done.length} scanned${failed ? `, ${failed} failed` : ''}; ${sound} rated Strong or Sound` : 'none scanned yet')),
    stat('#/machines', '', 'Machines', String(hosts.length),
      h('span', { class: 'stat-note' }, hosts.length ? plural(hostVuln, 'quantum-vulnerable component') : 'run the inventory script to add one')),
    stat('#/findings', problems ? 'bad' : 'good', 'Findings', String(problems),
      h('span', { class: 'stat-note' }, problems ? `problems on ${withProblems} of ${done.length} endpoints` : 'no problems found'),
      sevChips.length ? h('span', { class: 'stat-chips' }, sevChips) : null),
    stat('#/endpoints', done.length && hybrid === done.length ? 'good' : 'warn', 'Post-quantum', done.length ? `${hybrid} of ${done.length}` : 'none',
      h('span', { class: 'stat-note' }, 'endpoints use post-quantum key exchange'),
      exposed ? h('span', { class: 'stat-note fleet-warn' }, `${exposed} exposed to harvest-now-decrypt-later`) : null),
    stat('#/inventory', inv && inv.quantumVulnerable ? 'warn' : '', 'Inventory', inv ? String(inv.algorithm || 0) : 'none',
      h('span', { class: 'stat-note' }, inv ? `algorithms; ${inv.quantumVulnerable || 0} quantum-vulnerable, ${plural(inv.certificates || 0, 'certificate')}` : 'nothing yet')),
    stat('#/inventory/certificates', soonest && soonest.days <= 30 ? 'warn' : '', 'Next certificate expiry',
      soonest ? (soonest.days < 0 ? 'expired' : `${soonest.days} days`) : 'none',
      h('span', { class: 'stat-note' }, soonest ? soonest.name : 'no certificate seen')));
}

function recentRow(a) {
  const d = a.lastDone;
  const running = a.latest && (a.latest.status === 'queued' || a.latest.status === 'running');
  const p = problemsOf(d);
  return h('a', { class: 'recent-row', href: `#/endpoints/${a.id}` },
    h('span', { class: 'recent-name' }, a.name),
    h('span', { class: 'recent-verdict' },
      running ? statusPill(a.latest.status) : null,
      d ? levelBadge(d.readinessLevel) : null,
      d ? bandBadge(d.band, d.score) : null,
      !d && !running && a.latest ? statusPill(a.latest.status) : null),
    h('span', { class: 'recent-when' }, d ? `${p ? plural(p, 'problem') : 'no problems'} · ${relTime(d.finishedAt)}` : ''));
}

function fixFirst(findings) {
  const groups = groupFindings(findings.filter((f) => f.severity && f.severity !== 'info')).slice(0, 6);
  return h('section', { class: 'card', 'aria-labelledby': 'fixfirst-h' },
    h('div', { class: 'panel-head' }, h('h2', { id: 'fixfirst-h' }, 'What to fix first'), groups.length ? h('a', { href: '#/findings' }, 'All findings') : null),
    groups.length
      ? h('ul', { class: 'firstfix' }, groups.map((fs) => h('li', null,
        h('a', { href: '#/findings', class: 'firstfix-row' }, sevBadge(fs[0].severity), h('span', { class: 'firstfix-title' }, fs[0].title),
          h('span', { class: 'muted' }, fs.length === 1 ? fs[0].assetName : plural(fs.length, 'place'))))))
      : h('p', { class: 'muted' }, 'Nothing to fix. Findings from your scans and machines appear here, worst first.'));
}

function hero() {
  const { input, nodes } = scanForm('scan-target');
  const upload = () => uploadDialog((a) => { location.hash = `#/machines/${a.id}`; });
  const link = (label, fn) => h('a', { href: '#', onclick: (e) => { e.preventDefault(); fn(); } }, label);
  const section = h('section', { class: 'hero', 'aria-labelledby': 'scan-h' },
    h('div', { class: 'hero-main' },
      h('h1', { id: 'scan-h', class: 'hero-title' }, 'Scan a website or endpoint'),
      h('p', { class: 'hero-lede' }, 'TLS configuration, certificate, weaknesses, post-quantum readiness and a CBOM, from one address.'),
      ...nodes,
      h('p', { class: 'hero-more' },
        link('Scan many endpoints', () => openAddDialog(() => { location.hash = '#/endpoints'; })),
        link('Inventory a machine', () => collectDialog(upload)),
        link('Import a CBOM', () => addDataDialog()))),
    h('aside', { class: 'hero-scale', 'aria-labelledby': 'scale-h' },
      h('h2', { id: 'scale-h' }, 'Post-quantum readiness levels'),
      h('ol', { class: 'levels' }, SCALE.map(([l, code, name, what]) => h('li', { class: `level lv${l}` },
        h('span', { class: 'level-code' }, code),
        h('span', { class: 'level-name' }, name),
        h('span', { class: 'level-what' }, what))))));
  return { section, input };
}

export async function render(root) {
  const { section, input } = hero();
  const band = h('div');
  const lower = h('div', { class: 'overview-grid' });
  root.append(section, band, lower);
  input.focus();

  const [assets, hosts, inv, findings] = await Promise.all([
    api.assets('tls-endpoint').catch(() => []), api.hosts().catch(() => []),
    api.inventorySummary().catch(() => null), api.fleetFindings('').catch(() => [])]);
  if (!assets.length && !hosts.length) {
    lower.appendChild(h('p', { class: 'overview-empty' }, 'Scan an endpoint above, or inventory a machine, and this page shows where you stand.'));
    return null;
  }
  band.replaceWith(statusBand(assets, hosts, inv));
  const shown = assets.filter((a) => a.lastDone || a.latest)
    .sort((a, b) => new Date(b.lastDone?.finishedAt || b.latest?.queuedAt || 0) - new Date(a.lastDone?.finishedAt || a.latest?.queuedAt || 0))
    .slice(0, 6);
  clear(lower).append(
    h('section', { class: 'card recent', 'aria-labelledby': 'recent-h' },
      h('div', { class: 'panel-head' }, h('h2', { id: 'recent-h' }, 'Latest results'), h('a', { href: '#/endpoints' }, 'All endpoints')),
      shown.length ? h('div', { class: 'recent-list' }, shown.map(recentRow)) : h('p', { class: 'muted' }, 'No endpoint scanned yet.'),
      hosts.length ? h('p', { class: 'hint' }, `${plural(hosts.length, 'machine')} inventoried. `, h('a', { href: '#/machines' }, 'Machines')) : null),
    fixFirst(findings));
  return null;
}
