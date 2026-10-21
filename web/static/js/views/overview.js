// Overview: the home page (UX-DESIGN-005, DESIGN.md §8; UX-DESIGN-007 §5). The hero says what the
// product does and lets you do it (scan an address), with the readiness scale beside it as the
// legend for every level badge, across every protocol. Below: where you stand as one status band
// with a card per protocol (each with its own measure, never added together), then the latest
// results and what to fix first.
import { h, clear, relTime, daysUntil } from '../dom.js';
import { api } from '../api.js';
import { levelBadge, bandBadge, statusPill, sevBadge, countUp } from '../ui.js';
import { mark } from '../charts.js';
import { scanForm } from './scan.js';
import { openAddDialog, protocolOf, reportHref, baselineWords } from './assets.js';
import { addDataDialog } from './inventory.js';
import { collectDialog } from '../guide.js';
import { uploadDialog } from './hosts.js';
import { groupFindings } from './findings.js';

const plural = (n, one, many) => `${n} ${n === 1 ? one : many || `${one}s`}`;
const problemsOf = (d) => (d ? d.critical + d.high + d.medium + (d.low || 0) : 0);

// What each level means, in the words a reader needs to judge an endpoint; then, per protocol,
// the rule that reaches it (the scale is shared, the rubric is each protocol's own).
const SCALE = [
  [4, 'L4', 'PQ-authenticated', 'Post-quantum key exchange and post-quantum authentication.',
    'L3 and an ML-DSA certificate, presented or held.', 'L3 and an ML-DSA host key (ssh-mldsa44-ed25519).'],
  [3, 'L3', 'Hybrid negotiated', 'A current client gets a post-quantum hybrid key exchange.',
    'Go’s client negotiates X25519MLKEM768.', 'OpenSSH 10.6 negotiates mlkem768x25519 or sntrup761.'],
  [2, 'L2', 'Hybrid available', 'Offered, but a current client does not get it by default.',
    'A hybrid group is accepted, not chosen.', 'A hybrid is offered, not chosen.'],
  [1, 'L1', 'Exposed', 'Only classical key exchange: recorded traffic is exposed.',
    'TLS 1.3 with no post-quantum group.', 'No post-quantum hybrid offered.'],
  [0, 'L0', 'Not ready', 'The protocol in use can not carry it.',
    'No TLS 1.3.', 'SSH-1 only.'],
];

// A figure of the status band: the whole cell opens its place (a stretched link), and `links` are
// doors of their own beside it, such as "2 critical" (PRD-009 REQ-CHT-4). They sit outside the
// cell's link, never inside it: a link inside a link is neither valid nor reachable by keyboard.
function stat(href, tone, label, figure, rest, links) {
  const fig = h('span', { class: 'stat-figure' }, figure);
  countUp(fig, `overview:${label}`, figure);
  const shown = (links || []).filter(Boolean);
  return h('div', { class: `stat-cell ${tone}` },
    h('a', { class: `stat ${tone}`, href }, h('span', { class: 'stat-label' }, label), fig, ...(rest || [])),
    shown.length ? h('div', { class: 'stat-links' }, shown) : null);
}

/** A protocol's card (UX-DESIGN-007 §5): how many, how many exposed, and its own measure. The
 *  exposed count opens that protocol's list filtered to the exposed ones (PRD-009 REQ-CHT-4). */
function protocolCard(protocol, list) {
  const done = list.filter((a) => a.lastDone);
  const failed = list.filter((a) => !a.lastDone && a.latest?.status === 'failed').length;
  const exposed = done.filter((a) => a.lastDone.hndlExposed).length;
  const exposedLink = exposed ? h('a', { class: 'stat-sublink fleet-warn', href: `${protocol === 'ssh' ? '#/ssh' : '#/endpoints'}?exposed=1` },
    `${exposed} exposed to harvest-now-decrypt-later`) : null;
  if (protocol === 'ssh') {
    const judged = done.filter((a) => a.lastDone.baselineMeets === true || a.lastDone.baselineMeets === false);
    const meets = judged.filter((a) => a.lastDone.baselineMeets).length;
    const ssh1 = done.filter((a) => a.lastDone.readinessLevel === 0).length;
    return stat('#/ssh', judged.length && meets < judged.length ? 'warn' : '', 'SSH servers', String(list.length), [
      h('span', { class: 'stat-note' }, !list.length ? 'none added yet: add one'
        : done.length ? `${meets} of ${judged.length} meet the baseline${failed ? `; ${failed} failed` : ''}` : 'none scanned yet'),
      ssh1 ? h('span', { class: 'stat-note fleet-warn' }, `${ssh1} offer${ssh1 === 1 ? 's' : ''} SSH-1 only`) : null], [exposedLink]);
  }
  const expiring = done.filter((a) => { const d = daysUntil(a.lastDone.certNotAfter); return d !== null && d <= 30; }).length;
  return stat('#/endpoints', expiring ? 'warn' : '', 'TLS endpoints', String(list.length), [
    h('span', { class: 'stat-note' }, !list.length ? 'none added yet: scan one above'
      : !done.length ? 'none scanned yet' : failed ? `${failed} failed to scan` : `${done.length} scanned`),
    expiring ? h('span', { class: 'stat-note fleet-warn' }, `${plural(expiring, 'certificate')} expire${expiring === 1 ? 's' : ''} within 30 days`) : null], [exposedLink]);
}

/** Where you stand, as one band of figures; each opens its place. */
function statusBand(assets, hosts, inv) {
  const done = assets.filter((a) => a.lastDone);
  let hybrid = 0, problems = 0, withProblems = 0;
  const sev = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const a of done) {
    const d = a.lastDone;
    if (d.readinessLevel >= 3) hybrid++;
    for (const k of Object.keys(sev)) sev[k] += d[k] || 0;
    const p = problemsOf(d);
    problems += p;
    if (p) withProblems++;
  }
  const exposed = done.filter((a) => a.lastDone.hndlExposed).length;
  const hostVuln = hosts.reduce((n, x) => n + (x.summary?.vulnerable || 0), 0);
  // Each severity chip opens the findings of that severity (PRD-009 REQ-CHT-4).
  const sevChips = [['critical', 'bad'], ['high', 'bad'], ['medium', 'warn'], ['low', 'neutral']].filter(([k]) => sev[k]).map(([k, t]) =>
    h('a', { class: `badge b-${t} stat-chip`, href: `#/findings?severity=${k}`, 'aria-label': `${sev[k]} ${k}: open the ${k} findings` }, `${sev[k]} ${k}`));
  return h('section', { class: 'statusband', 'aria-label': 'Where you stand' },
    protocolCard('tls', assets.filter((a) => protocolOf(a) === 'tls')),
    protocolCard('ssh', assets.filter((a) => protocolOf(a) === 'ssh')),
    stat('#/machines', '', 'Machines', String(hosts.length), [
      h('span', { class: 'stat-note' }, hosts.length ? plural(hostVuln, 'quantum-vulnerable component') : 'run the inventory script to add one')]),
    stat('#/findings', problems ? 'bad' : 'good', 'Findings', String(problems), [
      h('span', { class: 'stat-note' }, problems ? `problems on ${withProblems} of ${done.length} scanned` : 'no problems found')], sevChips),
    stat('#/findings', done.length && hybrid === done.length ? 'good' : 'warn', 'Post-quantum', done.length ? `${hybrid} of ${done.length}` : 'none', [
      h('span', { class: 'stat-note' }, 'use post-quantum key exchange, across every protocol'),
      exposed ? h('span', { class: 'stat-note fleet-warn' }, `${exposed} exposed to harvest-now-decrypt-later`) : null]),
    stat('#/inventory', inv && inv.quantumVulnerable ? 'warn' : '', 'Inventory', inv ? String(inv.algorithm || 0) : 'none', [
      h('span', { class: 'stat-note' }, inv ? `algorithms; ${inv.quantumVulnerable || 0} quantum-vulnerable, ${plural(inv.certificates || 0, 'certificate')}` : 'nothing yet')]));
}

function recentRow(a) {
  const d = a.lastDone;
  const running = a.latest && (a.latest.status === 'queued' || a.latest.status === 'running');
  const p = problemsOf(d);
  const ssh = protocolOf(a) === 'ssh';
  return h('a', { class: 'recent-row', href: reportHref(a) },
    h('span', { class: 'recent-name' }, a.name, h('span', { class: 'tag' }, ssh ? 'SSH' : 'TLS')),
    h('span', { class: 'recent-verdict' },
      running ? statusPill(a.latest.status) : null,
      d ? levelBadge(d.readinessLevel) : null,
      d ? (ssh ? baselineWords(d) : bandBadge(d.band, d.score)) : null,
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
      h('p', { class: 'eyebrow' }, 'Post-quantum readiness · TLS · SSH · CBOM'),
      h('h1', { id: 'scan-h', class: 'hero-title' }, 'Scan an endpoint for post‑quantum readiness'),
      h('p', { class: 'hero-lede' }, 'See what each protocol you run would expose to a future quantum computer, and what to change first: a TLS endpoint or an SSH server, a readiness level from L0 to L4, every check with its source, and one CycloneDX CBOM.'),
      ...nodes,
      h('p', { class: 'hero-more' },
        link('Add many TLS endpoints', () => openAddDialog(() => { location.hash = '#/endpoints'; })),
        link('Add SSH servers', () => openAddDialog(() => { location.hash = '#/ssh'; }, { protocol: 'ssh' })),
        link('Inventory a machine', () => collectDialog(upload)),
        link('Import a CBOM', () => addDataDialog()))),
    h('aside', { class: 'hero-scale', 'aria-labelledby': 'scale-h' },
      h('h2', { id: 'scale-h' }, 'Post-quantum readiness levels'),
      h('ol', { class: 'levels' }, SCALE.map(([l, code, name, what]) => h('li', { class: `level lv${l}`, 'data-level': String(l) },
        h('span', { class: 'level-code' }, code),
        h('span', { class: 'level-name' }, name),
        h('span', { class: 'level-count' }),
        h('span', { class: 'level-what' }, what)))),
      h('details', { class: 'level-rules' }, h('summary', null, 'How each protocol reaches a level'),
        h('table', { class: 'compact' },
          h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Level'), h('th', { scope: 'col' }, 'For TLS'), h('th', { scope: 'col' }, 'For SSH'))),
          h('tbody', null, SCALE.map(([, code, , , tls, ssh]) => h('tr', null, h('th', { scope: 'row' }, code), h('td', null, tls), h('td', null, ssh))))))));
  return { section, input };
}

// UX-REVIEW-008 O1: once endpoints are scanned, the scale counts them, so the legend becomes the
// fleet's readiness at a glance instead of the same five lines on every visit.
function countLevels(assets) {
  const scanned = assets.filter((a) => a.lastDone && a.lastDone.readinessLevel !== null && a.lastDone.readinessLevel !== undefined);
  if (!scanned.length) return;
  const h2 = document.getElementById('scale-h');
  if (h2) h2.textContent = 'Your endpoints by post-quantum readiness';
  const ol = document.querySelector('.hero-scale .levels');
  if (ol) ol.setAttribute('data-chart', 'levels');
  // Each level with something at it opens the list of what is there (PRD-009 REQ-CHT-1): the row
  // itself when one protocol is at that level, two links when both are.
  for (const li of document.querySelectorAll('.hero-scale .level')) {
    const lv = Number(li.dataset.level);
    const at = scanned.filter((a) => a.lastDone.readinessLevel === lv);
    const n = at.length;
    const ssh = at.filter((a) => protocolOf(a) === 'ssh').length;
    const tls = n - ssh;
    const name = li.querySelector('.level-name')?.textContent || '';
    const slot = li.querySelector('.level-count');
    let count;
    if (!n) count = h('span', { class: 'muted' }, '0');
    else if (tls && ssh) {
      count = h('span', { class: 'level-split' },
        h('a', { href: `#/endpoints?level=${lv}`, 'aria-label': `${plural(tls, 'TLS endpoint')} at L${lv}: open them` }, `${tls} TLS`),
        h('a', { href: `#/ssh?level=${lv}`, 'aria-label': `${plural(ssh, 'SSH server')} at L${lv}: open them` }, `${ssh} SSH`));
    } else {
      const fig = h('span', null, String(n));
      countUp(fig, `levels:${lv}`, n);
      count = fig;
      const href = `${ssh ? '#/ssh' : '#/endpoints'}?level=${lv}`;
      const what = ssh ? plural(ssh, 'SSH server') : plural(tls, 'TLS endpoint');
      for (const [k, v] of Object.entries(mark({}, href, `${what} at L${lv} ${name}: open them`, { tip: `L${lv} ${name}`, sub: what }))) {
        if (k === 'class') li.classList.add(...v.split(' '));
        else if (v !== null) li.setAttribute(k, v);
      }
    }
    clear(slot).append(count);
    li.classList.toggle('level-empty', !n);
  }
}

export async function render(root) {
  const { section, input } = hero();
  const band = h('div');
  const lower = h('div', { class: 'overview-grid' });
  root.append(section, band, lower);
  input.focus();

  const [assets, hosts, inv, findings] = await Promise.all([
    api.assets().catch(() => []), api.hosts().catch(() => []),
    api.inventorySummary().catch(() => null), api.fleetFindings('').catch(() => [])]);
  if (!assets.length && !hosts.length) {
    lower.appendChild(h('p', { class: 'overview-empty' }, 'Scan an endpoint above, or inventory a machine, and this page shows where you stand.'));
    return null;
  }
  band.replaceWith(statusBand(assets, hosts, inv));
  countLevels(assets);
  const shown = assets.filter((a) => a.lastDone || a.latest)
    .sort((a, b) => new Date(b.lastDone?.finishedAt || b.latest?.queuedAt || 0) - new Date(a.lastDone?.finishedAt || a.latest?.queuedAt || 0))
    .slice(0, 6);
  clear(lower).append(
    h('section', { class: 'card recent', 'aria-labelledby': 'recent-h' },
      h('div', { class: 'panel-head' }, h('h2', { id: 'recent-h' }, 'Latest results'),
        h('span', { class: 'row' }, h('a', { href: '#/endpoints' }, 'TLS endpoints'), h('a', { href: '#/ssh' }, 'SSH servers'))),
      shown.length ? h('div', { class: 'recent-list' }, shown.map(recentRow)) : h('p', { class: 'muted' }, 'No endpoint scanned yet.'),
      hosts.length ? h('p', { class: 'hint' }, `${plural(hosts.length, 'machine')} inventoried. `, h('a', { href: '#/machines' }, 'Machines')) : null),
    fixFirst(findings));
  return null;
}
