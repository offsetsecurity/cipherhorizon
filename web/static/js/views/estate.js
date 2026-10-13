// Estate: the systems, in the order to look at them (PRD-003 REQ-UI-2). There is no score: each row
// says which published rule put it there, with the sources, and says when it rests on evidence alone.
import { h, clear } from '../dom.js';
import { api } from '../api.js';
import { badge, button, toast, skeleton, citations, empty } from '../ui.js';
import { getStartedEstate } from '../guide.js';
import { reasonList, systemHref } from '../estate-ui.js';
import { openAddDialog } from './assets.js';
import { uploadDialog } from './hosts.js';
import { importDialog } from './imports.js';

const EVIDENCE = {
  observed: ['scanned', 'good', 'Seen by this product’s own scan or collector'],
  imported: ['imported only', 'warn', 'Known only from imported documents: a lead, not verified'],
  none: ['nothing yet', 'none', 'No scan, collector or import has described it'],
};

/** The rank is a position, not a score, but the first few rows are worth a glance rather than a
 * read: a small filled pill instead of plain text, fading out after the third place. */
function rankPill(n) {
  const tier = n <= 3 ? `rank-${n}` : 'rank-n';
  return h('span', { class: `rankpill ${tier}` }, String(n));
}

function rulesPanel(rules) {
  return h('details', { class: 'more' }, h('summary', null, 'How the order is decided'),
    h('p', { class: 'hint' }, 'Four rules, applied in this order. Where two systems tie on one rule the next one decides. There is no composite score.'),
    h('ol', { class: 'why-list' }, (rules || []).map((r) => h('li', null,
      h('span', { class: 'why-rule' }, r.id), h('span', { class: 'why-text' }, r.title),
      h('span', { class: 'hint' }, r.text), citations(r.citations)))));
}

let stopPrevious = null;
let showAll = false;

export async function render(root, ctx = {}) {
  let timer = null;
  let alive = true;
  const stop = () => { alive = false; if (timer) clearTimeout(timer); };
  if (stopPrevious) stopPrevious(); // only one refresh loop ever runs
  stopPrevious = stop;
  root.appendChild(skeleton(5));
  const [est, sys, proposed] = await Promise.all([api.estate(), api.systems(), api.links('proposed')]);
  clear(root);
  const byId = new Map(sys.systems.map((s) => [s.id, s]));
  const reload = () => { stop(); root.replaceChildren(); return render(root, ctx); };
  // Adding a service from here means "scan it": the estate is only useful once something has been observed.
  const scanAll = async () => {
    try {
      const r = await api.scanMany({ all: true });
      if (r.queued) toast(`${r.queued} scan${r.queued === 1 ? '' : 's'} started. The order updates as they finish.`, 'success');
    } catch (e) { toast(e.message, 'error'); }
    await reload();
  };
  const addEndpoints = () => openAddDialog(scanAll, { scan: false }); // scanAll scans and the order updates here
  const upload = () => uploadDialog(reload);
  const doImport = () => importDialog(reload);

  root.appendChild(h('div', { class: 'page-head' },
    ctx.embedded ? h('div') : h('div', null, h('h1', null, 'Systems'),
      h('div', { class: 'sub' }, 'Your systems, in the order to move them to post-quantum cryptography')),
    h('div', { class: 'row' },
      est.ranking.length ? button('Export details (CSV)', () => api.download('/api/v1/systems/export.csv', 'systems.csv').catch((e) => toast(e.message, 'error'))) : null)));

  if (!est.ranking.length) {
    root.appendChild(ctx.embedded
      ? empty('No systems yet', 'Every endpoint you scan and every machine you inventory becomes part of a system. Start by scanning an endpoint.',
        button('Scan an endpoint', () => { location.hash = '#/'; }, 'primary'))
      : getStartedEstate({ onAddEndpoints: addEndpoints, onUpload: upload, onImport: doImport }));
    return stop;
  }

  // One line naming the next useful step.
  const evidenceOnly = est.ranking.filter((r) => r.evidenceOnly).length;
  const waiting = proposed.length;
  const next = waiting
    ? h('p', null, `${waiting} endpoint${waiting === 1 ? ' or machine may' : 's or machines may'} belong to an existing system. `, h('a', { href: '#/systems?tab=decisions' }, 'Decide'))
    : evidenceOnly
      ? h('p', null, `${evidenceOnly} system${evidenceOnly === 1 ? ' has' : 's have'} no owner details yet. Open one to add its owner, exposure and how long its data must stay secret; the order gets better.`)
      : null;
  if (next) root.appendChild(h('div', { class: 'callout info nextstep-line', role: 'status' }, next));

  root.appendChild(h('p', { class: 'text-2' }, 'Most exposed to later decryption first, then by exposure, criticality and defects. “Why” on a row shows the rule.'));
  root.appendChild(rulesPanel(est.rules));

  const PAGE = 300; // a large estate is drawn in part; the order is the same and the rest is one click away
  const rows = [];
  for (const r of est.ranking.slice(0, showAll ? est.ranking.length : PAGE)) {
    const meta = byId.get(r.systemId) || {};
    const [evLabel, evTone, evWhy] = EVIDENCE[r.evidence] || EVIDENCE.none;
    const detail = h('tr', { class: 'why-row', hidden: true }, h('td', { colspan: '7' },
      reasonList(r.reasons),
      r.missing && r.missing.length ? h('p', { class: 'hint' }, `Would change the order if provided: ${r.missing.join(', ')}.`) : null));
    const toggle = h('button', { type: 'button', class: 'btn btn-sm btn-secondary', 'aria-expanded': 'false', onclick: () => {
      const open = detail.hidden;
      detail.hidden = !open;
      toggle.setAttribute('aria-expanded', String(open));
      toggle.textContent = open ? 'Hide' : 'Why';
    } }, 'Why');
    rows.push(h('tr', null,
      h('td', { class: 'rankcell' }, rankPill(r.rank)),
      h('td', { class: 'namecell' }, h('a', { href: systemHref(r.systemId) }, r.name),
        r.evidenceOnly ? h('div', null, badge('no owner details yet', 'warn', r.basis)) : null),
      h('td', { class: 'nowrapcell' }, meta.owner || h('span', { class: 'muted' }, 'not provided')),
      h('td', { class: 'nowrapcell' }, [meta.environment, meta.exposure].filter(Boolean).join(' · ') || h('span', { class: 'muted' }, 'not provided')),
      h('td', { class: 'tiercell' }, r.tier),
      h('td', null, badge(evLabel, evTone, evWhy)),
      h('td', null, toggle)), detail);
  }
  // While scans are running, refresh the order every few seconds so it settles by itself.
  const poll = async () => {
    if (!alive) return;
    try {
      const running = (await api.scans('?status=running')).length + (await api.scans('?status=queued')).length;
      if (!alive) return;
      if (running) { timer = setTimeout(async () => { if (alive && location.hash === '#/' && !root.querySelector('[aria-expanded="true"]')) await reload(); else if (alive && location.hash === '#/') poll(); }, 3000); }
    } catch { /* the refresh is a convenience */ }
  };
  poll();
  root.appendChild(h('div', { class: 'tablewrap' }, h('table', null,
    h('caption', { class: 'sr-only' }, 'Systems in the order to look at them'),
    h('thead', null, h('tr', null, ['#', 'System', 'Owner', 'Environment · exposure', 'Placed by', 'Known from', ''].map((c) => h('th', { scope: 'col' }, c)))),
    h('tbody', null, rows))));
  if (!showAll && est.ranking.length > PAGE) {
    root.appendChild(h('p', { class: 'hint' }, `The first ${PAGE} of ${est.ranking.length} systems are shown, in order. `,
      button(`Show all ${est.ranking.length}`, () => { showAll = true; reload(); })));
  }
  return stop;
}
