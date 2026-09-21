// One host: what its CBOM says, algorithm by algorithm, with sources.
import { h, fmtDate } from '../dom.js';
import { api } from '../api.js';
import { badge, citations, button, empty } from '../ui.js';
import { uploadDialog } from './hosts.js';

export async function render(root, { args }) {
  const id = Number(args[0]);
  let data;
  try { data = await api.host(id); } catch (e) {
    if (e.status === 404) {
      root.appendChild(empty('This host no longer exists', null, button('Back to hosts', () => { location.hash = '#/hosts'; }, 'primary')));
      return null;
    }
    throw e;
  }
  const { host, history } = data;
  const s = host.summary;

  root.appendChild(h('p', null, h('a', { href: '#/hosts' }, '← Hosts')));
  root.appendChild(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, host.name),
      h('div', { class: 'sub' }, s ? `${s.producer || 'unknown producer'} · uploaded ${fmtDate(host.snapshotAt)}` : 'No CBOM uploaded')),
    h('div', { class: 'row' }, button('Upload a newer CBOM', () => uploadDialog(() => window.dispatchEvent(new HashChangeEvent('hashchange'))), 'primary'))));

  if (!s) { root.appendChild(empty('No CBOM for this host yet')); return null; }

  root.appendChild(h('div', { class: 'grid kpis' },
    h('div', { class: `card kpi ${s.vulnerable ? 'alert' : 'good'}` }, h('div', { class: 'n' }, String(s.vulnerable)), h('div', { class: 'l' }, 'Quantum-vulnerable algorithms')),
    h('div', { class: 'card kpi good' }, h('div', { class: 'n' }, String(s.safe)), h('div', { class: 'l' }, 'Quantum-safe algorithms')),
    h('div', { class: 'card kpi' }, h('div', { class: 'n' }, String(s.packages)), h('div', { class: 'l' }, 'Packages')),
    h('div', { class: 'card kpi' }, h('div', { class: 'n' }, String(s.unclassified.length)), h('div', { class: 'l' }, 'Not classified'))));

  root.appendChild(h('div', { class: 'callout info' }, h('b', null, 'Capability, not use. '),
    'A package listed under an algorithm can provide it. This inventory shows what the software is able to do, not what it is doing at runtime.'));

  root.appendChild(h('section', { class: 'card' }, h('h2', null, 'Algorithms'),
    s.algorithms.length ? h('div', { class: 'tablewrap' }, h('table', null,
      h('thead', null, h('tr', null, ['Algorithm', 'Verdict', 'Why', 'Provided by'].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, s.algorithms.map((a) => h('tr', null,
        h('td', null, h('b', null, a.name), a.oid ? h('div', { class: 'hint' }, `OID ${a.oid}`) : null),
        h('td', null, a.class === 'quantum-vulnerable' ? badge('▲ quantum-vulnerable', 'bad') : badge('✓ quantum-safe', 'good')),
        h('td', null, h('div', null, a.rationale), citations(a.basis), h('div', { class: 'hint' }, `Matched by ${a.matchedBy}`)),
        h('td', { class: 'muted' }, (a.providedBy || []).join(', ') || '–')))))) : h('p', { class: 'muted' }, 'No algorithms were found in this CBOM.')));

  if (s.unclassified.length) {
    root.appendChild(h('section', { class: 'card' }, h('h2', null, 'Not classified'),
      h('p', { class: 'muted' }, 'No evidence-backed rule exists for these, so they are listed rather than guessed at.'),
      h('ul', null, s.unclassified.map((u) => h('li', null, u)))));
  }

  root.appendChild(h('section', { class: 'card' }, h('h2', null, 'Upload history'),
    h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
      h('thead', null, h('tr', null, ['When', 'Vulnerable', 'Safe', 'Packages'].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, history.map((x) => h('tr', null, h('td', null, fmtDate(x.at)), h('td', null, String(x.vulnerable)), h('td', null, String(x.safe)), h('td', null, String(x.packages)))))))));
  return null;
}
