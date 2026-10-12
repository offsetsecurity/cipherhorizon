// All scans across every endpoint, with live progress and cancel.
import { h, clear, relTime, fmtDate, duration, startedByWord } from '../dom.js';
import { api } from '../api.js';
import { levelBadge, bandBadge, statusPill, progressBar, button, empty, toast, skeleton } from '../ui.js';

const FILTERS = [['', 'All'], ['running', 'Running'], ['queued', 'Queued'], ['done', 'Done'], ['failed', 'Failed'], ['canceled', 'Canceled']];

export async function render(root, ctx = {}) {
  let stopped = false, timer = null, status = '';
  const head = h('div', { class: 'page-head' }, ctx.embedded ? h('div') : h('div', null, h('h1', null, 'Scans'), h('div', { class: 'sub' }, 'Every scan, newest first')));
  const bar = h('div', { class: 'toolbar' });
  const list = h('div');
  root.append(head, bar, list);
  list.appendChild(skeleton(4));

  const drawBar = () => {
    clear(bar).appendChild(h('div', { class: 'tabs', role: 'tablist' }, FILTERS.map(([k, label]) =>
      h('button', { type: 'button', class: 'tab', role: 'tab', 'aria-selected': String(status === k),
        onclick: () => { status = k; drawBar(); load(); } }, label))));
  };

  const paint = (scans) => {
    clear(list);
    if (!scans.length) {
      list.appendChild(empty(status ? 'No scans with this status' : 'No scans yet', status ? null : 'Scans appear here once you scan an endpoint.',
        status ? null : button('Go to endpoints', () => { location.hash = '#/endpoints'; }, 'primary')));
      return;
    }
    list.appendChild(h('div', { class: 'tablewrap' }, h('table', null,
      h('thead', null, h('tr', null, ['Endpoint', 'Status', 'Readiness', 'Hygiene', 'Started by', 'Started', 'Took', ''].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, scans.map((s) => {
        const active = s.status === 'queued' || s.status === 'running';
        return h('tr', null,
          h('td', { class: 'namecell' }, h('a', { href: `#/endpoints/${s.assetId}${s.status === 'done' ? `?scan=${s.id}` : ''}` }, s.assetName),
            h('div', { class: 'sub' }, s.assetAddress)),
          h('td', null, statusPill(s.status), active ? progressBar(s.progressPct) : null,
            s.error ? h('div', { class: 'hint' }, s.error) : null),
          h('td', null, s.status === 'done' ? levelBadge(s.readinessLevel) : '·'),
          h('td', null, s.status === 'done' ? bandBadge(s.band, s.score) : '·'),
          h('td', { class: 'muted' }, startedByWord(s)),
          h('td', { class: 'muted', title: fmtDate(s.startedAt || s.queuedAt) }, relTime(s.startedAt || s.queuedAt)),
          h('td', { class: 'muted' }, s.startedAt ? duration(s.startedAt, s.finishedAt) : '·'),
          h('td', null, active ? button('Cancel', async () => {
            try { await api.cancelScan(s.id); toast('Scan canceled'); load(); } catch (e) { toast(e.message, 'error'); }
          }, 'secondary', { class: 'btn btn-secondary btn-sm' }) : null));
      })))));
  };

  const load = async () => {
    if (stopped) return;
    clearTimeout(timer);
    try {
      const scans = await api.scans(`?limit=100${status ? `&status=${status}` : ''}`);
      if (stopped) return;
      paint(scans);
      timer = setTimeout(load, scans.some((s) => s.status === 'queued' || s.status === 'running') ? 1200 : 6000);
    } catch (e) { toast(e.message, 'error'); timer = setTimeout(load, 8000); }
  };
  drawBar();
  await load();
  return () => { stopped = true; clearTimeout(timer); };
}
