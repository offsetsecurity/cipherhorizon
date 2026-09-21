// Endpoints: add, list, filter, select and scan.
import { h, clear, relTime, fmtDate } from '../dom.js';
import { api } from '../api.js';
import { levelBadge, bandBadge, statusPill, progressBar, button, empty, toast, modal, certExpiry, badge } from '../ui.js';

const NOTICE = 'Only add systems you own or are authorised to test. A scan makes a few hundred short TLS handshakes to each endpoint.';

// ---- the add dialog (AC-01.1 .. AC-01.4) -------------------------------------------------------

export function openAddDialog(onDone) {
  modal('Add endpoints', (close) => {
    let mode = 'single';
    const body = h('div', { class: 'modal-body' });
    const results = h('div');

    const parseTags = (s) => s.split(',').map((t) => t.trim()).filter(Boolean);

    const draw = () => {
      clear(body);
      const tabBar = h('div', { class: 'tabs', role: 'tablist' },
        [['single', 'Single endpoint'], ['bulk', 'Paste a list']].map(([k, label]) =>
          h('button', { type: 'button', class: 'tab', role: 'tab', 'aria-selected': String(mode === k), onclick: () => { mode = k; clear(results); draw(); } }, label)));
      body.appendChild(tabBar);

      const tags = h('input', { type: 'text', id: 'add-tags', placeholder: 'prod, payments' });
      const err = h('div', { class: 'callout bad', role: 'alert', hidden: true });
      const showErr = (m) => { err.textContent = m; err.hidden = false; };

      if (mode === 'single') {
        const target = h('input', { type: 'text', id: 'add-target', placeholder: 'example.com or example.com:8443', autocomplete: 'off', spellcheck: 'false' });
        const name = h('input', { type: 'text', id: 'add-name', placeholder: 'Optional friendly name' });
        body.appendChild(h('form', { onsubmit: async (e) => {
          e.preventDefault();
          err.hidden = true;
          try {
            const a = await api.addAsset(target.value, name.value, parseTags(tags.value));
            toast(`Added ${a.address}`, 'success');
            close();
            onDone && onDone(a);
          } catch (ex) { showErr(ex.message); }
        } },
          err,
          h('label', { for: 'add-target' }, 'Host or URL'), target,
          h('div', { class: 'hint' }, 'A hostname or IP, optionally with a port (default 443). A pasted URL is reduced to its host and port.'),
          h('label', { for: 'add-name' }, 'Name'), name,
          h('label', { for: 'add-tags' }, 'Tags'), tags,
          h('p', { class: 'hint' }, NOTICE),
          h('div', { class: 'row end' }, button('Cancel', close), h('button', { type: 'submit', class: 'btn btn-primary' }, 'Add endpoint'))));
        target.focus();
      } else {
        const text = h('textarea', { id: 'add-list', placeholder: 'api.example.com\nmail.example.com:993\nhttps://shop.example.com/', spellcheck: 'false' });
        body.appendChild(h('form', { onsubmit: async (e) => {
          e.preventDefault();
          err.hidden = true;
          clear(results);
          try {
            const r = await api.addBulk(text.value, parseTags(tags.value));
            results.appendChild(h('div', { class: r.invalid ? 'callout' : 'callout info', role: 'status' },
              `${r.added} added, ${r.duplicate} already present, ${r.invalid} invalid.`));
            if (r.results.length) {
              results.appendChild(h('ul', { class: 'results' }, r.results.map((x) => h('li', null,
                badge(x.status, x.status === 'added' ? 'good' : x.status === 'duplicate' ? 'neutral' : 'bad'), ' ',
                h('code', null, x.input), x.reason ? h('span', { class: 'muted' }, ` · ${x.reason}`) : null))));
            }
            if (r.added) { toast(`${r.added} endpoint(s) added`, 'success'); onDone && onDone(); }
          } catch (ex) { showErr(ex.message); }
        } },
          err,
          h('label', { for: 'add-list' }, 'One endpoint per line'), text,
          h('div', { class: 'hint' }, 'Blank lines and lines starting with # are ignored. One bad line never blocks the others.'),
          h('label', { for: 'add-tags' }, 'Tags for all of them'), tags,
          h('p', { class: 'hint' }, NOTICE),
          h('div', { class: 'row end' }, button('Close', close), h('button', { type: 'submit', class: 'btn btn-primary' }, 'Add endpoints'))));
        text.focus();
      }
      body.appendChild(results);
    };
    draw();
    return body;
  });
}

// ---- the list ------------------------------------------------------------------------------------

const SORTS = {
  name: (a, b) => a.name.localeCompare(b.name),
  level: (a, b) => (a.lastDone?.readinessLevel ?? 99) - (b.lastDone?.readinessLevel ?? 99),
  hygiene: (a, b) => (a.lastDone?.score ?? 999) - (b.lastDone?.score ?? 999),
  expiry: (a, b) => (new Date(a.lastDone?.certNotAfter || 8.64e15)) - (new Date(b.lastDone?.certNotAfter || 8.64e15)),
  scanned: (a, b) => (new Date(b.lastDone?.finishedAt || 0)) - (new Date(a.lastDone?.finishedAt || 0)),
};

export async function render(root) {
  let assets = [];
  let stopped = false, timer = null;
  const state = { q: '', sort: 'level', exposed: false, selected: new Set(), frozen: null };

  const header = h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Endpoints'), h('div', { class: 'sub' }, 'TLS endpoints you assess')),
    h('div', { class: 'row' },
      button('Add endpoints', () => openAddDialog(load), 'primary'),
      button('Scan all', async () => {
        try {
          const r = await api.scanMany({ all: true });
          toast(`${r.queued} scan(s) queued${r.alreadyActive ? `, ${r.alreadyActive} already running` : ''}.`, 'success');
          load();
        } catch (e) { toast(e.message, 'error'); }
      }),
      button('Export CSV', () => api.download('/api/v1/export/assets.csv', 'assets.csv').catch((e) => toast(e.message, 'error')))));
  const bar = h('div');
  const table = h('div');
  root.append(header, bar, table);

  // While scans are running their results arrive and would re-sort the list under the
  // cursor. Keep the order the user was looking at until the scans finish or they re-sort.
  const visible = () => {
    const list = assets
      .filter((a) => !state.q || `${a.name} ${a.address} ${a.tags.join(' ')}`.toLowerCase().includes(state.q.toLowerCase()))
      .filter((a) => !state.exposed || a.lastDone?.hndlExposed)
      .sort(SORTS[state.sort]);
    const busy = assets.some((a) => a.latest && (a.latest.status === 'queued' || a.latest.status === 'running'));
    if (!busy) { state.frozen = null; return list; }
    if (!state.frozen) { state.frozen = list.map((a) => a.id); return list; }
    const pos = (a) => { const i = state.frozen.indexOf(a.id); return i < 0 ? Infinity : i; };
    return list.sort((a, b) => pos(a) - pos(b));
  };

  const paint = () => {
    clear(bar); clear(table);
    if (!assets.length) {
      table.appendChild(empty('No endpoints yet', 'Add the TLS endpoints you want to assess.', button('Add endpoints', () => openAddDialog(load), 'primary')));
      return;
    }
    const list = visible();
    bar.appendChild(h('div', { class: 'toolbar' },
      h('input', { type: 'search', placeholder: 'Filter by name, address or tag', 'aria-label': 'Filter endpoints', value: state.q,
        oninput: (e) => {
          state.q = e.target.value; paint();
          const el = document.querySelector('#main input[type=search]');
          if (el) { el.focus(); el.setSelectionRange(el.value.length, el.value.length); }
        } }),
      h('label', { class: 'row' }, h('input', { type: 'checkbox', checked: state.exposed, onchange: (e) => { state.exposed = e.target.checked; paint(); } }),
        ' Only exposed to harvest-now-decrypt-later'),
      h('span', { class: 'grow' }),
      h('span', { class: 'muted' }, `${list.length} of ${assets.length}`)));
    if (state.selected.size) {
      bar.appendChild(h('div', { class: 'selbar' }, `${state.selected.size} selected`,
        button('Scan selected', async () => {
          try {
            const r = await api.scanMany({ assetIds: [...state.selected] });
            toast(`${r.queued} scan(s) queued.`, 'success');
            state.selected.clear(); load();
          } catch (e) { toast(e.message, 'error'); }
        }, 'primary', { class: 'btn btn-primary btn-sm' }),
        button('Clear', () => { state.selected.clear(); paint(); }, 'secondary', { class: 'btn btn-secondary btn-sm' })));
    }

    const th = (key, label) => h('th', { scope: 'col', 'aria-sort': state.sort === key ? 'ascending' : 'none' },
      key ? h('button', { type: 'button', onclick: () => { state.sort = key; state.frozen = null; paint(); } }, label + (state.sort === key ? ' ▲' : '')) : label);
    const allBox = h('input', { type: 'checkbox', 'aria-label': 'Select all shown', checked: list.length > 0 && list.every((a) => state.selected.has(a.id)),
      onchange: (e) => { for (const a of list) e.target.checked ? state.selected.add(a.id) : state.selected.delete(a.id); paint(); } });

    table.appendChild(h('div', { class: 'tablewrap' }, h('table', null,
      h('thead', null, h('tr', null, h('th', { scope: 'col' }, allBox), th('name', 'Endpoint'), th('level', 'PQC readiness'), th('hygiene', 'TLS hygiene'),
        th(null, 'Findings'), th('expiry', 'Certificate'), th('scanned', 'Last scan'), th(null, ''))),
      h('tbody', null, list.map(row)))));
  };

  const row = (a) => {
    const d = a.lastDone;
    const active = a.latest && (a.latest.status === 'queued' || a.latest.status === 'running');
    return h('tr', null,
      h('td', null, h('input', { type: 'checkbox', 'aria-label': `Select ${a.name}`, checked: state.selected.has(a.id),
        onchange: (e) => { e.target.checked ? state.selected.add(a.id) : state.selected.delete(a.id); paint(); } })),
      h('td', { class: 'namecell' }, h('a', { href: `#/assets/${a.id}` }, a.name), h('div', { class: 'sub' }, a.address,
        a.tags.length ? h('span', null, ' ', a.tags.map((t) => h('span', { class: 'tag' }, t))) : null)),
      h('td', null, d ? [levelBadge(d.readinessLevel), d.hndlExposed ? h('div', { class: 'hint' }, 'exposed to HNDL') : null]
        : (a.latest?.status === 'failed' ? badge('scan failed', 'bad', a.latest.error) : badge('Not scanned', 'none'))),
      h('td', null, d ? bandBadge(d.band, d.score) : '–'),
      h('td', null, d ? h('span', null, d.critical ? badge(`${d.critical} critical`, 'bad') : null, ' ', d.high ? badge(`${d.high} high`, 'warn') : null,
        !d.critical && !d.high ? h('span', { class: 'muted' }, 'none') : null) : '–'),
      h('td', null, d ? certExpiry(d.certNotAfter) : '–'),
      h('td', null, active ? h('div', null, statusPill(a.latest.status), progressBar(a.latest.progressPct))
        : d ? h('span', { class: 'muted', title: fmtDate(d.finishedAt) }, relTime(d.finishedAt)) : '–'),
      h('td', null, button(active ? 'Scanning…' : 'Scan', async () => {
        try { await api.scanAsset(a.id); toast(`Scan queued for ${a.address}`, 'success'); load(); } catch (e) { toast(e.message, 'error'); }
      }, 'secondary', { class: 'btn btn-secondary btn-sm', disabled: active })));
  };

  const load = async () => {
    if (stopped) return;
    clearTimeout(timer);
    try {
      assets = await api.assets();
      const active = assets.some((a) => a.latest && (a.latest.status === 'queued' || a.latest.status === 'running'));
      const typing = document.activeElement && document.activeElement.type === 'search';
      if (!typing) paint();
      timer = setTimeout(load, active ? 1200 : 7000);
    } catch (e) { toast(e.message, 'error'); timer = setTimeout(load, 8000); }
  };
  await load();
  return () => { stopped = true; clearTimeout(timer); };
}
