// TLS endpoints and SSH servers: add, list, filter, select and scan. One list serves both pages
// (UX-DESIGN-007 §3, §4.1); each protocol has its own columns and measure, never mixed.
import { h, clear, relTime, fmtDate, daysUntil, STARTTLS_NAMES } from '../dom.js';
import { api, ApiError } from '../api.js';
import { quickScan } from './scan.js';
import { levelBadge, bandBadge, statusPill, progressBar, button, empty, toast, modal, badge, skeleton } from '../ui.js';

// What a scan sends, said where something is added: each page for its own protocol.
const NOTICE = {
  tls: 'Only add systems you own or are authorised to test. A scan makes a few hundred short TLS handshakes.',
  ssh: 'Only add systems you own or are authorised to test. A scan runs a handful of SSH key exchanges and never logs in.',
};

// ---- the add dialog (AC-01.1 .. AC-01.4) -------------------------------------------------------

/** Where a protocol's endpoints live, and what they are called. */
export const PLACES = {
  tls: { list: '#/endpoints', one: 'TLS endpoint', many: 'TLS endpoints' },
  ssh: { list: '#/ssh', one: 'SSH server', many: 'SSH servers' },
};
export const protocolOf = (a) => (a.protocol === 'ssh' ? 'ssh' : 'tls');
export const reportHref = (a) => `${PLACES[protocolOf(a)].list}/${a.id}`;

// ENDPOINTS_CHANGED asks an open list to reload in place: the page's add button lives outside the
// list, and re-routing to refresh it would close the dialog showing a pasted list's results.
export const ENDPOINTS_CHANGED = 'cipherhorizon:endpoints-changed';

/**
 * openAddDialog is the one way to add endpoints on a page (UX-DESIGN-007): one address with its name,
 * tags and (for TLS) how it starts, or a pasted list. *Scan now* (on by default) scans what was
 * added; one address then opens its report, as the Overview's scan box does.
 */
export function openAddDialog(onDone, { protocol = 'tls', scan = true } = {}) {
  const here = PLACES[protocol];
  const added = (a) => `Added ${a.address}`;
  modal(`Add ${here.many}`, (close) => {
    let mode = 'single';
    // Kept across the two tabs, so the choice is not lost when switching.
    // A caller that scans what was added itself (the Systems first-run door) passes scan: false.
    let scanNow = scan;
    // The button says what will happen: add, or add and scan.
    const submitLabel = () => (scanNow ? 'Add and scan' : mode === 'single' ? `Add ${here.one}` : `Add ${here.many}`);
    const scanBox = () => !scan ? null : h('label', { class: 'row checkrow', for: 'add-scan' },
      h('input', { type: 'checkbox', id: 'add-scan', checked: scanNow, onchange: (e) => { scanNow = e.target.checked; const b = e.target.closest('form')?.querySelector('button[type=submit]'); if (b) b.textContent = submitLabel(); } }),
      h('span', null, 'Scan now'), h('span', { class: 'hint' }, mode === 'single' ? ' and open the report' : ' everything added'));
    const body = h('div', { class: 'modal-body' });
    const results = h('div');

    const parseTags = (s) => s.split(',').map((t) => t.trim()).filter(Boolean);

    const draw = () => {
      clear(body);
      const tabBar = h('div', { class: 'tabs', role: 'tablist' },
        [['single', protocol === 'ssh' ? 'One server' : 'Single endpoint'], ['bulk', 'Paste a list']].map(([k, label]) =>
          h('button', { type: 'button', class: 'tab', role: 'tab', 'aria-selected': String(mode === k), onclick: () => { mode = k; clear(results); draw(); } }, label)));
      body.appendChild(tabBar);

      const tags = h('input', { type: 'text', id: 'add-tags', placeholder: 'prod, payments' });
      const err = h('div', { class: 'callout bad', role: 'alert', hidden: true });
      const showErr = (m) => { err.textContent = m; err.hidden = false; };

      if (mode === 'single') {
        const target = h('input', { type: 'text', id: 'add-target', autocomplete: 'off', spellcheck: 'false',
          placeholder: protocol === 'ssh' ? 'bastion.example.com or bastion.example.com:2222' : 'example.com, example.com:8443 or smtp://mail.example.com' });
        const name = h('input', { type: 'text', id: 'add-name', placeholder: 'Optional friendly name' });
        // Each page adds its own protocol (UX-DESIGN-007 §3, §4.1): SSH servers asks nothing more; TLS
        // endpoints asks only how TLS starts. An address of the other protocol is refused with where it goes.
        const proto = protocol === 'ssh' ? null : h('select', { id: 'add-protocol' },
          h('option', { value: 'auto' }, 'Automatic (by port)'),
          h('option', { value: 'none' }, 'TLS from the first byte (HTTPS, IMAPS, LDAPS...)'),
          Object.entries(STARTTLS_NAMES).map(([v, l]) => h('option', { value: v }, `STARTTLS: ${l}`)));
        body.appendChild(h('form', { onsubmit: async (e) => {
          e.preventDefault();
          err.hidden = true;
          try {
            let a;
            try {
              a = await api.addAsset(target.value, name.value, parseTags(tags.value), proto ? proto.value : 'auto', protocol);
            } catch (ex) {
              // Already here: with Scan now, scan it again rather than refuse it.
              if (!(scanNow && ex instanceof ApiError && ex.status === 409)) throw ex;
              a = await quickScan(target.value, protocol);
              toast(`${a.address} was already here: scanning it again`, 'success');
              close();
              location.hash = reportHref(a);
              return;
            }
            if (scanNow) {
              await api.scanAsset(a.id);
              toast(`${added(a)}; scanning`, 'success');
              close();
              location.hash = reportHref(a);
              return;
            }
            toast(added(a), 'success');
            close();
            onDone && onDone(a);
          } catch (ex) { showErr(ex.message); }
        } },
          err,
          ...(protocol === 'ssh' ? [
            h('label', { for: 'add-target' }, 'Server'), target,
            h('div', { class: 'hint' }, 'A hostname or IP, optionally with a port: 22 unless you give one. ssh://host works too.'),
          ] : [
            h('label', { for: 'add-target' }, 'Host or URL'), target,
            h('div', { class: 'hint' }, 'A hostname or IP, optionally with a port (443 by default). A pasted URL is reduced to its host and port; smtp://, imap:// and the like choose STARTTLS.'),
            h('label', { for: 'add-protocol' }, 'How it starts TLS'), proto,
            h('div', { class: 'hint' }, 'Automatic: ports 25, 587, 143, 110, 21, 5222, 389 and 5432 use STARTTLS; everything else is TLS from the first byte.'),
          ]),
          h('label', { for: 'add-name' }, 'Name'), name,
          h('label', { for: 'add-tags' }, 'Tags'), tags,
          scanBox(),
          h('p', { class: 'hint' }, NOTICE[protocol]),
          h('div', { class: 'row end' }, button('Cancel', close), h('button', { type: 'submit', class: 'btn btn-primary' }, submitLabel()))));
        target.focus();
      } else {
        const text = h('textarea', { id: 'add-list', spellcheck: 'false', placeholder: protocol === 'ssh'
          ? 'bastion.example.com\ngit.example.com:2222\n10.0.0.12'
          : 'api.example.com\nmail.example.com:993\nsmtp://mail.example.com\nhttps://shop.example.com/' });
        body.appendChild(h('form', { onsubmit: async (e) => {
          e.preventDefault();
          err.hidden = true;
          clear(results);
          try {
            const r = await api.addBulk(text.value, parseTags(tags.value), protocol);
            results.appendChild(h('div', { class: r.invalid ? 'callout' : 'callout info', role: 'status' },
              `${r.added} added, ${r.duplicate} already present, ${r.invalid} invalid.`));
            if (r.results.length) {
              results.appendChild(h('ul', { class: 'results' }, r.results.map((x) => h('li', null,
                badge(x.status, x.status === 'added' ? 'good' : x.status === 'duplicate' ? 'neutral' : 'bad'), ' ',
                h('code', null, x.input), x.reason ? h('span', { class: 'muted' }, ` · ${x.reason}`) : null))));
            }
            if (r.added) {
              const ids = r.results.filter((x) => x.status === 'added' && x.asset).map((x) => x.asset.id);
              if (scanNow && ids.length) await api.scanMany({ assetIds: ids });
              toast(scanNow ? `${r.added} added; scanning` : `${r.added} added`, 'success');
              onDone && onDone();
            }
          } catch (ex) { showErr(ex.message); }
        } },
          err,
          h('label', { for: 'add-list' }, protocol === 'ssh' ? 'One server per line' : 'One endpoint per line'), text,
          h('div', { class: 'hint' }, protocol === 'ssh'
            ? 'Blank lines and lines starting with # are ignored. One bad line never blocks the others. Each line is an SSH server, on port 22 unless it gives one.'
            : 'Blank lines and lines starting with # are ignored. One bad line never blocks the others. STARTTLS is chosen by port, or by a scheme such as smtp:// or ldap://.'),
          h('label', { for: 'add-tags' }, 'Tags for all of them'), tags,
          scanBox(),
          h('p', { class: 'hint' }, NOTICE[protocol]),
          h('div', { class: 'row end' }, button('Close', close), h('button', { type: 'submit', class: 'btn btn-primary' }, submitLabel()))));
        text.focus();
      }
      body.appendChild(results);
    };
    draw();
    return body;
  });
}

// ---- the list ------------------------------------------------------------------------------------

const problems = (d) => (d ? d.critical + d.high + d.medium + (d.low || 0) : -1);

/** The findings of a result by severity, worst first; "No problems" when only notes remain. */
// One badge per row (UX-REVIEW-008 E2): the worst severity and its count, then how many problems
// in all. The report has the breakdown.
function findingCounts(d) {
  const worst = [['critical', 'bad'], ['high', 'bad'], ['medium', 'warn'], ['low', 'neutral']].find(([k]) => d[k]);
  if (!worst) return h('span', { class: 'ok-text' }, d.info ? `No problems · ${d.info} note${d.info === 1 ? '' : 's'}` : 'No problems');
  const total = problems(d);
  return h('span', { class: 'sevcounts' }, badge(`${d[worst[0]]} ${worst[0]}`, worst[1]),
    total > d[worst[0]] ? h('span', { class: 'muted' }, ` of ${total}`) : null);
}

/** An SSH server's default host key type (it does not expire). */
function hostKeyWords(d) {
  return d.hostKey ? h('span', null, d.hostKey) : h('span', { class: 'muted', title: 'No key exchange in common with this scanner, or the server answered none' }, 'not fetched');
}

/** An SSH server's baseline verdict (PRD-008 REQ-SHB-5): meets, N changes, or not judged. Text, never colour alone. */
export function baselineWords(d) {
  if (d.baselineMeets === true) return badge('✓ Meets', 'good', 'Meets the CipherHorizon SSH baseline 2026');
  if (d.baselineMeets === false) {
    const n = d.baselineChanges || 0;
    return badge(`${n} change${n === 1 ? '' : 's'}`, 'bad', 'Changes needed to meet the CipherHorizon SSH baseline 2026');
  }
  return h('span', { class: 'muted', title: 'The server\'s algorithm lists were not read, so it was not judged' }, 'not judged');
}
// meets first, then fewest changes; not judged last.
const baselineRank = (d) => (!d || d.baselineMeets === undefined || d.baselineMeets === null ? 1e6 : d.baselineMeets ? -1 : d.baselineChanges || 0);

/** Days until the certificate expires, in words (the column says Certificate). */
function certWords(iso) {
  const d = daysUntil(iso);
  if (d === null) return h('span', { class: 'muted' }, '·');
  if (d < 0) return badge(`expired ${-d} days ago`, 'bad');
  if (d <= 30) return badge(`${d} days left`, 'warn');
  return h('span', null, `${d} days left`);
}

const SORTS = {
  name: (a, b) => a.name.localeCompare(b.name),
  level: (a, b) => (a.lastDone?.readinessLevel ?? 99) - (b.lastDone?.readinessLevel ?? 99),
  hygiene: (a, b) => (a.lastDone?.score ?? 999) - (b.lastDone?.score ?? 999),
  baseline: (a, b) => baselineRank(a.lastDone) - baselineRank(b.lastDone),
  expiry: (a, b) => (new Date(a.lastDone?.certNotAfter || 8.64e15)) - (new Date(b.lastDone?.certNotAfter || 8.64e15)),
  findings: (a, b) => problems(b.lastDone) - problems(a.lastDone),
  scanned: (a, b) => (new Date(b.lastDone?.finishedAt || 0)) - (new Date(a.lastDone?.finishedAt || 0)),
};

export async function render(root, ctx = {}) {
  const protocol = ctx.protocol === 'ssh' ? 'ssh' : 'tls';
  const place = PLACES[protocol];
  let assets = [];
  let stopped = false, timer = null;
  const state = { q: '', sort: 'level', exposed: false, selected: new Set(), frozen: null };

  // The page's one way to add is its primary button (endpoints.js); the toolbar acts on the list.
  const actions = h('div', { class: 'row toolbar-actions' },
      button('Scan all', async () => {
        try {
          // This page's protocol only: Scan all on SSH servers scans the SSH servers.
          if (!assets.length) { toast(`No ${place.many} to scan yet.`); return; }
          const r = await api.scanMany({ assetIds: assets.map((a) => a.id) });
          toast(`${r.queued} scan(s) queued${r.alreadyActive ? `, ${r.alreadyActive} already running` : ''}.`, 'success');
          load();
        } catch (e) { toast(e.message, 'error'); }
      }),
      button('Export CSV', () => api.download('/api/v1/export/assets.csv', 'assets.csv').catch((e) => toast(e.message, 'error'))));
  const bar = h('div');
  const table = h('div');
  if (!ctx.embedded) root.append(h('div', { class: 'page-head' }, h('div', null, h('h1', null, place.many))));
  root.append(bar, table);
  table.appendChild(skeleton(4));

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
      bar.appendChild(h('div', { class: 'toolbar' }, h('span', { class: 'grow' }), actions));
      table.appendChild(protocol === 'ssh'
        ? empty('No SSH servers yet', 'Add the SSH servers you want to assess. A scan reads what the server offers and runs a few key exchanges; it never logs in.',
          button('Add SSH servers', () => openAddDialog(load, { protocol }), 'primary'))
        : empty('No TLS endpoints yet', 'Add the websites and TLS services you want to assess.', button('Add TLS endpoints', () => openAddDialog(load, { protocol }), 'primary')));
      return;
    }
    const list = visible();
    bar.appendChild(h('div', { class: 'toolbar' },
      h('input', { type: 'search', placeholder: 'Filter by name, address or tag', 'aria-label': `Filter ${place.many}`, value: state.q,
        oninput: (e) => {
          state.q = e.target.value; paint();
          const el = document.querySelector('#main input[type=search]');
          if (el) { el.focus(); el.setSelectionRange(el.value.length, el.value.length); }
        } }),
      h('label', { class: 'row' }, h('input', { type: 'checkbox', checked: state.exposed, onchange: (e) => { state.exposed = e.target.checked; paint(); } }),
        ' Only exposed to harvest-now-decrypt-later'),
      h('span', { class: 'muted' }, `${list.length} of ${assets.length}`),
      h('span', { class: 'grow' }),
      actions));
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
      h('thead', null, h('tr', null, h('th', { scope: 'col' }, allBox), protocol === 'ssh'
        ? [th('name', 'Server'), th('level', 'PQC readiness'), th('baseline', 'Baseline'), th('findings', 'Findings'), th(null, 'Host key')]
        : [th('name', 'Endpoint'), th('level', 'PQC readiness'), th('hygiene', 'TLS hygiene'), th('findings', 'Findings'), th('expiry', 'Certificate expiry')],
        th('scanned', 'Last scan'), th(null, h('span', { class: 'sr-only' }, 'Actions')))),
      h('tbody', null, list.map(row)))));
  };

  const row = (a) => {
    const d = a.lastDone;
    const active = a.latest && (a.latest.status === 'queued' || a.latest.status === 'running');
    const href = reportHref(a);
    const proto = protocol === 'ssh' ? (d && d.service ? d.service : null)
      : a.starttlsUsed ? `${STARTTLS_NAMES[a.starttlsUsed] || a.starttlsUsed} · STARTTLS` : null;
    const sub = [a.name !== a.address ? a.address : null, proto, ...a.tags.map((t) => h('span', { class: 'tag' }, t))].filter(Boolean);
    // The whole row opens the report; the checkbox and the Scan button keep their own clicks.
    return h('tr', { class: 'rowlink', onclick: (e) => { if (!e.target.closest('a, button, input, label')) location.hash = href; } },
      h('td', null, h('input', { type: 'checkbox', 'aria-label': `Select ${a.name}`, checked: state.selected.has(a.id),
        onchange: (e) => { e.target.checked ? state.selected.add(a.id) : state.selected.delete(a.id); paint(); } })),
      h('td', { class: 'namecell' }, h('a', { href }, a.name), sub.length ? h('div', { class: 'sub' }, sub.map((x, i) => [i ? (typeof x === 'string' && typeof sub[i - 1] === 'string' ? ' · ' : ' ') : '', x])) : null),
      h('td', null, d ? [levelBadge(d.readinessLevel), d.hndlExposed ? h('div', { class: 'hint' }, 'exposed to harvest-now-decrypt-later') : null]
        : (a.latest?.status === 'failed' ? badge('scan failed', 'bad', a.latest.error) : badge('Not scanned', 'none'))),
      protocol === 'ssh'
        ? [h('td', null, d ? baselineWords(d) : '·'), h('td', null, d ? findingCounts(d) : '·'), h('td', { class: 'nowrap' }, d ? hostKeyWords(d) : '·')]
        : [h('td', null, d ? bandBadge(d.band, d.score) : '·'), h('td', null, d ? findingCounts(d) : '·'), h('td', { class: 'nowrap' }, d ? certWords(d.certNotAfter) : '·')],
      h('td', { class: 'nowrap' }, active ? h('div', null, statusPill(a.latest.status), progressBar(a.latest.progressPct))
        : d ? h('span', { class: 'muted', title: fmtDate(d.finishedAt) }, relTime(d.finishedAt)) : '·'),
      h('td', { class: 'rowactions' },
        button(active ? 'Scanning…' : 'Scan', async () => {
          try { await api.scanAsset(a.id); toast(`Scan queued for ${a.address}`, 'success'); load(); } catch (e) { toast(e.message, 'error'); }
        }, 'secondary', { class: 'btn btn-ghost btn-sm', disabled: active })));
  };

  const load = async () => {
    if (stopped) return;
    clearTimeout(timer);
    try {
      assets = (await api.assets()).filter((a) => protocolOf(a) === protocol);
      const active = assets.some((a) => a.latest && (a.latest.status === 'queued' || a.latest.status === 'running'));
      const typing = document.activeElement && document.activeElement.type === 'search';
      if (!typing) paint();
      timer = setTimeout(load, active ? 1200 : 7000);
    } catch (e) { toast(e.message, 'error'); timer = setTimeout(load, 8000); }
  };
  const reload = () => load();
  window.addEventListener(ENDPOINTS_CHANGED, reload);
  await load();
  return () => { stopped = true; clearTimeout(timer); window.removeEventListener(ENDPOINTS_CHANGED, reload); };
}
