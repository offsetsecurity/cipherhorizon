// Find endpoints from a domain (PRD-022): give a domain, see the host names under it with where
// each came from, choose, and only then add and scan. Two pages share this module: the form with
// earlier runs (#/discover) and one run's review list (#/discover/ID).
import { h, clear, relTime, fmtDate } from '../dom.js';
import { api } from '../api.js';
import { badge, button, toast, empty, notice, skeleton, crumbs, confirmDialog, progressBar } from '../ui.js';

const SOURCES = {
  stored: ['Already here', 'Names in certificates this server has seen, and the endpoints it already has. Nothing leaves this server.'],
  dns: ['DNS records', 'The domain’s own name servers, mail servers, SPF and service records. Ordinary DNS queries.'],
  ct: ['Certificate logs', 'Every name that ever got a public certificate, from the public Certificate Transparency logs. Usually finds the most names.'],
  wordlist: ['Common names', 'Tries about 1,600 usual labels (www, mail, vpn, dev-api and the like). A few thousand DNS queries; about a minute.'],
  list: ['Your list', 'Names you supply, such as an export of your DNS zone. The only source that can be complete.'],
  domain: ['The domain', 'The domain itself.'],
};
const sourceWord = (id) => (SOURCES[id] || [id])[0];
const plural = (n, one, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
const STATUS = { running: ['Running', 'neutral'], done: ['Done', 'good'], failed: ['Failed', 'bad'], canceled: ['Canceled', 'neutral'] };
const statusBadge = (s) => badge((STATUS[s] || [s])[0], (STATUS[s] || [s, 'neutral'])[1]);

export async function render(root, { args }) {
  return args && args[0] ? renderRun(root, Number(args[0])) : renderHome(root);
}

// ---- the form and earlier runs ----------------------------------------------------------------

async function renderHome(root) {
  root.appendChild(crumbs([['TLS endpoints', '#/endpoints'], ['Find from a domain']]));
  root.appendChild(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Find from a domain'),
      h('div', { class: 'sub' }, 'Give a domain you own. CipherHorizon lists the host names under it and what answers on each. Nothing is added or scanned until you choose.'))));
  const formHost = h('div');
  const runsHost = h('div');
  root.append(formHost, runsHost);
  formHost.appendChild(skeleton(4));

  const data = await api.discoveries();
  const ct = data.settings || {};
  const running = (data.discoveries || []).find((d) => d.status === 'running');

  const domain = h('input', { type: 'text', id: 'disc-domain', placeholder: 'example.com', autocapitalize: 'none', spellcheck: 'false', autocomplete: 'off', required: true });
  const list = h('textarea', { id: 'disc-list', rows: 6, spellcheck: 'false', placeholder: 'intranet.example.com\nvpn.example.com\nbuild.corp.example.com' });
  const err = h('div', { class: 'callout bad', role: 'alert', hidden: true });
  const chosen = { stored: true, dns: true, ct: false, wordlist: false };
  const sourceRow = (id, disabled, note) => {
    const box = h('input', { type: 'checkbox', id: `disc-src-${id}`, checked: chosen[id] && !disabled, disabled, onchange: (e) => { chosen[id] = e.target.checked; } });
    return h('div', { class: 'setrow' },
      h('div', { class: 'setrow-switch' }, box),
      h('div', { class: 'setrow-text' },
        h('label', { for: `disc-src-${id}`, class: 'setrow-label' }, SOURCES[id][0]),
        h('p', { class: 'setrow-help' }, SOURCES[id][1], note ? [' ', note] : null)));
  };
  const ctNote = ct.certificateTransparency
    ? h('strong', null, `This sends the domain name to ${ct.service}.`)
    : h('span', null, `Turned off: it would send the domain name to ${ct.service}. An administrator can turn it on in `, h('a', { href: '#/settings' }, 'Settings'), '.');
  const submit = h('button', { type: 'submit', class: 'btn btn-primary', id: 'disc-start' }, 'Find names');
  const form = h('form', { class: 'card discover-form', 'aria-labelledby': 'disc-form-h', onsubmit: async (e) => {
    e.preventDefault();
    err.hidden = true;
    submit.disabled = true;
    try {
      const sources = Object.keys(chosen).filter((k) => chosen[k]);
      const rec = await api.startDiscovery({ domain: domain.value.trim(), sources, list: list.value });
      location.hash = `#/discover/${rec.id}`;
    } catch (ex) {
      err.textContent = ex.message;
      err.hidden = false;
      submit.disabled = false;
    }
  } },
  h('h2', { id: 'disc-form-h' }, 'A new search'),
  err,
  h('label', { for: 'disc-domain' }, 'Domain'), domain,
  h('div', { class: 'hint' }, 'The domain alone, without https:// or a path. Look only under domains you own or are authorised to test.',
    (data.scanScope || []).length ? ` This server may only scan ${data.scanScope.join(', ')}.` : ''),
  h('h3', { class: 'discover-h3' }, 'Where to look'),
  h('p', { class: 'text-2' }, 'No single place knows every name, so the result says which place reported each one.'),
  h('div', { class: 'setrows' }, sourceRow('stored'), sourceRow('dns'), sourceRow('ct', !ct.certificateTransparency, ctNote), sourceRow('wordlist')),
  h('details', { class: 'discover-list' },
    h('summary', null, 'Add names you already know'),
    h('label', { for: 'disc-list' }, 'One name per line'), list,
    h('div', { class: 'hint' }, 'Up to 20,000 names. An export of your DNS zone is the best list there is: it includes names used only inside your network. Names outside the domain are left out.')),
  h('div', { class: 'row' }, submit,
    running ? h('span', { class: 'hint' }, 'A search of ', h('a', { href: `#/discover/${running.id}` }, running.domain), ' is running; one runs at a time.') : null));
  if (running) submit.disabled = true;
  clear(formHost).appendChild(form);

  const runs = data.discoveries || [];
  if (runs.length) {
    runsHost.append(h('h2', { class: 'section-h' }, 'Earlier searches'),
      h('div', { class: 'tablewrap' }, h('table', null,
        h('thead', null, h('tr', null, ['Domain', 'Started', 'Status', 'Names found', 'Added', ''].map((c, i) => h('th', { scope: 'col', class: i === 3 || i === 4 ? 'num' : null }, c)))),
        h('tbody', null, runs.map((d) => h('tr', { class: 'rowlink', onclick: (e) => { if (!e.target.closest('a,button')) location.hash = `#/discover/${d.id}`; } },
          h('td', null, h('a', { class: 'mono', href: `#/discover/${d.id}` }, d.domain)),
          h('td', { class: 'nowrap', title: fmtDate(d.createdAt) }, relTime(d.createdAt), d.startedBy ? h('span', { class: 'muted' }, ` by ${d.startedBy}`) : null),
          h('td', null, statusBadge(d.status), d.status === 'running' ? h('span', { class: 'muted small' }, ` ${d.stage}`) : null),
          h('td', { class: 'num' }, d.status === 'done' ? d.names.toLocaleString() : '·'),
          h('td', { class: 'num' }, d.accepted ? d.accepted.toLocaleString() : '·'),
          h('td', { class: 'nowrap' }, h('a', { href: `#/discover/${d.id}` }, d.status === 'done' ? 'Review' : 'Open'))))))));
  }
  domain.focus();
  return null;
}

// ---- one run ------------------------------------------------------------------------------------

const FILTERS = {
  all: 'every name found', answering: 'names that answer on a port', external: 'names hosted elsewhere', silent: 'names on which nothing answered',
  unresolved: 'names that do not resolve', new: 'names new since the previous search',
  wildcard: 'names that resolve only to the address of any name',
};
const SHOWN = 300;

function matches(n, f) {
  switch (f) {
    // A name that only matches wildcard DNS answers wherever any name would: not counted here.
    case 'answering': return n.ports.length > 0 && !n.wildcard;
    case 'wildcard': return n.wildcard;
    case 'new': return n.new;
    case 'external': return n.external;
    case 'silent': return n.addresses.length > 0 && !n.ports.length;
    case 'unresolved': return !n.addresses.length;
    default: return true;
  }
}
// A name can be added when something answered on it and it may be reached.
const addable = (n) => n.ports.length > 0 && !n.refused;

async function renderRun(root, id) {
  let stopped = false;
  let timer = null;
  const head = h('div');
  const body = h('div');
  root.append(head, body);
  body.appendChild(skeleton(5));

  const state = { filter: 'answering', q: '', selected: new Set(), shown: SHOWN, scan: true, primed: false, result: null };

  const paintHead = (d) => {
    clear(head).append(
      crumbs([['TLS endpoints', '#/endpoints'], ['Find from a domain', '#/discover'], [d.domain]]),
      h('div', { class: 'page-head' },
        h('div', null, h('h1', null, h('span', { class: 'mono' }, d.domain), ' ', statusBadge(d.status)),
          h('div', { class: 'sub' }, `Searched ${relTime(d.createdAt)}${d.startedBy ? ` by ${d.startedBy}` : ''}. Looked in: ${d.sources.map(sourceWord).join(', ')}.`)),
        h('div', { class: 'row' },
          d.status === 'running'
            ? button('Cancel', async () => { try { await api.cancelDiscovery(id); load(); } catch (e) { toast(e.message, 'error'); } })
            : [h('a', { class: 'btn btn-secondary', href: '#/discover' }, 'New search'),
              button('Delete', async () => {
                if (!(await confirmDialog('Delete this search?', 'The list of names is removed. Endpoints you added from it stay.', 'Delete'))) return;
                try { await api.deleteDiscovery(id); location.hash = '#/discover'; } catch (e) { toast(e.message, 'error'); }
              }, 'ghost')])));
  };

  async function load() {
    if (stopped) return;
    let data;
    try { data = await api.discovery(id); } catch (e) {
      clear(head);
      clear(body).appendChild(notice('We could not find that search', 'It may have been deleted.', h('a', { class: 'btn btn-primary', href: '#/discover' }, 'Find from a domain')));
      return;
    }
    if (stopped) return;
    const d = data.discovery;
    paintHead(d);
    if (d.status === 'running') {
      const m = /(\d+) of (\d+)/.exec(d.stage || '');
      clear(body).appendChild(h('section', { class: 'card discover-running', 'aria-live': 'polite' },
        h('h2', null, 'Looking for names'),
        h('p', { class: 'discover-stage' }, d.stage ? `${d.stage[0].toUpperCase()}${d.stage.slice(1)}` : 'Starting'),
        progressBar(m ? Math.round((100 * Number(m[1])) / Math.max(1, Number(m[2]))) : 4),
        h('p', { class: 'hint' }, 'This page updates by itself. You can leave it: the search goes on, and the result is kept under Earlier searches.')));
      timer = setTimeout(load, 1500);
      return;
    }
    if (d.status !== 'done') {
      clear(body).appendChild(h('div', { class: 'callout bad', role: 'status' },
        d.status === 'canceled' ? 'This search was canceled before it finished, so it has no result.' : `This search failed: ${d.error || 'no reason was recorded'}.`));
      return;
    }
    paintResult(d, data.names || []);
  }

  function paintResult(d, names) {
    const rep = d.report || {};
    const count = (f) => names.filter((n) => matches(n, f)).length;
    const anyNew = count('new');
    if (!state.primed) {
      // Start with what a person most likely wants: what answers, runs on their own hosts and is not added yet.
      for (const n of names) if (addable(n) && !n.external && !n.accepted && !n.tracked && !n.wildcard) state.selected.add(n.name);
      if (!count('answering')) state.filter = 'all';
      state.primed = true;
    }
    clear(body);

    const stat = (f, label, figure, note, tone = '') => h('div', { class: 'stat-cell' },
      h('button', { type: 'button', class: `stat stat-btn ${tone}`, 'aria-pressed': String(state.filter === f), onclick: () => { state.filter = f; state.shown = SHOWN; paintResult(d, names); } },
        h('span', { class: 'stat-label' }, label), h('span', { class: 'stat-figure' }, figure.toLocaleString()), h('span', { class: 'stat-note' }, note)));
    body.appendChild(h('section', { class: `statusband${anyNew ? '' : ' five'}`, 'aria-label': 'What was found; choose a figure to list those names' },
      stat('all', 'Names found', names.length, rep.truncated ? `stopped at the limit of ${(rep.maxNames || 0).toLocaleString()}` : `under ${d.domain}`),
      stat('answering', 'Answering', count('answering'), `on port ${(rep.ports || []).join(', ')}${rep.mailPort ? `, or ${rep.mailPort} on mail servers` : ''}`, count('answering') ? 'good' : ''),
      stat('external', 'Hosted elsewhere', count('external'), 'an alias for a supplier’s host'),
      stat('silent', 'Nothing answered', count('silent'), 'resolve, but no port answered'),
      stat('unresolved', 'Do not resolve', count('unresolved'), 'named somewhere, no address now'),
      anyNew ? stat('new', 'New', anyNew, 'since the previous search', 'warn') : null));

    // Wildcard DNS: every name under the domain resolves, so a name from an old certificate looks
    // as alive as a real site. Say so once, with the count, and leave those names unchosen.
    const wild = count('wildcard');
    if (wild) {
      body.appendChild(h('div', { class: 'callout', role: 'note' },
        h('strong', null, `Every name under ${d.domain} resolves to ${(rep.wildcardAddresses || []).join(', ')}. `),
        `So ${plural(wild, 'name')} that ${wild === 1 ? 'resolves' : 'resolve'} only there look alive whether or not a site is behind them, and what answers there answers for any name. They are listed and not chosen. `,
        state.filter === 'wildcard' ? null : button('List them', () => { state.filter = 'wildcard'; state.shown = SHOWN; paintResult(d, names); }, 'secondary', { class: 'btn btn-secondary btn-sm' })));
    }
    if (state.result) body.appendChild(state.result);

    // The names.
    const bar = h('div', { class: 'toolbar' });
    const tableHost = h('div');
    const selbar = h('div', { class: 'selbar', role: 'region', 'aria-label': 'Add the chosen names' });
    const visible = () => {
      const q = state.q.trim().toLowerCase();
      return names.filter((n) => matches(n, state.filter) && (!q || n.name.includes(q) || n.addresses.join(' ').includes(q)));
    };
    const paintSel = () => {
      const picked = names.filter((n) => state.selected.has(n.name));
      const endpoints = picked.reduce((s, n) => s + n.ports.length, 0);
      const scanBox = h('input', { type: 'checkbox', id: 'disc-scan', checked: state.scan, onchange: (e) => { state.scan = e.target.checked; paintSel(); } });
      const go = button(picked.length ? `Add ${plural(endpoints, 'endpoint')}${state.scan ? ' and scan' : ''}` : 'Choose names to add', async () => {
        go.disabled = true;
        try {
          const r = await api.acceptDiscovery(id, { names: picked.map((n) => n.name), scan: state.scan });
          state.selected.clear();
          const parts = [`${plural(r.added, 'endpoint')} added from ${plural(r.names, 'name')}`];
          if (r.duplicate) parts.push(`${r.duplicate.toLocaleString()} already present`);
          if (r.queued) parts.push(`${plural(r.queued, 'scan')} queued`);
          state.result = h('div', { class: `callout ${r.invalid ? '' : 'info'}`, role: 'status' },
            `${parts.join(', ')}. They are tagged `, h('code', null, r.tag), '. ',
            h('a', { href: '#/endpoints' }, 'Open TLS endpoints'), ' or ', h('a', { href: '#/ssh' }, 'SSH servers'), '.',
            r.invalid ? h('ul', { class: 'results' }, (r.problems || []).filter((p) => p.status === 'invalid').map((p) => h('li', null, h('code', null, p.target), h('span', { class: 'muted' }, ` · ${p.reason}`)))) : null);
          toast(r.queued ? `${r.added} added; scanning` : `${r.added} added`, 'success');
          load();
        } catch (e) { toast(e.message, 'error'); go.disabled = false; }
      }, 'primary', { id: 'disc-accept', disabled: !picked.length });
      clear(selbar).append(
        h('span', { class: 'selbar-count' }, h('strong', null, picked.length.toLocaleString()), ` of ${names.filter(addable).length.toLocaleString()} answering names chosen`),
        h('span', { class: 'grow' }),
        h('label', { class: 'row checkrow', for: 'disc-scan' }, scanBox, h('span', null, 'Scan now')),
        go);
    };
    const paintTable = () => {
      const list = visible();
      const pickable = list.filter(addable);
      const allOn = pickable.length > 0 && pickable.every((n) => state.selected.has(n.name));
      const someOn = pickable.some((n) => state.selected.has(n.name));
      const all = h('input', { type: 'checkbox', 'aria-label': `Choose all ${pickable.length} answering names in this view`, checked: allOn, disabled: !pickable.length,
        onchange: (e) => { for (const n of pickable) { if (e.target.checked) state.selected.add(n.name); else state.selected.delete(n.name); } paintTable(); paintSel(); } });
      all.indeterminate = someOn && !allOn;
      clear(tableHost);
      if (!list.length) {
        tableHost.appendChild(empty(state.q ? 'No name matches that filter' : 'No names in this view', state.q ? 'Clear the filter to see every name.' : 'Choose All names to see everything this search found.'));
        return;
      }
      tableHost.appendChild(h('div', { class: 'tablewrap' }, h('table', { class: 'discover-names' },
        h('thead', null, h('tr', null, h('th', { class: 'checkcol' }, all),
          ['Name', 'Address', 'Answers on', 'Found by', 'Notes'].map((c) => h('th', { scope: 'col' }, c)))),
        h('tbody', null, list.slice(0, state.shown).map((n) => {
          const can = addable(n);
          const box = h('input', { type: 'checkbox', 'aria-label': `Choose ${n.name}`, checked: state.selected.has(n.name), disabled: !can,
            onchange: (e) => { if (e.target.checked) state.selected.add(n.name); else state.selected.delete(n.name); paintSel(); all.checked = pickable.every((x) => state.selected.has(x.name)); all.indeterminate = !all.checked && pickable.some((x) => state.selected.has(x.name)); } });
          const notes = [];
          if (n.accepted) notes.push(badge('Added', 'good'));
          else if (n.tracked) notes.push(badge('Already an endpoint', 'neutral'));
          if (n.new) notes.push(badge('New', 'warn'));
          if (n.wildcard) notes.push(h('span', { class: 'note muted' }, 'Same address as any name under the domain'));
          if (n.external) notes.push(h('span', { class: 'note' }, 'Hosted elsewhere: ', h('span', { class: 'mono' }, n.cname)));
          else if (n.cname) notes.push(h('span', { class: 'note muted' }, 'Alias for ', h('span', { class: 'mono' }, n.cname)));
          if (n.refused) notes.push(h('span', { class: 'note' }, `May not be reached: ${n.refused}`));
          if (!n.addresses.length) notes.push(h('span', { class: 'note muted' }, 'Does not resolve'));
          else if (!n.ports.length && !n.refused) notes.push(h('span', { class: 'note muted' }, 'Nothing answered'));
          return h('tr', { class: can ? null : 'dim' },
            h('td', { class: 'checkcol' }, box),
            h('td', { class: 'mono' }, n.name),
            h('td', { class: 'mono small' }, n.addresses.length ? [n.addresses[0], n.addresses.length > 1 ? h('span', { class: 'muted' }, ` +${n.addresses.length - 1}`) : null] : h('span', { class: 'muted' }, '·')),
            h('td', { class: 'nowrap' }, n.ports.length ? n.ports.map((p) => h('span', { class: 'tag' }, p === 22 ? '22 SSH' : p === 25 ? '25 mail' : String(p))) : h('span', { class: 'muted' }, '·')),
            h('td', { class: 'small' }, n.sources.map(sourceWord).join(', ')),
            h('td', { class: 'small' }, notes.length ? h('span', { class: 'notes' }, notes) : null));
        })))));
      if (list.length > state.shown) {
        tableHost.appendChild(h('div', { class: 'row discover-more' },
          h('span', { class: 'muted' }, `Showing ${state.shown.toLocaleString()} of ${list.length.toLocaleString()}. Choosing all applies to all ${pickable.length.toLocaleString()} answering names in this view.`),
          button('Show more', () => { state.shown += 1000; paintTable(); }, 'secondary', { class: 'btn btn-secondary btn-sm' })));
      }
    };
    const search = h('input', { type: 'search', placeholder: 'Filter by name or address', 'aria-label': 'Filter names', value: state.q,
      oninput: (e) => { state.q = e.target.value; state.shown = SHOWN; paintTable(); } });
    bar.append(search, h('span', { class: 'muted' }, `Listing: ${FILTERS[state.filter]}`));
    body.append(h('h2', { class: 'section-h' }, 'Names'), bar, tableHost, selbar);
    paintTable();
    paintSel();

    // Where the names came from, and what the search could not see.
    const srcRows = (rep.sources || []).map((s) => h('tr', null,
      h('td', { class: 'nowrap' }, h('strong', null, sourceWord(s.id))),
      h('td', null, s.status === 'ran' ? badge('Looked', 'good') : s.status === 'failed' ? badge('Failed', 'bad') : badge('Not used', 'neutral')),
      h('td', { class: 'num' }, s.status === 'ran' ? s.found.toLocaleString() : '·'),
      h('td', { class: 'small text-2' }, s.detail || (SOURCES[s.id] || [])[1] || '')));
    const limits = [];
    for (const s of rep.sources || []) if (s.status === 'failed') limits.push(`${sourceWord(s.id)} failed (${s.detail}), so names only it knows are missing. Search again later.`);
    if ((rep.sources || []).some((s) => s.id === 'ct' && s.status === 'off')) limits.push('Certificate logs were not searched. They usually know the most names.');
    if ((rep.wildcardCerts || []).length) limits.push(`Wildcard certificates (${rep.wildcardCerts.join(', ')}) cover names that no public source can list.`);
    if (rep.wildcard) limits.push(`Every name under ${d.domain} resolves (wildcard DNS), so whether a name with only that address is a real site cannot be told from DNS.${(rep.sources || []).some((s) => s.id === 'wordlist' && s.status === 'ran') ? ' Guessed names that only matched it were dropped.' : ''}`);
    if (rep.truncated) limits.push(`The search stopped at ${(rep.maxNames || 0).toLocaleString()} names; there are more.`);
    if (rep.outside) limits.push(`${plural(rep.outside, 'supplied name')} ${rep.outside === 1 ? 'is' : 'are'} not under ${d.domain} and ${rep.outside === 1 ? 'was' : 'were'} left out.`);
    limits.push('A name that appears in none of these places is not found. Your own DNS zone is the complete list: paste it under Add names you already know.');
    body.append(h('div', { class: 'discover-foot' },
      h('section', { 'aria-labelledby': 'disc-src-h' },
        h('h2', { class: 'section-h', id: 'disc-src-h' }, 'Where the names came from'),
        h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
          h('thead', null, h('tr', null, ['Place', 'This search', 'Names', ''].map((c, i) => h('th', { scope: 'col', class: i === 2 ? 'num' : null }, c)))),
          h('tbody', null, srcRows)))),
      h('section', { 'aria-labelledby': 'disc-lim-h' },
        h('h2', { class: 'section-h', id: 'disc-lim-h' }, 'What this search could not see'),
        h('ul', { class: 'discover-limits' }, limits.map((l) => h('li', null, l))))));
  }

  await load();
  return () => { stopped = true; clearTimeout(timer); };
}
