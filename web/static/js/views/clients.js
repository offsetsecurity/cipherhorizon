// Clients (PRD-018): what each named client would negotiate with this server, simulated from
// the scan. The page answers, in order: who connects and who does not (and why); what each gets
// (version, suite, group, forward secrecy, post-quantum); then the profiles' provenance.
import { h, toCSV } from '../dom.js';
import { api } from '../api.js';
import { button } from '../ui.js';
import { stackBar } from '../viz.js';

const plural = (n, one, many) => `${n} ${n === 1 ? one : many || `${one}s`}`;
const FAMILY = { browser: 'Browsers', mobile: 'Mobile platforms', runtime: 'Runtimes', library: 'Libraries', legacy: 'Legacy clients' };
const FAMILY_ORDER = ['browser', 'mobile', 'runtime', 'library', 'legacy'];

/** One line for the Summary: "22 of 24 clients connect · 6 with post-quantum key exchange · 2 fail". */
export function clientsLine(sims) {
  const ok = sims.filter((c) => c.connects);
  const parts = [`${ok.length} of ${sims.length} clients connect`];
  const pq = ok.filter((c) => c.pq).length;
  if (pq) parts.push(`${pq} with post-quantum key exchange`);
  const noFs = ok.filter((c) => !c.forwardSecrecy).length;
  if (noFs) parts.push(`${noFs} without forward secrecy`);
  return parts.join(' · ');
}

function outcomeBar(sims) {
  const ok = sims.filter((c) => c.connects);
  return stackBar([
    { n: ok.filter((c) => c.pq).length, label: 'connect with post-quantum key exchange', tone: 'good' },
    { n: ok.filter((c) => !c.pq && c.forwardSecrecy).length, label: 'connect with forward secrecy', tone: 'ok' },
    { n: ok.filter((c) => !c.forwardSecrecy).length, label: 'connect without forward secrecy', tone: 'attention' },
    { n: sims.length - ok.length, label: 'cannot connect', tone: 'problem' },
  ]);
}

const shortSuite = (s) => (s || '').replace(/^TLS_/, '').replace(/_WITH_/, ' ').replace(/_/g, '-');

function row(c) {
  if (!c.connects) {
    return h('tr', { class: 'cl-row cl-fail' },
      h('td', { class: 'cl-name' }, h('b', null, c.name), h('div', { class: 'sub' }, c.released)),
      h('td', { colspan: 4, class: 'cl-why' }, h('span', { class: 'badge b-bad' }, 'Cannot connect'), ' ', c.why));
  }
  const tone = c.pq ? 'good' : c.forwardSecrecy ? 'ok' : 'warn';
  return h('tr', { class: `cl-row cl-${tone}` },
    h('td', { class: 'cl-name' }, h('b', null, c.name), h('div', { class: 'sub' }, c.released)),
    h('td', { class: 'nowrap' }, h('span', { class: `badge ${c.version === 'TLSv1.3' ? 'b-good' : c.version === 'TLSv1.2' ? 'b-neutral' : 'b-warn'}` }, c.version)),
    h('td', null, h('code', { title: c.suite }, shortSuite(c.suite)), c.decided === 'client' ? h('span', { class: 'lvltag', title: 'The server follows the client’s order' }, 'client order') : null),
    h('td', { class: 'nowrap' }, c.group ? h('span', { class: c.pq ? 'cl-pq' : '' }, c.pq ? '⬢ ' : '', c.group, c.helloRetry ? h('span', { class: 'lvltag', title: 'The client’s first key share did not match: one extra round trip' }, 'retry') : null) : h('span', { class: 'muted' }, 'static RSA')),
    h('td', { class: 'cl-flags' },
      h('span', { class: `badge ${c.forwardSecrecy ? 'b-good' : 'b-warn'}` }, c.forwardSecrecy ? 'forward secrecy' : 'no forward secrecy'),
      c.pq ? h('span', { class: 'badge b-good' }, 'post-quantum') : null,
      c.defaultCertificate ? h('span', { class: 'badge b-warn', title: c.note }, 'default certificate') : null));
}

function csv(ctx, sims) {
  const rows = sims.map((c) => [c.name, c.released, c.connects ? 'connects' : 'cannot connect', c.version || '', c.suite || '', c.group || '',
    c.connects ? (c.forwardSecrecy ? 'yes' : 'no') : '', c.connects ? (c.pq ? 'yes' : 'no') : '', c.why || c.note || '']);
  api.downloadBlob(`${ctx.stem}-clients.csv`, toCSV(['client', 'released', 'outcome', 'version', 'suite', 'group', 'forward secrecy', 'post-quantum', 'note'], rows), 'text/csv');
}

/** The Clients tab. ctx: { ev, stem } */
export function clientsView(ctx) {
  const sims = ctx.ev.clients || [];
  const wrap = h('div', { class: 'report clients' });
  if (!sims.length) {
    wrap.appendChild(h('section', { class: 'card' }, h('h2', null, 'Clients'),
      h('p', { class: 'muted' }, 'No simulation for this scan: it predates client simulation, or its protocol and suite stages did not run. Re-evaluate (More → Re-evaluate) or scan again.')));
    return wrap;
  }
  const failing = sims.filter((c) => !c.connects);
  const bar = outcomeBar(sims);
  const state = { only: false };
  const head = h('section', { class: 'card', 'aria-labelledby': 'cl-h' },
    h('div', { class: 'cfg-head' }, h('h2', { id: 'cl-h' }, failing.length ? `${plural(failing.length, 'client')} cannot connect` : 'Every client connects'),
      h('div', { class: 'row' },
        h('label', { class: 'row small' }, h('input', { type: 'checkbox', checked: state.only, onchange: (e) => { state.only = e.target.checked; paint(); } }), ' Only clients that fail or lose forward secrecy'),
        button('CSV', () => csv(ctx, sims), 'secondary', { class: 'btn btn-secondary btn-sm' }))),
    h('p', { class: 'std-lede' }, clientsLine(sims), '. Simulated from what this scan enumerated and each client’s published defaults; nothing was sent to the server. ',
      h('a', { href: '#/help?topic=clients' }, 'How clients are simulated')),
    bar.bar, bar.legend,
    failing.length ? h('div', { class: 'stdchips' }, failing.map((c) => h('span', { class: 'stdchip stdchip-bad', title: c.why },
      h('span', { class: 'stdchip-glyph', 'aria-hidden': 'true' }, '✕'), h('span', { class: 'stdchip-name' }, c.name)))) : null);
  wrap.appendChild(head);
  const body = h('div');
  const paint = () => {
    body.replaceChildren(...FAMILY_ORDER.map((fam) => {
      const list = sims.filter((c) => c.family === fam && (!state.only || !c.connects || !c.forwardSecrecy));
      if (!list.length) return null;
      return h('section', { class: 'card cl-group', 'aria-labelledby': `cl-${fam}` },
        h('h2', { id: `cl-${fam}` }, FAMILY[fam]),
        h('div', { class: 'tablewrap' }, h('table', { class: 'cl-table' },
          h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Client'), h('th', { scope: 'col' }, 'Version'), h('th', { scope: 'col' }, 'Cipher suite'), h('th', { scope: 'col' }, 'Key exchange'), h('th', { scope: 'col' }, 'Properties'))),
          h('tbody', null, list.map(row)))));
    }).filter(Boolean));
  };
  paint();
  wrap.appendChild(body);
  return wrap;
}

/** The Summary's clients card. */
export function clientsCard(ctx) {
  const sims = ctx.ev.clients || [];
  if (!sims.length) return null;
  const failing = sims.filter((c) => !c.connects);
  const go = (e) => { e.preventDefault(); ctx.goTab('clients'); };
  const bar = outcomeBar(sims);
  return h('section', { class: 'card clcard', 'aria-labelledby': 'clcard-h' },
    h('div', { class: 'cfg-head' }, h('h2', { id: 'clcard-h' }, clientsLine(sims)), h('a', { href: '#', class: 'xlink', onclick: go }, 'Client by client')),
    bar.bar, bar.legend,
    failing.length ? h('p', { class: 'cl-failing' }, h('b', null, 'Cannot connect: '), failing.map((c) => c.name).join(', '), '.') : null);
}
