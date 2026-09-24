// One host: what its CBOM says, algorithm by algorithm, with sources.
import { h, clear, fmtDate } from '../dom.js';
import { api } from '../api.js';
import { badge, citations, button, empty, toast, modal } from '../ui.js';
import { uploadDialog } from './hosts.js';

function linkDialog(hostId, alreadyLinked, onDone) {
  modal('Link to a TLS endpoint', (close) => {
    const body = h('div', { class: 'modal-body' });
    api.assets().then((endpoints) => {
      const choices = endpoints.filter((e) => !alreadyLinked.includes(e.id));
      clear(body);
      if (!choices.length) {
        body.appendChild(h('p', { class: 'muted' }, 'No unlinked TLS endpoints exist to link to.'));
        body.appendChild(h('div', { class: 'row end' }, button('Close', close)));
        return;
      }
      const sel = h('select', { 'aria-label': 'Endpoint to link' }, choices.map((e) => h('option', { value: e.id }, `${e.name} (${e.address})`)));
      body.append(
        h('p', { class: 'muted' }, 'Record that this host and a TLS endpoint are the same machine. This is never guessed — only what you confirm here.'),
        h('label', { for: 'link-target' }, 'TLS endpoint'), sel,
        h('div', { class: 'row end' }, button('Cancel', close), button('Link', async () => {
          try { await api.linkAsset(hostId, Number(sel.value)); toast('Linked'); close(); onDone(); } catch (e) { toast(e.message, 'error'); }
        }, 'primary')));
    }).catch((e) => { clear(body); body.appendChild(h('p', { class: 'callout bad' }, e.message)); });
    return body;
  });
}

async function linkedAssetsCard(linkedIds, hostId, onDone) {
  const rows = await Promise.all(linkedIds.map((lid) => api.asset(lid).catch(() => null)));
  return h('section', { class: 'card' },
    h('div', { class: 'row' }, h('h2', null, 'Linked assets'), button('Link an endpoint', () => linkDialog(hostId, linkedIds, onDone), 'secondary', { class: 'btn btn-sm' })),
    h('p', { class: 'hint' }, 'Assets a person has confirmed are the same machine as this host.'),
    rows.filter(Boolean).length
      ? h('ul', { class: 'stack' }, rows.filter(Boolean).map((a) => h('li', { class: 'row' },
          h('span', { class: 'kind-badge' }, 'Endpoint'),
          h('a', { href: `#/assets/${a.id}` }, a.name),
          button('Unlink', async () => { try { await api.unlinkAsset(hostId, a.id); toast('Unlinked'); onDone(); } catch (e) { toast(e.message, 'error'); } }, 'secondary', { class: 'btn btn-sm' }))))
      : h('p', { class: 'muted' }, 'Not linked to any TLS endpoint yet.'));
}

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
  const reload = () => window.dispatchEvent(new HashChangeEvent('hashchange'));

  root.appendChild(h('p', null, h('a', { href: '#/hosts' }, '← Hosts')));
  root.appendChild(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, host.name),
      h('div', { class: 'sub' }, s ? `${s.producer || 'unknown producer'} · uploaded ${fmtDate(host.snapshotAt)}` : 'No CBOM uploaded')),
    h('div', { class: 'row' },
      history.length ? button('Download CBOM', () => api.download(`/api/v1/hosts/${id}/snapshots/${history[0].id}/cbom?download=1`, `host-${id}-cbom.json`)
        .catch((e) => toast(e.message, 'error'))) : null,
      button('Upload a newer CBOM', () => uploadDialog(reload), 'primary'))));

  if (!s) {
    root.appendChild(empty('No CBOM for this host yet', 'Upload a CycloneDX CBOM to see this host’s algorithms and post-quantum verdicts.',
      button('Upload a CBOM', () => uploadDialog(reload), 'primary')));
    root.appendChild(await linkedAssetsCard(host.linkedAssetIds || [], id, reload));
    return null;
  }

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
        h('td', null, h('div', null, a.rationale), citations(a.basis),
          h('div', { class: 'hint', title: 'The rule that identified this algorithm: an exact OID match, an OID family match, or an exact catalogue name match — never a guess from a similar-looking name.' },
            `Matched by ${a.matchedBy}`)),
        h('td', { class: 'muted' }, (a.providedBy || []).join(', ') || '–')))))) : h('p', { class: 'muted' }, 'No algorithms were found in this CBOM.')));

  root.appendChild(await linkedAssetsCard(host.linkedAssetIds || [], id, reload));

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
