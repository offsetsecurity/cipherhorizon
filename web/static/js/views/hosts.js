// Hosts: machines described by an uploaded CBOM (the inventory side of the product).
import { h, clear, relTime, fmtDate } from '../dom.js';
import { api } from '../api.js';
import { badge, button, toast, modal, skeleton } from '../ui.js';
import { collectSteps, collectDialog, accessState, osLabel } from '../guide.js';

const MAX_BYTES = 32 * 1024 * 1024;

/** Reads a chosen CBOM file and uploads it. */
export function uploadDialog(onDone) {
  modal('Upload a CBOM', (close) => {
    const file = h('input', { type: 'file', id: 'cbom-file', accept: '.json,application/json' });
    const name = h('input', { type: 'text', id: 'cbom-name', placeholder: 'Only needed if the CBOM names no host' });
    const err = h('div', { class: 'callout bad', role: 'alert', hidden: true });
    return h('form', { class: 'modal-body', onsubmit: async (e) => {
      e.preventDefault();
      err.hidden = true;
      const f = file.files && file.files[0];
      if (!f) { err.textContent = 'Choose a CycloneDX JSON file.'; err.hidden = false; return; }
      if (f.size > MAX_BYTES) { err.textContent = 'That file is larger than 32 MiB.'; err.hidden = false; return; }
      try {
        const r = await api.ingest(await f.text(), name.value.trim());
        toast(`${r.created ? 'Added' : 'Updated'} host ${r.asset.name}`, 'success');
        close();
        onDone(r.asset);
      } catch (ex) { err.textContent = ex.message; err.hidden = false; }
    } },
    err,
    h('p', null, 'Upload a CycloneDX 1.x JSON CBOM, such as the ', h('code', null, 'host.cbom.json'), ' the collector writes. ',
      'Each algorithm in it gets a post-quantum verdict with its source.'),
    h('label', { for: 'cbom-file' }, 'CBOM file'), file,
    h('label', { for: 'cbom-name' }, 'Host name'), name,
    h('div', { class: 'row end' }, button('Cancel', close), h('button', { type: 'submit', class: 'btn btn-primary' }, 'Upload')));
  });
}

export async function render(root) {
  root.appendChild(skeleton(4));
  const hosts = await api.hosts();
  clear(root);
  const open = () => uploadDialog((a) => { location.hash = `#/hosts/${a.id}`; });
  root.appendChild(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Hosts'), h('div', { class: 'sub' }, 'The cryptographic software found inside your machines')),
    h('div', { class: 'row' },
      hosts.length ? button('How do I collect?', () => collectDialog(open)) : null,
      button('Upload CBOM', open, 'primary'))));

  if (!hosts.length) {
    // Nothing uploaded yet: teach the whole loop here rather than send people to the docs.
    root.appendChild(h('section', { class: 'card guide-card' },
      h('h2', null, 'Inventory your first machine'),
      h('p', { class: 'text-2' }, 'A host inventory lists the cryptographic software installed on a computer and says which of its algorithms a quantum computer could break. It takes three steps.'),
      collectSteps(open)));
    return null;
  }
  const dash = h('span', { class: 'muted' }, '–');
  root.appendChild(h('div', { class: 'tablewrap' }, h('table', null,
    h('thead', null, h('tr', null, ['Host', 'System', 'Access', 'Quantum-vulnerable', 'Quantum-safe', 'Components', 'Last upload'].map((c) => h('th', { scope: 'col' }, c)))),
    h('tbody', null, hosts.map((x) => {
      const cov = x.summary && x.summary.coverage;
      const acc = accessState(cov);
      return h('tr', null,
        h('td', { class: 'namecell' }, h('a', { href: `#/hosts/${x.id}` }, x.name)),
        h('td', { class: 'muted' }, (cov && osLabel(cov.os)) || dash),
        h('td', null, x.summary ? badge(acc.label, acc.tone, acc.why) : dash),
        h('td', null, x.summary ? badge(String(x.summary.vulnerable), x.summary.vulnerable ? 'warn' : 'good') : dash),
        h('td', null, x.summary ? badge(String(x.summary.safe), 'good') : dash),
        h('td', null, x.summary ? String(x.summary.packages) : dash),
        h('td', { class: 'muted', title: fmtDate(x.snapshotAt) }, relTime(x.snapshotAt)));
    })))));
  return null;
}

