// Hosts: machines described by an uploaded CBOM (the inventory side of the product).
import { h, relTime, fmtDate } from '../dom.js';
import { api } from '../api.js';
import { badge, button, empty, toast, modal } from '../ui.js';

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
    h('p', null, 'Upload a CycloneDX 1.x JSON CBOM, such as one produced by ', h('code', null, 'cbom-scan run'),
      '. Each algorithm in it gets a post-quantum verdict with its source.'),
    h('label', { for: 'cbom-file' }, 'CBOM file'), file,
    h('label', { for: 'cbom-name' }, 'Host name'), name,
    h('div', { class: 'row end' }, button('Cancel', close), h('button', { type: 'submit', class: 'btn btn-primary' }, 'Upload')));
  });
}

export async function render(root) {
  const hosts = await api.hosts();
  root.appendChild(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Hosts'), h('div', { class: 'sub' }, 'Cryptography found inside machines, from uploaded CBOMs')),
    h('div', { class: 'row' }, button('Upload CBOM', () => uploadDialog((a) => { location.hash = `#/hosts/${a.id}`; }), 'primary'))));

  if (!hosts.length) {
    root.appendChild(empty('No hosts yet',
      'Run “cbom-scan run” on a machine to produce a CBOM, then upload it here to see which of its algorithms a quantum computer would break.',
      button('Upload CBOM', () => uploadDialog((a) => { location.hash = `#/hosts/${a.id}`; }), 'primary')));
    return null;
  }
  root.appendChild(h('div', { class: 'tablewrap' }, h('table', null,
    h('thead', null, h('tr', null, ['Host', 'Quantum-vulnerable', 'Quantum-safe', 'Packages', 'Snapshots', 'Last upload'].map((c) => h('th', { scope: 'col' }, c)))),
    h('tbody', null, hosts.map((x) => h('tr', null,
      h('td', { class: 'namecell' }, h('a', { href: `#/hosts/${x.id}` }, x.name)),
      h('td', null, x.summary ? badge(String(x.summary.vulnerable), x.summary.vulnerable ? 'bad' : 'good') : '–'),
      h('td', null, x.summary ? badge(String(x.summary.safe), 'good') : '–'),
      h('td', null, x.summary ? String(x.summary.packages) : '–'),
      h('td', null, String(x.snapshots)),
      h('td', { class: 'muted', title: fmtDate(x.snapshotAt) }, relTime(x.snapshotAt))))))));
  return null;
}

