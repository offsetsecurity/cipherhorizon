// Imports: documents from other tools, and the flow that brings one in (PRD-003 REQ-UI-6). The
// person names the system; whatever the document says about its own subject is only recorded.
import { h, clear, fmtDate, relTime } from '../dom.js';
import { api } from '../api.js';
import { badge, button, toast, modal, skeleton, empty, confirmDialog } from '../ui.js';
import { systemHref, validId, reasonDialog } from '../estate-ui.js';

const MAX_BYTES = 32 * 1024 * 1024;

/** What was and was not interpreted, so a person can see how much of a file was set aside. */
export function notInterpretedTable(map) {
  const entries = Object.entries(map || {}).filter(([, n]) => n > 0);
  if (!entries.length) return h('p', { class: 'hint' }, 'Every component in the document was used.');
  return h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
    h('caption', { class: 'sr-only' }, 'Parts of the document that were not interpreted'),
    h('thead', null, h('tr', null, ['Not interpreted', 'Count'].map((c) => h('th', { scope: 'col' }, c)))),
    h('tbody', null, entries.sort((a, b) => b[1] - a[1]).map(([k, n]) => h('tr', null, h('td', null, k), h('td', null, String(n)))))));
}

function resultPanel(reply) {
  const rec = reply.import;
  return h('div', { class: 'stack', role: 'status' },
    h('div', { class: reply.duplicate ? 'callout' : 'callout info' },
      reply.duplicate ? 'This exact document was already imported for that system, so nothing changed.'
        : `Imported. ${rec.observations} fact${rec.observations === 1 ? '' : 's'} added to `, reply.duplicate ? null : h('a', { href: systemHref(rec.systemId) }, rec.systemName), reply.duplicate ? null : '.'),
    h('dl', { class: 'facts' },
      h('div', null, h('dt', null, 'Detected producer'), h('dd', null, reply.profileLabel || 'unrecognised producer (read generically)')),
      h('div', null, h('dt', null, 'Tool named in the file'), h('dd', null, [rec.toolName, rec.toolVersion].filter(Boolean).join(' ') || 'none')),
      h('div', null, h('dt', null, 'CycloneDX version'), h('dd', null, rec.specVersion)),
      h('div', null, h('dt', null, 'The file’s own subject'), h('dd', null, rec.subjectClaim || 'none named'))),
    notInterpretedTable(rec.notInterpreted),
    h('p', { class: 'hint' }, 'Imports add facts; they never overwrite what a scan or collector observed, and never claim a key was used.'));
}

/** The import dialog: choose a file, assign it to a system, see what was made of it. */
export function importDialog(onDone) {
  modal('Import a CBOM', (close) => {
    const file = h('input', { type: 'file', id: 'import-file', accept: '.json,application/json' });
    const existing = h('select', { id: 'import-system', 'aria-label': 'Existing system' }, h('option', { value: '' }, 'Loading systems…'));
    const newName = h('input', { type: 'text', id: 'import-new', maxlength: '200', placeholder: 'Name of a new system', autocomplete: 'off' });
    const err = h('div', { class: 'callout bad', role: 'alert', hidden: true });
    const out = h('div');
    const submit = h('button', { type: 'submit', class: 'btn btn-primary' }, 'Import');
    api.systems().then((r) => {
      clear(existing);
      existing.appendChild(h('option', { value: '' }, r.systems.length ? 'Choose an existing system…' : 'No systems yet'));
      for (const s of r.systems) if (validId(s.id)) existing.appendChild(h('option', { value: String(s.id) }, s.name));
    }).catch(() => { clear(existing); existing.appendChild(h('option', { value: '' }, 'Could not load systems')); });

    const form = h('form', { class: 'modal-body', onsubmit: async (e) => {
      e.preventDefault();
      err.hidden = true;
      clear(out);
      const f = file.files && file.files[0];
      if (!f) { err.textContent = 'Choose a CycloneDX JSON file.'; err.hidden = false; return; }
      if (f.size > MAX_BYTES) { err.textContent = 'That file is larger than 32 MiB.'; err.hidden = false; return; }
      const nm = newName.value.trim();
      if ((existing.value === '') === (nm === '')) { err.textContent = 'Say which system this describes: choose an existing one, or name a new one (not both).'; err.hidden = false; return; }
      submit.disabled = true;
      try {
        const target = existing.value ? `system=${existing.value}` : `newSystem=${encodeURIComponent(nm)}`;
        const reply = await api.importDocument(await f.text(), target);
        out.appendChild(resultPanel(reply));
        toast('Import finished', 'success');
        if (onDone) onDone(reply);
      } catch (ex) {
        err.textContent = ex.message;
        err.hidden = false;
      } finally { submit.disabled = false; }
    } },
    err,
    h('p', null, 'Bring in a CycloneDX 1.6 or 1.7 CBOM from another tool. It is checked against the schema and the limits before anything is stored.'),
    h('label', { for: 'import-file' }, '1. The file'), file,
    h('label', { for: 'import-system' }, '2. Which system does it describe?'), existing,
    h('div', { class: 'hint' }, 'or'), newName,
    h('p', { class: 'hint' }, 'You decide this. What the document says about its own subject is recorded but never decides where its data goes.'),
    out,
    h('div', { class: 'row end' }, button('Close', close), submit));
    return form;
  }, { wide: true });
}

export async function render(root) {
  root.appendChild(skeleton(4));
  const list = await api.imports();
  clear(root);
  const reload = () => { root.replaceChildren(); return render(root); };
  root.appendChild(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Imports'), h('div', { class: 'sub' }, 'Documents from other tools, and where their facts went')),
    h('div', { class: 'row' }, button('Import a CBOM', () => importDialog(reload), 'primary'))));
  if (!list.length) {
    root.appendChild(empty('Nothing imported yet', 'Import a CycloneDX CBOM from another tool. Its facts join the system you choose, marked as imported, and never overwrite what was observed.', button('Import a CBOM', () => importDialog(reload), 'primary')));
    return null;
  }
  root.appendChild(h('div', { class: 'tablewrap' }, h('table', null,
    h('caption', { class: 'sr-only' }, 'Imported documents'),
    h('thead', null, h('tr', null, ['Received', 'Producer', 'System', 'Version', 'Status', 'Facts', 'Not interpreted', ''].map((c) => h('th', { scope: 'col' }, c)))),
    h('tbody', null, list.map((r) => {
      const skipped = Object.values(r.notInterpreted || {}).reduce((a, b) => a + b, 0);
      const withdraw = h('button', { type: 'button', class: 'btn btn-sm btn-secondary', onclick: async () => {
        if (!(await confirmDialog('Withdraw this import?', 'Its facts stop counting toward the system. The document itself is kept, and it can be imported again.', 'Withdraw'))) return;
        const reason = await reasonDialog('Withdraw import', 'Say why, for the audit trail.', 'Withdraw');
        if (reason === null) return;
        try { await api.withdrawImport(r.id, reason); toast('Import withdrawn', 'success'); reload(); } catch (ex) { toast(ex.message, 'error'); }
      } }, 'Withdraw');
      return h('tr', null,
        h('td', { class: 'muted', title: fmtDate(r.receivedAt) }, relTime(r.receivedAt)),
        h('td', null, [r.toolName, r.toolVersion].filter(Boolean).join(' ') || h('span', { class: 'muted' }, 'unnamed'),
          h('div', { class: 'muted small' }, `${r.profile}; submitted by ${r.submittedBy || 'unknown'}`)),
        h('td', { class: 'namecell' }, h('a', { href: systemHref(r.systemId) }, r.systemName)),
        h('td', null, r.specVersion),
        h('td', null, badge(r.status, r.status === 'active' ? 'good' : 'neutral')),
        h('td', null, String(r.observations)),
        h('td', null, skipped ? `${skipped} part${skipped === 1 ? '' : 's'}` : h('span', { class: 'muted' }, 'none')),
        h('td', null, r.status === 'active' ? withdraw : null));
    })))));
  return null;
}
