// Tracked work (PRD-023): the pieces other pages share. A marker and a verification each read the
// same everywhere: a glyph, a word and a tone, never colour alone (DESIGN.md §2).
import { h } from './dom.js';
import { api } from './api.js';
import { modal, button, toast } from './ui.js';

// What each marker means to a reader. The stage name comes from the workflow; the marker says where
// that stage sits in any workflow.
export const MARKERS = {
  requested: { word: 'Requested', tone: 'neutral', glyph: '○' },
  '': { word: 'In progress', tone: 'info', glyph: '◐' },
  approved: { word: 'Approved', tone: 'info', glyph: '✓' },
  executed: { word: 'Changed, not verified', tone: 'warn', glyph: '◷' },
  reported: { word: 'Reported, not verified', tone: 'warn', glyph: '◷' },
  verified: { word: 'Verified by scan', tone: 'good', glyph: '✓' },
  complete: { word: 'Complete', tone: 'ok', glyph: '■' },
  exception: { word: 'Risk accepted', tone: 'warn', glyph: '⏸' },
  cancelled: { word: 'Cancelled', tone: 'none', glyph: '✕' },
};

export function markerBadge(marker, stageLabel) {
  const m = MARKERS[marker] || MARKERS[''];
  return h('span', { class: `badge b-${m.tone}`, title: m.word }, h('span', { 'aria-hidden': 'true' }, `${m.glyph} `), stageLabel || m.word);
}

export const VERIFY = {
  verified: { word: 'Verified', tone: 'good', glyph: '✓', tile: 'good' },
  'not-verified': { word: 'Not verified', tone: 'bad', glyph: '✕', tile: 'problem' },
  waiting: { word: 'Waiting for a scan', tone: 'warn', glyph: '◷', tile: 'attention' },
  'not-verifiable': { word: 'Cannot be verified by scan', tone: 'none', glyph: '·', tile: 'na' },
};

export function verifyBadge(status) {
  if (!status) return h('span', { class: 'muted small' }, 'not checked');
  const v = VERIFY[status] || { word: status, tone: 'neutral', glyph: '·' };
  return h('span', { class: `badge b-${v.tone}` }, h('span', { 'aria-hidden': 'true' }, `${v.glyph} `), v.word);
}

/** The verification a piece of work carries, if any (the API returns it as raw JSON). */
export function verificationOf(item) {
  return item && item.verification && typeof item.verification === 'object' ? item.verification : null;
}

const SUBJECT_WORDS = { finding: 'Finding', certificate: 'Certificate', readiness: 'Readiness target', endpoint: 'Endpoint', system: 'System' };
export const subjectWord = (k) => SUBJECT_WORDS[k] || k;

/** Where the subject lives in the interface, and how to name it in one line. */
export function subjectLink(item, assetName) {
  const name = assetName || (item.assetId ? `endpoint ${item.assetId}` : '');
  switch (item.subjectKind) {
    case 'finding':
      return h('span', null, h('code', null, item.findingKey), ' on ', item.assetId ? h('a', { href: `#/endpoints/${item.assetId}` }, name) : h('span', { class: 'muted' }, 'a deleted endpoint'));
    case 'readiness':
      return h('span', null, item.assetId ? h('a', { href: `#/endpoints/${item.assetId}` }, name) : h('span', { class: 'muted' }, 'a deleted endpoint'), ` to L${item.targetLevel}`);
    case 'certificate':
      return h('a', { class: 'mono', href: `#/certificates/${item.certificate}`, title: item.certificate }, `${item.certificate.slice(0, 16)}…`);
    case 'endpoint':
      return item.assetId ? h('a', { href: `#/endpoints/${item.assetId}` }, name) : h('span', { class: 'muted' }, 'a deleted endpoint');
    default:
      return item.systemId ? h('a', { href: `#/systems/${item.systemId}` }, `system ${item.systemId}`) : h('span', { class: 'muted' }, 'a deleted system');
  }
}

let workflowCache = null;
export async function workflows() {
  if (!workflowCache) workflowCache = await api.workflows();
  return workflowCache;
}
export function forgetWorkflows() { workflowCache = null; }

/**
 * Opens the "Track this" dialog for a subject: a title, a workflow that applies to it, an owner, a due
 * date and a project. On success it goes to the new work's page.
 * subject: { kind, assetId?, systemId?, certificate?, findingKey?, targetLevel? }
 */
export async function trackDialog(subject, { title = '', workflow = '', owner = '', project = '', what = '' } = {}) {
  let flows;
  try {
    flows = (await workflows()).filter((f) => (f.subjects || []).includes(subject.kind));
  } catch (e) {
    toast(e.message, 'error');
    return;
  }
  if (!flows.length) {
    toast(`No workflow applies to a ${subjectWord(subject.kind).toLowerCase()}.`, 'error');
    return;
  }
  modal('Track this as work', (close) => {
    const err = h('div', { class: 'callout bad', role: 'alert', hidden: true });
    const tIn = h('input', { type: 'text', id: 'track-title', value: title, maxlength: '200', required: true, autocomplete: 'off' });
    const fIn = h('select', { id: 'track-workflow' }, flows.map((f) => h('option', { value: f.id, selected: f.id === workflow }, f.title)));
    const purpose = h('p', { class: 'hint', id: 'track-purpose' });
    const showPurpose = () => {
      const f = flows.find((x) => x.id === fIn.value) || flows[0];
      purpose.textContent = `${f.purpose || ''} ${f.verifies ? 'Closed as verified only when a later scan shows the change.' : 'The product cannot verify this; it closes as complete.'}`.trim();
    };
    fIn.addEventListener('change', showPurpose);
    showPurpose();
    const oIn = h('input', { type: 'text', id: 'track-owner', value: owner, maxlength: '100', autocomplete: 'off', placeholder: 'a person or a team' });
    const dIn = h('input', { type: 'date', id: 'track-due' });
    const pIn = h('input', { type: 'text', id: 'track-project', value: project, maxlength: '100', autocomplete: 'off', placeholder: 'e.g. PQC wave 1' });
    const submit = h('button', { type: 'submit', class: 'btn btn-primary', id: 'track-submit' }, 'Create work');
    return h('form', { class: 'modal-body', onsubmit: async (e) => {
      e.preventDefault();
      err.hidden = true;
      submit.disabled = true;
      try {
        const w = await api.createWork({ title: tIn.value.trim(), workflow: fIn.value, owner: oIn.value.trim(), due: dIn.value, project: pIn.value.trim(), subject });
        close();
        toast('Work created.', 'success');
        location.hash = `#/work/${w.id}`;
      } catch (ex) {
        err.textContent = ex.message;
        err.hidden = false;
        submit.disabled = false;
      }
    } },
    what ? h('p', { class: 'text-2' }, what) : null,
    err,
    h('label', { for: 'track-title' }, 'Title'), tIn,
    h('label', { for: 'track-workflow' }, 'Workflow'), fIn, purpose,
    h('div', { class: 'form-2col' },
      h('div', null, h('label', { for: 'track-owner' }, 'Owner'), oIn),
      h('div', null, h('label', { for: 'track-due' }, 'Due'), dIn)),
    h('label', { for: 'track-project' }, 'Project (optional)'), pIn,
    h('div', { class: 'row end' }, button('Cancel', close), submit));
  });
}

/** A "Track" button for a subject (rows and headers of other pages). */
export function trackButton(subject, opts = {}, label = 'Track', kind = 'secondary') {
  return button(label, (e) => { e.stopPropagation(); trackDialog(subject, opts); }, kind, { class: `btn btn-${kind} btn-sm`, 'data-track': subject.kind });
}
