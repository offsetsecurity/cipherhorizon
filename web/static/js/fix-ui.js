// Fixes (UX-DESIGN-024): the pieces pages share. A problem is assigned once; after that only scans
// change its state, so there is one form (Assign) and one sentence per fix that says where it stands.
import { h, relTime, fmtDay } from './dom.js';
import { api } from './api.js';
import { modal, button, toast } from './ui.js';

// A date a person entered (a due date, a hold) is a calendar day: show that day in any time zone.
export const dayOf = (iso) => (iso ? fmtDay(`${String(iso).slice(0, 10)}T12:00:00`) : '');

/** Where a fix stands, as one sentence and a tone (good, bad, warn or plain). */
export function standing(f) {
  switch (f.group) {
    case 'fixed':
      return { tone: 'good', text: `Fixed. Confirmed by the scan of ${fmtDay(f.checkedAt || f.fixedAt)}.` };
    case 'came-back':
      return { tone: 'bad', text: `Was fixed. The scan of ${fmtDay(f.checkedAt || f.cameBackAt)} found it again.` };
    case 'on-hold':
      return { tone: 'plain', text: `On hold until ${dayOf(f.holdUntil)}.` };
    case 'closed':
      return { tone: 'plain', text: 'Closed.' };
    default: {
      const late = f.overdue ? 'Overdue. ' : '';
      const tone = f.overdue ? 'warn' : 'plain';
      if (f.result === 'not-fixed') return { tone, text: `${late}Not fixed yet. Checked ${relTime(f.checkedAt)}.` };
      if (f.result === 'cannot-check') return { tone, text: `${late}A scan cannot check this one. Close it yourself when it is done.` };
      return { tone, text: `${late}Not checked yet. ${f.nextScanAt ? `Next scan ${relTime(f.nextScanAt)}.` : 'It is checked at the next scan.'}` };
    }
  }
}

export const fixHref = (id) => `#/fixes/${id}`;

/**
 * The only form: who, by when, and optionally a link to the organisation's own ticket.
 * subject: { kind: 'finding' | 'certificate' | 'readiness', assetId?, findingKey?, certificate? }
 */
export function assignDialog(subject, { what = '', owner = '', onDone = null } = {}) {
  modal('Assign this fix', (close) => {
    const err = h('div', { class: 'callout bad', role: 'alert', hidden: true });
    const oIn = h('input', { type: 'text', id: 'assign-owner', value: owner, maxlength: '100', autocomplete: 'off', placeholder: 'a person or a team' });
    const dIn = h('input', { type: 'date', id: 'assign-due' });
    const tIn = h('input', { type: 'url', id: 'assign-ticket', maxlength: '500', autocomplete: 'off', placeholder: 'Paste a link from Jira, ServiceNow or wherever you track changes' });
    const submit = h('button', { type: 'submit', class: 'btn btn-primary', id: 'assign-submit' }, 'Assign');
    return h('form', { class: 'modal-body', onsubmit: async (e) => {
      e.preventDefault();
      err.hidden = true;
      submit.disabled = true;
      try {
        const r = await api.assignFix({ subject, owner: oIn.value.trim(), due: dIn.value, ticket: tIn.value.trim() });
        close();
        toast(r.scheduled && r.scheduled.length ? `Assigned. ${r.scheduled.join(', ')} will now be scanned every day.` : 'Assigned.', 'success');
        if (onDone) onDone(r.fix); else location.hash = fixHref(r.fix.id);
      } catch (ex) {
        if (ex.status === 409 && ex.data && ex.data.id) { close(); location.hash = fixHref(ex.data.id); return; }
        err.textContent = ex.message;
        err.hidden = false;
        submit.disabled = false;
      }
    } },
    what ? h('p', { class: 'text-2' }, what) : null,
    err,
    h('div', { class: 'form-2col' },
      h('div', null, h('label', { for: 'assign-owner' }, 'Who will fix it'), oIn),
      h('div', null, h('label', { for: 'assign-due' }, 'By when'), dIn)),
    h('label', { for: 'assign-ticket' }, 'Your ticket ', h('span', { class: 'muted' }, '(optional)')), tIn,
    h('p', { class: 'hint' }, 'Approvals and change windows stay in your own tool. This only links to it.'),
    h('div', { class: 'callout assign-note' }, h('b', null, 'That is all you do here. '),
      'Every scan after this checks it. When a scan shows the problem gone, the fix is marked done with the date. If it is undone later, it comes back to the top of the list.'),
    h('div', { class: 'row end' }, button('Cancel', close), submit));
  });
}

/** An "Assign" button for a problem shown on another page. */
export function assignButton(subject, opts = {}, label = 'Assign', kind = 'secondary') {
  return button(label, (e) => { e.stopPropagation(); assignDialog(subject, opts); }, kind, { class: `btn btn-${kind} btn-sm`, 'data-assign': subject.kind });
}
