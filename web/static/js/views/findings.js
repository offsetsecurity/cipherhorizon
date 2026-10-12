// Findings: every open finding across the fleet, one line per problem, worst first. A line says
// how many endpoints and machines have it; opening it gives the fix once, then each place with
// its own evidence and triage actions (PRD-005: detail behind a disclosure, not on every card).
import { h, clear } from '../dom.js';
import { api } from '../api.js';
import { sevBadge, evidenceBadge, citations, badge, button, empty, toast, modal, skeleton, playEnter } from '../ui.js';

const SEVERITIES = [['', 'Any severity'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['info', 'Info'], ['vulnerable', 'Quantum-vulnerable (machine)']];
const STATUSES = [['', 'Any status'], ['new', 'New'], ['acknowledged', 'Acknowledged'], ['accepted-risk', 'Accepted risk']];
const KINDS = [['', 'Endpoints & machines'], ['endpoint', 'Endpoints only'], ['host', 'Machines only']];

const plural = (n, one) => `${n} ${one}${n === 1 ? '' : 's'}`;

// The fleet list arrives worst first, one entry per finding per endpoint or machine; group it
// by problem and keep the first (worst) position of each group.
export function groupFindings(findings) {
  const groups = new Map();
  for (const f of findings) {
    const k = `${f.severity || f.class || ''}\u0000${f.title}`;
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(f);
  }
  return [...groups.values()];
}

export async function render(root, ctx = {}) {
  let severity = '', status = '', kind = '';
  const head = h('div');
  const body = h('div');
  root.append(head, body);
  body.appendChild(skeleton(4));

  const acceptRiskDialog = (f, onDone) => {
    modal('Accept risk', (close) => {
      const note = h('textarea', { id: 'fleet-triage-note', placeholder: 'Optional: why, and any ticket reference' });
      return h('form', { class: 'modal-body', onsubmit: async (e) => {
        e.preventDefault();
        close();
        try { await api.setFindingStatus(f.assetId, f.key, 'accepted-risk', note.value.trim()); toast('Marked as accepted risk'); onDone(); }
        catch (ex) { toast(ex.message, 'error'); }
      } },
      h('p', { class: 'muted' }, `On ${f.assetName}. This finding will keep appearing, marked as an accepted risk, until it stops being detected.`),
      h('label', { for: 'fleet-triage-note' }, 'Note'), note,
      h('div', { class: 'row end' }, button('Cancel', close), h('button', { type: 'submit', class: 'btn btn-primary' }, 'Accept risk')));
    });
  };

  // One endpoint or machine that has the finding: a link, its triage, and its evidence on demand.
  const place = (f, redraw) => {
    const triage = f.status
      ? [h('span', { class: `badge triage-${f.status.status}` }, f.status.status === 'accepted-risk' ? 'accepted risk' : 'acknowledged'),
        f.status.note ? h('span', { class: 'muted' }, ` ${f.status.note} `) : null,
        button('Clear', async () => { try { await api.clearFindingStatus(f.assetId, f.key); toast('Triage cleared'); redraw(); } catch (e) { toast(e.message, 'error'); } }, 'secondary', { class: 'btn btn-sm' })]
      : [button('Acknowledge', async () => { try { await api.setFindingStatus(f.assetId, f.key, 'acknowledged', ''); toast('Acknowledged'); redraw(); } catch (e) { toast(e.message, 'error'); } }, 'secondary', { class: 'btn btn-sm' }),
        button('Accept risk', () => acceptRiskDialog(f, redraw), 'secondary', { class: 'btn btn-sm' })];
    return h('li', { class: 'fgroup-place' },
      h('div', { class: 'row' },
        h('a', { href: f.assetKind === 'host' ? `#/machines/${f.assetId}` : `#/endpoints/${f.assetId}`, class: 'xlink' }, h('b', null, f.assetName)),
        h('span', { class: 'muted' }, f.assetKind === 'host' ? 'machine' : 'endpoint'),
        h('span', { class: 'fgroup-triage' }, triage)),
      f.detail ? h('details', { class: 'why' }, h('summary', null, 'Why'), h('div', { class: 'detail' }, f.detail, f.evidence ? [' ', evidenceBadge(f.evidence)] : null)) : null);
  };

  const draw = async () => {
    clear(head);
    head.appendChild(h('div', { class: 'page-head' },
      ctx.embedded ? h('div') : h('div', null, h('h1', null, 'Findings'), h('div', { class: 'sub' }, 'Every open finding across your fleet, worst first.'))));
    head.appendChild(h('div', { class: 'toolbar' },
      h('select', { 'aria-label': 'Filter by severity', onchange: (e) => { severity = e.target.value; draw().then(() => playEnter(body, 700)); } }, SEVERITIES.map(([v, l]) => h('option', { value: v, selected: v === severity }, l))),
      h('select', { 'aria-label': 'Filter by triage status', onchange: (e) => { status = e.target.value; draw().then(() => playEnter(body, 700)); } }, STATUSES.map(([v, l]) => h('option', { value: v, selected: v === status }, l))),
      h('select', { 'aria-label': 'Filter by endpoint or machine', onchange: (e) => { kind = e.target.value; draw().then(() => playEnter(body, 700)); } }, KINDS.map(([v, l]) => h('option', { value: v, selected: v === kind }, l)))));

    clear(body);
    let findings;
    try {
      const q = new URLSearchParams();
      if (severity) q.set('severity', severity);
      if (status) q.set('status', status);
      if (kind) q.set('kind', kind);
      const qs = q.toString();
      findings = await api.fleetFindings(qs ? `?${qs}` : '');
    } catch (e) {
      toast(e.message, 'error');
      return;
    }

    if (!findings.length) {
      body.appendChild(empty('No findings match this filter', 'Try a different severity, status or source.'));
      return;
    }

    const groups = groupFindings(findings);
    body.appendChild(h('p', { class: 'hint' }, `${plural(groups.length, 'problem')} across ${((n) => `${n} ${n === 1 ? 'endpoint or machine' : 'endpoints and machines'}`)(new Set(findings.map((f) => `${f.assetKind}:${f.assetId}`)).size)}. Open a line for the fix and where it is.`));
    body.appendChild(h('div', { class: 'fgroups' }, groups.map((fs) => {
      const f = fs[0];
      const open = fs.filter((x) => !x.status).length;
      const where = fs.length === 1 ? fs[0].assetName : plural(fs.length, fs.every((x) => x.assetKind === 'host') ? 'machine' : fs.every((x) => x.assetKind !== 'host') ? 'endpoint' : 'place');
      return h('details', { class: `fgroup ${f.severity ? `sev-${f.severity}` : 'sev-medium'}` },
        h('summary', { class: 'fgroup-line' },
          f.severity ? sevBadge(f.severity) : badge('PQC', 'warn', 'quantum-vulnerable: a large quantum computer could break it'),
          h('span', { class: 'fgroup-title' }, f.title),
          h('span', { class: 'fgroup-where muted' }, where, open < fs.length ? ` · ${fs.length - open} triaged` : '')),
        h('div', { class: 'fgroup-body' },
          f.remediation ? h('p', { class: 'fix' }, h('b', null, 'Fix: '), f.remediation) : null,
          (f.citations || []).length ? h('details', { class: 'why' }, h('summary', null, 'Sources'), citations(f.citations)) : null,
          h('ul', { class: 'fgroup-places' }, fs.map((x) => place(x, draw)))));
    })));
  };

  await draw();
  return null;
}
