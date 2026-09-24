// Findings: every open finding across the fleet, ranked worst first, filterable
// by severity, triage status and asset kind, with triage actions in place.
import { h, clear } from '../dom.js';
import { api } from '../api.js';
import { sevBadge, evidenceBadge, citations, badge, button, empty, toast, modal, skeleton, playEnter } from '../ui.js';

const SEVERITIES = [['', 'Any severity'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['info', 'Info'], ['vulnerable', 'Quantum-vulnerable (host)']];
const STATUSES = [['', 'Any status'], ['new', 'New'], ['acknowledged', 'Acknowledged'], ['accepted-risk', 'Accepted risk']];
const KINDS = [['', 'Endpoints & hosts'], ['tls-endpoint', 'TLS endpoints only'], ['host', 'Hosts only']];

export async function render(root) {
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

  const draw = async () => {
    clear(head);
    head.appendChild(h('div', { class: 'page-head' },
      h('div', null, h('h1', null, 'Findings'), h('div', { class: 'sub' }, 'Every open finding across your fleet, ranked worst first.'))));
    head.appendChild(h('div', { class: 'toolbar' },
      h('select', { 'aria-label': 'Filter by severity', onchange: (e) => { severity = e.target.value; draw().then(() => playEnter(body, 700)); } }, SEVERITIES.map(([v, l]) => h('option', { value: v, selected: v === severity }, l))),
      h('select', { 'aria-label': 'Filter by triage status', onchange: (e) => { status = e.target.value; draw().then(() => playEnter(body, 700)); } }, STATUSES.map(([v, l]) => h('option', { value: v, selected: v === status }, l))),
      h('select', { 'aria-label': 'Filter by asset kind', onchange: (e) => { kind = e.target.value; draw().then(() => playEnter(body, 700)); } }, KINDS.map(([v, l]) => h('option', { value: v, selected: v === kind }, l)))));

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
      body.appendChild(empty('No findings match this filter', 'Try a different severity, status or asset kind.'));
      return;
    }

    body.appendChild(h('div', { class: 'findings' }, findings.map((f) => {
      const kindLabel = f.assetKind === 'host' ? 'Host' : 'Endpoint';
      const sevOrClass = f.severity ? sevBadge(f.severity) : badge('quantum-vulnerable', 'warn');
      const triageBadge = f.status
        ? h('span', { class: `badge triage-${f.status.status}` }, f.status.status === 'accepted-risk' ? 'accepted risk' : 'acknowledged')
        : null;
      const actions = f.status
        ? h('div', { class: 'row mt-sm' },
            triageBadge, f.status.note ? h('span', { class: 'muted' }, f.status.note) : null,
            button('Clear', async () => { try { await api.clearFindingStatus(f.assetId, f.key); toast('Triage cleared'); draw(); } catch (e) { toast(e.message, 'error'); } }, 'secondary', { class: 'btn btn-sm' }))
        : h('div', { class: 'row mt-sm' },
            button('Acknowledge', async () => { try { await api.setFindingStatus(f.assetId, f.key, 'acknowledged', ''); toast('Acknowledged'); draw(); } catch (e) { toast(e.message, 'error'); } }, 'secondary', { class: 'btn btn-sm' }),
            button('Accept risk', () => acceptRiskDialog(f, draw), 'secondary', { class: 'btn btn-sm' }));

      return h('article', { class: `finding ${f.severity ? `s-${f.severity}` : 's-medium'}` },
        h('div', { class: 'finding-head' },
          sevOrClass, h('strong', null, f.title),
          f.evidence ? evidenceBadge(f.evidence) : null,
          f.category ? badge(f.category, 'neutral') : null,
          h('span', { class: 'kind-badge' }, kindLabel),
          h('a', { href: `#/${f.assetKind === 'host' ? 'hosts' : 'assets'}/${f.assetId}`, class: 'pf-asset xlink' }, f.assetName)),
        f.detail ? h('div', { class: 'detail' }, f.detail) : null,
        f.remediation ? h('div', { class: 'fix' }, h('b', null, 'Fix: '), f.remediation) : null,
        citations(f.citations),
        actions);
    })));
  };

  await draw();
  return null;
}
