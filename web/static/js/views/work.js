// Tracked work (PRD-023): the changes in progress, who owns them, and whether the product's own scans
// have confirmed them. Two pages share this module: the list (#/work) and one piece of work (#/work/ID).
import { h, clear, relTime, fmtDate, fmtDay } from '../dom.js';
import { api, ApiError } from '../api.js';
import { badge, button, toast, empty, skeleton, crumbs, modal, sevBadge } from '../ui.js';
import { stackBar, statusTile } from '../viz.js';
import { MARKERS, VERIFY, markerBadge, verifyBadge, verificationOf, subjectLink, subjectWord, trackDialog, workflows } from '../work-ui.js';
import { session } from '../auth.js';

export async function render(root, { args, query }) {
  return args && args[0] ? renderItem(root, Number(args[0])) : renderList(root, query);
}

// A due date or an end date is a calendar day a person entered (stored as its last second, UTC): show that day.
const dayOf = (iso) => (iso ? fmtDay(`${iso.slice(0, 10)}T12:00:00`) : '');
const plural = (n, one, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
const pct = (n, d) => (d ? Math.round((100 * n) / d) : 0);

// ---- the list ---------------------------------------------------------------------------------

const VIEWS = {
  open: ['Open', (w) => !['verified', 'complete', 'cancelled'].includes(w.marker)],
  approval: ['Waiting for approval', (w, s) => s.approval.has(w.id)],
  verify: ['Changed, not verified', (w) => w.marker === 'executed' || w.marker === 'reported'],
  verified: ['Verified', (w) => w.marker === 'verified' || (w.marker === 'complete' && verificationOf(w)?.status === 'verified')],
  overdue: ['Overdue', (w) => w.overdue],
  all: ['All', () => true],
};

async function renderList(root, query) {
  const view = VIEWS[query.get('view')] ? query.get('view') : 'open';
  const tab = ['work', 'attention', 'suggested'].includes(query.get('tab')) ? query.get('tab') : 'work';
  root.appendChild(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Work'),
      h('div', { class: 'sub' }, 'Changes in progress, who owns them, and whether a scan has confirmed them. Work is verified only by this product’s own scans.')),
    h('div', { class: 'row' }, button('New work', () => newWorkDialog(), 'primary', { id: 'work-new' }))));
  const band = h('div');
  const body = h('div');
  root.append(band, body);
  body.appendChild(skeleton(5));

  const [items, sum, events, sugg] = await Promise.all([api.work('?limit=5000'), api.workSummary(), api.lifecycleEvents(), api.workSuggestions()]);
  const assets = await api.assets().catch(() => []);
  const names = new Map(assets.map((a) => [a.id, a.name]));
  // Which open work waits for an approval: the summary knows by count; the list needs the ids.
  const approvalIds = new Set(events.filter((e) => e.kind === 'work.awaiting-approval').map((e) => e.workId));
  const ctx = { approval: approvalIds };

  // The status band: each figure lists what it counts.
  const go = (v) => { location.hash = `#/work?view=${v}`; };
  const cell = (v, label, figure, note, tone = '') => h('div', { class: 'stat-cell' },
    h('button', { type: 'button', class: `stat stat-btn ${tone}`, 'aria-pressed': String(tab === 'work' && view === v), onclick: () => go(v) },
      h('span', { class: 'stat-label' }, label), h('span', { class: 'stat-figure' }, figure.toLocaleString()), h('span', { class: 'stat-note' }, note)));
  clear(band).append(
    h('section', { class: 'statusband five', 'aria-label': 'Where the work stands; choose a figure to list it' },
      cell('open', 'Open', sum.open, `of ${plural(sum.total, 'piece')} of work`),
      cell('approval', 'Waiting for approval', sum.awaitingApproval, 'a second person must approve', sum.awaitingApproval ? 'warn' : ''),
      cell('verify', 'Changed, not verified', sum.awaitingVerification, 'waiting for a scan to confirm', sum.awaitingVerification ? 'warn' : ''),
      cell('verified', 'Verified by scan', sum.verified, `of ${sum.total}; ${sum.completeUnverified} closed without verification`, sum.verified ? 'good' : ''),
      cell('overdue', 'Overdue', sum.overdue, `of ${plural(sum.withDueDate, 'open piece')} with a due date`, sum.overdue ? 'bad' : '')),
    pipeline(sum),
    readinessStrip(sum.readiness));

  const tabs = h('div', { class: 'tabs', role: 'tablist' },
    [['work', 'Work', items.length], ['attention', 'Needs attention', events.length], ['suggested', 'Suggested', sugg.length]].map(([id, label, n]) =>
      h('button', { type: 'button', role: 'tab', class: 'tab', id: `work-tab-${id}`, 'aria-selected': String(tab === id),
        onclick: () => { location.hash = id === 'work' ? `#/work?view=${view}` : `#/work?tab=${id}`; } },
      label, h('span', { class: 'count' }, String(n)))));
  clear(body).appendChild(tabs);
  if (tab === 'attention') body.appendChild(attentionList(events));
  else if (tab === 'suggested') body.appendChild(suggestionList(sugg));
  else body.appendChild(workTable(items, view, ctx, names));
  return null;
}

/** Where every piece of work is, as one proportional bar: the instrument, not a sentence. */
function pipeline(sum) {
  const m = sum.byMarker || {};
  const { bar, legend } = stackBar([
    { n: m.requested || 0, label: 'requested', tone: 'na' },
    { n: (m[''] || 0) + (m.approved || 0), label: 'in progress', tone: 'info' },
    { n: (m.executed || 0) + (m.reported || 0), label: 'changed, not verified', tone: 'warn' },
    { n: m.verified || 0, label: 'verified', tone: 'good' },
    { n: m.complete || 0, label: 'complete', tone: 'ok' },
    { n: m.exception || 0, label: 'risk accepted', tone: 'warn' },
    { n: m.cancelled || 0, label: 'cancelled', tone: 'none' },
  ], 'Work by where it stands');
  return sum.total ? h('section', { class: 'card work-pipeline', 'aria-label': 'Work by where it stands' },
    h('div', { class: 'panel-head' }, h('h2', null, 'Where the work stands'), h('span', { class: 'muted small' }, plural(sum.total, 'piece'))),
    bar, legend) : null;
}

/** Post-quantum key exchange across the endpoints, out of what was scanned, with the unknown kept apart. */
function readinessStrip(r) {
  if (!r || !r.endpoints) return null;
  const unknown = r.endpoints - r.scanned;
  const belowNoWork = r.belowL3 - r.withWork;
  const { bar, legend } = stackBar([
    { n: r.atL3, label: 'at L3 or above', tone: 'good' },
    { n: r.withWork, label: 'below L3, work open', tone: 'info' },
    { n: belowNoWork, label: 'below L3, no work', tone: 'warn' },
    { n: unknown, label: 'not scanned (unknown)', tone: 'na' },
  ], 'Endpoints by post-quantum key exchange');
  return h('section', { class: 'card work-pipeline', 'aria-label': 'Post-quantum key exchange across the endpoints' },
    h('div', { class: 'panel-head' }, h('h2', null, 'Post-quantum key exchange'),
      h('span', { class: 'muted small' }, `${r.atL3} of ${r.scanned} scanned endpoints (${pct(r.atL3, r.scanned)}%) · ${unknown} not scanned`)),
    bar, legend,
    h('p', { class: 'hint' }, 'Out of scanned endpoints only. An endpoint never scanned is unknown: it is not counted as ready or as not ready.'));
}

function workTable(items, view, ctx, names) {
  const [label, keep] = VIEWS[view];
  const rows = items.filter((w) => keep(w, ctx));
  const chips = h('div', { class: 'chips work-views', role: 'group', 'aria-label': 'Show' },
    Object.entries(VIEWS).map(([id, [l]]) => h('a', { class: 'chip', href: `#/work?view=${id}`, 'aria-current': id === view ? 'true' : null }, l)));
  const exports = h('div', { class: 'row work-exports' },
    button('Download CSV', () => api.download('/api/v1/work/export.csv', 'cipherhorizon-work.csv').catch((e) => toast(e.message, 'error')), 'secondary', { class: 'btn btn-secondary btn-sm' }),
    button('Evidence pack (JSON)', () => api.download('/api/v1/work/evidence.json', 'cipherhorizon-work-evidence.json').catch((e) => toast(e.message, 'error')), 'secondary', { class: 'btn btn-secondary btn-sm' }));
  const head = h('div', { class: 'toolbar' }, chips, exports);
  if (!items.length) {
    return h('div', null, head, empty('No work yet', 'Track a finding, a certificate or an endpoint’s readiness from its page, or start from the Suggested tab: it lists what your scans point at.',
      button('See suggestions', () => { location.hash = '#/work?tab=suggested'; }, 'primary')));
  }
  if (!rows.length) return h('div', null, head, h('p', { class: 'muted pad' }, `Nothing is ${label.toLowerCase()}.`));
  return h('div', null, head, h('div', { class: 'tablewrap' }, h('table', { id: 'work-table' },
    h('thead', null, h('tr', null, ['Work', 'Stage', 'Verification', 'Owner', 'Due', ''].map((c) => h('th', { scope: 'col' }, c)))),
    h('tbody', null, rows.map((w) => h('tr', { class: 'rowlink', 'data-work': String(w.id), onclick: (e) => { if (!e.target.closest('a,button')) location.hash = `#/work/${w.id}`; } },
      h('td', null, h('a', { href: `#/work/${w.id}`, class: 'work-title' }, w.title),
        h('div', { class: 'small muted' }, `#${w.id} · ${w.workflowTitle} · `, subjectLink(w, names.get(w.assetId)), w.project ? ` · ${w.project}` : '')),
      h('td', null, markerBadge(w.marker, w.stageLabel)),
      h('td', null, verifyBadge(verificationOf(w)?.status)),
      h('td', { class: 'nowrap work-owner' }, w.owner || h('span', { class: 'muted' }, 'not set')),
      h('td', { class: 'nowrap' }, w.dueAt ? [dayOf(w.dueAt), w.overdue ? [' ', badge('overdue', 'bad')] : null] : h('span', { class: 'muted' }, '·')),
      h('td', { class: 'nowrap' }, h('a', { href: `#/work/${w.id}` }, 'Open'))))))));
}

const EVENT_WORDS = {
  'work.overdue': 'Overdue', 'work.due-soon': 'Due soon', 'work.awaiting-approval': 'Approval needed', 'work.exception-expired': 'Exception ended',
  'work.regressed': 'No longer holds', 'certificate.expired': 'Expired', 'certificate.expiring': 'Expiring', 'certificate.unplanned-change': 'Unplanned change',
};

function attentionList(events) {
  if (!events.length) return empty('Nothing needs a person', 'No work is overdue or waiting for an approval, nothing verified has regressed, and no certificate is about to expire or changed without planned work.');
  return h('div', null,
    h('p', { class: 'text-2' }, 'What the lifecycle monitor finds now. An administrator can have each event sent once to a webhook (Settings → Notifications).'),
    h('div', { class: 'tablewrap' }, h('table', { id: 'attention-table' },
      h('thead', null, h('tr', null, ['Severity', 'What', 'Kind', ''].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, events.map((e) => h('tr', { 'data-kind': e.kind },
        h('td', null, sevBadge(e.severity === 'info' ? 'info' : e.severity)),
        h('td', null, h('b', null, e.title), h('div', { class: 'small muted' }, e.detail)),
        h('td', { class: 'nowrap small' }, EVENT_WORDS[e.kind] || e.kind),
        h('td', { class: 'nowrap' }, e.link ? h('a', { href: e.link }, 'Open') : null)))))));
}

function suggestionList(sugg) {
  if (!sugg.length) return empty('Nothing to suggest', 'Every endpoint your scans reached negotiates hybrid key exchange or already has work, no critical or high finding is untracked, and no certificate is near its end.');
  return h('div', null,
    h('p', { class: 'text-2' }, 'Work your scans point at that nobody has opened yet, most severe first. Each says why and, where a standard sets a date, which one.'),
    h('div', { class: 'tablewrap' }, h('table', { id: 'suggestion-table' },
      h('thead', null, h('tr', null, ['Severity', 'Suggested work', 'Basis', ''].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, sugg.map((s) => h('tr', { 'data-suggestion': s.key },
        h('td', null, sevBadge(s.severity)),
        h('td', null, h('a', { href: s.link }, s.title), h('div', { class: 'small muted' }, s.reason)),
        h('td', { class: 'small' }, s.basis ? h('a', { href: s.basis.url, target: '_blank', rel: 'noopener', title: s.basis.text }, s.basis.document) : h('span', { class: 'muted' }, 'scan finding')),
        h('td', { class: 'nowrap' }, button('Track', () => trackDialog(s.subject, { title: s.title, workflow: s.workflow }), 'secondary', { class: 'btn btn-secondary btn-sm' }))))))));
}

/** New work from the list page: about a system or an endpoint (findings, certificates and readiness
 *  targets are tracked from their own pages, where the subject is unambiguous). */
async function newWorkDialog() {
  let systems = [];
  let assets = [];
  try {
    [systems, assets] = await Promise.all([api.systems().then((r) => r.systems || []), api.assets()]);
  } catch (e) {
    toast(e.message, 'error');
    return;
  }
  modal('New work', (close) => {
    const kind = h('select', { id: 'new-kind' }, h('option', { value: 'system' }, 'A system'), h('option', { value: 'endpoint' }, 'An endpoint'));
    const target = h('select', { id: 'new-target' });
    const fill = () => {
      const list = kind.value === 'system' ? systems.map((s) => [s.id, s.name]) : assets.map((a) => [a.id, a.name]);
      clear(target).append(...list.map(([id, n]) => h('option', { value: String(id) }, n)));
    };
    kind.addEventListener('change', fill);
    fill();
    const next = h('button', { type: 'submit', class: 'btn btn-primary' }, 'Next');
    return h('form', { class: 'modal-body', onsubmit: (e) => {
      e.preventDefault();
      const id = Number(target.value);
      if (!id) return;
      close();
      const subject = kind.value === 'system' ? { kind: 'system', systemId: id } : { kind: 'endpoint', assetId: id };
      setTimeout(() => trackDialog(subject, { workflow: 'manual' }), 180);
    } },
    h('p', { class: 'text-2' }, 'To track a finding, a certificate or a readiness target, open it and press Track: the product can then verify the change by scanning.'),
    h('label', { for: 'new-kind' }, 'About'), kind,
    h('label', { for: 'new-target' }, 'Which'), target,
    h('div', { class: 'row end' }, button('Cancel', close), next));
  });
}

// ---- one piece of work --------------------------------------------------------------------------

async function renderItem(root, id) {
  const host = h('div');
  root.appendChild(host);
  host.appendChild(skeleton(6));
  const paint = async () => {
    const w = await api.workItem(id);
    const assetName = w.assetId ? await api.asset(w.assetId).then((a) => a.name).catch(() => '') : '';
    const flows = await workflows().catch(() => []);
    clear(host).append(...itemPage(w, assetName, flows, paint));
  };
  await paint();
  return null;
}

function itemPage(w, assetName, flows, repaint) {
  const v = verificationOf(w);
  const finished = ['verified', 'complete', 'cancelled'].includes(w.marker);
  return [
    crumbs([['Work', '#/work'], [`#${w.id}`]]),
    h('div', { class: 'page-head' },
      h('div', null, h('h1', { id: 'work-h1' }, w.title),
        h('div', { class: 'sub' }, `${subjectWord(w.subjectKind)}: `, subjectLink(w, assetName), ` · ${w.workflowTitle}`)),
      h('div', { class: 'row' }, button('Edit', () => editDialog(w, repaint), 'secondary', { id: 'work-edit' }))),
    stageTrack(w),
    h('div', { class: 'work-grid' },
      h('div', null,
        nextSteps(w, finished, repaint),
        verificationPanel(w, v, repaint),
        historyPanel(w)),
      h('div', null,
        facts(w),
        depsPanel(w, repaint),
        w.description ? h('section', { class: 'card' }, h('h2', null, 'Description'), h('p', { class: 'work-desc' }, w.description)) : null)),
  ];
}

/** The workflow's stages as a track: done, current, ahead. Cancel and exception stages sit apart. */
function stageTrack(w) {
  const visited = new Set((w.history || []).map((e) => { try { return e.after?.stage; } catch { return null; } }).filter(Boolean));
  visited.add(w.stages[0]?.id);
  const main = w.stages.filter((s) => s.marker !== 'cancelled' && s.marker !== 'exception');
  const side = w.stages.filter((s) => s.marker === 'cancelled' || s.marker === 'exception');
  const curIdx = main.findIndex((s) => s.id === w.stage);
  const step = (s, i) => {
    const state = s.id === w.stage ? 'current' : (curIdx >= 0 ? i < curIdx : visited.has(s.id)) ? 'done' : 'ahead';
    const m = MARKERS[s.marker || ''];
    return h('li', { class: `wstage wstage-${state}`, 'aria-current': state === 'current' ? 'step' : null, title: s.marker ? m.word : null },
      h('span', { class: 'wstage-dot', 'aria-hidden': 'true' }, state === 'done' ? '✓' : String(i + 1)),
      h('span', { class: 'wstage-label' }, s.label));
  };
  return h('section', { class: 'card wtrack', 'aria-label': 'Stages of this work' },
    h('ol', { class: 'wstages' }, main.map(step)),
    side.some((s) => s.id === w.stage) ? h('p', { class: 'wtrack-side' }, markerBadge(w.marker, w.stageLabel),
      w.exceptionUntil ? ` until ${dayOf(w.exceptionUntil)}` : '', w.exceptionExpired ? [' ', badge('ended', 'bad')] : '') : null);
}

const FIELD_WORDS = { note: 'Note', evidence: 'Evidence (a change ticket, a log or a link)', until: 'Until' };

function nextSteps(w, finished, repaint) {
  const box = h('section', { class: 'card', id: 'work-next' }, h('h2', null, finished ? 'Done' : 'Next step'));
  if (finished || !w.transitions.length) {
    box.appendChild(h('p', { class: 'text-2' }, w.marker === 'cancelled' ? 'This work was cancelled.' : w.marker === 'verified' ? 'Verified by scan. Close it when you are ready.' : 'Nothing more to do.'));
    if (w.transitions.length) box.appendChild(h('div', { class: 'row' }, w.transitions.map((t) => transitionButton(w, t, repaint, 'secondary'))));
    return box;
  }
  const forward = w.transitions.find((t) => t.verify) || w.transitions.find((t) => !/cancel|fail|back|rework|retry|reopen|resume|redeploy/.test(t.id)) || w.transitions[0];
  box.appendChild(h('div', { class: 'row' }, w.transitions.map((t) => transitionButton(w, t, repaint, t === forward ? 'primary' : (t.id === 'cancel' ? 'ghost' : 'secondary')))));
  const notes = [];
  const signedIn = !!(session.user && session.user.username);
  if (w.transitions.some((t) => t.approval)) {
    notes.push(signedIn ? `An approval must come from a signed-in person other than ${w.createdBy}.`
      : 'Sign-in is off, so nobody can approve: two people cannot be told apart. Turn sign-in on in Settings, or use a workflow without approvals.');
  }
  if (w.transitions.some((t) => t.verify)) notes.push('Verify asks this product’s latest scan; it succeeds only if the scan shows the change.');
  if (w.transitions.some((t) => t.role === 'admin')) notes.push('Some steps need an administrator.');
  if (notes.length) box.appendChild(h('p', { class: 'hint' }, notes.join(' ')));
  return box;
}

function transitionButton(w, t, repaint, kind) {
  return button(t.label, () => transitionDialog(w, t, repaint), kind, { class: `btn btn-${kind}`, 'data-transition': t.id });
}

function transitionDialog(w, t, repaint) {
  const needs = t.require || [];
  const run = async (body, close, err, submit) => {
    try {
      await api.moveWork(w.id, { transition: t.id, ...body });
      if (close) close();
      toast(`${t.label}: done.`, 'success');
      await repaint();
    } catch (e) {
      const msg = e instanceof ApiError && e.data?.verification ? `${e.message}` : e.message;
      if (err) { err.textContent = msg; err.hidden = false; if (submit) submit.disabled = false; } else toast(msg, 'error');
    }
  };
  if (!needs.length && !t.approval && !t.verify) {
    return modal(t.label, (close) => {
      const err = h('div', { class: 'callout bad', role: 'alert', hidden: true });
      const note = h('textarea', { id: 'move-note', rows: 2, maxlength: '1000' });
      const submit = h('button', { type: 'submit', class: 'btn btn-primary', id: 'move-submit' }, t.label);
      return h('form', { class: 'modal-body', onsubmit: (e) => { e.preventDefault(); submit.disabled = true; run({ note: note.value.trim() }, close, err, submit); } },
        err, h('label', { for: 'move-note' }, 'Note (optional, kept in the history)'), note, h('div', { class: 'row end' }, button('Cancel', close), submit));
    });
  }
  return modal(t.label, (close) => {
    const err = h('div', { class: 'callout bad', role: 'alert', hidden: true });
    const inputs = {};
    const fields = ['note', 'evidence', 'until'].map((f) => {
      const required = needs.includes(f);
      if (!required && f === 'until') return null;
      if (!required && f === 'evidence') return null;
      inputs[f] = f === 'until' ? h('input', { type: 'date', id: `move-${f}`, required })
        : f === 'evidence' ? h('input', { type: 'text', id: `move-${f}`, maxlength: '500', required, autocomplete: 'off', placeholder: 'CHG-1042, a log line or a link' })
          : h('textarea', { id: `move-${f}`, rows: 3, maxlength: '1000', required });
      return [h('label', { for: `move-${f}` }, `${FIELD_WORDS[f]}${required ? '' : ' (optional)'}`), inputs[f]];
    });
    const lead = t.verify ? 'The product checks its own scans made after the change was recorded. If a scan has not run since, scan the endpoint first.'
      : t.approval ? `You approve as ${session.user?.username || 'the signed-in person'}. The person who requested the work cannot approve it.` : null;
    const submit = h('button', { type: 'submit', class: 'btn btn-primary', id: 'move-submit' }, t.label);
    return h('form', { class: 'modal-body', onsubmit: (e) => {
      e.preventDefault();
      submit.disabled = true;
      const body = {};
      for (const [f, el] of Object.entries(inputs)) body[f] = el.value.trim();
      run(body, close, err, submit);
    } }, lead ? h('p', { class: 'text-2' }, lead) : null, err, fields, h('div', { class: 'row end' }, button('Cancel', close), submit));
  });
}

function verificationPanel(w, v, repaint) {
  const box = h('section', { class: 'card', id: 'work-verification' }, h('div', { class: 'panel-head' }, h('h2', null, 'Verification'),
    v?.at ? h('span', { class: 'muted small' }, `checked ${relTime(v.at)}`) : null));
  const tileFor = (ver) => {
    const meta = VERIFY[ver.status] || { word: ver.status, tile: 'na' };
    return statusTile(meta.word, ver.detail, meta.tile);
  };
  const live = h('div', { class: 'stiles one' }, v ? tileFor(v) : statusTile('Not checked yet', w.executedAt ? 'Check now, or record a step that verifies.' : 'Verification starts once the change is recorded as made.', 'na'));
  box.appendChild(live);
  if (v?.evidence?.length) box.appendChild(h('p', { class: 'small muted' }, `Evidence: ${v.evidence.join(', ')}`));
  const actions = h('div', { class: 'row' },
    button('Check now', async (e) => {
      e.target.disabled = true;
      try {
        const nv = await api.workVerification(w.id);
        clear(live).appendChild(tileFor(nv));
      } catch (ex) { toast(ex.message, 'error'); }
      e.target.disabled = false;
    }, 'secondary', { id: 'work-check' }),
    w.assetId && ['finding', 'readiness'].includes(w.subjectKind) ? button('Scan the endpoint now', async (e) => {
      e.target.disabled = true;
      try {
        await api.scanAsset(w.assetId);
        toast('Scan queued. Check again when it finishes.', 'success');
      } catch (ex) { toast(ex.message, 'error'); }
      e.target.disabled = false;
    }, 'secondary', { id: 'work-scan' }) : null);
  box.appendChild(actions);
  box.appendChild(h('p', { class: 'hint' }, 'Only a scan or upload made after the change counts. Typing that a change was made never verifies it.'));
  return box;
}

function facts(w) {
  const row = (k, val) => [h('dt', null, k), h('dd', null, val)];
  return h('section', { class: 'card' }, h('h2', null, 'Details'), h('dl', { class: 'kv work-kv' },
    row('Owner', w.owner || h('span', { class: 'muted' }, 'not set')),
    row('Due', w.dueAt ? [dayOf(w.dueAt), w.overdue ? [' ', badge('overdue', 'bad')] : null] : h('span', { class: 'muted' }, 'none')),
    row('Project', w.project || h('span', { class: 'muted' }, 'none')),
    row('Workflow', `${w.workflowTitle} (v${w.workflowVersion})`),
    row('Requested by', [w.createdBy, h('span', { class: 'muted' }, ` · ${fmtDate(w.createdAt)}`)]),
    row('Approved by', w.approvers.length ? w.approvers.join(', ') : h('span', { class: 'muted' }, 'nobody yet')),
    row('Change recorded', w.executedAt ? fmtDate(w.executedAt) : h('span', { class: 'muted' }, 'not yet')),
    w.closedAt ? row('Closed', fmtDate(w.closedAt)) : null));
}

function depsPanel(w, repaint) {
  const box = h('section', { class: 'card', id: 'work-deps' }, h('h2', null, 'Waits for'));
  if (!w.dependencies.length) box.appendChild(h('p', { class: 'muted small' }, 'Nothing. Add work that must finish first: this work cannot be marked as changed or done until it has.'));
  else box.appendChild(h('ul', { class: 'mini-list' }, w.dependencies.map((d) => h('li', null,
    h('a', { href: `#/work/${d.id}` }, `#${d.id} ${d.title}`), ' ', markerBadge(d.marker, d.stage),
    button('Remove', async () => { try { await api.removeWorkDep(w.id, d.id); await repaint(); } catch (e) { toast(e.message, 'error'); } }, 'ghost', { class: 'btn btn-ghost btn-sm' })))));
  const input = h('input', { type: 'number', min: '1', id: 'dep-id', placeholder: 'work number', class: 'dep-input' });
  box.appendChild(h('form', { class: 'row', onsubmit: async (e) => {
    e.preventDefault();
    const other = Number(input.value);
    if (!other) return;
    try { await api.addWorkDep(w.id, other); await repaint(); } catch (ex) { toast(ex.message, 'error'); }
  } }, h('label', { for: 'dep-id', class: 'sr-only' }, 'Work number to wait for'), input, h('button', { type: 'submit', class: 'btn btn-secondary btn-sm' }, 'Add')));
  return box;
}

const ACTION_WORDS = { created: 'Created', edited: 'Edited', 'dependency added': 'Now waits for other work', 'dependency removed': 'No longer waits' };

function historyPanel(w) {
  const stageLabel = (id) => (w.stages.find((s) => s.id === id) || {}).label || id;
  return h('section', { class: 'card', id: 'work-history' }, h('h2', null, 'History'),
    h('ol', { class: 'timeline' }, (w.history || []).map((e) => {
      const after = e.after || {};
      const ver = after.verification;
      return h('li', { class: 'timeline-row' },
        h('span', { class: 'timeline-when', title: fmtDate(e.at) }, relTime(e.at)),
        h('span', { class: 'timeline-what' },
          h('b', null, ACTION_WORDS[e.action] || (w.labels || {})[e.action] || e.action.replace(/-/g, ' ')), ` by ${e.actor}`,
          after.stage && e.action !== 'created' && e.action !== 'edited' ? h('span', { class: 'muted' }, ` → ${stageLabel(after.stage)}`) : null,
          after.approval ? [' ', badge('approval', 'info')] : null,
          ver ? [' ', verifyBadge(ver.status)] : null,
          e.reason ? h('div', { class: 'small' }, e.reason) : null,
          after.evidence ? h('div', { class: 'small mono' }, after.evidence) : null,
          ver?.detail ? h('div', { class: 'small muted' }, ver.detail) : null));
    })));
}

function editDialog(w, repaint) {
  modal('Edit work', (close) => {
    const err = h('div', { class: 'callout bad', role: 'alert', hidden: true });
    const t = h('input', { type: 'text', id: 'edit-title', value: w.title, maxlength: '200' });
    const o = h('input', { type: 'text', id: 'edit-owner', value: w.owner, maxlength: '100' });
    const d = h('input', { type: 'date', id: 'edit-due', value: w.dueAt ? w.dueAt.slice(0, 10) : '' });
    const p = h('input', { type: 'text', id: 'edit-project', value: w.project, maxlength: '100' });
    const desc = h('textarea', { id: 'edit-desc', rows: 4, maxlength: '4000' }, w.description);
    const r = h('input', { type: 'text', id: 'edit-reason', maxlength: '200' });
    return h('form', { class: 'modal-body', onsubmit: async (e) => {
      e.preventDefault();
      try {
        await api.patchWork(w.id, { title: t.value.trim(), owner: o.value.trim(), due: d.value, project: p.value.trim(), description: desc.value.trim() }, r.value.trim());
        close();
        await repaint();
      } catch (ex) { err.textContent = ex.message; err.hidden = false; }
    } }, err,
    h('label', { for: 'edit-title' }, 'Title'), t,
    h('div', { class: 'form-2col' }, h('div', null, h('label', { for: 'edit-owner' }, 'Owner'), o), h('div', null, h('label', { for: 'edit-due' }, 'Due'), d)),
    h('label', { for: 'edit-project' }, 'Project'), p,
    h('label', { for: 'edit-desc' }, 'Description'), desc,
    h('label', { for: 'edit-reason' }, 'Reason (optional, kept in the history)'), r,
    h('div', { class: 'row end' }, button('Cancel', close), h('button', { type: 'submit', class: 'btn btn-primary' }, 'Save')));
  });
}
