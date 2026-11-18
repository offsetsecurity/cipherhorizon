// Fixes (UX-DESIGN-024): give a problem an owner and a date; every scan after that checks it and
// says when it is really fixed. Two pages: the list (#/fixes) and one fix (#/fixes/ID).
import { h, clear, relTime, fmtDate, fmtDay } from '../dom.js';
import { api } from '../api.js';
import { button, toast, empty, skeleton, crumbs, modal, citations } from '../ui.js';
import { standing, assignDialog, dayOf, fixHref } from '../fix-ui.js';

export async function render(root, { args }) {
  return args && args[0] ? renderFix(root, Number(args[0])) : renderList(root);
}

const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const SEV_WORD = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: '' };
const SHOWN = 5;

// ---- the list -------------------------------------------------------------------------------

function fixRow(f) {
  const s = standing(f);
  return h('li', { class: 'fxrow', 'data-fix': String(f.id) },
    h('div', { class: 'fxrow-main' },
      h('a', { href: fixHref(f.id), class: 'fxrow-title' }, f.title),
      h('div', { class: `fxrow-state fix-${s.tone}` }, s.text)),
    h('div', { class: 'fxrow-owner' }, f.owner || h('span', { class: 'muted' }, 'nobody yet')),
    h('div', { class: `fxrow-due${f.overdue ? ' fix-warn' : ''}` }, f.dueAt ? `due ${dayOf(f.dueAt)}` : h('span', { class: 'muted' }, 'no date')));
}

function progressPanel(p) {
  if (!p.endpoints) return null;
  const unknown = p.endpoints - p.scanned + p.undetermined;
  const notStarted = p.belowL3 - p.withWork;
  const seg = (n, cls) => { const e = h('div', { class: `fixbar-seg ${cls}` }); e.style.flexGrow = String(n); return n ? e : null; };
  const parts = [`${p.withWork} being fixed`, `${notStarted} not started`];
  if (unknown) parts.push(`${unknown} not scanned yet`);
  return h('section', { class: 'card fixprogress', 'aria-label': 'Progress' },
    h('div', { class: 'fixprogress-head' },
      h('div', { class: 'fixprogress-line', id: 'fix-progress' }, `${p.atL3} of ${plural(p.scanned, 'scanned endpoint')} ${p.atL3 === 1 ? 'keeps' : 'keep'} today’s traffic safe from later decryption`),
      h('div', { class: 'small muted' }, parts.join(' · '))),
    h('div', { class: 'fixbar', role: 'img', 'aria-label': `${p.atL3} safe, ${p.withWork} being fixed, ${notStarted} not started, ${unknown} not scanned` },
      seg(p.atL3, 'fixbar-good'), seg(p.withWork, 'fixbar-doing'), seg(notStarted, 'fixbar-todo'), seg(unknown, 'fixbar-unknown')));
}

async function renderList(root) {
  root.appendChild(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Fixes'),
      h('div', { class: 'sub' }, 'Give a problem an owner and a date. Every scan after that checks it for you and says when it is really fixed.'))));
  const body = h('div', { class: 'fixpage' });
  root.appendChild(body);
  body.appendChild(skeleton(5));
  let showAllNext = false;
  let showFixed = false;

  const paint = async () => {
    const d = await api.fixes();
    clear(body);
    const nothing = !d.cameBack.length && !d.beingFixed.length && !d.onHold.length && !d.fixed.length && !d.toFix.length;
    if (nothing) {
      body.appendChild(empty(d.progress.endpoints ? 'Nothing to fix' : 'Scan something first',
        d.progress.endpoints ? 'No scan found a serious problem, an endpoint without post-quantum key exchange, or a certificate about to run out.'
          : 'Add an endpoint and scan it. What needs fixing appears here, most serious first; you give each one an owner and a date, and the scans do the checking.',
        button('Add an endpoint', () => { location.hash = '#/endpoints'; }, 'primary')));
      return;
    }
    const prog = progressPanel(d.progress);
    if (prog) body.appendChild(prog);

    if (d.cameBack.length) {
      body.appendChild(h('section', { 'aria-labelledby': 'fx-back' },
        h('h2', { id: 'fx-back', class: 'fix-h' }, 'Came back ', h('span', { class: 'fx-count' }, String(d.cameBack.length))),
        h('ul', { class: 'fxrows fxrows-bad', id: 'fixes-back' }, d.cameBack.map(fixRow))));
    }
    if (d.beingFixed.length) {
      body.appendChild(h('section', { 'aria-labelledby': 'fx-doing' },
        h('h2', { id: 'fx-doing', class: 'fix-h' }, 'Being fixed ', h('span', { class: 'fx-count' }, String(d.beingFixed.length))),
        h('ul', { class: 'fxrows', id: 'fixes-doing' }, d.beingFixed.map(fixRow))));
    }

    const next = showAllNext ? d.toFix : d.toFix.slice(0, SHOWN);
    body.appendChild(h('section', { 'aria-labelledby': 'fx-next' },
      h('div', { class: 'fix-headrow' },
        h('h2', { id: 'fx-next', class: 'fix-h' }, 'To fix next ', h('span', { class: 'fx-count' }, String(d.toFix.length))),
        d.toFix.length ? h('span', { class: 'small muted' }, 'Most serious first. One line per endpoint.') : null),
      d.toFix.length ? h('ul', { class: 'fxrows', id: 'fixes-next' }, next.map((s, i) => h('li', { class: 'fxrow', 'data-next': s.key },
        h('div', { class: 'fxrow-main' },
          h('a', { href: s.link, class: 'fxrow-title' }, s.title),
          h('div', { class: 'fxrow-state' }, [SEV_WORD[s.severity], s.reason].filter(Boolean).join('. '),
            s.basis ? [' ', h('a', { href: s.basis.url, target: '_blank', rel: 'noopener', title: s.basis.text }, 'Why, and by when')] : null)),
        button('Assign', () => assignDialog(s.subject, { what: s.title, onDone: () => { toast('Assigned.', 'success'); paint(); } }), i === 0 && !d.beingFixed.length && !d.cameBack.length ? 'primary' : 'secondary',
          { 'data-assign': s.subject.kind }))))
        : h('p', { class: 'muted' }, 'Nothing is waiting: every problem the scans found has an owner.'),
      d.toFix.length > SHOWN && !showAllNext ? button(`Show ${d.toFix.length - SHOWN} more`, () => { showAllNext = true; paint(); }, 'ghost', { class: 'btn btn-ghost btn-sm' }) : null));

    if (d.onHold.length) {
      body.appendChild(h('section', { 'aria-labelledby': 'fx-hold' },
        h('h2', { id: 'fx-hold', class: 'fix-h' }, 'On hold ', h('span', { class: 'fx-count' }, String(d.onHold.length))),
        h('ul', { class: 'fxrows', id: 'fixes-hold' }, d.onHold.map(fixRow))));
    }

    body.appendChild(h('section', { class: 'fix-foot', 'aria-labelledby': 'fx-done' },
      h('h2', { id: 'fx-done', class: 'fix-h fix-h-sm' }, 'Fixed and still holding ', h('span', { class: 'fx-count' }, String(d.fixed.length))),
      h('div', { class: 'row' },
        d.fixed.length ? button(showFixed ? 'Hide them' : 'Show them', () => { showFixed = !showFixed; paint(); }, 'ghost', { class: 'btn btn-ghost btn-sm', id: 'fixes-show-fixed' }) : null,
        button('Download the record for an auditor', () => api.download('/api/v1/work/evidence.json', 'cipherhorizon-fixes-record.json').catch((e) => toast(e.message, 'error')), 'ghost', { class: 'btn btn-ghost btn-sm' }))));
    if (showFixed && d.fixed.length) body.appendChild(h('ul', { class: 'fxrows', id: 'fixes-fixed' }, d.fixed.map(fixRow)));
  };
  await paint();
  return null;
}

// ---- one fix ----------------------------------------------------------------------------------

const BIG = { fixed: 'Fixed', 'came-back': 'Came back', 'on-hold': 'On hold', closed: 'Closed' };
const EVENT = {
  assigned: (e) => `Assigned by ${e.by}.`,
  fixed: () => 'A scan confirmed it is fixed.',
  'came-back': () => 'A scan found it again.',
  hold: (e) => `Put on hold by ${e.by}${e.text ? `: ${e.text}` : '.'}`,
  resumed: (e) => (e.by === 'scanner' ? 'The hold ended.' : `Resumed by ${e.by}.`),
  changed: (e) => `Owner, date or ticket changed by ${e.by}.`,
  closed: (e) => `Closed without a check by ${e.by}${e.text ? `: ${e.text}` : '.'}`,
  dropped: (e) => `Dropped by ${e.by}${e.text ? `: ${e.text}` : '.'}`,
};

async function renderFix(root, id) {
  const host = h('div', { class: 'fixpage' });
  root.appendChild(host);
  host.appendChild(skeleton(6));
  const paint = async () => {
    const f = await api.fix(id);
    const s = standing(f);
    const open = f.group === 'being-fixed' || f.group === 'came-back';
    const big = BIG[f.group] || (f.result === 'not-fixed' ? 'Not fixed yet' : f.result === 'cannot-check' ? 'A scan cannot check this' : 'Not checked yet');
    clear(host).append(
      crumbs([['Fixes', '#/fixes'], [f.title]]),
      h('div', { class: 'page-head' },
        h('div', null, h('h1', { id: 'fix-h1' }, f.title),
          h('div', { class: 'sub' }, f.owner || 'Nobody assigned', f.dueAt ? ` · due ${dayOf(f.dueAt)}` : '',
            f.ticket ? [' · ', h('a', { href: f.ticket, target: '_blank', rel: 'noopener noreferrer' }, 'Your ticket')] : null)),
        h('div', { class: 'row' },
          f.assetId && open ? button('Scan now', async (e) => {
            e.target.disabled = true;
            try { await api.scanAsset(f.assetId); toast('Scanning. This page updates when the scan finishes.', 'success'); waitForScan(f.assetId, paint); } catch (ex) { toast(ex.message, 'error'); e.target.disabled = false; }
          }, 'primary', { id: 'fix-scan' }) : null,
          f.group !== 'closed' ? button('Change owner or date', () => editDialog(f, paint), 'secondary', { id: 'fix-edit' }) : null)),
      h('section', { class: `card fixstate fixstate-${s.tone}`, id: 'fix-state', 'aria-label': 'Where it stands' },
        h('div', { class: 'fixstate-big' }, big),
        h('div', { class: 'fixstate-line' }, s.text),
        f.detail && f.group !== 'fixed' ? h('div', { class: 'small muted' }, `What the scan saw: ${f.detail}`) : null),
      h('div', { class: 'fixgrid' },
        h('section', { class: 'card', id: 'fix-how', 'aria-labelledby': 'fix-how-h' },
          h('h2', { id: 'fix-how-h' }, f.group === 'fixed' ? 'What was fixed' : 'How to fix it'),
          f.howTo ? h('p', null, f.howTo) : h('p', { class: 'muted' }, 'The report has the details.'),
          f.why && f.group !== 'fixed' ? h('p', { class: 'text-2' }, f.why) : null,
          h('div', { class: 'row' }, f.report ? h('a', { href: f.report }, 'Open the full report') : null),
          f.sources && f.sources.length ? citations(f.sources) : null),
        h('section', { class: 'card', id: 'fix-history', 'aria-labelledby': 'fix-hist-h' },
          h('h2', { id: 'fix-hist-h' }, 'What has happened'),
          h('ol', { class: 'fixhist' }, f.history.map((e) => h('li', null,
            h('span', { class: 'fixhist-when', title: fmtDate(e.at) }, fmtDay(e.at)),
            h('span', null, (EVENT[e.kind] || (() => e.kind))(e))))),
          h('p', { class: 'hint' }, 'Only scans change whether this is fixed. Nobody can mark it fixed by hand.'))),
      open ? h('div', { class: 'row fix-more' },
        button('Put on hold', () => holdDialog(f, paint), 'ghost', { class: 'btn btn-ghost btn-sm', id: 'fix-hold' }),
        f.result === 'cannot-check' ? button('Close it', () => noteDialog(f, 'close', 'Close this fix', 'What was done', paint), 'ghost', { class: 'btn btn-ghost btn-sm' }) : null,
        button('Drop it', () => noteDialog(f, 'drop', 'Drop this fix', 'Why it is not needed', paint), 'ghost', { class: 'btn btn-ghost btn-sm' }))
        : f.group === 'on-hold' ? h('div', { class: 'row fix-more' }, button('Resume now', async () => { try { await api.moveWork(f.id, { transition: 'resume' }); await paint(); } catch (e) { toast(e.message, 'error'); } }, 'secondary', { id: 'fix-resume' })) : null);
  };
  await paint();
  return null;
}

/** After "Scan now": repaint when the endpoint's scan is no longer queued or running. */
async function waitForScan(assetId, repaint) {
  for (let i = 0; i < 90; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    let a;
    try { a = await api.asset(assetId); } catch { return; }
    if (!a.latest || (a.latest.status !== 'queued' && a.latest.status !== 'running')) { await repaint(); return; }
  }
}

function editDialog(f, repaint) {
  modal('Change owner or date', (close) => {
    const err = h('div', { class: 'callout bad', role: 'alert', hidden: true });
    const o = h('input', { type: 'text', id: 'fix-owner', value: f.owner || '', maxlength: '100', autocomplete: 'off' });
    const d = h('input', { type: 'date', id: 'fix-due', value: f.dueAt ? f.dueAt.slice(0, 10) : '' });
    const t = h('input', { type: 'url', id: 'fix-ticket', value: f.ticket || '', maxlength: '500', autocomplete: 'off' });
    return h('form', { class: 'modal-body', onsubmit: async (e) => {
      e.preventDefault();
      try { await api.patchWork(f.id, { owner: o.value.trim(), due: d.value, ticket: t.value.trim() }); close(); await repaint(); } catch (ex) { err.textContent = ex.message; err.hidden = false; }
    } }, err,
    h('div', { class: 'form-2col' }, h('div', null, h('label', { for: 'fix-owner' }, 'Who will fix it'), o), h('div', null, h('label', { for: 'fix-due' }, 'By when'), d)),
    h('label', { for: 'fix-ticket' }, 'Your ticket ', h('span', { class: 'muted' }, '(optional)')), t,
    h('div', { class: 'row end' }, button('Cancel', close), h('button', { type: 'submit', class: 'btn btn-primary' }, 'Save')));
  });
}

function holdDialog(f, repaint) {
  modal('Put on hold', (close) => {
    const err = h('div', { class: 'callout bad', role: 'alert', hidden: true });
    const why = h('input', { type: 'text', id: 'hold-why', maxlength: '200', required: true, autocomplete: 'off', placeholder: 'change freeze, waiting for the vendor, …' });
    const until = h('input', { type: 'date', id: 'hold-until', required: true });
    return h('form', { class: 'modal-body', onsubmit: async (e) => {
      e.preventDefault();
      try { await api.moveWork(f.id, { transition: 'hold', note: why.value.trim(), until: until.value }); close(); await repaint(); } catch (ex) { err.textContent = ex.message; err.hidden = false; }
    } },
    h('p', { class: 'text-2' }, 'A fix on hold is not counted as overdue. It comes back by itself on the date, within a year.'), err,
    h('label', { for: 'hold-why' }, 'Why'), why,
    h('label', { for: 'hold-until' }, 'Until'), until,
    h('div', { class: 'row end' }, button('Cancel', close), h('button', { type: 'submit', class: 'btn btn-primary', id: 'hold-submit' }, 'Put on hold')));
  });
}

function noteDialog(f, transition, title, label, repaint) {
  modal(title, (close) => {
    const err = h('div', { class: 'callout bad', role: 'alert', hidden: true });
    const note = h('input', { type: 'text', id: 'fix-note', maxlength: '200', required: true, autocomplete: 'off' });
    return h('form', { class: 'modal-body', onsubmit: async (e) => {
      e.preventDefault();
      try { await api.moveWork(f.id, { transition, note: note.value.trim() }); close(); await repaint(); } catch (ex) { err.textContent = ex.message; err.hidden = false; }
    } }, err, h('label', { for: 'fix-note' }, label), note,
    h('div', { class: 'row end' }, button('Cancel', close), h('button', { type: 'submit', class: 'btn btn-primary' }, title)));
  });
}
