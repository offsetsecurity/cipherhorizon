// Standards (PRD-017): how an endpoint measures against each published standard, clause by
// clause. The data is the evaluation's standards[]; nothing here judges. The page answers, in
// order: which standards does this endpoint meet; for one that it does not, which clauses, with
// the document's own section numbers, and what was seen; what a network scan cannot assess.
import { h, toCSV } from '../dom.js';
import { api } from '../api.js';
import { button } from '../ui.js';
import { stackBar } from '../viz.js';

const plural = (n, one, many) => `${n} ${n === 1 ? one : many || `${one}s`}`;

export const VERDICT = {
  meets: ['Meets', 'good'],
  'does-not-meet': ['Does not meet', 'bad'],
  'not-assessed': ['Not assessed', 'neutral'],
};

const STATUS = {
  met: ['Met', 'good'],
  'not-met': ['Not met', 'bad'],
  'not-followed': ['Not followed', 'warn'],
  'not-assessed': ['Not assessed', 'neutral'],
  'not-applicable': ['Does not apply', 'neutral'],
};

/** A requirement's status word: a recommendation not met reads "not followed", never "not met". */
export const statusOf = (r) => (r.status === 'not-met' && r.level === 'should' ? 'not-followed' : r.status);

/** The verdict in words and a tone: "Does not meet · 3 clauses", "Meets · 2 recommendations not followed". */
export function verdictWords(s) {
  const [word, tone] = VERDICT[s.verdict] || ['·', 'neutral'];
  if (s.verdict === 'does-not-meet') return [`${word} · ${plural(s.mustFailures, 'clause')}`, tone];
  if (s.verdict === 'meets' && s.shouldFailures) return [`${word} · ${plural(s.shouldFailures, 'recommendation')} not followed`, tone];
  return [word, tone];
}

/** One verdict chip, for the Summary and the lists; opens the standard's checklist. */
export function verdictChip(s, onclick) {
  const [words, tone] = verdictWords(s);
  return h('a', { class: `stdchip stdchip-${tone}`, href: `#std-${s.id}`, title: `${s.title}: ${words}`, onclick },
    h('span', { class: 'stdchip-glyph', 'aria-hidden': 'true' }, { good: '✓', bad: '✕', warn: '!', neutral: '·' }[tone]),
    h('span', { class: 'stdchip-name' }, s.title),
    h('span', { class: 'stdchip-words' }, words));
}

/** The tally of one standard's clauses as a bar: met, not met, not followed, not assessed, do not apply. */
function tally(s) {
  const n = (st) => s.requirements.filter((r) => statusOf(r) === st).length;
  return stackBar([
    { n: n('met'), label: 'met', tone: 'good' },
    { n: n('not-met'), label: 'not met', tone: 'problem' },
    { n: n('not-followed'), label: 'not followed', tone: 'attention' },
    { n: n('not-assessed'), label: 'not assessed', tone: 'na' },
    { n: n('not-applicable'), label: 'do not apply', tone: 'na' },
  ]);
}

function checklistCSV(ctx, s) {
  const rows = s.requirements.map((r) => [s.title, r.clause, r.level, r.text, STATUS[statusOf(r)][0], r.detail || '']);
  api.downloadBlob(`${ctx.stem}-${s.id}.csv`, toCSV([['standard', 'clause', 'level', 'requirement', 'status', 'seen'], ...rows]), 'text/csv');
}

/** The Standards tab. ctx: { ev, stem, goTab } */
export function standardsView(ctx) {
  const list = ctx.ev.standards || [];
  const wrap = h('div', { class: 'report standards' });
  if (!list.length) {
    wrap.appendChild(h('section', { class: 'card' }, h('h2', null, 'Standards'),
      h('p', { class: 'muted' }, 'This scan was evaluated before standards were judged. Re-evaluate it (More → Re-evaluate) or scan again to see how it measures against NIST SP 800-52, BSI TR-02102, BCP 195 and the other standards.')));
    return wrap;
  }
  const state = { only: false };
  const meets = list.filter((s) => s.verdict === 'meets').length;
  const fails = list.filter((s) => s.verdict === 'does-not-meet').length;
  const lede = fails ? `Meets ${meets} of ${list.length}; does not meet ${plural(fails, 'standard')}.`
    : meets === list.length ? `Meets every standard this program carries.` : `Meets ${meets} of ${list.length}; the rest could not be assessed from this scan.`;

  // The verdicts, one card per standard: the headline a reader scans first.
  const cards = h('div', { class: 'std-grid' }, list.map((s) => {
    const [words, tone] = verdictWords(s);
    const bar = tally(s);
    return h('a', { class: `std-card std-${tone}`, href: `#std-${s.id}`, onclick: (e) => { e.preventDefault(); document.getElementById(`std-${s.id}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' }); } },
      h('div', { class: 'std-card-head' }, h('b', null, s.title), h('span', { class: 'std-pub' }, s.publisher)),
      h('div', { class: `std-verdict tone-${tone}` }, words),
      bar.bar);
  }));
  wrap.appendChild(h('section', { class: 'card', 'aria-labelledby': 'std-h' },
    h('div', { class: 'cfg-head' }, h('h2', { id: 'std-h' }, 'Standards'),
      h('label', { class: 'row small' }, h('input', { type: 'checkbox', checked: state.only, onchange: (e) => { state.only = e.target.checked; paintLists(); } }), ' Only clauses not met')),
    h('p', { class: 'std-lede' }, lede, ' A standard is met when none of its binding clauses fails; a recommendation not followed is counted beside it. A clause the scan holds no evidence for is ',
      h('i', null, 'not assessed'), ', never met. ', h('a', { href: '#/help?topic=standards' }, 'How standards are judged')),
    cards));

  // One checklist per standard.
  const lists = h('div');
  const paintLists = () => {
    lists.replaceChildren(...list.map((s) => {
      const [words, tone] = verdictWords(s);
      const shown = s.requirements.filter((r) => !state.only || ['not-met', 'not-followed'].includes(statusOf(r)));
      const rows = shown.map((r) => {
        const st = statusOf(r);
        const [word, t] = STATUS[st];
        return h('tr', { class: `std-row std-row-${t}` },
          h('td', { class: 'std-clause' }, h('code', null, r.clause)),
          h('td', null, r.text, h('span', { class: `lvltag lvltag-${r.level}`, title: r.level === 'must' ? 'A binding clause: shall, must, or something the document does not recommend' : 'A recommendation' }, r.level)),
          h('td', { class: 'nowrap' }, h('span', { class: `badge b-${t}` }, word)),
          h('td', { class: 'std-seen' }, r.detail || ''));
      });
      return h('section', { class: 'card std-list', id: `std-${s.id}`, 'aria-labelledby': `std-${s.id}-h` },
        h('div', { class: 'cfg-head' },
          h('div', null, h('h2', { id: `std-${s.id}-h` }, s.title, ' ', h('span', { class: `badge b-${tone}` }, words)),
            h('div', { class: 'sub' }, `${s.publisher} · ${s.edition} · `, h('a', { href: s.url, target: '_blank', rel: 'noopener' }, 'the document'))),
          button('Checklist (CSV)', () => checklistCSV(ctx, s), 'secondary', { class: 'btn btn-secondary btn-sm' })),
        h('p', { class: 'std-scope' }, s.scope),
        rows.length ? h('div', { class: 'tablewrap' }, h('table', { class: 'std-table' },
          h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Clause'), h('th', { scope: 'col' }, 'Requirement'), h('th', { scope: 'col' }, 'Status'), h('th', { scope: 'col' }, 'Seen on this endpoint'))),
          h('tbody', null, rows)))
          : h('p', { class: 'muted' }, 'Every clause is met, not assessed, or does not apply.'),
        s.limits && s.limits.length ? h('details', { class: 'std-limits' }, h('summary', null, `Not assessed by a network scan (${s.limits.length})`),
          h('ul', null, s.limits.map((l) => h('li', null, l)))) : null);
    }));
  };
  paintLists();
  wrap.appendChild(lists);
  return wrap;
}

/** The Summary's standards card: every verdict as a chip; opens the Standards tab. */
export function standardsCard(ctx) {
  const list = ctx.ev.standards || [];
  if (!list.length) return null;
  const fails = list.filter((s) => s.verdict === 'does-not-meet').length;
  const go = (e) => { e.preventDefault(); ctx.goTab('standards'); };
  return h('section', { class: 'card stdcard', 'aria-labelledby': 'stdcard-h' },
    h('div', { class: 'cfg-head' },
      h('h2', { id: 'stdcard-h' }, fails ? `Does not meet ${plural(fails, 'standard')}` : `Meets ${list.filter((s) => s.verdict === 'meets').length} of ${list.length} standards`),
      h('a', { href: '#', class: 'xlink', onclick: go }, 'Clause by clause')),
    h('div', { class: 'stdchips' }, list.map((s) => verdictChip(s, go))));
}
