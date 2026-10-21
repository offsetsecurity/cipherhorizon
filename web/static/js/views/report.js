// The endpoint report (PRD-006): Summary for anyone (the verdict, how much was checked, action
// items in plain words); Configuration (what the server ran, version by version); Weaknesses
// (every check run, found or not, with evidence); CBOM (the endpoint's CycloneDX CBOM).
// Everything the target or its certificates supplied reaches the page through the
// textContent-only DOM builder.
import { h, svg, clear, fmtDate, fmtDay, daysUntil } from '../dom.js';
import { levelClass, levelName } from '../charts.js';
import { badge, sevBadge, evidenceBadge, citations, bandTone, bandWord, button } from '../ui.js';
import { tlsConfiguration, weakestAlgorithm, certHref } from './tls-config.js';
import { bitsBar, gauge, levelStepper, lifetimeBar, stackBar, statusTile } from '../viz.js';

export const SECTIONS = [
  ['certificates', 'Certificates & trust', 'Who issued the certificate, who trusts it, and how long it lasts.'],
  ['revocation', 'Revocation & transparency', 'The stapled revocation proof and Certificate Transparency proofs.'],
  ['protocols', 'Protocols', 'Which SSL and TLS versions the server accepts.'],
  ['suites', 'Cipher suites', 'Every cipher suite accepted, and who chooses the order.'],
  ['key-exchange', 'Key exchange & post-quantum', 'How session keys are agreed, including post-quantum hybrids.'],
  ['features', 'Features & sessions', 'Renegotiation, compression, downgrade protection and client certificates.'],
  ['http', 'HTTP security', 'Whether browsers are told to use HTTPS only (HSTS).'],
  ['vulnerabilities', 'Vulnerabilities', 'Published attacks the configuration makes possible, inferred, never attempted.'],
];

const STATUS = {
  problem: ['✖', 'Problem'], attention: ['▲', 'Needs attention'], good: ['✔', 'Good'],
  'not-checked': ['○', 'Not checked'], 'not-collected': ['○', 'Not collected'], inconclusive: ['?', 'Inconclusive'],
  'not-applicable': ['·', 'Not applicable'],
};

export function statusChip(st) {
  const [sym, word] = STATUS[st] || ['?', st];
  return h('span', { class: `secstatus ss-${st}` }, h('span', { 'aria-hidden': 'true' }, sym), ` ${word}`);
}

const humanDuration = (s) => (s >= 86400 * 365 ? `${(s / (86400 * 365)).toFixed(s % (86400 * 365) ? 1 : 0)} years`
  : s >= 86400 ? `${Math.floor(s / 86400)} days` : s >= 3600 ? `${Math.floor(s / 3600)} hours` : s >= 60 ? `${Math.floor(s / 60)} minutes` : `${s} seconds`);
const plural = (n, one, many) => `${n} ${n === 1 ? one : many || `${one}s`}`;
const legacyVersion = (v) => ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'].includes(v);
const ianaLabel = (r) => ({ Y: 'Recommended', N: 'Not recommended', D: 'Discouraged' }[r] || r);
const keyDesc = (k) => (k ? `${k.algorithm}${k.bits ? ` ${k.bits}-bit` : ''}${k.curve ? ` (${k.curve})` : ''}` : 'unknown key');
const cn = (subject) => { const m = /CN=([^,]+)/.exec(subject || ''); return m ? m[1] : (subject || 'unknown'); };
const chainLabel = (v) => {
  if (v.noSni) return 'Without SNI';
  const s = v.source || '';
  if (s.startsWith('tls-default')) return 'Default';
  if (s.includes('ecdsa')) return 'ECDSA';
  if (s.includes('rsa')) return 'RSA';
  return s;
};

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const BUILDERS = () => ({ certificates: certificatesBody, revocation: revocationBody, protocols: protocolsBody, suites: suitesBody,
  'key-exchange': keyExchangeBody, features: featuresBody, http: httpBody, vulnerabilities: vulnerabilitiesBody });
const capital = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : '');

// Plain words for a reader who is not a TLS specialist (PRD-006 D6): why a kind of finding matters,
// and how urgent a severity is. Kept per category and severity so they stay consistent.
const WHY = {
  protocol: 'Old protocol versions have known weaknesses, and current browsers and clients no longer need them.',
  cipher: 'Weak cipher suites can let an attacker read or change traffic, or lower the protection modern clients get.',
  'key-exchange': 'The key exchange protects each session’s keys; a weak one exposes the whole session.',
  pqc: 'Traffic recorded today could be decrypted once large quantum computers exist (harvest now, decrypt later).',
  certificate: 'Clients trust the server through its certificate: a problem here makes connections fail or lets someone impersonate the server.',
  revocation: 'Revocation information lets clients refuse a stolen or wrongly issued certificate quickly.',
  feature: 'These protocol features close known attack paths such as downgrades and renegotiation attacks.',
  http: 'Without HSTS a browser may first connect over plain HTTP, where traffic can be intercepted or changed.',
  vulnerability: 'This configuration makes a published attack possible.',
};
const GROUP_WORD = { protocol: 'Protocol versions', cipher: 'Cipher suites', 'key-exchange': 'Key exchange', pqc: 'Post-quantum',
  certificate: 'Certificate', revocation: 'Revocation', feature: 'Protocol features', http: 'HTTP security', vulnerability: 'Published attacks' };
const URGENCY = { critical: 'Fix now', high: 'Fix soon', medium: 'Plan a fix', low: 'When convenient', info: 'For information' };
const whyOf = (f, prof = TLS) => (prof.why === WHY && (f.section === 'http' || f.section === 'revocation') ? WHY[f.section] : null) || prof.why[f.category] || WHY.vulnerability;

// ---- protocol profiles (PRD-008 D-18) ---------------------------------------------------------
// The report's shared parts (verdict, coverage line, action items, every check, CBOM) work for any
// protocol; what differs is in a profile: the areas and their fact builders, the summary tiles,
// the words for why a finding matters, and the scan stages. report-ssh.js registers SSH's.
const PROFILES = {};
export function registerProfile(name, prof) { PROFILES[name] = prof; }
const TLS = {
  sections: SECTIONS, builders: () => BUILDERS(), strip: (ctx, sections) => summaryStrip(ctx, sections), why: WHY, groupWord: GROUP_WORD,
  hygiene: 'TLS hygiene', configuration: (ctx, about) => tlsConfiguration(ctx, about), skipCards: ['protocols', 'suites', 'vulnerabilities'],
  stageTitles: { protocols: 'Protocols', suites: 'Cipher suites', 'key-exchange': 'Key exchange', signatures: 'Signature schemes', features: 'Features',
    certificates: 'Certificates', revocation: 'Revocation & transparency', http: 'HTTP' },
  schema: 'tls-report/1',
};
/** The profile of an evaluation (or a ctx holding one). */
export const profileOf = (x) => { const ev = x && x.ev ? x.ev : x; return (ev && PROFILES[ev.protocol]) || TLS; };
const sectionTitleIn = (prof, id) => (prof.sections.find(([s]) => s === id) || [id, id])[1];

/** What each area says in one sentence, and its facts, computed once per render. */
function sectionData(ctx) {
  const prof = profileOf(ctx);
  const sections = Object.fromEntries((ctx.ev.sections || []).map((x) => [x.id, x]));
  const builders = prof.builders();
  return prof.sections.map(([id, title, purpose]) => {
    const sec = sections[id] || { id, status: 'not-collected', findings: [] };
    const body = builders[id](ctx, sec);
    const facts = (body.facts || []).filter(Boolean);
    const verdict = capital(body.verdict || facts[0] || sec.reason || '');
    return { id, title, purpose, sec, body, facts, verdict };
  });
}

/** One finding per rule, worst first, then by section order. */
export function uniqueFindings(ev) {
  const order = Object.fromEntries(profileOf(ev).sections.map(([id], i) => [id, i]));
  const seen = new Set();
  return ev.findings.filter((f) => (seen.has(f.id) ? false : seen.add(f.id)))
    .sort((a, b) => (SEV_RANK[a.severity] - SEV_RANK[b.severity]) || ((order[a.section] ?? 9) - (order[b.section] ?? 9)));
}

/** The checks this evaluation ran; an older evaluation that does not list them gets its findings only. */
function checksOf(ev) {
  if (Array.isArray(ev.checks) && ev.checks.length) return ev.checks;
  return uniqueFindings(ev).map((f) => ({ id: f.id, title: f.title, section: f.section, severity: f.severity, result: 'found' }));
}

/**
 * summaryView is for anyone: the verdict, how much was checked, and the action items in plain
 * words (PRD-006 REQ-RV-2).
 * ctx: { ev, rep, goTab(tab, anchor), goIssue(id), goDetails(sectionId) }
 */
export function summaryView(ctx) {
  const { ev } = ctx;
  const data = sectionData(ctx);
  const sections = Object.fromEntries(data.map((d) => [d.id, d.sec]));
  const act = uniqueFindings(ev).filter((f) => f.severity !== 'info');
  const wrap = h('div', { class: 'report summary' });
  if (ev.legacyReport) {
    wrap.appendChild(h('div', { class: 'callout info', role: 'status' },
      h('b', null, 'Scanned by an earlier version. '), 'Some areas were not collected. Scan again to see them.'));
  }
  const worst = act[0] ? act[0].severity : null;
  // A profile can add an action of its own (SSH: meeting the baseline), counted with the findings.
  const extra = profileOf(ctx).extraAction ? profileOf(ctx).extraAction(ctx) : null;
  const todo = act.length + (extra ? 1 : 0);
  wrap.appendChild(h('section', { class: `card verdict${worst ? ` v-${worst}` : extra ? ' v-medium' : ' v-none'}`, 'aria-label': 'Verdict' },
    h('div', { class: 'verdict-head' },
      h('h2', null, todo ? `${plural(todo, 'thing')} to fix` : 'Nothing to fix'),
      // UX-REVIEW-010 U-2: the line under the headline is the first thing to fix, then the post-quantum news.
      act[0] ? h('p', { class: 'verdict-line verdict-first' }, h('b', null, 'First: '), act[0].title, ` (${URGENCY[act[0].severity].toLowerCase()}).`) : null,
      ev.readiness.summary ? h('p', { class: 'verdict-line' }, h('b', null, 'Post-quantum: '), ev.readiness.summary) : null,
      null),
    profileOf(ctx).strip(ctx, sections)));

  const items = h('section', { class: 'card fixcard', id: 'fix', 'aria-labelledby': 'fix-h' },
    h('div', { class: 'cfg-head' }, h('h2', { id: 'fix-h' }, 'Fix first'),
      h('a', { href: '#', class: 'xlink', onclick: (e) => { e.preventDefault(); ctx.goTab('weaknesses'); } }, 'Every check')));
  if (extra) items.appendChild(extra);
  if (!act.length) {
    if (!extra) items.appendChild(h('p', { class: 'muted' }, 'Nothing needs fixing. The checks that found nothing are listed under Weaknesses.'));
  } else {
    // One numbered line per finding, worst first: what it is and what to do. Why it matters is in
    // its evidence (UX-DESIGN-011 §3.1).
    items.appendChild(h('ol', { class: 'fixlist actions' }, act.map((f, i) => h('li', { class: `action sev-${f.severity}`, id: `issue-${f.id}` },
      h('span', { class: 'fix-n' }, String(i + 1)),
      sevBadge(f.severity),
      h('span', { class: 'fix-main' },
        h('span', { class: 'action-head' }, h('span', { class: 'action-title' }, f.title), h('span', { class: `urgency u-${f.severity}` }, URGENCY[f.severity]),
          f.availability ? badge('clients fail to connect', 'bad', 'Clients that hit this refuse the connection') : null,
          ctx.triage && ctx.triage[f.id] ? badge(ctx.triage[f.id].status === 'accepted-risk' ? 'accepted risk' : 'acknowledged', 'neutral') : null),
        h('span', { class: 'action-fix', title: whyOf(f, profileOf(ctx)) }, f.remediation)),
      h('a', { href: `#chk-${f.id}`, class: 'xlink action-more', onclick: (e) => { e.preventDefault(); ctx.goIssue(f.id); } }, 'Evidence')))));
  }
  wrap.appendChild(items);

  // The checks, as one bar of counts.
  const cs = checksOf(ev);
  const sevOf = {};
  for (const f of ev.findings) sevOf[f.id] = f.severity;
  const cnt = (r) => cs.filter((c) => c.result === r).length;
  const problems = cs.filter((c) => c.result === 'found' && (sevOf[c.id] || c.severity) !== 'info').length;
  const sb = stackBar([
    { n: problems, label: problems === 1 ? 'problem' : 'problems', tone: 'problem' },
    { n: cnt('found') - problems, label: 'to note', tone: 'attention' },
    { n: cnt('not-found'), label: 'passed', tone: 'good' },
    { n: cnt('not-checked'), label: 'could not run', tone: 'na' },
    { n: cnt('not-applicable'), label: 'do not apply', tone: 'na' },
  ]);
  wrap.appendChild(h('section', { class: 'card checksbar', 'aria-labelledby': 'checks-h' },
    h('div', { class: 'cfg-head' }, h('h2', { id: 'checks-h', class: 'coverage-line' }, `${cs.length} checks run`),
      h('a', { href: '#', class: 'xlink', onclick: (e) => { e.preventDefault(); ctx.goTab('weaknesses'); } }, 'See every check')),
    sb.bar, sb.legend));

  // Each area as a tile: its state and its one line.
  const TONE = { problem: 'problem', attention: 'attention', good: 'good' };
  wrap.appendChild(h('section', { class: 'card areas', id: 'checks', 'aria-labelledby': 'areas-h' },
    h('h2', { id: 'areas-h' }, 'By area'),
    h('div', { class: 'stiles area-tiles' }, data.map((d) => {
      const t = statusTile(d.title, d.verdict || (STATUS[d.sec.status] || [])[1] || '', TONE[d.sec.status] || 'na', `#sec-${d.id}`, (e) => { e.preventDefault(); ctx.goDetails(d.id); });
      t.classList.add('check-row', `ss-${d.sec.status}`);
      t.querySelector('.stile-state').classList.add('check-verdict');
      // The glyph becomes the section's own chip: a symbol and a word, never colour alone.
      t.querySelector('.stile-glyph').replaceWith(statusChip(d.sec.status));
      t.querySelector('.stile-head .sr-only')?.remove();
      return t;
    }))));
  return wrap;
}

// ---- configuration: what the server ran --------------------------------------------------------

const VERSION_ORDER = ['TLSv1.3', 'TLSv1.2', 'TLSv1.1', 'TLSv1.0', 'SSLv3', 'SSLv2'];
const versionLabel = (v) => v.replace('TLSv', 'TLS ').replace('SSLv', 'SSL ');



function versionState([tone, sym, state, judgement]) {
  return h('span', { class: `vstate vs-${tone}` }, h('span', { class: 'vs-sym', 'aria-hidden': 'true' }, sym),
    h('b', null, state), judgement ? h('span', { class: 'vs-judge' }, ` · ${judgement}`) : null);
}


/** A card of facts for one area (no finding cards; issues are named and link to Weaknesses). */
function factCard(ctx, d, byId) {
  const issues = (d.sec.findings || []).map((fid) => byId[fid]).filter((f) => f && f.section === d.id);
  const said = d.verdict.toLowerCase();
  const rest = d.facts.filter((f) => !said.includes(f.toLowerCase().replace(/\.$/, '')));
  return h('section', { class: `card detcard ss-${d.sec.status}`, id: `sec-${d.id}`, 'aria-labelledby': `sec-${d.id}-h` },
    h('div', { class: 'detcard-head' }, h('h2', { id: `sec-${d.id}-h` }, d.title), statusChip(d.sec.status)),
    h('p', { class: 'detcard-verdict' }, d.verdict),
    notChecked(d.sec),
    rest.length ? h('ul', { class: 'facts' }, rest.map((f) => h('li', null, f))) : null,
    d.body.detail || d.body.lead || null,
    d.body.detail ? null : d.body.all || null,
    issues.length ? h('p', { class: 'detcard-issues' }, h('b', null, issues.length === 1 ? 'Issue: ' : 'Issues: '),
      issues.map((f, i) => [i ? ' · ' : '', h('a', { href: `#chk-${f.id}`, class: 'xlink', onclick: (e) => { e.preventDefault(); ctx.goIssue(f.id); } }, f.title)])) : null,
    h('p', { class: 'purpose' }, d.purpose));
}

/**
 * configurationView shows what the server ran: the protocol matrix, then the certificate, key
 * exchange, features and HTTP as facts (PRD-006 REQ-RV-3).
 */
export function configurationView(ctx) {
  const { rep, ev } = ctx;
  const data = sectionData(ctx);
  const byId = {};
  for (const f of uniqueFindings(ev)) byId[f.id] = f;
  const stages = Object.fromEntries((rep.stages || []).map((x) => [x.name, x]));
  const prof = profileOf(ctx);
  // TLS draws its own one-stop Configuration (UX-DESIGN-011 §3.2); other protocols keep fact cards.
  if (prof.configuration) {
    const about = aboutReport(ctx, stages);
    return prof.configuration(ctx, about);
  }
  const wrap = h('div', { class: 'report configuration' });
  if (prof.matrix) wrap.appendChild(prof.matrix(ctx));
  for (const d of data) {
    if (prof.skipCards.includes(d.id)) continue;
    wrap.appendChild(factCard(ctx, d, byId));
  }
  const about = aboutReport(ctx, stages);
  about.open = true;
  wrap.appendChild(about);
  return wrap;
}

// ---- weaknesses: every check, found or not -----------------------------------------------------

/**
 * weaknessesView is the technical record: every check run, grouped by area, found ones open to
 * their evidence; then the attacks and how the score was worked out (PRD-006 REQ-RV-4).
 */
export function weaknessesView(ctx) {
  const { ev } = ctx;
  const checks = checksOf(ev);
  const byId = {};
  for (const f of ev.findings) (byId[f.id] = byId[f.id] || []).push(f);
  const sevOf = (c) => (byId[c.id] || [{}])[0].severity || c.severity;
  const sections = Object.fromEntries((ev.sections || []).map((x) => [x.id, x]));
  const wrap = h('div', { class: 'report weaknesses show-all' });
  const n = (r) => checks.filter((c) => c.result === r).length;
  const problems = checks.filter((c) => c.result === 'found' && sevOf(c) !== 'info').length;
  const notes = n('found') - problems;

  // One line of totals, and a filter: everything, only what was found, only what passed.
  const filters = [['all', 'All', checks.length], ['found', 'Found', n('found')], ['passed', 'Passed', n('not-found')], ['skipped', 'Not run', n('not-checked')]]
    .filter(([k, , c]) => k === 'all' || c > 0);
  const filterBar = h('div', { class: 'chkfilter', role: 'group', 'aria-label': 'Show checks' }, filters.map(([k, label, c]) =>
    h('button', { type: 'button', class: 'chkfilter-btn', 'aria-pressed': String(k === 'all'), 'data-show': k,
      onclick: (e) => {
        wrap.className = `report weaknesses show-${k}`;
        for (const x of filterBar.querySelectorAll('button')) x.setAttribute('aria-pressed', String(x === e.currentTarget));
      } }, `${label} `, h('span', { class: 'chkfilter-n' }, String(c)))));
  wrap.appendChild(h('section', { class: 'card chktotals', 'aria-label': 'Checks run' },
    h('p', { class: 'chktotals-line' },
      h('b', null, `${checks.length} checks run. `),
      problems ? h('span', { class: 'cov-found' }, `${problems} found a problem`) : h('span', { class: 'cov-clean' }, 'None found a problem'), ', ',
      notes ? [h('span', null, `${notes} found something to note`), ', '] : null,
      h('span', { class: 'cov-clean' }, `${n('not-found')} passed`),
      n('not-checked') ? [', ', h('span', { class: 'cov-skip' }, `${n('not-checked')} could not run`)] : null,
      n('not-applicable') ? [', ', h('span', { class: 'muted' }, `${n('not-applicable')} do not apply to this service`)] : null, '.'),
    filterBar));

  for (const [sid, title] of profileOf(ctx).sections) {
    const cs = checks.filter((c) => c.section === sid);
    if (!cs.length) continue;
    const found = cs.filter((c) => c.result === 'found').sort((a, b) => SEV_RANK[sevOf(a)] - SEV_RANK[sevOf(b)]);
    const passed = cs.filter((c) => c.result === 'not-found');
    const skipped = cs.filter((c) => c.result === 'not-checked');
    const na = cs.filter((c) => c.result === 'not-applicable');
    const bad = found.filter((c) => sevOf(c) !== 'info').length;
    const tally = [
      bad ? badge(`${bad} ${bad === 1 ? 'problem' : 'problems'}`, 'bad') : null,
      found.length - bad ? badge(`${found.length - bad} to note`, 'info') : null,
      passed.length ? badge(`${passed.length} passed`, 'good') : null,
      skipped.length ? badge(`${skipped.length} not run`, 'none') : null,
      na.length ? badge(`${na.length} do not apply`, 'none') : null,
    ];
    const has = [found.length ? 'has-found' : '', passed.length ? 'has-passed' : '', skipped.length ? 'has-skipped' : ''].join(' ');
    wrap.appendChild(h('section', { class: `card weakcard ${has}`, 'aria-label': title },
      h('div', { class: 'detcard-head' }, h('h2', null, title), h('span', { class: 'weak-tally' }, tally)),
      found.length ? h('div', { class: 'chk-found' },
        h('h3', { class: 'chk-h' }, 'Found'),
        h('ol', { class: 'issues' }, found.map((c) => checkFound(c, byId[c.id] || [], ctx)))) : null,
      passed.length ? h('div', { class: 'chk-passed' },
        h('h3', { class: 'chk-h' }, 'Passed'),
        h('ul', { class: 'clean-checks' }, passed.map((c) => h('li', { class: 'clean', id: `chk-${c.id}`, title: `Check: ${c.title}` },
          h('span', { class: 'clean-mark', 'aria-hidden': 'true' }, '✔'),
          h('span', null, c.pass || `${c.title}: not found`))))) : null,
      skipped.length ? h('div', { class: 'chk-skipped' },
        h('h3', { class: 'chk-h' }, 'Not run'),
        h('ul', { class: 'clean-checks' }, skipped.map((c) => h('li', { class: 'clean r-not-checked', id: `chk-${c.id}` },
          h('span', { class: 'clean-mark', 'aria-hidden': 'true' }, '○'),
          h('span', null, c.title),
          h('span', { class: 'muted' }, sections[sid]?.reason ? ` (${sections[sid].reason})` : ' (this area could not be tested)'))))) : null,
      na.length ? h('div', { class: 'chk-skipped' },
        h('h3', { class: 'chk-h' }, 'Does not apply'),
        h('ul', { class: 'clean-checks' }, na.map((c) => h('li', { class: 'clean r-not-checked', id: `chk-${c.id}` },
          h('span', { class: 'clean-mark', 'aria-hidden': 'true' }, '·'),
          h('span', null, c.title),
          h('span', { class: 'muted' }, sections[sid]?.reason ? ` (${sections[sid].reason})` : ''))))) : null));
  }
  const vb = vulnerabilitiesBody(ctx);
  if (vb.detail) wrap.appendChild(h('section', { class: 'card', 'aria-labelledby': 'att-h' }, h('h2', { id: 'att-h' }, 'Published attacks'), vb.detail));
  if (ctx.hygieneBody && profileOf(ctx).hygiene) wrap.appendChild(h('section', { class: 'card', id: 'score', 'aria-labelledby': 'score-h' }, h('h2', { id: 'score-h' }, `How the ${profileOf(ctx).hygiene} score was worked out`), ctx.hygieneBody(ev.hygiene)));
  return wrap;
}

function checkFound(c, fs, ctx) {
  const f = fs[0] || { severity: c.severity, title: c.title, category: '', citations: [], remediation: '', labels: [] };
  return h('li', { class: `issue sev-${f.severity}`, id: `chk-${c.id}` },
    h('details', null,
      h('summary', { class: 'issue-line' },
        sevBadge(f.severity), h('span', { class: 'issue-title' }, c.title),
        (f.labels || []).length ? h('span', { class: 'issue-area' }, `enables ${f.labels.join(', ')}`) : null,
        h('span', { class: 'issue-toggle' }, h('span', { class: 't-show' }, 'Details'), h('span', { class: 't-hide' }, 'Hide'))),
      h('div', { class: 'issue-body' },
        h('p', null, h('b', null, 'What we saw: '), fs.length > 1 ? null : [f.detail, ' ', evidenceBadge(f.evidence)]),
        fs.length > 1 ? h('ul', { class: 'facts' }, fs.map((x) => h('li', null, x.detail, ' ', evidenceBadge(x.evidence)))) : null,
        h('p', null, h('b', null, 'Why it matters: '), whyOf(f, profileOf(ctx))),
        h('p', { class: 'fix' }, h('b', null, 'Fix: '), f.remediation),
        citations(f.citations),
        c.section !== 'vulnerabilities' ? h('a', { href: `#sec-${c.section}`, class: 'xlink', onclick: (e) => { e.preventDefault(); ctx.goDetails(c.section); } },
          `See ${sectionTitleIn(profileOf(ctx), c.section)} in Configuration →`) : null,
        ctx.triageControls ? ctx.triageControls(c.id) : null)));
}

// ---- CBOM: what this endpoint adds to the inventory --------------------------------------------

const PRIM_WORD = { ae: 'authenticated encryption', 'block-cipher': 'block cipher', 'stream-cipher': 'stream cipher', pke: 'public-key encryption',
  signature: 'signature', 'key-agree': 'key agreement', kem: 'key encapsulation', hash: 'hash', mac: 'message authentication',
  combiner: 'hybrid key exchange', 'public-key': 'public key', 'private-key': 'private key', tls: 'TLS' };
const cbomName = (c) => (/ public key$/.test(c.name) ? `${cn(c.name.replace(/ public key$/, ''))} (public key)` : /^CN=|,O=/.test(c.name) ? cn(c.name) : c.name);
const ASSET_WORD = { algorithm: 'Algorithms', certificate: 'Certificates', protocol: 'Protocols', 'related-crypto-material': 'Keys' };

/** cbomView shows the endpoint's CycloneDX CBOM as a table, with downloads (PRD-006 REQ-RV-5). */
export function cbomView(ctx) {
  const wrap = h('div', { class: 'report cbom' });
  const body = h('div', null, h('p', { class: 'muted' }, 'Building the CBOM…'));
  const dl = (spec) => button(`Download CycloneDX ${spec}`, () => ctx.download(`/api/v1/scans/${ctx.scanId}/cbom?spec=${spec}&download=1`,
    `${ctx.stem}-cbom-${spec}.json`), spec === '1.7' ? 'primary' : 'secondary');
  wrap.appendChild(h('section', { class: 'card', 'aria-labelledby': 'cbom-h' },
    h('div', { class: 'detcard-head' }, h('h2', { id: 'cbom-h' }, 'Cryptographic bill of materials'), h('span', { class: 'row' }, dl('1.7'), dl('1.6'))),
    h('p', { class: 'verdict-line' }, 'Every algorithm, key, certificate and protocol this endpoint showed, as a CycloneDX CBOM: the standard format for a cryptographic inventory. Each algorithm carries its post-quantum classification and the sources for it.'),
    body,
    h('p', { class: 'hint' }, 'The same items are part of your ', h('a', { href: '#/inventory' }, 'Inventory'), ', merged with your other endpoints and machines.')));
  ctx.fetchCBOM().then((bom) => {
    clear(body);
    const comps = (bom.components || []).filter((c) => c.cryptoProperties);
    const prop = (c, n) => ((c.properties || []).find((p) => p.name === n) || {}).value;
    const type = (c) => c.cryptoProperties.assetType;
    const counts = {};
    for (const c of comps) counts[type(c)] = (counts[type(c)] || 0) + 1;
    body.appendChild(h('div', { class: 'cbom-counts' }, Object.entries(ASSET_WORD).filter(([k]) => counts[k]).map(([k, w]) =>
      h('div', { class: 'cbom-count' }, h('b', null, String(counts[k])), h('span', null, w)))));
    const order = { algorithm: 0, 'related-crypto-material': 1, certificate: 2, protocol: 3 };
    const q = (c) => prop(c, 'cipherhorizon:pqc:status');
    // PRD-011 REQ-CLS-7: the CBOM's classicalSecurityLevel (PRD-010), or its cited classical status.
    const classical = (c) => {
      const a = c.cryptoProperties.algorithmProperties;
      if (a && typeof a.classicalSecurityLevel === 'number') return `${a.classicalSecurityLevel} bits`;
      const st = prop(c, 'cipherhorizon:classical-status');
      return st ? h('span', { class: 'text-bad', title: st }, 'legacy') : h('span', { class: 'muted' }, '·');
    };
    const qBadge = (s) => (s === 'quantum-vulnerable' ? badge('✖ quantum-vulnerable', 'bad') : s === 'quantum-safe' ? badge('✔ quantum-safe', 'good') : h('span', { class: 'muted' }, '·'));
    const detail = (c) => {
      const cp = c.cryptoProperties;
      const a = cp.algorithmProperties, p = cp.protocolProperties, k = cp.relatedCryptoMaterialProperties, ce = cp.certificateProperties;
      if (a) return [PRIM_WORD[a.primitive] || a.primitive, a.parameterSetIdentifier, a.curve].filter(Boolean).join(' · ');
      if (p) return [PRIM_WORD[p.type] || p.type, p.version].filter(Boolean).join(' ');
      if (k) return [PRIM_WORD[k.type] || k.type, k.size ? `${k.size} bits` : ''].filter(Boolean).join(' · ');
      if (ce) return [ce.subjectName ? cn(ce.subjectName) : '', ce.notValidAfter ? `until ${fmtDay(ce.notValidAfter)}` : ''].filter(Boolean).join(' · ');
      return '';
    };
    body.appendChild(h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
      h('thead', null, h('tr', null, ['Name', 'Type', 'Detail', 'Classical strength', 'Post-quantum'].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, comps.slice().sort((x, y) => (order[type(x)] - order[type(y)]) || x.name.localeCompare(y.name)).map((c) => h('tr', null,
        h('td', null, type(c) === 'certificate' && /^crypto\/certificate\/[0-9a-f]{64}$/.test(c['bom-ref'] || '')
          ? h('a', { href: certHref(c['bom-ref'].slice('crypto/certificate/'.length), ctx.scanId), title: c.name }, h('b', null, cbomName(c)))
          : h('b', { title: c.name }, cbomName(c))), h('td', { class: 'muted' }, (ASSET_WORD[type(c)] || type(c)).replace(/s$/, '')),
        h('td', { class: 'muted' }, detail(c)), h('td', null, classical(c)), h('td', null, type(c) === 'algorithm' || type(c) === 'related-crypto-material' ? qBadge(q(c)) : h('span', { class: 'muted' }, '·'))))))));
    body.appendChild(h('p', { class: 'hint' }, `${comps.length} cryptographic components; CycloneDX ${bom.specVersion}, serial ${bom.serialNumber || ''}.`));
  }).catch((e) => { clear(body); body.appendChild(h('p', { class: 'callout bad' }, e.message)); });
  return wrap;
}

// ---- summary strip ------------------------------------------------------------------

function summaryStrip(ctx, sections) {
  const { ev } = ctx;
  const r = ev.readiness;
  const g = ev.hygiene;
  const notChecked = Object.values(sections).filter((s) => ['not-checked', 'not-collected', 'inconclusive'].includes(s.status));
  const pki = (ev.pki || []).find((v) => !v.noSni) || (ev.pki || [])[0];
  // Each instrument opens the section it summarises.
  const tile = (href, cls, label, ...body) => h('a', { class: `sumtile ${cls}`, href, onclick: (e) => {
    e.preventDefault();
    // The hygiene figure opens how it was worked out, on Weaknesses (UX-REVIEW-010 U-7).
    if (href === '#score' && ctx.goTab) { ctx.goTab('weaknesses'); setTimeout(() => document.getElementById('score')?.scrollIntoView({ block: 'start' }), 0); return; }
    if (ctx.goDetails) { ctx.goDetails(href.replace('#sec-', '')); return; }
    const el = document.querySelector(href); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } }, h('div', { class: 'sumtile-label' }, label), ...body);
  const ready = tile('#sec-key-exchange', `sumtile-lead bigLevel ${levelClass(r.level)}`, 'Post-quantum readiness',
    h('div', { class: 'sumtile-figure' }, h('span', { class: `sumtile-big ${levelClass(r.level)}` }, r.level < 0 ? '?' : `L${r.level}`), h('span', { class: 'sumtile-sub' }, r.label || levelName(r.level))),
    levelStepper(r.level));
  const gtone = { good: 'good', ok: 'ok', warn: 'warn', bad: 'bad', neutral: 'neutral' }[bandTone(g ? g.band : '')] || 'neutral';
  const hyg = tile('#score', 'sumtile-gauge', 'TLS hygiene',
    g && g.score >= 0 ? gauge(g.score, bandWord(g.band), gtone) : h('div', { class: 'sumtile-big' }, '·'),
    h('div', { class: 'sumtile-sub' }, g && g.ceiling ? `Capped at ${g.ceiling.score}: ${g.ceiling.reason}` : g && g.score >= 0 ? 'No finding caps the score' : 'Not rated'));
  const weak = weakestAlgorithm(ev);
  const strength = tile('#sec-algorithms', 'sumtile-strength', 'Weakest classical strength',
    h('div', { class: 'sumtile-figure' }, h('span', { class: 'sumtile-big' }, weak ? (weak.strength.status === 'broken' ? 'broken' : String(weak.strength.bits)) : '·'),
      h('span', { class: 'sumtile-sub' }, weak ? `${weak.strength.status === 'broken' ? '' : 'bits · '}${weak.name}` : 'not rated')),
    weak ? bitsBar(weak.strength, { name: weak.name }) : null);
  let certFig = 'No certificate', certSub = '', certBar = null, chips = null, ctone = 'lvu';
  const certs = ctx.rep.certificates || [];
  const crOf = pki ? certs.find((c) => c.chain && c.chain[0] && c.chain[0].sha256 === pki.leaf) : certs[0];
  const leaf = crOf && crOf.chain ? crOf.chain[0] : null;
  if (leaf) {
    const left = daysUntil(leaf.notAfter);
    certFig = left === null ? '·' : left < 0 ? 'Expired' : String(left);
    certSub = left === null ? '' : left < 0 ? `on ${fmtDay(leaf.notAfter)}` : 'days left';
    ctone = left === null ? 'lvu' : left < 0 ? 'lv0' : left <= 30 ? 'lv1' : 'lv3';
    certBar = lifetimeBar(leaf.notBefore, leaf.notAfter);
    const stores = pki ? [...(pki.trust || []), pki.private].filter(Boolean) : [];
    chips = stores.length ? h('div', { class: 'trust-chips' }, stores.map((t) => h('span', { class: `tchip ${t.trusted ? 'tchip-good' : 'tchip-bad'}` }, `${t.store} ${t.trusted ? '✓' : '✕'}`)))
      : h('div', { class: 'sumtile-sub' }, 'trust not analysed by this scan version');
  }
  const cert = tile('#sec-certificates', 'sumtile-cert', 'Certificate',
    h('div', { class: 'sumtile-figure' }, h('span', { class: `sumtile-big ${ctone}` }, certFig), h('span', { class: 'sumtile-sub' }, certSub)), certBar, chips);
  return h('div', { class: 'sumstrip', role: 'group', 'aria-label': 'Where this endpoint stands' },
    ready, hyg, strength, cert,
    notChecked.length ? tile(`#sec-${notChecked[0].id}`, 'lv1', 'Not checked',
      h('div', { class: 'sumtile-figure' }, h('span', { class: 'sumtile-big' }, String(notChecked.length)),
        h('span', { class: 'sumtile-sub' }, notChecked.map((x) => (SECTIONS.find(([id]) => id === x.id) || [0, x.id])[1]).join(', ')))) : null);
}

// ---- section anatomy ------------------------------------------------------------------------

function notChecked(sec) {
  if (!['not-checked', 'not-collected', 'inconclusive'].includes(sec.status)) return null;
  const how = {
    'option-off': sec.id === 'http' ? 'It is on by default; the server was started with --http-checks=false.' : 'An option turned it off for this scan.',
    'not-applicable': 'It does not apply to this service.',
    'not-reached': 'The scan did not get far enough to run it.',
    budget: 'The connection budget ran out before it could run.',
    'legacy-report': 'Scan again to collect it.',
  }[sec.reasonCode] || '';
  return h('div', { class: 'callout notchecked', role: 'note' },
    h('b', null, `${STATUS[sec.status][1]}. `), sec.reason || '', how ? ` ${how}` : '');
}

// ---- certificates ---------------------------------------------------------------------------

function certificatesBody(ctx) {
  const { rep, ev } = ctx;
  const certs = rep.certificates || [];
  if (!certs.length) return { facts: ['No certificate was received.'] };
  const views = ev.pki || [];
  if (!views.length) return { facts: [`${plural(certs.length, 'certificate chain')} presented.`] };
  const first = views.find((v) => !v.noSni) || views[0];
  const cr = certs.find((c) => c.chain[0].sha256 === first.leaf) || certs[0];
  const leaf = cr.chain[0];
  const left = daysUntil(leaf.notAfter);
  const trustedBy = (first.trust || []).filter((t) => t.trusted).map((t) => t.store);
  if (first.private && first.private.trusted) trustedBy.push('your CA bundle');
  const facts = [
    `Issued to ${cn(leaf.subject)} by ${cn(leaf.issuer)}; ${keyDesc(leaf.publicKey)} key, signed with ${leaf.signatureAlgorithm.name}.`,
    left === null ? null : left < 0 ? `Expired ${-left} days ago (${fmtDay(leaf.notAfter)}).`
      : `Valid until ${fmtDay(leaf.notAfter)}: ${left} days left of a ${first.lifetime.days}-day lifetime.`,
    trustedBy.length ? `Trusted by ${trustedBy.join(', ')}.` : 'Not trusted by any root store checked.',
    first.names.matchedBy ? `Valid for ${first.names.host} (matched by ${first.names.matchedBy}).` : `Not valid for ${first.names.host}.`,
    rep.noSni === 'same' ? 'Clients that send no server name get the same certificate.'
      : rep.noSni === 'different' ? 'Clients that send no server name get a different certificate (see the “Without SNI” tab).' : null,
  ];
  const verdict = `${trustedBy.length ? `Trusted by ${trustedBy.join(', ')}` : 'Not trusted by any store checked'} · ${left === null ? '' : left < 0 ? 'expired' : `${left} days left`}`;
  return { verdict, facts };
}






// ---- revocation & transparency ----------------------------------------------------------------

function revocationBody(ctx) {
  const { ev, rep } = ctx;
  const views = ev.pki || [];
  if (!views.length) return { facts: [] };
  const v = views.find((x) => !x.noSni) || views[0];
  const cr = (rep.certificates || []).find((c) => c.chain[0] && c.chain[0].sha256 === v.leaf);
  const leaf = cr ? cr.chain[0] : {};
  const o = v.ocsp;
  let ocspLine;
  if (!o) {
    ocspLine = leaf.ocspMustStaple ? 'No OCSP response was stapled, although the certificate requires one (Must-Staple).'
      : (v.ocspUrls || []).length ? 'No OCSP response was stapled.' : 'No OCSP response was stapled, and the certificate names no OCSP responder.';
  } else if (o.error) {
    ocspLine = `A stapled OCSP response was sent but is not usable: ${o.error}.`;
  } else if (!o.forThisCert) {
    ocspLine = 'A stapled OCSP response was sent, but it is for a different certificate.';
  } else {
    const sig = { valid: o.delegated ? 'signed by a delegated responder the issuer authorised' : 'signed by the issuer', invalid: 'its signature does NOT verify',
      unsupported: 'its signature algorithm could not be verified', 'no-issuer': 'its signature could not be checked (issuer not available)' }[o.signature];
    ocspLine = `Stapled OCSP response: ${o.status}${o.status === 'revoked' ? ` since ${fmtDay(o.revokedAt)}${o.reason ? ` (${o.reason})` : ''}` : ''}` +
      `${o.nextUpdate ? `, valid until ${fmtDate(o.nextUpdate)}` : ''}; ${sig}.`;
  }
  const scts = v.scts || [];
  const facts = [
    ocspLine,
    scts.length ? `${plural(scts.length, 'Certificate Transparency proof')} (${[...new Set(scts.map((s) => s.source))].join(', ')}).`
      : v.public ? 'No Certificate Transparency proof was found in any of the three places it can travel.' : 'No Certificate Transparency proof; not required for a privately trusted certificate.',
  ];
  const urls = [...(v.ocspUrls || []).map((u) => ['OCSP', u]), ...(v.crlUrls || []).map((u) => ['CRL', u])];
  const lead = h('div', null,
    h('h3', null, 'Revocation sources the certificate names'),
    urls.length ? h('ul', { class: 'urls' }, urls.map(([k, u]) => h('li', null, badge(k, 'neutral'), ' ', h('code', null, u), ' ', h('span', { class: 'hint' }, 'not looked up'))))
      : h('p', { class: 'muted' }, 'None.'),
    h('p', { class: 'hint' }, 'This scan contacts only the endpoint, so the CA’s OCSP responder and CRL were not queried. Live lookups are planned as an option, off by default.'),
    h('h3', null, 'Certificate Transparency'),
    scts.length ? h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
      h('thead', null, h('tr', null, ['Source', 'Log', 'Timestamp'].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, scts.map((s) => h('tr', null, h('td', null, s.source),
        h('td', null, s.logName ? `${s.logName} (${s.operator})` : h('span', null, 'unknown log ', h('code', { class: 'hint' }, s.logId))),
        h('td', null, fmtDate(s.timestamp)))))))
      : h('p', { class: 'muted' }, 'None found.'),
    h('p', { class: 'hint' }, 'SCT signatures are not verified in this version; the log is named from the bundled CT log list.'));
  const ocspAll = o ? h('dl', { class: 'kv' }, [
    ['Response', o.response], ['Status', o.status], ['Produced', o.producedAt && fmtDate(o.producedAt)], ['This update', o.thisUpdate && fmtDate(o.thisUpdate)],
    ['Next update', o.nextUpdate && fmtDate(o.nextUpdate)], ['Responder', o.responder], ['Signature', o.signature], ['For this certificate', o.forThisCert ? 'yes' : 'no'],
  ].filter(([, val]) => val).flatMap(([k, val]) => [h('dt', null, k), h('dd', null, val)])) : null;
  return { facts, all: h('div', null, lead, ocspAll ? [h('h3', null, 'Stapled OCSP response'), ocspAll] : null) };
}

// ---- protocols, suites, key exchange, features, HTTP, vulnerabilities --------------------------

function protocolsBody(ctx) {
  const { rep } = ctx;
  const on = rep.protocols.filter((p) => p.supported).map((p) => p.version);
  const old = on.filter(legacyVersion);
  const facts = [
    on.length ? `Accepts ${on.join(', ')}.` : 'No protocol version was accepted.',
    old.length ? `${old.join(' and ')} ${old.length === 1 ? 'is' : 'are'} deprecated.` : on.length ? 'No deprecated version is accepted.' : null,
    rep.negotiated && rep.negotiated.version ? `A current client negotiates ${rep.negotiated.version}.` : null,
  ];
  const lead = h('div', { class: 'pillrow', role: 'list' }, rep.protocols.map((p) => h('span', { role: 'listitem',
    class: `protopill ${p.evidence === 'inconclusive' ? 'p-unknown' : p.supported ? (legacyVersion(p.version) ? 'p-bad' : 'p-on') : 'p-off'}` },
  h('b', null, p.version), ' ', p.evidence === 'inconclusive' ? '? unknown' : p.supported ? '✔ yes' : '✖ no')));
  const all = h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
    h('thead', null, h('tr', null, ['Version', 'Supported', 'Evidence', 'Detail'].map((c) => h('th', { scope: 'col' }, c)))),
    h('tbody', null, rep.protocols.map((p) => h('tr', null, h('td', null, h('b', null, p.version)),
      h('td', null, p.evidence === 'inconclusive' ? badge('unknown', 'warn') : p.supported ? badge('Yes', legacyVersion(p.version) ? 'bad' : 'good') : badge('No', 'neutral')),
      h('td', null, p.evidence), h('td', { class: 'muted' }, p.detail || ''))))));
  return { facts, lead, all, detail: all };
}

function suiteProblems(s) {
  const out = [];
  if (s.cipher === 'NULL') out.push(['no encryption', 'bad']);
  if (s.export) out.push(['export', 'bad']);
  if (s.anon) out.push(['anonymous', 'bad']);
  if (s.cipher === 'RC4') out.push(['RC4', 'bad']);
  if (s.blockBits === 64 && !s.export) out.push(['64-bit block', 'warn']);
  if (s.kx && !s.ephemeral && ['RSA', 'DH', 'ECDH'].includes(s.kx)) out.push(['no forward secrecy', 'warn']);
  if (s.mode === 'CBC' && s.version !== 'TLSv1.3') out.push(['CBC', 'neutral']);
  if (s.ianaRecommended === 'D') out.push(['IANA discouraged', 'warn']);
  return out;
}


function suitesBody(ctx) {
  const { rep, ev } = ctx;
  const suites = rep.suites || [];
  const problem = suites.filter((s) => suiteProblems(s).some(([, k]) => k !== 'neutral'));
  const aead = suites.filter((s) => s.aead).length;
  const cbc = suites.filter((s) => s.mode === 'CBC' && s.version !== 'TLSv1.3').length;
  const order = (rep.preference || []).filter((p) => p.subject === 'suites').map((p) => `${p.version}: ${{ server: 'server decides', client: 'client decides', mixed: 'depends on the offer', unknown: 'not determined' }[p.order]}`);
  const facts = [
    `${plural(suites.length, 'suite')} accepted: ${aead} AEAD${cbc ? `, ${cbc} CBC` : ''}${problem.length ? `, ${problem.length} with a weakness` : ''}.`,
    order.length ? `Order: ${order.join('; ')}.` : null,
  ];
  // UX-REVIEW-010 U-3: the Summary says how strong the weakest suite is.
  const rank = { insecure: 0, weak: 1, acceptable: 2, strong: 3 };
  const worst = (ev.suiteStrength || []).slice().sort((a, b) => (rank[a.word] - rank[b.word]) || ((a.bits || 0) - (b.bits || 0)))[0];
  const verdict = worst ? `${plural(suites.length, 'suite')} accepted; the weakest is ${worst.word}${worst.bits ? `, ${worst.bits} bits` : ''}${worst.weakest ? ` (${worst.weakest})` : ''}.` : null;
  return { facts, verdict };
}

function keyExchangeBody(ctx) {
  const { rep, ev } = ctx;
  const r = ev.readiness;
  const groups = rep.groups || [];
  const pq = groups.filter((g) => g.pq && !g.obsolete).map((g) => g.name);
  const n = rep.negotiated || {};
  const facts = [
    pq.length ? `Post-quantum hybrid groups accepted: ${pq.join(', ')}.` : 'No post-quantum key exchange is accepted.',
    n.group ? `A current client negotiates ${n.group}${n.pq ? ' (post-quantum hybrid)' : ' (classical)'}.` : null,
    r.hndlExposed ? 'Traffic recorded today could be decrypted by a future quantum computer (harvest now, decrypt later).' : null,
    rep.dh ? (ev.dhGroup ? `Diffie-Hellman uses ${ev.dhGroup.name} (${ev.dhGroup.source}), ${rep.dh.primeBits} bits.`
      : `Diffie-Hellman uses a ${rep.dh.primeBits}-bit prime that is not a published group.`) : null,
    signatureFact(rep.signatures),
  ];
  return { facts };
}

/** One sentence on the TLS 1.3 signature schemes the server holds keys for (PRD-008 REQ-PQS-6). */
function signatureFact(sig) {
  if (!sig) return null;
  if (sig.control !== 'refused') return 'Which signature schemes the server can use could not be told: it answers whatever is offered.';
  const acc = (sig.schemes || []).filter((s) => s.result === 'accepted');
  const pq = acc.filter((s) => s.pq).map((s) => s.algorithm);
  if (!acc.length) return null;
  return pq.length ? `The server can authenticate with ${pq.join(', ')} (post-quantum) as well as ${[...new Set(acc.filter((s) => !s.pq).map((s) => s.algorithm))].join(', ') || 'nothing classical'}.`
    : `The server authenticates with ${[...new Set(acc.map((s) => s.algorithm))].join(', ')}; no post-quantum signature scheme is accepted.`;
}


function featuresBody(ctx) {
  const f = ctx.rep.features || {};
  const said = (v, yes, no) => (v === null || v === undefined ? null : v ? yes : no);
  const facts = [
    said(f.secureRenegotiation, 'Secure renegotiation is advertised.', 'Secure renegotiation is NOT advertised.'),
    said(f.compression, 'TLS compression is accepted (CRIME).', 'TLS compression is refused.'),
    said(f.fallbackScsv, 'Downgrade protection (TLS_FALLBACK_SCSV) is enforced.', 'Downgrade protection (TLS_FALLBACK_SCSV) is not enforced.'),
    said(f.sessionTickets, 'Session tickets are offered.', 'Session tickets are not offered.'),
    said(f.clientCertRequested, 'The server asks for a client certificate (mutual TLS).', null),
  ];
  const row = (label, v, yes, no) => (v === null || v === undefined ? null : h('tr', null, h('td', null, label), h('td', null, v ? yes : no)));
  const all = h('table', { class: 'compact' }, h('tbody', null, [
    row('Secure renegotiation (RFC 5746)', f.secureRenegotiation, badge('advertised', 'good'), badge('not advertised', 'warn')),
    row('Extended master secret (RFC 7627)', f.extendedMasterSecret, badge('supported', 'good'), badge('not offered', 'neutral')),
    row('Encrypt-then-MAC (RFC 7366)', f.encryptThenMac, badge('supported', 'good'), badge('not offered', 'neutral')),
    row('Session tickets', f.sessionTickets, badge('offered', 'neutral'), badge('not offered', 'neutral')),
    row('OCSP stapling (status_request)', f.ocspStapling, badge('supported', 'good'), badge('not offered', 'neutral')),
    row('TLS compression', f.compression, badge('accepted', 'bad'), badge('refused', 'good')),
    row('TLS_FALLBACK_SCSV (RFC 7507)', f.fallbackScsv, badge('enforced', 'good'), badge('not enforced', 'warn')),
    row('Client certificate requested', f.clientCertRequested, badge('requested', 'neutral'), badge('not requested', 'neutral')),
  ].filter(Boolean)));
  return { facts, all };
}

function httpBody(ctx) {
  const hd = ctx.rep.hstsHeader;
  if (!hd) {
    if (ctx.rep.hsts === true) return { facts: ['A Strict-Transport-Security header was sent (details were not collected by the version that ran this scan).'] };
    if (ctx.rep.hsts === false) return { facts: ['The HTTP response had no Strict-Transport-Security header.'] };
    return { facts: [] };
  }
  if (!(hd.values || []).length) return { facts: ['The HTTP response had no Strict-Transport-Security header, so browsers may still use plain HTTP.'] };
  const ma = hd.maxAge;
  const facts = [
    ma === undefined || ma === null ? 'max-age could not be read.' : ma === 0 ? 'max-age is 0: the header switches HSTS off.'
      : `Browsers remember to use HTTPS for ${ma.toLocaleString()} seconds (${humanDuration(ma)}).`,
    hd.includeSubDomains ? 'It covers every subdomain (includeSubDomains).' : 'It does not cover subdomains.',
    hd.preload ? 'It asks to be preloaded into browsers (preload).' : null,
    (hd.problems || []).length ? `Problems: ${hd.problems.join('; ')}.` : null,
  ];
  return { facts, all: h('div', null, h('p', { class: 'hint' }, 'Header values as received:'),
    h('ul', null, hd.values.map((v) => h('li', null, h('code', null, v))))) };
}

function vulnerabilitiesBody(ctx) {
  const list = ctx.ev.vulnerabilities || [];
  if (!list.length) return { facts: [] };
  const exposed = list.filter((a) => a.status === 'exposed');
  const facts = [exposed.length ? `Exposed to ${exposed.map((a) => a.name).join(', ')}.` : 'Not exposed to any attack this scan can infer.'];
  // One table, possible attacks first: each line states its result for this server.
  const order = { exposed: 0, 'not-exposed': 1, 'not-tested': 2 };
  const word = { exposed: ['Possible', 'bad'], 'not-exposed': ['Not possible', 'good'], 'not-tested': ['Not tested', 'neutral'] };
  const rows = list.slice().sort((x, y) => order[x.status] - order[y.status]);
  const detail = h('div', { class: 'tablewrap' }, h('table', { class: 'compact attacktable' },
    h('thead', null, h('tr', null, ['Attack', 'Here', 'Why'].map((c) => h('th', { scope: 'col' }, c)))),
    h('tbody', null, rows.map((x) => h('tr', null,
      h('td', null, h('b', null, x.name)),
      h('td', null, badge(word[x.status][0], word[x.status][1])),
      h('td', { class: 'muted' }, capital(x.why.replace(/^(Possible|Not tested): /, ''))))))));
  return { facts, detail };
}

// ---- about this report -----------------------------------------------------------------------

function aboutReport(ctx, stages) {
  const { rep, ev } = ctx;
  const addrs = rep.addresses || [];
  const prof = profileOf(ctx);
  const how = Object.entries(prof.stageTitles).map(([k, title]) => {
    const st = stages[k];
    if (!st) return null;
    return h('li', null, h('b', null, `${title}: `), st.outcome === 'skipped' ? `not run: ${st.reason || st.reasonCode}` : (st.probes || []).join('; '),
      st.connections ? h('span', { class: 'muted' }, ` (${plural(st.connections, 'connection')})`) : null,
      (st.inconclusive || []).length ? h('div', { class: 'hint' }, `Inconclusive: ${st.inconclusive.join('; ')}`) : null);
  }).filter(Boolean);
  return h('details', { class: 'card about-report', id: 'sec-details' },
    h('summary', null, h('span', { class: 'repsec-name' }, 'About this report'),
      h('span', { class: 'muted' }, `scanned ${fmtDate(rep.started)} · ${rep.connections} connections · ${ev.version}`)),
    h('dl', { class: 'kv' },
      h('dt', null, 'Scanned'), h('dd', null, fmtDate(rep.started)),
      h('dt', null, 'Duration'), h('dd', null, `${rep.durationMs < 1000 ? `${rep.durationMs} ms` : `${(rep.durationMs / 1000).toFixed(1)} s`}, ${rep.connections} connections`),
      h('dt', null, 'Address'), h('dd', null, rep.address, addrs.length > 1 ? h('span', { class: 'hint' }, ` (1 of ${addrs.length}: ${addrs.join(', ')})`) : null),
      h('dt', null, 'Report format'), h('dd', null, rep.schemaVersion || prof.schema),
      h('dt', null, 'Evaluation'), h('dd', null, `${ev.version}${ev.evaluatedAt ? `, ${fmtDate(ev.evaluatedAt)}` : ''} `,
        ctx.viewScanId ? null : button('Re-evaluate', ctx.onReevaluate, 'secondary', { class: 'btn btn-sm', title: 'Judge the stored report again with the current trust anchors and reference data (no new scan)' }))),
    h('h3', null, 'How we tested'),
    h('ul', { class: 'howlist' }, how),
    (ev.referenceData || []).length ? [h('h3', null, 'Reference data'),
      h('ul', null, ev.referenceData.map((r) => h('li', null, `${r.name}: ${r.count} entries, retrieved ${r.retrieved}`,
        r.stale ? [' ', badge(`${r.ageDays} days old`, 'warn')] : null)))] : null,
    (rep.notes || []).length ? [h('h3', null, 'Notes on the scan'), h('ul', null, rep.notes.map((n) => h('li', null, n)))] : null);
}
export { aboutReport, factCard, sectionData, notChecked, versionState, plural, capital };
