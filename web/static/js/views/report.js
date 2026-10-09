// The endpoint report (PRD-006): Summary for anyone (the verdict, how much was checked, action
// items in plain words); Configuration (what the server ran, version by version); Weaknesses
// (every check run, found or not, with evidence); CBOM (the endpoint's CycloneDX CBOM).
// Everything the target or its certificates supplied reaches the page through the
// textContent-only DOM builder.
import { h, svg, clear, fmtDate, fmtDay, daysUntil } from '../dom.js';
import { levelClass, levelName } from '../charts.js';
import { badge, sevBadge, evidenceBadge, citations, bandTone, certChain, button } from '../ui.js';

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
const sectionTitle = (id) => (SECTIONS.find(([s]) => s === id) || [id, id])[1];
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
const whyOf = (f) => (f.section === 'http' || f.section === 'revocation' ? WHY[f.section] : null) || WHY[f.category] || WHY.vulnerability;

/** What each area says in one sentence, and its facts, computed once per render. */
function sectionData(ctx) {
  const sections = Object.fromEntries((ctx.ev.sections || []).map((x) => [x.id, x]));
  const builders = BUILDERS();
  return SECTIONS.map(([id, title, purpose]) => {
    const sec = sections[id] || { id, status: 'not-collected', findings: [] };
    const body = builders[id](ctx, sec);
    const facts = (body.facts || []).filter(Boolean);
    const verdict = capital(body.verdict || facts[0] || sec.reason || '');
    return { id, title, purpose, sec, body, facts, verdict };
  });
}

/** One finding per rule, worst first, then by section order. */
function uniqueFindings(ev) {
  const order = Object.fromEntries(SECTIONS.map(([id], i) => [id, i]));
  const seen = new Set();
  return ev.findings.filter((f) => (seen.has(f.id) ? false : seen.add(f.id)))
    .sort((a, b) => (SEV_RANK[a.severity] - SEV_RANK[b.severity]) || ((order[a.section] ?? 9) - (order[b.section] ?? 9)));
}

/** The checks this evaluation ran; an older evaluation that does not list them gets its findings only. */
function checksOf(ev) {
  if (Array.isArray(ev.checks) && ev.checks.length) return ev.checks;
  return uniqueFindings(ev).map((f) => ({ id: f.id, title: f.title, section: f.section, severity: f.severity, result: 'found' }));
}

function coverageLine(ev, onWeak) {
  const cs = checksOf(ev);
  const n = (r) => cs.filter((c) => c.result === r).length;
  const sevOf = {};
  for (const f of ev.findings) sevOf[f.id] = f.severity;
  const problems = cs.filter((c) => c.result === 'found' && (sevOf[c.id] || c.severity) !== 'info').length;
  const notes = n('found') - problems, clean = n('not-found'), skipped = n('not-checked');
  return h('p', { class: 'coverage-line' },
    h('b', null, `${cs.length} checks run: `),
    h('span', { class: 'cov-found' }, `${problems} found a problem`), ', ',
    notes ? [h('span', null, `${notes} found something to note`), ', '] : null,
    h('span', { class: 'cov-clean' }, `${clean} passed`),
    skipped ? [', ', h('span', { class: 'cov-skip' }, `${skipped} could not run`)] : null,
    n('not-applicable') ? [', ', h('span', { class: 'muted' }, `${n('not-applicable')} do not apply`)] : null, '. ',
    h('a', { href: '#', class: 'xlink', onclick: (e) => { e.preventDefault(); onWeak(); } }, 'See every check →'));
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
  wrap.appendChild(h('section', { class: `card verdict${worst ? ` v-${worst}` : ' v-none'}`, 'aria-label': 'Verdict' },
    h('div', { class: 'verdict-head' },
      h('h2', null, act.length ? `${plural(act.length, 'thing')} to fix` : 'Nothing to fix'),
      ev.readiness.summary ? h('p', { class: 'verdict-line' }, h('b', null, 'Post-quantum: '), ev.readiness.summary) : null,
      coverageLine(ev, () => ctx.goTab('weaknesses'))),
    summaryStrip(ctx, sections)));

  const items = h('section', { class: 'card fixcard', id: 'fix', 'aria-labelledby': 'fix-h' }, h('h2', { id: 'fix-h' }, 'Action items'));
  if (!act.length) {
    items.appendChild(h('p', { class: 'muted' }, 'Nothing needs fixing. The checks that found nothing are listed under Weaknesses.'));
  } else {
    // Findings that matter for the same reason share it: the reason is said once per group, each
    // finding then says only what to do (DESIGN.md: no repeated copy).
    const groups = [];
    for (const f of act) {
      const why = whyOf(f);
      let g = groups.find((x) => x.why === why);
      if (!g) groups.push(g = { why, label: GROUP_WORD[f.section === 'http' || f.section === 'revocation' ? f.section : f.category] || 'Other', items: [] });
      g.items.push(f);
    }
    items.appendChild(h('div', { class: 'action-groups' }, groups.map((g) => h('div', { class: 'action-group' },
      h('div', { class: 'action-group-head' }, h('h3', null, g.label), h('p', { class: 'action-why' }, h('b', null, 'Why it matters: '), g.why)),
      h('ol', { class: 'actions' }, g.items.map((f) => h('li', { class: `action sev-${f.severity}`, id: `issue-${f.id}` },
        h('div', { class: 'action-head' },
          sevBadge(f.severity), h('span', { class: 'action-title' }, f.title), h('span', { class: `urgency u-${f.severity}` }, URGENCY[f.severity]),
          f.availability ? badge('clients fail to connect', 'bad', 'Clients that hit this refuse the connection') : null,
          ctx.triage && ctx.triage[f.id] ? badge(ctx.triage[f.id].status === 'accepted-risk' ? 'accepted risk' : 'acknowledged', 'neutral') : null),
        h('p', { class: 'action-fix' }, h('b', null, 'What to do: '), f.remediation),
        h('a', { href: `#chk-${f.id}`, class: 'xlink action-more', onclick: (e) => { e.preventDefault(); ctx.goIssue(f.id); } }, 'Evidence and sources'))))))));
  }
  wrap.appendChild(items);

  wrap.appendChild(h('section', { class: 'card areas', id: 'checks', 'aria-labelledby': 'areas-h' },
    h('h2', { id: 'areas-h' }, 'What was evaluated'),
    h('ul', { class: 'checklist' }, data.map((d) => h('li', { class: `check-row ss-${d.sec.status}` },
      h('span', { class: 'check-status' }, statusChip(d.sec.status)),
      h('span', { class: 'check-name' }, d.title),
      h('span', { class: 'check-verdict' }, d.verdict),
      h('a', { href: `#sec-${d.id}`, class: 'check-go', onclick: (e) => { e.preventDefault(); ctx.goDetails(d.id); } }, 'Show'))))));
  return wrap;
}

// ---- configuration: what the server ran --------------------------------------------------------

const VERSION_ORDER = ['TLSv1.3', 'TLSv1.2', 'TLSv1.1', 'TLSv1.0', 'SSLv3', 'SSLv2'];
const versionLabel = (v) => v.replace('TLSv', 'TLS ').replace('SSLv', 'SSL ');

/** How strong a cipher suite is, in four words a reader can compare across versions. */
function suiteStrength(s) {
  if (s.cipher === 'NULL' || s.export || s.anon || s.cipher === 'RC4') return 'insecure';
  if (s.blockBits === 64 || (s.kx && !s.ephemeral && ['RSA', 'DH', 'ECDH'].includes(s.kx))) return 'weak';
  if (!s.aead && s.version !== 'TLSv1.3') return 'acceptable';
  return 'strong';
}
const STRENGTHS = [['strong', 'Strong', 'good'], ['acceptable', 'Acceptable', 'neutral'], ['weak', 'Weak', 'warn'], ['insecure', 'Insecure', 'bad']];

function strengthBar(counts, total, max) {
  const W = 160, H = 10;
  const root = svg('svg', { viewBox: `0 0 ${W} ${H}`, class: 'hbar strength-bar', preserveAspectRatio: 'none', role: 'img',
    'aria-label': STRENGTHS.map(([k, w]) => `${counts[k] || 0} ${w.toLowerCase()}`).join(', ') });
  root.appendChild(svg('rect', { x: 0, y: 0, width: W, height: H, rx: 5, class: 'hbar-track' }));
  let x = 0;
  for (const [k] of STRENGTHS) {
    const n = counts[k] || 0;
    if (!n) continue;
    const w = (W * n) / Math.max(1, max);
    root.appendChild(svg('rect', { x, y: 0, width: w, height: H, class: `fill-st-${k}` }));
    x += w;
  }
  return root;
}

/**
 * What a version being on or off means, in words: the state the server is in, then whether that
 * is right. [tone, symbol, state, judgement]
 */
function versionVerdict(v, on, unknown, modernOn) {
  if (unknown) return ['warn', '?', 'Not determined', 'the probe got no clear answer'];
  if (on) {
    if (legacyVersion(v)) return ['bad', '✖', 'Enabled', 'should be off'];
    return ['good', '✔', 'Enabled', v === 'TLSv1.3' ? 'recommended' : 'fine'];
  }
  if (v === 'TLSv1.3') return ['warn', '▲', 'Disabled', 'should be on'];
  if (v === 'TLSv1.2') return modernOn ? ['neutral', '·', 'Disabled', 'fine, TLS 1.3 is on'] : ['bad', '✖', 'Disabled', 'no modern version is on'];
  return ['good', '✔', 'Disabled', 'good'];
}

function versionState([tone, sym, state, judgement]) {
  return h('span', { class: `vstate vs-${tone}` }, h('span', { class: 'vs-sym', 'aria-hidden': 'true' }, sym),
    h('b', null, state), h('span', { class: 'vs-judge' }, ` · ${judgement}`));
}

/** The protocol matrix: every version, accepted or not, and for each accepted one what it ran. */
function protocolMatrix(ctx) {
  const { rep } = ctx;
  const byVersion = Object.fromEntries((rep.protocols || []).map((p) => [p.version, p]));
  const suites = rep.suites || [];
  const groups = rep.groups || [];
  const pref = (v, subject) => ((rep.preference || []).find((p) => p.version === v && p.subject === subject) || {}).order;
  const orderWord = { server: 'server chooses', client: 'client chooses', mixed: 'depends on the offer', unknown: 'not determined' };
  const versions = VERSION_ORDER.filter((v) => byVersion[v]);
  const max = Math.max(1, ...versions.map((v) => suites.filter((s) => s.version === v).length));
  const modernOn = !!(byVersion['TLSv1.3']?.supported || byVersion['TLSv1.2']?.supported);
  const on = versions.filter((v) => byVersion[v].supported);
  const shouldOff = on.filter(legacyVersion);
  const summary = h('p', { class: 'ver-sum' },
    h('b', null, 'Enabled: '), on.length ? on.map(versionLabel).join(', ') : 'none', '. ',
    shouldOff.length ? h('span', { class: 'ver-sum-bad' }, `${shouldOff.map(versionLabel).join(' and ')} should be switched off.`)
      : h('span', { class: 'ver-sum-good' }, 'No outdated version is enabled.'),
    byVersion['TLSv1.3'] && !byVersion['TLSv1.3'].supported ? h('span', { class: 'ver-sum-bad' }, ' TLS 1.3 should be switched on.') : null);
  const rows = versions.map((v) => {
    const p = byVersion[v];
    const vs = suites.filter((s) => s.version === v);
    const counts = {};
    for (const s of vs) counts[suiteStrength(s)] = (counts[suiteStrength(s)] || 0) + 1;
    const fs = vs.filter((s) => s.version === 'TLSv1.3' || s.ephemeral).length;
    const vg = groups.filter((g) => g.version === v);
    const pq = vg.filter((g) => g.pq && !g.obsolete);
    const accepted = p.supported;
    const unknown = p.evidence === 'inconclusive';
    const verdict = versionVerdict(v, accepted, unknown, modernOn);
    const state = versionState(verdict);
    const line = h('summary', { class: 'ver-line' },
      h('span', { class: 'ver-name' }, versionLabel(v)),
      h('span', { class: 'ver-state' }, state),
      accepted ? h('span', { class: 'ver-suites' }, strengthBar(counts, vs.length, max), h('span', { class: 'ver-count' }, plural(vs.length, 'suite'))) : h('span', null),
      accepted ? h('span', { class: 'ver-fs' }, vs.length ? (fs === vs.length ? 'all suites' : fs ? `${fs} of ${vs.length} suites` : 'none') : '') : h('span', null),
      accepted ? h('span', { class: 'ver-kx' }, vg.length ? `${plural(vg.length, 'group')}${pq.length ? ' · post-quantum' : ''}` : '') : h('span', null),
      accepted ? h('span', { class: 'ver-open' }, h('span', { class: 't-show' }, 'Show suites'), h('span', { class: 't-hide' }, 'Hide suites')) : h('span', null));
    if (!accepted) return h('div', { class: `ver-row off vr-${verdict[0]}` }, h('div', { class: 'ver-line' }, ...line.childNodes));
    const suiteRows = vs.map((s) => {
      const st = suiteStrength(s);
      const [, word, tone] = STRENGTHS.find(([k]) => k === st);
      return h('tr', null, h('td', { class: 'num' }, s.rank || '·'), h('td', null, h('code', null, s.name)),
        h('td', null, s.cipher === 'NULL' ? 'none' : `${s.cipher}-${s.keyBits} ${s.mode}`), h('td', null, s.kx || 'TLS 1.3'),
        h('td', null, badge(word, tone)), h('td', { class: 'muted' }, ianaLabel(s.ianaRecommended)));
    });
    return h('details', { class: `ver-row on vr-${verdict[0]}`, id: `ver-${v}` }, line,
      h('div', { class: 'ver-body' },
        vs.length ? h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
          h('thead', null, h('tr', null, ['#', 'Suite', 'Cipher', 'Key exchange', 'Strength', 'IANA'].map((c) => h('th', { scope: 'col' }, c)))),
          h('tbody', null, suiteRows))) : h('p', { class: 'muted' }, 'No cipher suites were recorded for this version.'),
        pref(v, 'suites') ? h('p', { class: 'hint' }, `Suite order: ${orderWord[pref(v, 'suites')] || pref(v, 'suites')}.`) : null,
        vg.length ? h('p', null, h('b', null, 'Key-exchange groups: '), vg.map((g, i) => [i ? ', ' : '',
          h('span', { class: g.pq && !g.obsolete ? 'pq-group' : '' }, g.name), g.pq && !g.obsolete ? ' (post-quantum)' : ''])) : null));
  });
  const legend = h('p', { class: 'hint strength-legend' }, h('span', null, 'Suite strength:'), STRENGTHS.map(([k, w]) => h('span', null, h('span', { class: `swatch sw-st-${k}`, 'aria-hidden': 'true' }), ` ${w} `)));
  const n = rep.negotiated || {};
  return h('section', { class: 'card matrix', id: 'sec-protocols', 'aria-labelledby': 'matrix-h' },
    h('span', { id: 'sec-suites' }),
    h('h2', { id: 'matrix-h' }, 'Protocols and cipher suites, version by version'),
    n.version ? h('p', { class: 'verdict-line' }, `A current client negotiates ${versionLabel(n.version)} with `, h('code', null, n.suite || ''),
      n.group ? ` and ${n.group}${n.pq ? ' (post-quantum hybrid)' : ''}` : '', '.') : null,
    summary,
    h('div', { class: 'ver-head', 'aria-hidden': 'true' }, h('span', null, 'Version'), h('span', null, 'Status'), h('span', null, 'Cipher suites by strength'),
      h('span', null, 'Forward secrecy'), h('span', null, 'Key exchange'), h('span', null, '')),
    h('div', { class: 'ver-rows' }, rows),
    legend);
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
  const wrap = h('div', { class: 'report configuration' });
  wrap.appendChild(protocolMatrix(ctx));
  for (const d of data) {
    if (d.id === 'protocols' || d.id === 'suites' || d.id === 'vulnerabilities') continue;
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

  for (const [sid, title] of SECTIONS) {
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
  if (ctx.hygieneBody) wrap.appendChild(h('section', { class: 'card', id: 'score', 'aria-labelledby': 'score-h' }, h('h2', { id: 'score-h' }, 'How the TLS hygiene score was worked out'), ctx.hygieneBody(ev.hygiene)));
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
        h('p', null, h('b', null, 'Why it matters: '), whyOf(f)),
        h('p', { class: 'fix' }, h('b', null, 'Fix: '), f.remediation),
        citations(f.citations),
        c.section !== 'vulnerabilities' ? h('a', { href: `#sec-${c.section}`, class: 'xlink', onclick: (e) => { e.preventDefault(); ctx.goDetails(c.section); } },
          `See ${sectionTitle(c.section)} in Configuration →`) : null,
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
      h('thead', null, h('tr', null, ['Name', 'Type', 'Detail', 'Post-quantum'].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, comps.slice().sort((x, y) => (order[type(x)] - order[type(y)]) || x.name.localeCompare(y.name)).map((c) => h('tr', null,
        h('td', null, h('b', { title: c.name }, cbomName(c))), h('td', { class: 'muted' }, (ASSET_WORD[type(c)] || type(c)).replace(/s$/, '')),
        h('td', { class: 'muted' }, detail(c)), h('td', null, type(c) === 'algorithm' || type(c) === 'related-crypto-material' ? qBadge(q(c)) : h('span', { class: 'muted' }, '·'))))))));
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
  let certHead = 'No certificate';
  let certSub = '';
  let certTone = 'lvu';
  if (pki && ctx.rep.certificates) {
    const cr = ctx.rep.certificates.find((c) => c.chain && c.chain[0] && c.chain[0].sha256 === pki.leaf);
    const left = cr ? daysUntil(cr.chain[0].notAfter) : null;
    const trusted = (pki.trust || []).filter((t) => t.trusted).length + (pki.private && pki.private.trusted ? 1 : 0);
    const total = (pki.trust || []).length + (pki.private ? 1 : 0);
    certHead = left === null ? '·' : left < 0 ? 'Expired' : `${left} days left`;
    // UX-REVIEW-008 R2: the colour is about time; trust is said in words, so "89 days left" is
    // never red because of something else.
    certSub = trusted === 0 ? 'not trusted by any store checked' : `trusted by ${trusted} of ${total} ${total === 1 ? 'store' : 'stores'}`;
    certTone = left === null ? 'lvu' : left < 0 ? 'lv0' : left <= 30 ? 'lv1' : 'lv3';
  } else if (ctx.rep.certificates && ctx.rep.certificates.length) {
    const left = daysUntil(ctx.rep.certificates[0].chain[0].notAfter);
    certHead = left === null ? '·' : left < 0 ? 'Expired' : `${left} days left`;
    certSub = 'trust not analysed by this scan version';
  }
  // Each figure opens the Details card it summarises.
  const tile = (href, cls, big, label, sub) => h('a', { class: `sumtile ${cls}`, href, onclick: (e) => {
    e.preventDefault();
    if (ctx.goDetails) { ctx.goDetails(href.replace('#sec-', '')); return; }
    const el = document.querySelector(href); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } }, h('div', { class: 'sumtile-big' }, big), h('div', { class: 'sumtile-label' }, label), h('div', { class: 'sumtile-sub' }, sub));
  const tone = { good: 'lv3', ok: 'lv2', warn: 'lv1', bad: 'lv0', neutral: 'lvu' }[bandTone(g ? g.band : '')];
  // UX-REVIEW-008 R1: post-quantum readiness leads, placed on its L0 to L4 scale.
  const ready = tile('#sec-key-exchange', `bigLevel sumtile-lead ${levelClass(r.level)}`, r.level < 0 ? '?' : `L${r.level}`, 'Post-quantum readiness', r.label || levelName(r.level));
  ready.appendChild(h('div', { class: 'lvscale', 'aria-hidden': 'true' }, [0, 1, 2, 3, 4].map((l) => h('span', { class: l <= r.level ? 'on' : '' }))));
  return h('div', { class: 'sumstrip', role: 'group', 'aria-label': 'Summary' },
    ready,
    tile('#sec-details', `bigLevel ${tone}`, g && g.score >= 0 ? String(g.score) : '·', 'TLS hygiene', g ? g.band : 'Not rated'),
    tile('#sec-certificates', `bigLevel ${certTone}`, certHead, 'Certificate', certSub),
    notChecked.length ? tile(`#sec-${notChecked[0].id}`, 'bigLevel lv1', String(notChecked.length), 'Not checked',
      notChecked.map((s) => (SECTIONS.find(([id]) => id === s.id) || [0, s.id])[1]).join(', ')) : null);
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
  const { rep, ev, asset } = ctx;
  const certs = rep.certificates || [];
  if (!certs.length) return { facts: ['No certificate was received.'] };
  const views = ev.pki || [];
  if (!views.length) {
    return { facts: [`${plural(certs.length, 'certificate chain')} presented.`],
      all: h('div', null, certs.map((c) => certChain(c, { host: asset.host }))) };
  }
  let selected = 0;
  const panel = h('div');
  const tabs = h('div', { class: 'chaintabs', role: 'tablist', 'aria-label': 'Certificate chains' });
  const draw = () => {
    tabs.replaceChildren(...views.map((v, i) => h('button', { type: 'button', role: 'tab', class: 'chaintab', 'aria-selected': String(i === selected),
      onclick: () => { selected = i; draw(); } }, chainLabel(v))));
    panel.replaceChildren(chainPanel(views[selected], certs, asset));
  };
  draw();
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
  return { verdict, facts, lead: h('div', null, views.length > 1 ? tabs : null, panel) };
}

function chainPanel(v, certs, asset) {
  const cr = certs.find((c) => c.chain[0] && c.chain[0].sha256 === v.leaf && !!c.noSni === !!v.noSni) || certs.find((c) => c.chain[0] && c.chain[0].sha256 === v.leaf);
  if (v.error || !cr) return h('p', { class: 'muted' }, v.error || 'This chain could not be analysed.');
  return h('div', { class: 'chainpanel' },
    v.noSni ? h('div', { class: 'callout info', role: 'note' }, h('b', null, 'Only clients that send no server name see this certificate. '),
      'Every current client sends one, and many large sites deliberately serve a placeholder here. It is shown for information and is not scored.') : null,
    h('h3', null, 'Chain as served'),
    servedDiagram(v, cr),
    h('h3', null, 'Trust'),
    trustRows(v),
    h('details', { class: 'alldata' }, h('summary', null, 'Validity, names and every field'),
      h('h3', null, 'Validity'),
      validityBar(cr.chain[0], v.lifetime),
      h('h3', null, 'Names'),
      h('p', null, v.names.matchedBy ? `${v.names.host} matches ${v.names.matchedBy}.` : `${v.names.host} matches none of the names.`,
        ' Checked: ', (v.names.checked || []).join(', ') || 'no subject alternative names', '.',
        h('span', { class: 'hint' }, ' The common name is never used (RFC 9525).')),
      certChain(cr, { host: asset.host, noTrust: true })));
}

function servedDiagram(v, cr) {
  const issuesAt = {};
  for (const i of v.served.issues || []) (issuesAt[i.index] = issuesAt[i.index] || []).push(i);
  const onPath = new Set(v.served.path || []);
  const items = cr.chain.map((c, i) => h('li', { class: `servednode${onPath.has(i) ? '' : ' offpath'}${issuesAt[i] ? ' hasissue' : ''}` },
    h('span', { class: 'servedpos' }, String(i)),
    h('div', null,
      h('div', { class: 'servedcn' }, cn(c.subject)),
      h('div', { class: 'hint' }, i === 0 ? 'leaf' : c.selfSigned ? 'root' : 'intermediate', ` · ${keyDesc(c.publicKey)} · until ${fmtDay(c.notAfter)}`),
      (issuesAt[i] || []).map((is) => h('div', { class: 'servedissue' }, `⚠ ${is.kind}: ${is.detail}`)),
      (v.served.expiresFirst || []).includes(i) ? h('div', { class: 'servedissue' }, '⚠ expires before the leaf') : null)));
  if (v.served.missing) {
    const root = v.served.missing.likely === 'root';
    items.push(h('li', { class: `servednode missing${root ? ' unknownroot' : ''}` }, h('span', { class: 'servedpos' }, '?'),
      h('div', null, h('div', { class: 'servedcn' }, `${root ? 'Unknown root' : 'Missing'}: ${cn(v.served.missing.issuer)}`),
        h('div', { class: 'hint' }, root
          ? 'Not in any trusted store. Servers do not send their root; if this is your private CA, add it to the system’s CA bundle.'
          : 'Not sent by the server and not in any trusted store.'),
        (v.served.missing.aia || []).length ? h('div', { class: 'hint' }, 'The certificate says it is available at ', v.served.missing.aia.join(', '), ' (not fetched).') : null)));
  }
  return h('div', null, h('ol', { class: 'served' }, items),
    h('p', { class: 'hint' }, `${plural(cr.chain.length, 'certificate')}, ${v.served.sizeBytes.toLocaleString()} bytes`,
      v.served.sizeBytes > 4096 ? ': more than fits a typical first round trip; trim extra certificates.' : '.'));
}

function validityBar(leaf, lifetime) {
  const from = Date.parse(leaf.notBefore), to = Date.parse(leaf.notAfter), now = Date.now();
  const limitEnd = lifetime && lifetime.limitDays ? from + lifetime.limitDays * 86400000 : null;
  const end = Math.max(to, limitEnd || 0, now);
  const start = Math.min(from, now);
  const W = 600, x = (t) => Math.round(((t - start) / Math.max(1, end - start)) * W);
  const pieces = [
    svg('rect', { x: 0, y: 14, width: W, height: 10, rx: 5, class: 'vb-track' }),
    svg('rect', { x: x(from), y: 14, width: Math.max(2, x(to) - x(from)), height: 10, rx: 5, class: now > to ? 'vb-expired' : 'vb-valid' }),
    svg('line', { x1: x(now), x2: x(now), y1: 6, y2: 32, class: 'vb-today' }),
    svg('text', { x: Math.min(W - 40, Math.max(0, x(now) - 18)), y: 44, class: 'vb-label' }, 'today'),
  ];
  if (limitEnd && lifetime.applies) {
    pieces.push(svg('line', { x1: x(limitEnd), x2: x(limitEnd), y1: 8, y2: 30, class: 'vb-limit' }),
      svg('text', { x: Math.min(W - 70, Math.max(0, x(limitEnd) - 30)), y: 5, class: 'vb-label' }, `${lifetime.limitDays}-day limit`));
  }
  return h('div', { class: 'validity' },
    svg('svg', { viewBox: `0 -8 ${W} 56`, class: 'vbar', role: 'img', 'aria-label': `Valid ${fmtDay(leaf.notBefore)} to ${fmtDay(leaf.notAfter)}` }, ...pieces),
    h('div', { class: 'row spread hint' }, h('span', null, `issued ${fmtDay(leaf.notBefore)}`), h('span', null, `expires ${fmtDay(leaf.notAfter)}`)),
    lifetime && lifetime.limitDays ? h('p', { class: 'hint' }, lifetime.applies
      ? `Lifetime ${lifetime.days} days; the limit on its issue date was ${lifetime.limitDays} days (${lifetime.limitSource}).`
      : `Lifetime ${lifetime.days} days. The public limit (${lifetime.limitDays} days on its issue date) does not apply: no public root store trusts it.`) : null);
}

function trustRows(v) {
  const rows = [...(v.trust || []), v.private, v.os].filter(Boolean);
  if (!rows.length) return h('p', { class: 'muted' }, 'No trust store was available.');
  return h('div', null, h('div', { class: 'tablewrap' }, h('table', { class: 'compact trusttable' },
    h('thead', null, h('tr', null, ['Store', 'Result', 'Detail'].map((c) => h('th', { scope: 'col' }, c)))),
    h('tbody', null, rows.map((t) => h('tr', null,
      h('td', null, h('b', null, t.store), t.snapshot ? h('div', { class: 'hint' }, `snapshot ${t.snapshot}`) : null),
      h('td', null, t.trusted ? badge('✔ trusted', 'good') : t.distrust ? badge('✖ distrusted', 'bad') : t.expiredOnly ? badge('▲ expired', 'warn') : badge('✖ not trusted', 'bad')),
      h('td', { class: 'muted' }, t.trusted ? `path of ${(t.path || []).length} certificates` : (t.distrust || t.error || ''))))))),
    v.private ? null : h('p', { class: 'hint' }, 'Private CA? Add it to this endpoint’s system as a trust anchor (system page → CA bundle), and the result is re-evaluated without a rescan.'));
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

function suiteTable(rows) {
  return h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
    h('thead', null, h('tr', null, ['Version', '#', 'Suite', 'Cipher', 'Key exchange', 'Flags', 'IANA'].map((c) => h('th', { scope: 'col' }, c)))),
    h('tbody', null, rows.map((s) => h('tr', null, h('td', null, s.version), h('td', { class: 'num' }, s.rank || '·'), h('td', null, h('code', null, s.name)),
      h('td', null, s.cipher === 'NULL' ? 'none' : `${s.cipher}-${s.keyBits} ${s.mode}`), h('td', null, s.kx || 'TLS 1.3'),
      h('td', null, suiteProblems(s).filter(([t]) => t !== 'IANA discouraged').map(([t, k]) => h('span', null, badge(t, k), ' ')), s.aead ? badge('AEAD', 'good') : null),
      h('td', null, badge(ianaLabel(s.ianaRecommended), s.ianaRecommended === 'Y' ? 'good' : s.ianaRecommended === 'D' ? 'bad' : 'neutral')))))));
}

function suitesBody(ctx) {
  const { rep } = ctx;
  const suites = rep.suites || [];
  const problem = suites.filter((s) => suiteProblems(s).some(([, k]) => k !== 'neutral'));
  const fine = suites.filter((s) => !problem.includes(s));
  const aead = suites.filter((s) => s.aead).length;
  const cbc = suites.filter((s) => s.mode === 'CBC' && s.version !== 'TLSv1.3').length;
  const order = (rep.preference || []).filter((p) => p.subject === 'suites').map((p) => `${p.version}: ${{ server: 'server decides', client: 'client decides', mixed: 'depends on the offer', unknown: 'not determined' }[p.order]}`);
  const facts = [
    `${plural(suites.length, 'suite')} accepted: ${aead} AEAD${cbc ? `, ${cbc} CBC` : ''}${problem.length ? `, ${problem.length} with a weakness` : ''}.`,
    order.length ? `Order: ${order.join('; ')}.` : null,
  ];
  const lead = problem.length ? h('div', null, h('h3', null, 'Suites with a weakness'), suiteTable(problem)) : null;
  return { facts, lead, all: fine.length ? h('div', null, h('p', { class: 'hint' }, 'Suites with no weakness flagged:'), suiteTable(fine)) : null };
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
  ];
  const dim = (title, d) => h('div', { class: 'dim' }, h('h4', null, title, badge(d.status, 'neutral'), evidenceBadge(d.evidence)), h('div', null, d.detail), citations(d.citations));
  const lead = h('div', { class: 'pqpanel' },
    h('div', { class: 'readiness' }, h('div', { class: `bigLevel ${levelClass(r.level)}` }, r.level < 0 ? '?' : `L${r.level}`, h('small', null, r.label)),
      h('div', null, h('p', null, r.summary))),
    h('div', { class: 'scale', role: 'img', 'aria-label': `Level ${r.level} of 4` }, [0, 1, 2, 3, 4].map((l) =>
      h('span', { class: `${levelClass(l)}${l === r.level ? ' on' : ''}`, title: levelName(l) }, `L${l}`))),
    dim('Key establishment', r.keyEstablishment), dim('Authentication', r.authentication), dim('Symmetric strength', r.symmetric),
    h('h3', null, 'What to do next'), h('ol', { class: 'next' }, r.nextSteps.map((s) => h('li', null, s))),
    h('p', { class: 'hint' }, 'The level scale is this product’s own; each fact above cites its standard.'));
  const gv = [...new Set(groups.map((g) => g.version))];
  const groupRow = (g) => h('tr', null,
    h('td', { class: 'num' }, g.rank || '·'),
    h('td', null, h('code', null, g.name)),
    h('td', null, g.pq ? badge(g.hybrid ? 'hybrid post-quantum' : 'post-quantum', g.obsolete ? 'warn' : 'good') : h('span', { class: 'muted' }, 'classical'),
      g.obsolete ? badge('obsolete draft', 'warn') : null),
    h('td', null, badge(ianaLabel(g.ianaRecommended), g.ianaRecommended === 'Y' ? 'good' : 'neutral')));
  const groupTable = (v) => h('div', null, h('h3', null, v),
    h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
      h('thead', null, h('tr', null, ['#', 'Group', 'Post-quantum', 'IANA'].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, groups.filter((g) => g.version === v).map(groupRow)))));
  const all = h('div', null, gv.map(groupTable),
    rep.dh ? h('p', null, `DHE prime fingerprint ${rep.dh.primeSha256}, sampled from `, h('code', null, rep.dh.suite)) : null,
    h('details', null, h('summary', null, 'Sources for the readiness assessment'), citations(r.citations)));
  return { facts, all: h('div', null, lead, all) };
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
  const STAGE_TITLE = { protocols: 'Protocols', suites: 'Cipher suites', 'key-exchange': 'Key exchange', features: 'Features',
    certificates: 'Certificates', revocation: 'Revocation & transparency', http: 'HTTP' };
  const how = Object.entries(STAGE_TITLE).map(([k, title]) => {
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
      h('dt', null, 'Report format'), h('dd', null, rep.schemaVersion || 'tls-report/1'),
      h('dt', null, 'Evaluation'), h('dd', null, `${ev.version}${ev.evaluatedAt ? `, ${fmtDate(ev.evaluatedAt)}` : ''} `,
        ctx.viewScanId ? null : button('Re-evaluate', ctx.onReevaluate, 'secondary', { class: 'btn btn-sm', title: 'Judge the stored report again with the current trust anchors and reference data (no new scan)' }))),
    h('h3', null, 'How we tested'),
    h('ul', { class: 'howlist' }, how),
    h('h3', null, 'Reference data'),
    h('ul', null, (ev.referenceData || []).map((r) => h('li', null, `${r.name}: ${r.count} entries, retrieved ${r.retrieved}`,
      r.stale ? [' ', badge(`${r.ageDays} days old`, 'warn')] : null))),
    (rep.notes || []).length ? [h('h3', null, 'Notes on the scan'), h('ul', null, rep.notes.map((n) => h('li', null, n)))] : null);
}
