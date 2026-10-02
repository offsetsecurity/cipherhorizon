// The endpoint report (PRD-004 REQ-TUI-1..8): a summary strip, "Fix first", a
// section index, and one section per part of the scan, each with the same
// anatomy: purpose, status, key facts in sentences, its findings inline, the
// full data, and how it was tested. Everything the target or its certificates
// supplied reaches the page through the textContent-only DOM builder.
import { h, svg, fmtDate, fmtDay, daysUntil } from '../dom.js';
import { levelClass, levelName } from '../charts.js';
import { badge, sevBadge, evidenceBadge, citations, bandTone, certChain, button } from '../ui.js';

export const SECTIONS = [
  ['certificates', 'Certificates & trust',
    'Checks the certificate the server presents: who issued it, whether clients trust it, which names it covers and how long it lasts. A problem here usually stops clients connecting.'],
  ['revocation', 'Revocation & transparency',
    'Checks the revocation proof the server staples (OCSP) and the Certificate Transparency proofs browsers require. Nothing is looked up from the CA or the logs.'],
  ['protocols', 'Protocols',
    'Checks which SSL and TLS versions the server accepts. Old versions have known weaknesses and current standards prohibit them.'],
  ['suites', 'Cipher suites',
    'Checks every cipher suite the server accepts, per version, and who decides the order. Weak suites let an attacker read or alter traffic.'],
  ['key-exchange', 'Key exchange & post-quantum',
    'Checks how session keys are agreed, including post-quantum hybrids, and the strength of Diffie-Hellman parameters. This decides whether recorded traffic can be decrypted later.'],
  ['features', 'Features & sessions',
    'Checks behaviours the server advertises: secure renegotiation, compression, downgrade protection, session resumption and client certificates.'],
  ['http', 'HTTP security',
    'Reads one HTTP response for Strict-Transport-Security, which tells browsers never to use plain HTTP for this site.'],
  ['vulnerabilities', 'Vulnerabilities',
    'Names the published attacks the configuration above makes possible. They are inferred from what was observed; no attack traffic is ever sent.'],
];

const STATUS = {
  problem: ['✖', 'Problem'], attention: ['▲', 'Needs attention'], good: ['✔', 'Good'],
  'not-checked': ['○', 'Not checked'], 'not-collected': ['○', 'Not collected'], inconclusive: ['?', 'Inconclusive'],
};

const STAGE_OF = { certificates: 'certificates', revocation: 'revocation', protocols: 'protocols', suites: 'suites',
  'key-exchange': 'key-exchange', features: 'features', http: 'http', vulnerabilities: 'suites' };

const REF_OF = { certificates: ['Mozilla root store', 'Chrome Root Store', 'Certificate lifetime limits'],
  revocation: ['CT log list'], 'key-exchange': ['Published DH groups'] };

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

/**
 * reportView renders the sectioned report.
 * ctx: { asset, rep, ev, history, viewScanId, goToFinding(id), onReevaluate(), triageControls(key) }
 */
export function reportView(ctx) {
  const { rep, ev } = ctx;
  const sections = Object.fromEntries((ev.sections || []).map((s) => [s.id, s]));
  const stages = Object.fromEntries((rep.stages || []).map((s) => [s.name, s]));
  const byId = {};
  for (const f of ev.findings) (byId[f.id] = byId[f.id] || []).push(f);
  const sectionTitle = Object.fromEntries(SECTIONS.map(([id, t]) => [id, t]));

  const wrap = h('div', { class: 'report' });
  if (ev.legacyReport) {
    wrap.appendChild(h('div', { class: 'callout info', role: 'status' },
      h('b', null, 'Scanned by an earlier version. '),
      'Chain analysis, per-store trust, OCSP and Certificate Transparency need data that version did not collect. Scan again to see them.'));
  }
  wrap.appendChild(summaryStrip(ctx, sections));
  wrap.appendChild(fixFirst(ctx, byId, sectionTitle));

  const index = h('nav', { class: 'secindex', 'aria-label': 'Report sections' },
    h('div', { class: 'secindex-title' }, 'Sections'),
    h('ol', null, SECTIONS.map(([id, title]) => {
      const st = sections[id] ? sections[id].status : 'not-collected';
      return h('li', null, h('a', { href: `#sec-${id}`, class: `secindex-link ss-${st}`, onclick: (e) => { e.preventDefault(); jump(id); } },
        h('span', { class: 'secindex-name' }, title), statusChip(st)));
    }), h('li', null, h('a', { href: '#sec-details', class: 'secindex-link', onclick: (e) => { e.preventDefault(); jump('details'); } },
      h('span', { class: 'secindex-name' }, 'Scan details')))));

  const main = h('div', { class: 'secmain' });
  const builders = { certificates: certificatesBody, revocation: revocationBody, protocols: protocolsBody, suites: suitesBody,
    'key-exchange': keyExchangeBody, features: featuresBody, http: httpBody, vulnerabilities: vulnerabilitiesBody };
  for (const [id, title, purpose] of SECTIONS) {
    const sec = sections[id] || { id, status: 'not-collected', findings: [] };
    const stage = stages[STAGE_OF[id]];
    const fs = id === 'vulnerabilities'
      ? ev.findings.filter((f) => f.section === 'vulnerabilities')
      : ev.findings.filter((f) => f.section === id);
    const body = builders[id](ctx, sec);
    main.appendChild(h('section', { class: `card repsec ss-${sec.status}`, id: `sec-${id}`, 'aria-labelledby': `sec-${id}-h` },
      h('header', { class: 'repsec-head' }, h('h2', { id: `sec-${id}-h` }, title), statusChip(sec.status)),
      h('p', { class: 'purpose' }, purpose),
      notChecked(sec),
      body.facts && body.facts.length ? h('ul', { class: 'facts' }, body.facts.filter(Boolean).map((f) => h('li', null, f))) : null,
      body.lead || null,
      fs.length ? h('div', { class: 'secfindings' }, fs.map((f) => inlineFinding(f, ctx))) : null,
      body.all ? h('details', { class: 'alldata' }, h('summary', null, 'Show all data'), body.all) : null,
      howTested(id, stage, ev, sec)));
  }
  main.appendChild(detailsSection(ctx));

  wrap.appendChild(h('div', { class: 'reportgrid' }, index, main));
  return wrap;

  function jump(id) {
    const el = document.getElementById(`sec-${id}`);
    if (el) { el.scrollIntoView({ behavior: 'smooth', block: 'start' }); el.focus({ preventScroll: true }); }
  }
}

// ---- summary strip & fix first ------------------------------------------------------------------

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
    certHead = left === null ? '–' : left < 0 ? 'Expired' : `${left} days left`;
    certSub = `trusted by ${trusted} of ${total} ${total === 1 ? 'store' : 'stores'}`;
    certTone = left !== null && left < 0 || trusted === 0 ? 'lv0' : left !== null && left <= 30 ? 'lv1' : 'lv3';
  } else if (ctx.rep.certificates && ctx.rep.certificates.length) {
    const left = daysUntil(ctx.rep.certificates[0].chain[0].notAfter);
    certHead = left === null ? '–' : left < 0 ? 'Expired' : `${left} days left`;
    certSub = 'trust not analysed by this scan version';
  }
  const tile = (href, cls, big, label, sub) => h('a', { class: `sumtile ${cls}`, href, onclick: (e) => {
    e.preventDefault(); const el = document.querySelector(href); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } }, h('div', { class: 'sumtile-big' }, big), h('div', { class: 'sumtile-label' }, label), h('div', { class: 'sumtile-sub' }, sub));
  const tone = { good: 'lv3', ok: 'lv2', warn: 'lv1', bad: 'lv0', neutral: 'lvu' }[bandTone(g ? g.band : '')];
  return h('div', { class: 'sumstrip', role: 'group', 'aria-label': 'Summary' },
    tile('#sec-key-exchange', `bigLevel ${levelClass(r.level)}`, r.level < 0 ? '?' : `L${r.level}`, 'PQC readiness', r.label || levelName(r.level)),
    tile('#sec-details', `bigLevel ${tone}`, g && g.score >= 0 ? String(g.score) : '–', 'TLS hygiene', g ? g.band : 'Not rated'),
    tile('#sec-certificates', `bigLevel ${certTone}`, certHead, 'Certificate', certSub),
    tile(notChecked.length ? `#sec-${notChecked[0].id}` : '#sec-details', `bigLevel ${notChecked.length ? 'lv1' : 'lv3'}`,
      String(notChecked.length), 'Not checked', notChecked.length ? notChecked.map((s) => s.id).join(', ') : 'every section ran'));
}

function fixFirst(ctx, byId, sectionTitle) {
  const ids = ctx.ev.fixFirst || [];
  if (!ids.length) {
    return h('section', { class: 'card fixfirst good', 'aria-label': 'Fix first' },
      h('h2', null, 'Fix first'), h('p', null, 'Nothing needs fixing: every finding on this result is informational.'));
  }
  return h('section', { class: 'card fixfirst', 'aria-label': 'Fix first' },
    h('h2', null, 'Fix first'),
    h('p', { class: 'hint' }, 'The most important findings across all sections: by severity, then whether they stop clients connecting.'),
    h('ol', { class: 'fixlist' }, ids.map((id) => {
      const f = byId[id][0];
      return h('li', null,
        h('div', { class: 'fixhead' }, sevBadge(f.severity), h('b', null, f.title),
          f.availability ? badge('clients fail to connect', 'bad', 'Clients that hit this refuse the connection') : null),
        h('div', { class: 'fixaction' }, f.remediation),
        h('a', { href: `#sec-${f.section}`, class: 'xlink', onclick: (e) => {
          e.preventDefault(); const el = document.getElementById(`sec-${f.section}`); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        } }, `Go to ${sectionTitle[f.section] || f.section} →`));
    })));
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

function inlineFinding(f, ctx) {
  return h('article', { class: `finding compact s-${f.severity}` },
    h('div', { class: 'finding-head' }, sevBadge(f.severity), h('strong', null, f.title), evidenceBadge(f.evidence),
      (f.labels || []).map((l) => badge(l, 'neutral', 'Published attack this enables')),
      f.availability ? badge('clients fail to connect', 'bad') : null),
    h('div', { class: 'detail' }, f.detail),
    h('div', { class: 'fix' }, h('b', null, 'Fix: '), f.remediation),
    citations(f.citations),
    h('a', { href: '#', class: 'xlink', onclick: (e) => { e.preventDefault(); ctx.goToFinding(f.id); } }, 'Open in the findings list'));
}

function howTested(id, stage, ev, sec) {
  const refs = (REF_OF[id] || []).map((n) => (ev.referenceData || []).find((r) => r.name === n)).filter(Boolean);
  if (!stage && !refs.length) return null;
  return h('details', { class: 'howtested' }, h('summary', null, 'How we tested'),
    stage ? h('div', null,
      h('ul', null, (stage.probes || []).map((p) => h('li', null, p))),
      h('p', { class: 'hint' }, `${plural(stage.connections || 0, 'connection')} in this stage.`),
      (stage.inconclusive || []).length ? h('div', { class: 'callout' }, h('b', null, 'Inconclusive: '), stage.inconclusive.join('; ')) : null) : null,
    sec.inconclusive && sec.inconclusive.length && !stage ? h('p', null, sec.inconclusive.join('; ')) : null,
    refs.length ? h('div', null, h('p', { class: 'hint' }, 'Reference data used:'),
      h('ul', null, refs.map((r) => h('li', null, `${r.name}, retrieved ${r.retrieved}`, r.stale ? badge('older than 180 days', 'warn') : null)))) : null);
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
  return { facts, lead: h('div', null, views.length > 1 ? tabs : null, panel) };
}

function chainPanel(v, certs, asset) {
  const cr = certs.find((c) => c.chain[0] && c.chain[0].sha256 === v.leaf && !!c.noSni === !!v.noSni) || certs.find((c) => c.chain[0] && c.chain[0].sha256 === v.leaf);
  if (v.error || !cr) return h('p', { class: 'muted' }, v.error || 'This chain could not be analysed.');
  return h('div', { class: 'chainpanel' },
    h('h3', null, 'Chain as served'),
    servedDiagram(v, cr),
    h('h3', null, 'Validity'),
    validityBar(cr.chain[0], v.lifetime),
    h('h3', null, 'Trust'),
    trustRows(v),
    h('h3', null, 'Names'),
    h('p', null, v.names.matchedBy ? `${v.names.host} matches ${v.names.matchedBy}.` : `${v.names.host} matches none of the names.`,
      ' Checked: ', (v.names.checked || []).join(', ') || 'no subject alternative names', '.',
      h('span', { class: 'hint' }, ' The common name is never used (RFC 9525).')),
    h('details', { class: 'alldata' }, h('summary', null, 'Every certificate field'), certChain(cr, { host: asset.host, noTrust: true })));
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
      v.served.sizeBytes > 4096 ? ' — more than fits a typical first round trip; trim extra certificates.' : '.'));
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
  return { facts, lead, all: o ? h('dl', { class: 'kv' }, [
    ['Response', o.response], ['Status', o.status], ['Produced', o.producedAt && fmtDate(o.producedAt)], ['This update', o.thisUpdate && fmtDate(o.thisUpdate)],
    ['Next update', o.nextUpdate && fmtDate(o.nextUpdate)], ['Responder', o.responder], ['Signature', o.signature], ['For this certificate', o.forThisCert ? 'yes' : 'no'],
  ].filter(([, val]) => val).flatMap(([k, val]) => [h('dt', null, k), h('dd', null, val)])) : null };
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
  h('b', null, p.version), ' ', p.evidence === 'inconclusive' ? '? unknown' : p.supported ? '✔ yes' : '— no')));
  const all = h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
    h('thead', null, h('tr', null, ['Version', 'Supported', 'Evidence', 'Detail'].map((c) => h('th', { scope: 'col' }, c)))),
    h('tbody', null, rep.protocols.map((p) => h('tr', null, h('td', null, h('b', null, p.version)),
      h('td', null, p.evidence === 'inconclusive' ? badge('unknown', 'warn') : p.supported ? badge('Yes', legacyVersion(p.version) ? 'bad' : 'good') : badge('No', 'neutral')),
      h('td', null, p.evidence), h('td', { class: 'muted' }, p.detail || ''))))));
  return { facts, lead, all };
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
    h('tbody', null, rows.map((s) => h('tr', null, h('td', null, s.version), h('td', { class: 'num' }, s.rank || '–'), h('td', null, h('code', null, s.name)),
      h('td', null, s.cipher === 'NULL' ? 'none' : `${s.cipher}-${s.keyBits} ${s.mode}`), h('td', null, s.kx || 'TLS 1.3'),
      h('td', null, suiteProblems(s).map(([t, k]) => h('span', null, badge(t, k), ' ')), s.aead ? badge('AEAD', 'good') : null),
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
    order.length ? `Order — ${order.join('; ')}.` : null,
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
    h('td', { class: 'num' }, g.rank || '–'),
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
  return { facts, lead, all };
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
  const sym = { exposed: ['✖', 'Exposed', 'bad'], 'not-exposed': ['✔', 'Not exposed', 'good'], 'not-tested': ['○', 'Not tested by design', 'neutral'] };
  const facts = [exposed.length ? `Exposed to ${exposed.map((a) => a.name).join(', ')}.` : 'Not exposed to any attack this scan can infer.'];
  const lead = h('ul', { class: 'attacks' }, list.map((a) => {
    const [s, word, kind] = sym[a.status];
    return h('li', { class: `attack a-${a.status}` },
      h('span', { class: `badge b-${kind}` }, h('span', { 'aria-hidden': 'true' }, `${s} `), word),
      h('b', null, a.name),
      h('span', { class: 'muted' }, ` — ${a.why}`),
      (a.findings || []).map((id) => h('a', { href: '#', class: 'xlink', onclick: (e) => { e.preventDefault(); ctx.goToFinding(id); } }, ` ${id}`)));
  }));
  return { facts, lead };
}

// ---- scan details -----------------------------------------------------------------------------

function detailsSection(ctx) {
  const { rep, ev } = ctx;
  const g = ev.hygiene;
  const addrs = rep.addresses || [];
  return h('section', { class: 'card repsec', id: 'sec-details', 'aria-labelledby': 'sec-details-h' },
    h('header', { class: 'repsec-head' }, h('h2', { id: 'sec-details-h' }, 'Scan details')),
    h('p', { class: 'purpose' }, 'When and how this result was produced, how the TLS hygiene score was worked out, and the reference data it was judged against.'),
    h('dl', { class: 'kv' },
      h('dt', null, 'Scanned'), h('dd', null, fmtDate(rep.started)),
      h('dt', null, 'Duration'), h('dd', null, `${rep.durationMs < 1000 ? `${rep.durationMs} ms` : `${(rep.durationMs / 1000).toFixed(1)} s`}, ${rep.connections} connections`),
      h('dt', null, 'Address'), h('dd', null, rep.address, addrs.length > 1 ? h('span', { class: 'hint' }, ` (1 of ${addrs.length}: ${addrs.join(', ')})`) : null),
      h('dt', null, 'Report format'), h('dd', null, rep.schemaVersion || 'tls-report/1'),
      h('dt', null, 'Evaluation'), h('dd', null, `${ev.version}${ev.evaluatedAt ? `, ${fmtDate(ev.evaluatedAt)}` : ''} `,
        ctx.viewScanId ? null : button('Re-evaluate', ctx.onReevaluate, 'secondary', { class: 'btn btn-sm', title: 'Judge the stored report again with the current trust anchors and reference data (no new scan)' }))),
    h('h3', null, 'TLS hygiene'),
    ctx.hygieneBody(g),
    h('h3', null, 'Reference data'),
    h('ul', null, (ev.referenceData || []).map((r) => h('li', null, `${r.name}: ${r.count} entries, retrieved ${r.retrieved}`,
      r.stale ? [' ', badge(`${r.ageDays} days old`, 'warn')] : null))),
    (rep.notes || []).length ? h('details', null, h('summary', null, 'Notes on the scan'), h('ul', null, rep.notes.map((n) => h('li', null, n)))) : null);
}
