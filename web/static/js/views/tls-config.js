// The TLS report's Configuration: the one-stop check (UX-DESIGN-011 §3.2, PRD-013). In the order
// an experienced reviewer checks: protocols and suites, the certificate chain, key exchange and
// signatures, revocation, protocol features, and every algorithm by class. Every quantity is an
// instrument from viz.js; reasons and sources are in tooltips. Everything the target or its
// certificates supplied reaches the page through the textContent-only DOM builder.
import { h, fmtDay } from '../dom.js';

import { bitsBar, bitsAxis, strengthChip, partCell, pqGlyph, statusTile, lifetimeBar, levelStepper, jumpNav, strengthWords, bandOf } from '../viz.js';

const VERSION_ORDER = ['TLSv1.3', 'TLSv1.2', 'TLSv1.1', 'TLSv1.0', 'SSLv3', 'SSLv2'];
const versionLabel = (v) => v.replace('TLSv', 'TLS ').replace('SSLv', 'SSL ');
const legacyVersion = (v) => ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'].includes(v);
const plural = (n, one, many) => `${n} ${n === 1 ? one : many || `${one}s`}`;
const cn = (subject) => { const m = /CN=([^,]+)/.exec(subject || ''); return m ? m[1] : (subject || 'unknown'); };
const ianaWord = { Y: 'IANA recommended', N: 'IANA not recommended', D: 'IANA discouraged' };
const ORDER_WORD = { server: 'the server picks the order', client: 'the client picks the order', mixed: 'the order depends on the offer', unknown: 'order not determined' };

/** A certificate's page, read as this scan served it (PRD-012 REQ-XV-4). */
export const certHref = (sha256, scanId) => `#/certificates/${sha256}${scanId ? `?scan=${scanId}` : ''}`;

const toneOfSection = (st) => ({ problem: 'problem', attention: 'attention', good: 'good' }[st] || 'na');
const worstTone = (...tones) => ['problem', 'attention', 'good', 'na'].find((t) => tones.includes(t)) || 'na';

// The findings each section answers for, and the ctx that opens them; set by tlsConfiguration.
let ISSUES = {};
let OPEN_ISSUE = null;
const SECTION_FINDINGS = { 'sec-protocols': ['protocols', 'suites'], 'sec-certificates': ['certificates'], 'sec-key-exchange': ['key-exchange'],
  'sec-revocation': ['revocation'], 'sec-features': ['features', 'http'], 'sec-algorithms': [] };

function section(id, title, tone, aside, ...body) {
  const issues = (SECTION_FINDINGS[id] || []).flatMap((s) => ISSUES[s] || []);
  return h('section', { class: `card cfg ${tone ? `cfg-${tone}` : ''}`, id, 'aria-labelledby': `${id}-h` },
    h('div', { class: 'cfg-head' }, h('h2', { id: `${id}-h` }, title), aside || null), ...body,
    issues.length ? h('p', { class: 'detcard-issues' }, h('b', null, issues.length === 1 ? 'Issue: ' : 'Issues: '),
      issues.map((f, i) => [i ? ' · ' : '', h('a', { href: `#chk-${f.id}`, class: 'xlink', onclick: (e) => { e.preventDefault(); if (OPEN_ISSUE) OPEN_ISSUE(f.id); } }, f.title)])) : null);
}

const keyLabel = (k) => (!k ? 'unknown key' : k.curve ? `${k.algorithm} ${k.curve}` : k.bits && (k.algorithm === 'RSA' || k.algorithm === 'DSA') ? `${k.algorithm}-${k.bits}` : k.algorithm);
const keyStrengthOf = (ev, sha256) => ((ev.keyStrength || []).find((k) => k.kind === 'certificate-key' && k.name === sha256) || {}).strength;
const groupStrengthOf = (ev, name, version) => ((ev.keyStrength || []).find((k) => k.kind === 'group' && k.name === name && (!version || k.version === version)) || {}).strength;

/** A group as a chip: its rank, its name, post-quantum marked, its strength in the tooltip. */
function groupChip(ev, g) {
  const st = groupStrengthOf(ev, g.name, g.version);
  const pq = g.pq && !g.obsolete;
  return h('span', { class: `gchip${pq ? ' gchip-pq' : ''}${g.obsolete ? ' gchip-old' : ''}`, title: `${g.name}: ${strengthWords(st)}${pq ? ', post-quantum hybrid' : g.obsolete ? ', an obsolete draft' : ', classical'}` },
    g.rank ? h('span', { class: 'gchip-rank' }, String(g.rank)) : null, pq ? pqGlyph('quantum-safe') : null, g.name,
    h('span', { class: `gchip-bits gbits-${bandOf(st)}` }, st && st.status === 'rated' ? String(st.bits) : strengthWords(st)));
}

// ---- 1. protocols and suites ----------------------------------------------------------------

const PART_COLUMNS = [['cipher', 'Cipher'], ['key exchange', 'Key exchange'], ['authentication', 'Signature'], ['MAC', 'MAC'], ['hash', 'Hash']];

function suiteRow(ev, s, rep) {
  const r = ((ev.suiteStrength || []).find((x) => x.version === s.version && x.id === s.id)) || null;
  const parts = r ? r.parts || [] : [];
  const partFor = (role) => parts.find((p) => (role === 'hash' ? (p.role || '').startsWith('hash') : p.role === role)) || null;
  const weakestName = r && r.weakest;
  let ringed = false;
  const cells = PART_COLUMNS.map(([role]) => {
    const p = partFor(role);
    const weakest = !ringed && p && p.name === weakestName;
    if (weakest) ringed = true;
    const aead = s.aead || s.version === 'TLSv1.3';
    const absent = role === 'MAC' && aead ? 'unused'
      : role === 'key exchange' || role === 'authentication' ? ((rep.certificates || []).length ? 'Not measured in this scan' : 'Not measured: the server sent no certificate')
        : 'Not measured in this scan';
    return h('td', { class: 'pcol' }, partCell(p, weakest, absent));
  });
  const facts = [s.kx ? (s.ephemeral || s.version === 'TLSv1.3' ? `${s.kx} · forward secrecy` : `${s.kx} · no forward secrecy`) : 'forward secrecy',
    s.aead || s.version === 'TLSv1.3' ? 'AEAD' : s.mode, ianaWord[s.ianaRecommended] || ''].filter(Boolean).join(' · ');
  return h('tr', null,
    h('td', { class: 'num rank' }, s.rank ? String(s.rank) : '·'),
    h('th', { scope: 'row', class: 'suite' }, h('code', null, s.name), h('span', { class: 'suite-facts' }, facts),
      // On a phone the table scrolls; its strength stays beside the name (only one of the two is shown).
      h('span', { class: 'suite-strength-narrow', 'aria-hidden': 'true' }, r ? strengthChip(r.word) : strengthChip(''), r && r.bits ? ` ${r.bits} bits` : '')),
    cells,
    h('td', { class: 'strength-cell' }, r ? strengthChip(r.word, r.reason) : strengthChip(''), r && r.bits ? h('span', { class: 'strength-bits' }, `${r.bits} bits`) : null));
}

function protocolsSection(ctx, tone) {
  const { rep, ev } = ctx;
  const byVersion = Object.fromEntries((rep.protocols || []).map((p) => [p.version, p]));
  const versions = VERSION_ORDER.filter((v) => byVersion[v]);
  const on = versions.filter((v) => byVersion[v].supported);
  const off = versions.filter((v) => !byVersion[v].supported && byVersion[v].evidence !== 'inconclusive');
  const unknown = versions.filter((v) => byVersion[v].evidence === 'inconclusive');
  const modernOn = on.includes('TLSv1.3') || on.includes('TLSv1.2');
  const n = rep.negotiated || {};
  const pref = (v) => ((rep.preference || []).find((p) => p.version === v && p.subject === 'suites') || {}).order;

  const banner = n.version ? h('div', { class: 'negotiated', role: 'group', 'aria-label': 'What a current client gets' },
    h('span', { class: 'negotiated-label' }, 'A current client gets'),
    h('code', { class: 'nchip' }, versionLabel(n.version)), h('span', { class: 'nplus', 'aria-hidden': 'true' }, '+'),
    h('code', { class: 'nchip' }, n.suite || ''), n.group ? [h('span', { class: 'nplus', 'aria-hidden': 'true' }, '+'),
      h('code', { class: `nchip${n.pq ? ' nchip-pq' : ''}` }, n.pq ? pqGlyph('quantum-safe') : null, n.group)] : null,
    n.alpn ? h('span', { class: 'negotiated-alpn' }, `ALPN ${n.alpn}`) : null) : null;

  const blocks = on.map((v) => {
    const suites = (rep.suites || []).filter((s) => s.version === v).slice().sort((a, b) => (a.rank || 99) - (b.rank || 99));
    const groups = (rep.groups || []).filter((g) => g.version === v || (v !== 'TLSv1.3' && g.version === 'TLSv1.2' && !(rep.groups || []).some((x) => x.version === v)))
      .slice().sort((a, b) => (a.rank || 99) - (b.rank || 99));
    const fs = suites.filter((s) => s.version === 'TLSv1.3' || s.ephemeral).length;
    const bad = legacyVersion(v);
    // The words of this version's suites, worst first, for its one-line verdict when folded.
    const words = suites.map((x) => (((ev.suiteStrength || []).find((r) => r.version === x.version && r.id === x.id)) || {}).word || '');
    const order = ['insecure', 'weak', 'acceptable', 'strong', ''];
    const tally = order.map((w) => [w, words.filter((x) => x === w).length]).filter(([, c]) => c);
    // Every version starts folded (owner request): its head already says whether it should be on
    // and how its suites rate, and a click opens its suites. The only version opens by itself.
    const needsLook = on.length === 1;
    const verdict = h('span', { class: 'ver-verdict' }, tally.length === 1 && tally[0][0] === 'strong' ? [strengthChip('strong'), ` all ${suites.length}`]
      : tally.map(([w, c]) => h('span', { class: 'ver-tally' }, strengthChip(w), ` ${c}`)));
    const head = h('summary', { class: `ver-head-row${bad ? ' is-bad' : ''}`, title: 'Show or hide this version’s suites' },
      h('span', { class: 'ver-chev', 'aria-hidden': 'true' }),
      h('span', { class: 'ver-title' }, h('span', { class: `vglyph ${bad ? 'vg-bad' : 'vg-good'}`, 'aria-hidden': 'true' }, bad ? '✕' : '✓'),
        h('b', { class: 'ver-name' }, versionLabel(v)), bad ? h('span', { class: 'ver-bad' }, 'On · should be off') : null),
      h('span', { class: 'ver-meta' }, [plural(suites.length, 'suite'), ORDER_WORD[pref(v)] || null,
        suites.length ? (fs === suites.length ? 'forward secrecy on all' : `forward secrecy on ${fs} of ${suites.length}`) : null].filter(Boolean).join(' · ')),
      groups.length ? h('span', { class: 'ver-groups' }, h('span', { class: 'muted' }, 'Groups'), groups.map((g) => groupChip(ev, g))) : null,
      suites.length ? verdict : null);
    const ranked = suites.some((s) => s.rank);
    const table = suites.length ? h('div', { class: 'tablewrap ver-body' }, h('table', { class: `suites${ranked ? '' : ' unranked'}` },
      h('thead', null, h('tr', null, h('th', { scope: 'col', class: 'num', title: 'The server\u2019s order' }, '#'), h('th', { scope: 'col' }, 'Cipher suite'),
        PART_COLUMNS.map(([, w]) => h('th', { scope: 'col', class: 'pcol' }, w)), h('th', { scope: 'col' }, 'Strength'))),
      h('tbody', null, suites.map((s) => suiteRow(ev, s, rep))))) : h('p', { class: 'muted' }, 'No cipher suites were recorded for this version.');
    return h('details', { class: `ver-block${bad ? ' is-bad' : ''}`, id: `ver-${v}`, open: needsLook }, head, table);
  });

  const offLine = (off.length || unknown.length) ? h('div', { class: 'ver-off' },
    off.length ? [h('span', { class: 'muted' }, modernOn ? 'Off, as they should be' : 'Off'),
      off.map((v) => h('span', { class: `vchip${v === 'TLSv1.3' || (v === 'TLSv1.2' && !modernOn) ? ' vchip-warn' : ''}` },
        h('span', { 'aria-hidden': 'true' }, v === 'TLSv1.3' || (v === 'TLSv1.2' && !modernOn) ? '!' : '✓'), versionLabel(v),
        v === 'TLSv1.3' || (v === 'TLSv1.2' && !modernOn) ? h('span', { class: 'vchip-why' }, 'should be on') : null))] : null,
    unknown.map((v) => h('span', { class: 'vchip vchip-warn' }, h('span', { 'aria-hidden': 'true' }, '?'), versionLabel(v), h('span', { class: 'vchip-why' }, 'not determined')))) : null;

  const toggle = blocks.length > 1 ? h('button', { type: 'button', class: 'btn btn-secondary btn-sm ver-toggle', onclick: (e) => {
    const all = [...e.currentTarget.closest('section').querySelectorAll('details.ver-block')];
    const open = !all.every((d) => d.open);
    for (const d of all) d.open = open;
  } }, blocks.length && blocks.every((b) => b.open) ? 'Hide every version' : 'Show every version') : null;
  // The button says what it will do, whichever way a version was last opened or closed.
  if (toggle) for (const b of blocks) b.addEventListener('toggle', () => { toggle.textContent = blocks.every((x) => x.open) ? 'Hide every version' : 'Show every version'; });
  return section('sec-protocols', 'Protocols and cipher suites', tone,
    h('span', { class: 'cfg-aside' }, 'Suites in the server’s order. A suite is as strong as its weakest part, ringed. ', h('a', { href: '#/help?topic=strength' }, 'How strength is worked out'), toggle ? ' ' : null, toggle),
    h('span', { id: 'sec-suites' }), banner, blocks, offLine);
}

// ---- 2. the certificate chain ----------------------------------------------------------------

function chainCard(ev, c, i, chainLen, scanId, issues) {
  const key = keyStrengthOf(ev, c.sha256);
  const role = i === 0 ? 'Leaf' : c.selfSigned ? 'Root, sent by the server' : 'Intermediate';
  const linkable = /^[0-9a-f]{64}$/.test(c.sha256 || '');
  const name = linkable ? h('a', { href: certHref(c.sha256, scanId), class: 'servedcn-link', title: 'Open the whole certificate' }, cn(c.subject)) : cn(c.subject);
  return h('li', { class: `servednode chaincard${i === 0 ? ' is-leaf' : ''}${issues.length ? ' hasissue' : ''}` },
    h('span', { class: 'cc-role' }, role),
    h('span', { class: 'servedcn' }, name),
    h('span', { class: 'cc-chips' },
      h('span', { class: `cchip cchip-${bandOf(key)}`, title: key ? key.basis : '' }, `${keyLabel(c.publicKey)} · ${strengthWords(key)}`),
      h('span', { class: 'cchip', title: 'The signature on this certificate' }, (c.signatureAlgorithm || {}).name || 'unknown signature'),
      c.selfSigned ? h('span', { class: 'cchip cchip-weak' }, 'self-signed') : null),
    lifetimeBar(c.notBefore, c.notAfter),
    h('span', { class: 'cc-foot' }, (() => {
      const d = Math.ceil((Date.parse(c.notAfter) - Date.now()) / 86400000);
      return Number.isFinite(d) ? (d < 0 ? `expired ${fmtDay(c.notAfter)}` : `${d} days left · until ${fmtDay(c.notAfter)}`) : '';
    })()),
    i === 0 && (c.dnsNames || c.ipAddresses) ? h('span', { class: 'cc-names', title: 'Names it is valid for' }, [...(c.dnsNames || []), ...(c.ipAddresses || [])].join(', ')) : null,
    issues.map((is) => h('span', { class: 'cc-issue' }, `${is.kind}: ${is.detail}`)));
}

function certificateSection(ctx, tone) {
  const { rep, ev, scanId } = ctx;
  const certs = rep.certificates || [];
  if (!certs.length) return section('sec-certificates', 'Certificate chain', tone, null, h('p', { class: 'muted' }, 'No certificate was received.'));
  const views = (ev.pki || []).length ? ev.pki : certs.map((c) => ({ leaf: c.chain[0] && c.chain[0].sha256, noSni: c.noSni, source: c.source, served: { issues: [] }, trust: [], names: {} }));
  let selected = Math.max(0, views.findIndex((v) => !v.noSni));
  const panel = h('div');
  const tabs = h('div', { class: 'chaintabs', role: 'tablist', 'aria-label': 'Certificate chains' });
  const label = (v) => (v.noSni ? 'Without SNI' : /ecdsa/i.test(v.source || '') ? 'ECDSA' : /rsa/i.test(v.source || '') ? 'RSA' : 'Default');
  const draw = () => {
    tabs.replaceChildren(...views.map((v, i) => h('button', { type: 'button', role: 'tab', class: 'chaintab', 'aria-selected': String(i === selected), onclick: () => { selected = i; draw(); } }, label(v))));
    const v = views[selected];
    const cr = certs.find((c) => c.chain[0] && c.chain[0].sha256 === v.leaf && !!c.noSni === !!v.noSni) || certs.find((c) => c.chain[0] && c.chain[0].sha256 === v.leaf) || certs[0];
    const issuesAt = {};
    for (const is of (v.served && v.served.issues) || []) (issuesAt[is.index] = issuesAt[is.index] || []).push(is);
    const cards = cr.chain.map((c, i) => chainCard(ev, c, i, cr.chain.length, scanId, issuesAt[i] || []));
    const m = v.served && v.served.missing;
    if (m) {
      const root = m.likely === 'root';
      cards.push(h('li', { class: `servednode chaincard is-missing${root ? ' unknownroot' : ''}` },
        h('span', { class: 'cc-role cc-role-bad' }, root ? 'No trusted root' : 'Missing intermediate'),
        h('span', { class: 'servedcn' }, cn(m.issuer)),
        h('span', { class: 'cc-foot' }, root ? 'Not in any trusted store. If it is your private CA, add it to this system’s CA bundle.'
          : (m.aia || []).length ? 'Not sent. Serve it with the leaf; the certificate names where it is.' : 'Not sent and not in any trusted store. Serve it with the leaf.')));
    }
    const stores = [...(v.trust || []), v.private, v.os].filter(Boolean);
    const trust = h('span', { class: 'trust-chips' },
      stores.map((t) => h('span', { class: `tchip ${t.trusted ? 'tchip-good' : t.expiredOnly ? 'tchip-warn' : 'tchip-bad'}`, title: t.trusted ? `path of ${(t.path || []).length}` : (t.distrust || t.error || 'no path to a root in this store') },
        `${t.store} ${t.trusted ? '✓' : '✕'}`)),
      v.names && v.names.host ? h('span', { class: `tchip ${v.names.matchedBy ? 'tchip-good' : 'tchip-bad'}`, title: v.names.matchedBy ? `matched by ${v.names.matchedBy}` : `checked: ${(v.names.checked || []).join(', ')}` },
        v.names.matchedBy ? 'Name matches ✓' : 'Name does not match ✕') : null);
    panel.replaceChildren(...[
      v.noSni ? h('div', { class: 'callout info', role: 'note' }, h('b', null, 'Only clients that send no server name see this chain. '), 'It is shown for information and is not scored.') : null,
      trust,
      h('ol', { class: 'served chainribbon', 'aria-label': 'Chain as served, leaf first' }, cards),
      v.served && v.served.sizeBytes ? h('p', { class: 'hint' }, `${plural(cr.chain.length, 'certificate')}, ${v.served.sizeBytes.toLocaleString()} bytes`,
        v.served.sizeBytes > 4096 ? ': more than fits a typical first round trip.' : '.') : null].filter(Boolean));
  };
  draw();
  return section('sec-certificates', 'Certificate chain', tone, views.length > 1 ? tabs : null, panel);
}

// ---- 3. key exchange and signatures ---------------------------------------------------------

function chipRow(label, chips, note) {
  return h('div', { class: 'chiprow' }, h('span', { class: 'chiprow-label' }, label), h('span', { class: 'chiprow-chips' }, chips), note ? h('span', { class: 'chiprow-note' }, note) : null);
}

function keyExchangeSection(ctx, tone) {
  const { rep, ev } = ctx;
  const r = ev.readiness || {};
  const groups = rep.groups || [];
  const gv = VERSION_ORDER.filter((v) => groups.some((g) => g.version === v));
  const sig = rep.signatures;
  const acc = sig && sig.control === 'refused' ? (sig.schemes || []).filter((s) => s.result === 'accepted') : [];
  const keys = [...new Map((rep.certificates || []).filter((c) => !c.noSni && c.chain[0]).map((c) => [keyLabel(c.chain[0].publicKey), c.chain[0]])).values()];
  const dh = rep.dh;
  const rows = [
    ...gv.map((v) => chipRow(`Groups, ${versionLabel(v)}`, groups.filter((g) => g.version === v).slice().sort((a, b) => (a.rank || 99) - (b.rank || 99)).map((g) => groupChip(ev, g)))),
    chipRow('Finite-field DH', dh ? h('span', { class: `gchip${dh.primeBits < 2048 ? ' gchip-bad' : ''}`, title: ev.dhGroup ? `${ev.dhGroup.name} (${ev.dhGroup.source})` : 'a prime that is not a published group' },
      `${dh.primeBits}-bit prime`, ev.dhGroup ? ` · ${ev.dhGroup.name}` : ' · custom')
      // A DHE or anonymous DH suite was accepted but no prime was recorded: say that, never "not offered".
      : (rep.suites || []).some((x) => /^(DHE|DH)/.test(x.kx || '') || /_DHE?_|_DH_anon_/.test(x.name || '')) ? h('span', { class: 'gchip', title: 'A finite-field DH suite was accepted, but the prime was not recorded by this scan' }, 'offered · prime not recorded')
        : h('span', { class: 'gchip' }, 'not offered')),
    sig ? chipRow('Signature schemes, TLS 1.3', sig.control !== 'refused'
      ? h('span', { class: 'gchip', title: sig.control === 'accepted' ? 'The server answers whatever is offered, so its keys cannot be told' : (sig.controlWhy || 'no clear answer') }, 'could not be told')
      : [acc.map((s) => h('span', { class: `gchip${s.pq ? ' gchip-pq' : ''}`, title: `${s.algorithm}${s.detail ? ` (${s.detail})` : ''}` }, s.pq ? pqGlyph('quantum-safe') : null, s.name,
        s.pq && s.algorithm && s.algorithm !== s.name ? h('span', { class: 'gchip-alg' }, s.algorithm) : null)),
        acc.some((s) => s.pq) ? null : h('span', { class: 'gchip gchip-warn', title: 'No post-quantum signature scheme is accepted: readiness stays below L4' }, 'no ML-DSA')]) : null,
    keys.length ? chipRow('Certificate keys', keys.map((k) => h('span', { class: 'gchip', title: strengthWords(keyStrengthOf(ev, k.sha256)) }, keyLabel(k.publicKey)))) : null,
  ].filter(Boolean);
  const readiness = h('div', { class: 'readyrow' },
    h('span', { class: 'readyrow-level' }, h('b', null, r.level < 0 ? '?' : `L${r.level}`), h('span', null, r.label || '')),
    levelStepper(r.level),
    h('span', { class: 'readyrow-dims' }, [['Key establishment', r.keyEstablishment], ['Authentication', r.authentication], ['Symmetric', r.symmetric]].filter(([, d]) => d).map(([t, d]) =>
      h('span', { class: 'dimchip', title: d.detail || '' }, h('span', { class: 'muted' }, `${t} `), d.status))));
  const next = (r.nextSteps || []).length ? h('ol', { class: 'next compact' }, r.nextSteps.map((s) => h('li', null, s))) : null;
  return section('sec-key-exchange', 'Key exchange and signatures', tone, null, readiness, rows, next);
}

// ---- 4. revocation, 5. features -------------------------------------------------------------

function revocationSection(ctx, tone) {
  const { ev, rep } = ctx;
  const v = (ev.pki || []).find((x) => !x.noSni) || (ev.pki || [])[0];
  if (!v) {
    return section('sec-revocation', 'Revocation and transparency', tone, null, h('p', { class: 'muted' }, (rep.certificates || []).length
      ? 'Not analysed by the version that ran this scan. Re-evaluate it (About this report).' : 'No certificate was received, so there is nothing to revoke or log.'));
  }
  const cr = (rep.certificates || []).find((c) => c.chain[0] && c.chain[0].sha256 === v.leaf);
  const leaf = cr ? cr.chain[0] : {};
  const o = v.ocsp;
  const urls = [...(v.ocspUrls || []), ...(v.crlUrls || [])];
  const scts = v.scts || [];
  const tiles = [
    !o ? statusTile('OCSP stapling', leaf.ocspMustStaple ? 'No response stapled, though the certificate requires one' : 'No response stapled', leaf.ocspMustStaple ? 'problem' : 'na')
      : o.error || !o.forThisCert ? statusTile('OCSP stapling', o.error ? `Stapled but unusable: ${o.error}` : 'Stapled, for another certificate', 'problem')
        : statusTile('OCSP stapling', `Stapled: ${o.status}${o.nextUpdate ? `, until ${fmtDay(o.nextUpdate)}` : ''}`, o.status === 'good' && o.signature === 'valid' ? 'good' : 'problem'),
    statusTile('Must-staple', leaf.ocspMustStaple ? 'Required by the certificate' : 'Not set', 'na'),
    statusTile('OCSP and CRL', urls.length ? 'Named by the certificate, not contacted: revocation status unknown' : 'The certificate names none', urls.length ? 'na' : (v.public ? 'attention' : 'na'), null, null, urls.length ? urls.join('\n') : null),
    statusTile('Certificate Transparency', scts.length ? `${plural(scts.length, 'SCT')}: ${scts.map((s) => s.logName || 'unknown log').join(', ')}`
      : v.public ? 'No SCT in any of the three places' : 'No SCT: not needed for a private certificate', scts.length ? 'good' : v.public ? 'problem' : 'na'),
  ];
  return section('sec-revocation', 'Revocation and transparency', tone, h('span', { class: 'cfg-aside' }, 'The CA’s responder and CRL are not contacted.'), h('div', { class: 'stiles' }, tiles));
}

function featuresSection(ctx, tone) {
  const { rep } = ctx;
  const f = rep.features || {};
  const cbc = (rep.suites || []).some((s) => s.mode === 'CBC' && s.version !== 'TLSv1.3');
  const known = (v) => v !== null && v !== undefined;
  const t = (name, v, yes, no, tyes, tno) => (known(v) ? statusTile(name, v ? yes : no, v ? tyes : tno) : statusTile(name, 'Not determined', 'na'));
  const hd = rep.hstsHeader;
  const raw = hd && (hd.values || []).length ? hd.values.join('\n') : null;
  const hsts = hd ? (!raw ? statusTile('HSTS', 'No Strict-Transport-Security header', 'attention')
    : (hd.problems || []).length ? statusTile('HSTS', `Invalid, so browsers ignore it: ${hd.problems.join('; ')}`, 'problem', null, null, raw)
      : hd.maxAge ? statusTile('HSTS', `max-age ${hd.maxAge.toLocaleString()} s${hd.includeSubDomains ? ' · subdomains' : ''}${hd.preload ? ' · preload' : ''}`, hd.maxAge >= 15552000 ? 'good' : 'attention', null, null, raw)
        : statusTile('HSTS', 'max-age 0: switched off', 'attention', null, null, raw))
    : statusTile('HSTS', rep.hsts === undefined ? 'No HTTP response to read' : rep.hsts ? 'Sent' : 'Not sent', rep.hsts ? 'good' : 'na');
  const tiles = [
    t('Secure renegotiation', f.secureRenegotiation, 'Supported (RFC 5746)', 'Not advertised', 'good', 'problem'),
    t('Extended master secret', f.extendedMasterSecret, 'Supported (RFC 7627)', 'Not offered', 'good', 'attention'),
    t('Downgrade protection', f.fallbackScsv, 'TLS_FALLBACK_SCSV honoured', 'TLS_FALLBACK_SCSV not enforced', 'good', 'attention'),
    t('Compression', f.compression, 'Accepted: exposed to CRIME', 'Refused', 'problem', 'good'),
    known(f.encryptThenMac) ? statusTile('Encrypt-then-MAC', f.encryptThenMac ? 'Supported (RFC 7366)' : cbc ? 'Not offered: the CBC suites stay MAC-then-encrypt' : 'Not offered; no CBC suite needs it', f.encryptThenMac ? 'good' : cbc ? 'attention' : 'na')
      : statusTile('Encrypt-then-MAC', 'Not determined', 'na'),
    t('Session tickets', f.sessionTickets, 'Issued', 'Not issued', 'na', 'na'),
    statusTile('ALPN', rep.negotiated && rep.negotiated.alpn ? `Negotiated ${rep.negotiated.alpn}` : 'None negotiated', 'na'),
    t('Client certificates', f.clientCertRequested, 'Requested (mutual TLS)', 'Not requested', 'na', 'na'),
    known(f.heartbeat) ? statusTile('Heartbeat', f.heartbeat ? 'Negotiated: nothing needs it (where Heartbleed lived)' : 'Not negotiated', f.heartbeat ? 'attention' : 'good')
      : statusTile('Heartbeat', 'Not probed: no TLS 1.2 handshake answered', 'na'),
    statusTile('0-RTT early data', 'Not probed yet', 'na'),
    hsts,
  ];
  return section('sec-features', 'Protocol features', tone, h('span', { class: 'cfg-aside' }, 'Each says what was found and whether that is right.'),
    h('span', { id: 'sec-http' }), h('div', { class: 'stiles' }, tiles));
}

// ---- 6. every algorithm, by class -----------------------------------------------------------

const CLASSES = [['asymmetric', 'Asymmetric', 'agree keys, sign'], ['symmetric', 'Symmetric', 'encrypt, authenticate'], ['hash', 'Hash', 'derive keys, sign']];
const ROLE_WORD = { 'key exchange': 'key exchange', signature: 'signature', cipher: 'cipher', MAC: 'MAC', 'hash (HKDF)': 'key derivation (HKDF)', 'hash (PRF)': 'key derivation (PRF)', 'hash (signature)': 'in a signature' };

function usesOf(a) {
  const suites = (a.usedBy || []).filter((x) => /^(TLS|SSL)_/.test(x));
  const other = (a.usedBy || []).filter((x) => !suites.includes(x));
  return [suites.length ? `${plural(suites.length, 'suite')}${(a.versions || []).length ? ` · ${a.versions.map(versionLabel).join(', ')}` : ''}` : null,
    ...other.map((x) => (x === 'key exchange group' ? `group${(a.versions || []).length ? ` · ${a.versions.map(versionLabel).join(', ')}` : ''}` : x))].filter(Boolean).join('; ');
}

function classSection(ctx, tone) {
  const list = ctx.ev.algorithms || [];
  if (!list.length) {
    return section('sec-algorithms', 'Every algorithm, by class', tone, null,
      h('p', { class: 'muted' }, 'Evaluated by an earlier version. Re-evaluate it (About this report) to see every algorithm by class.'));
  }
  const lanes = CLASSES.map(([cls, name, what]) => {
    const rows = list.filter((a) => a.class === cls);
    if (!rows.length) return null;
    return h('div', { class: 'lane', role: 'group', 'aria-label': name },
      h('div', { class: 'lane-name' }, h('b', null, name), h('span', null, what)),
      h('div', { class: 'lane-rows' }, rows.map((a) => h('div', { class: `lane-row${a.weakest ? ' weakest' : ''}` },
        h('span', { class: 'lane-alg' }, h('code', null, a.name), h('span', null, ROLE_WORD[a.role] || a.role)),
        bitsBar(a.strength, { weakest: a.weakest, name: a.name }),
        h('span', { class: 'lane-pq' }, pqGlyph(a.pqc)),
        h('span', { class: 'lane-uses', title: (a.usedBy || []).join('\n') }, usesOf(a))))));
  });
  return section('sec-algorithms', 'Every algorithm, by class', tone, h('span', { class: 'cfg-aside' }, 'Bits as NIST estimates them. Hover a bar for its source. ', h('a', { href: '#/help?topic=strength' }, 'How strength is worked out')),
    h('div', { class: 'lane-axis' }, h('span'), bitsAxis(), h('span'), h('span', { class: 'muted' }, 'Used by')), lanes);
}

/** The whole Configuration tab for a TLS endpoint, and the jump row that leads through it. */
export function tlsConfiguration(ctx, about) {
  const sec = Object.fromEntries((ctx.ev.sections || []).map((x) => [x.id, x.status]));
  // Each finding once, under the section it belongs to (info-level notes included: they are facts to check).
  ISSUES = {};
  const seen = new Set();
  for (const f of ctx.ev.findings || []) {
    if (seen.has(f.id) || f.section === 'vulnerabilities') continue;
    seen.add(f.id);
    (ISSUES[f.section] = ISSUES[f.section] || []).push(f);
  }
  OPEN_ISSUE = ctx.goIssue || null;
  const tones = {
    protocols: worstTone(toneOfSection(sec.protocols), toneOfSection(sec.suites)),
    certificates: toneOfSection(sec.certificates),
    'key-exchange': toneOfSection(sec['key-exchange']),
    revocation: toneOfSection(sec.revocation),
    features: worstTone(toneOfSection(sec.features), toneOfSection(sec.http)),
  };
  const weak = (ctx.ev.algorithms || []).map((a) => bandOf(a.strength));
  tones.algorithms = weak.includes('broken') ? 'problem' : weak.includes('weak') ? 'attention' : weak.length ? 'good' : 'na';
  const goTo = (id) => document.getElementById(id)?.scrollIntoView({ block: 'start' });
  return h('div', { class: 'report configuration tls-config' },
    jumpNav([
      { id: 'sec-protocols', label: 'Protocols & suites', tone: tones.protocols },
      { id: 'sec-certificates', label: 'Certificate chain', tone: tones.certificates },
      { id: 'sec-key-exchange', label: 'Key exchange & signatures', tone: tones['key-exchange'] },
      { id: 'sec-revocation', label: 'Revocation', tone: tones.revocation },
      { id: 'sec-features', label: 'Features', tone: tones.features },
      { id: 'sec-algorithms', label: 'Every algorithm', tone: tones.algorithms },
    ], goTo),
    protocolsSection(ctx, tones.protocols),
    certificateSection(ctx, tones.certificates),
    keyExchangeSection(ctx, tones['key-exchange']),
    revocationSection(ctx, tones.revocation),
    featuresSection(ctx, tones.features),
    classSection(ctx, tones.algorithms),
    about);
}

/** For the Summary: the weakest classical strength on the endpoint, and which algorithm sets it. */
export function weakestAlgorithm(ev) {
  const rank = { broken: 0, weak: 1, acceptable: 2, strong: 3 };
  const list = (ev.algorithms || []).filter((a) => bandOf(a.strength) !== 'na');
  // At equal bits, one NIST no longer allows (3DES at 112) is weaker than one it does (RSA-2048).
  const allowed = (a) => (a.strength.status === 'disallowed' ? 0 : 1);
  return list.slice().sort((a, b) => (rank[bandOf(a.strength)] - rank[bandOf(b.strength)]) || ((a.strength.bits || 0) - (b.strength.bits || 0))
    || (allowed(a) - allowed(b)))[0] || null;
}

