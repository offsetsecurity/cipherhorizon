// The SSH endpoint report (PRD-008 WP-F; UX-DESIGN-006 §2.4). The tabs, verdict, action items,
// every-check list and CBOM are report.js's; this module gives them SSH's own areas, facts, tiles
// and words. Everything the server sent reaches the page through the textContent-only DOM builder.
import { h } from '../dom.js';
import { levelClass, levelName } from '../charts.js';
import { badge, bandTone, citations } from '../ui.js';
import { registerProfile, versionState, plural } from './report.js';

export const SSH_SECTIONS = [
  ['ssh-version', 'SSH version & software', 'Which protocol version the server speaks and what it says it runs.'],
  ['key-exchange', 'Key exchange & post-quantum', 'How session keys are agreed, including post-quantum hybrids.'],
  ['host-keys', 'Host keys', 'The keys the server proves its identity with.'],
  ['encryption', 'Encryption ciphers', 'The ciphers the server offers for the session.'],
  ['integrity', 'Integrity (MACs) & compression', 'How each packet is protected against tampering, and compression.'],
  ['vulnerabilities', 'Vulnerabilities', 'Published attacks the configuration makes possible, inferred, never attempted.'],
];

// Plain words on why a kind of finding matters, for a reader who is not an SSH specialist.
const WHY = {
  protocol: 'SSH-1 has been broken for two decades; only SSH-2 should answer.',
  'key-exchange': 'The key exchange protects every session’s keys; a weak one exposes the whole session.',
  pqc: 'Sessions recorded today could be decrypted once large quantum computers exist (harvest now, decrypt later).',
  'host-key': 'Clients recognise the server by its host key: a weak key or signature lets someone impersonate it.',
  cipher: 'A weak cipher can let an attacker read or change the session.',
  mac: 'The MAC stops anyone tampering with the session in transit.',
  feature: 'Compression before login exposes more code to anyone who can connect.',
  vulnerability: 'This configuration makes a published attack possible.',
};
const GROUP_WORD = { protocol: 'SSH version', 'key-exchange': 'Key exchange', pqc: 'Post-quantum', 'host-key': 'Host keys', cipher: 'Ciphers',
  mac: 'Integrity (MACs)', feature: 'Compression', vulnerability: 'Published attacks' };

const VERDICT = {
  'post-quantum': ['good', '✔', 'Offered', 'post-quantum'],
  fine: ['good', '✔', 'Offered', 'fine'],
  'should-be-off': ['bad', '✖', 'Offered', 'should be off'],
  unknown: ['neutral', '·', 'Offered', 'not in this program’s registry'],
};

/** One kind of algorithm as a table: name, what it is, its verdict, and the one a current client uses. */
function algoTable(ev, kind, caption) {
  const rows = (ev.sshAlgorithms || []).filter((a) => a.kind === kind);
  if (!rows.length) return null;
  return h('div', null, caption ? h('h3', null, caption) : null,
    h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
      h('thead', null, h('tr', null, ['Name', 'What it is', 'Status', ''].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, rows.map((a) => h('tr', null,
        h('td', null, h('code', null, a.name)),
        h('td', { class: 'muted' }, a.display || ''),
        h('td', null, versionState(VERDICT[a.verdict] || VERDICT.unknown)),
        h('td', null, a.used ? badge('used by OpenSSH 10.6', 'info', 'What a current client negotiates') : null)))))));
}

const keyLabel = (k) => (k.algorithm === 'RSA' && k.bits ? `RSA ${k.bits}` : k.curve ? `${k.algorithm} ${k.curve}` : k.algorithm);

function versionBody(ctx) {
  const id = ctx.rep.identification;
  if (!id) return { facts: ['No identification was read.'] };
  const facts = [`The server identifies as ${id.raw}.`, id.ssh1 ? (id.ssh1Only ? 'It speaks only SSH-1.' : 'It accepts SSH-1 as well as SSH-2.') : 'SSH-1 is not offered.'];
  if ((id.preamble || []).length) facts.push(`It sent ${plural(id.preamble.length, 'line')} before its identification.`);
  return { verdict: `SSH-${id.protoVersion}, ${id.software || 'software not named'}. ${id.ssh1 ? 'SSH-1 is accepted.' : 'SSH-1 is not offered.'}`, facts };
}

function kexBody(ctx) {
  if (!ctx.rep.algorithms) return { facts: [] };
  const { ev, rep } = ctx;
  const r = ev.readiness;
  const pq = (ev.sshAlgorithms || []).filter((a) => a.kind === 'kex' && a.verdict === 'post-quantum').map((a) => a.name);
  const facts = [
    pq.length ? `Post-quantum hybrid key exchanges offered: ${pq.join(', ')}.` : 'No post-quantum key exchange is offered.',
    // What a current client uses is said once, in the Key establishment dimension below.
    r.hndlExposed ? 'Sessions recorded today could be decrypted by a future quantum computer (harvest now, decrypt later).' : null,
    rep.algorithms && rep.algorithms.strictKex ? 'Strict key exchange is on (the countermeasure to Terrapin).' : 'Strict key exchange is not offered.',
  ].filter(Boolean);
  const dim = (title, d) => h('div', { class: 'dim' }, h('h4', null, title, badge(d.status, 'neutral')), h('div', null, d.detail), citations(d.citations));
  const lead = h('div', { class: 'pqpanel' },
    h('div', { class: 'readiness' }, h('div', { class: `bigLevel ${levelClass(r.level)}` }, r.level < 0 ? '?' : `L${r.level}`, h('small', null, r.label)),
      h('div', null, h('p', null, r.summary))),
    dim('Key establishment', r.keyEstablishment), dim('Authentication', r.authentication), dim('Symmetric strength', r.symmetric),
    h('h3', null, 'What to do next'), h('ol', { class: 'next' }, r.nextSteps.map((s) => h('li', null, s))),
    h('p', { class: 'hint' }, 'The level scale is this product’s own; each fact above cites its standard.'));
  return { facts, all: h('div', null, lead, algoTable(ev, 'kex', 'Key exchange methods')) };
}

function hostKeysBody(ctx) {
  const keys = ctx.rep.hostKeys || [];
  const attempts = ctx.rep.hostKeyAttempts || [];
  const facts = keys.length ? [`${plural(keys.length, 'host key')}: ${keys.map(keyLabel).join(', ')}.`,
    keys.every((k) => k.verified) ? 'Every key’s signature over the key exchange verified.' : 'Some signatures could not be verified (see each key).']
    : [];
  const table = keys.length ? h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
    h('thead', null, h('tr', null, ['Key', 'Fingerprint', 'Answers', 'Signature'].map((c) => h('th', { scope: 'col' }, c)))),
    h('tbody', null, keys.map((k) => h('tr', null,
      h('td', null, h('b', null, keyLabel(k)), k.pq ? [' ', badge('post-quantum', 'good')] : null,
        k.certificate ? h('div', { class: 'hint' }, `OpenSSH certificate from CA ${k.certificate.caFingerprint}`,
          (k.certificate.principals || []).length ? `, for ${k.certificate.principals.join(', ')}` : '') : null),
      h('td', null, h('code', { class: 'fp' }, k.fingerprint)),
      h('td', { class: 'muted' }, (k.servedBy || []).join(', ')),
      h('td', null, k.verified ? versionState(['good', '✔', 'Verified', 'the key signed the exchange'])
        : versionState(['warn', '?', 'Not verified', k.verifyNote || 'no reason given']))))))) : null;
  const failed = attempts.filter((a) => a.outcome !== 'key');
  return { facts, all: h('div', null, table, algoTable(ctx.ev, 'host-key', 'Host key algorithms offered'),
    failed.length ? h('p', { class: 'hint' }, `Not fetched: ${failed.map((a) => `${a.algorithm} (${a.detail || a.outcome})`).join('; ')}.`) : null) };
}

function encryptionBody(ctx) {
  if (!ctx.rep.algorithms) return { facts: [] };
  const all = (ctx.ev.sshAlgorithms || []).filter((a) => a.kind === 'cipher');
  const bad = all.filter((a) => a.verdict === 'should-be-off');
  const n = ctx.rep.negotiated || {};
  return { facts: [`${plural(all.length, 'cipher')} offered${bad.length ? `, ${bad.length} that should be off` : ', none that should be off'}.`,
    n.cipher ? `A current client uses ${n.cipher}.` : null].filter(Boolean),
  all: algoTable(ctx.ev, 'cipher') };
}

function integrityBody(ctx) {
  if (!ctx.rep.algorithms) return { facts: [] };
  const all = (ctx.ev.sshAlgorithms || []).filter((a) => a.kind === 'mac');
  const bad = all.filter((a) => a.verdict === 'should-be-off');
  const n = ctx.rep.negotiated || {};
  const comp = (ctx.ev.sshAlgorithms || []).filter((a) => a.kind === 'compression').map((a) => a.name);
  return { facts: [`${plural(all.length, 'MAC')} offered${bad.length ? `, ${bad.length} that should be off` : ', none that should be off'}.`,
    n.cipher && !n.mac ? 'The cipher a current client uses carries its own integrity, so no MAC is used.' : n.mac ? `A current client uses ${n.mac}.` : null,
    comp.length ? `Compression: ${comp.join(', ')}.` : null].filter(Boolean),
  all: h('div', null, algoTable(ctx.ev, 'mac'), algoTable(ctx.ev, 'compression', 'Compression')) };
}

function vulnerabilitiesBody(ctx) {
  if (!ctx.rep.algorithms) return { facts: [] };
  const list = ctx.ev.vulnerabilities || [];
  if (!list.length) return { facts: [] };
  const exposed = list.filter((a) => a.status === 'exposed');
  const order = { exposed: 0, 'not-exposed': 1, 'not-tested': 2 };
  const word = { exposed: ['Possible', 'bad'], 'not-exposed': ['Not possible', 'good'], 'not-tested': ['Not tested', 'neutral'] };
  return {
    facts: [exposed.length ? `Exposed to ${exposed.map((a) => a.name).join(', ')}.` : 'Not exposed to any attack this scan can infer.'],
    detail: h('div', { class: 'tablewrap' }, h('table', { class: 'compact attacktable' },
      h('thead', null, h('tr', null, ['Attack', 'Here', 'Why'].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, list.slice().sort((x, y) => order[x.status] - order[y.status]).map((x) => h('tr', null,
        h('td', null, h('b', null, x.name)), h('td', null, badge(word[x.status][0], word[x.status][1])), h('td', { class: 'muted' }, x.why)))))),
  };
}

/** The summary tiles: readiness on its scale, SSH hygiene, the host key. */
function sshStrip(ctx) {
  const { ev, rep } = ctx;
  const r = ev.readiness, g = ev.hygiene;
  const tile = (sec, cls, big, label, sub) => h('a', { class: `sumtile ${cls}`, href: `#sec-${sec}`, onclick: (e) => { e.preventDefault(); ctx.goDetails(sec); } },
    h('div', { class: 'sumtile-big' }, big), h('div', { class: 'sumtile-label' }, label), h('div', { class: 'sumtile-sub' }, sub));
  const ready = tile('key-exchange', `bigLevel sumtile-lead ${levelClass(r.level)}`, r.level < 0 ? '?' : `L${r.level}`, 'Post-quantum readiness', r.label || levelName(r.level));
  ready.appendChild(h('div', { class: 'lvscale', 'aria-hidden': 'true' }, [0, 1, 2, 3, 4].map((l) => h('span', { class: l <= r.level ? 'on' : '' }))));
  const tone = { good: 'lv3', ok: 'lv2', warn: 'lv1', bad: 'lv0', neutral: 'lvu' }[bandTone(g ? g.band : '')];
  const keys = rep.hostKeys || [];
  const k = keys.find((x) => (x.servedBy || []).includes((rep.negotiated || {}).hostKey)) || keys[0];
  const keySub = k ? `${k.pq ? 'post-quantum' : 'classical'} · ${k.fingerprint.slice(0, 19)}…` : 'no host key fetched';
  return h('div', { class: 'sumstrip', role: 'group', 'aria-label': 'Summary' },
    ready,
    tile('ssh-version', `bigLevel ${tone}`, g && g.score >= 0 ? String(g.score) : '·', 'SSH hygiene', g ? g.band : 'Not rated'),
    tile('host-keys', `bigLevel ${k ? (k.pq ? 'lv4' : 'lv3') : 'lvu'}`, k ? keyLabel(k) : 'None', 'Host key', keySub));
}

registerProfile('ssh', {
  sections: SSH_SECTIONS,
  builders: () => ({ 'ssh-version': versionBody, 'key-exchange': kexBody, 'host-keys': hostKeysBody, encryption: encryptionBody,
    integrity: integrityBody, vulnerabilities: vulnerabilitiesBody }),
  strip: sshStrip, why: WHY, groupWord: GROUP_WORD, hygiene: 'SSH hygiene', matrix: null, skipCards: ['vulnerabilities'],
  stageTitles: { identification: 'Identification', algorithms: 'Algorithm lists', negotiation: 'Negotiation', 'host-keys': 'Host keys' },
  schema: 'ssh-report/1',
});
