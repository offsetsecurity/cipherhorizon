// The SSH server report (PRD-008 WP-D, WP-G; UX-DESIGN-007 §4). The tabs, verdict, action items,
// every-check list and CBOM are report.js's; this module gives them SSH's own areas, facts, tiles
// and words. Everything the server sent reaches the page through the textContent-only DOM builder.
import { h } from '../dom.js';
import { levelClass, levelName } from '../charts.js';
import { badge, button, citations, toast } from '../ui.js';
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

// Each algorithm's status against the baseline (allowed or should be off), marked post-quantum
// where it is; a name this program does not know is not on the baseline either.
const statusOf = (a) => {
  if (a.baseline === 'off') return ['bad', '✖', 'Should be off', a.verdict === 'unknown' ? 'not on the baseline; not in this program’s registry' : 'not on the baseline'];
  if (a.verdict === 'post-quantum') return ['good', '✔', 'Allowed', 'post-quantum'];
  return ['good', '✔', 'Allowed', 'on the baseline'];
};
const offCount = (all) => all.filter((a) => a.baseline === 'off').length;

// An algorithm's classical strength (PRD-010): bits from NIST's methods, broken with its reason, or
// why it is not rated; the source is in the tooltip.
function strengthWords(st) {
  if (!st) return h('span', { class: 'muted' }, '·');
  if (st.status === 'broken') return badge('✖ broken', 'bad', st.basis);
  if (st.status === 'disallowed') return h('span', { title: st.basis }, `${st.bits} bits `, badge('disallowed', 'warn', st.basis));
  if (st.status === 'rated') return h('span', { class: st.bits < 112 ? 'text-bad' : '', title: st.basis }, `${st.bits} bits`);
  return h('span', { class: 'muted', title: st.basis }, 'not rated');
}

/** One kind of algorithm as a table: name, what it is, its strength, its verdict, and the one a current client uses. */
function algoTable(ev, kind, caption) {
  const rows = (ev.sshAlgorithms || []).filter((a) => a.kind === kind);
  if (!rows.length) return null;
  return h('div', null, caption ? h('h3', null, caption) : null,
    h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
      h('thead', null, h('tr', null, ['Name', 'What it is', 'Classical strength', 'Baseline', ''].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, rows.map((a) => h('tr', null,
        h('td', null, h('code', null, a.name)),
        h('td', { class: 'muted' }, a.display || ''),
        h('td', { class: 'nowrap' }, kind === 'compression' ? '' : strengthWords(a.strength)),
        h('td', null, versionState(statusOf(a))),
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
  const bad = offCount(all);
  const n = ctx.rep.negotiated || {};
  return { facts: [`${plural(all.length, 'cipher')} offered${bad ? `, ${bad} that should be off` : ', none that should be off'}.`,
    n.cipher ? `A current client uses ${n.cipher}.` : null].filter(Boolean),
  all: algoTable(ctx.ev, 'cipher') };
}

function integrityBody(ctx) {
  if (!ctx.rep.algorithms) return { facts: [] };
  const all = (ctx.ev.sshAlgorithms || []).filter((a) => a.kind === 'mac');
  const bad = offCount(all);
  const n = ctx.rep.negotiated || {};
  const comp = (ctx.ev.sshAlgorithms || []).filter((a) => a.kind === 'compression').map((a) => a.name);
  return { facts: [`${plural(all.length, 'MAC')} offered${bad ? `, ${bad} that should be off` : ', none that should be off'}.`,
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

/** The summary tiles: readiness on its scale, the baseline verdict, the host key. An SSH server has no score. */
function sshStrip(ctx) {
  const { ev, rep } = ctx;
  const r = ev.readiness, b = ev.baseline;
  const tile = (sec, cls, big, label, sub) => h('a', { class: `sumtile ${cls}`, href: `#sec-${sec}`, onclick: (e) => { e.preventDefault(); ctx.goDetails(sec); } },
    h('div', { class: 'sumtile-big' }, big), h('div', { class: 'sumtile-label' }, label), h('div', { class: 'sumtile-sub' }, sub));
  const ready = tile('key-exchange', `bigLevel sumtile-lead ${levelClass(r.level)}`, r.level < 0 ? '?' : `L${r.level}`, 'Post-quantum readiness', r.label || levelName(r.level));
  ready.appendChild(h('div', { class: 'lvscale', 'aria-hidden': 'true' }, [0, 1, 2, 3, 4].map((l) => h('span', { class: l <= r.level ? 'on' : '' }))));
  const [baseBig, baseTone, baseSub] = !b || !b.judged ? ['Not judged', 'lvu', b && b.reason ? b.reason : 'the server’s lists were not read']
    : b.meets ? ['✓ Meets', 'lv3', b.title]
      : [`${b.changes.length} change${b.changes.length === 1 ? '' : 's'}`, 'lv0', `to meet ${b.title}`];
  const keys = rep.hostKeys || [];
  const k = keys.find((x) => (x.servedBy || []).includes((rep.negotiated || {}).hostKey)) || keys[0];
  const keySub = k ? `${k.pq ? 'post-quantum' : 'classical'} · ${k.fingerprint.slice(0, 19)}…` : 'no host key fetched';
  return h('div', { class: 'sumstrip', role: 'group', 'aria-label': 'Summary' },
    ready,
    tile('baseline', `bigLevel ${baseTone}`, baseBig, 'Baseline', baseSub),
    tile('host-keys', `bigLevel ${k ? (k.pq ? 'lv4' : 'lv3') : 'lvu'}`, k ? keyLabel(k) : 'None', 'Host key', keySub));
}

/**
 * baselineBlock leads the Configuration tab (UX-DESIGN-007 §4.3): the verdict, what the baseline
 * requires (met or not, with its source) and, when the server does not meet it, the sshd_config
 * lines that would make it, with a Copy button.
 */
function baselineBlock(ctx) {
  const b = ctx.ev.baseline;
  if (!b) return h('div');
  const card = h('section', { class: 'card baseline', id: 'sec-baseline', 'aria-labelledby': 'baseline-h' }, h('h2', { id: 'baseline-h' }, `Baseline: ${b.title}`));
  if (!b.judged) {
    card.appendChild(h('p', { class: 'muted' }, `Not judged. ${b.reason || ''}`));
    return card;
  }
  card.appendChild(b.meets
    ? h('p', null, versionState(['good', '✔', 'Meets the baseline', 'every algorithm offered is on it, and every requirement holds']))
    : h('p', null, versionState(['bad', '✖', 'Does not meet the baseline', `${plural(b.changes.length, 'change')} to make`])));
  if (b.sshdConfig) {
    const lines = b.sshdConfig.replace(/\n$/, '').split('\n');
    card.appendChild(h('h3', null, 'Make this server meet the baseline'));
    card.appendChild(h('pre', { class: 'sshdconf', 'aria-label': 'sshd_config lines', tabindex: '0' },
      lines.map((l) => h('span', { class: l.startsWith('#') ? 'cmt' : null }, `${l}\n`))));
    card.appendChild(h('div', { class: 'row' },
      button('Copy the lines', async () => {
        try { await navigator.clipboard.writeText(b.sshdConfig); toast('Copied', 'success'); } catch { toast('Select the lines and copy them', 'error'); }
      }, 'secondary', { class: 'btn btn-secondary btn-sm' }),
      h('span', { class: 'hint' }, 'Put these lines at the top of /etc/ssh/sshd_config, or in a file under /etc/ssh/sshd_config.d/ that is read first: sshd uses the first value of each keyword. Check with sshd -t, reload sshd, and scan again.')));
  }
  card.appendChild(h('h3', null, 'What the baseline requires'));
  // A list, not a table: each requirement keeps its verdict whole at any width.
  card.appendChild(h('ul', { class: 'reqs' }, (b.requires || []).map((r) => h('li', null,
    h('div', { class: 'req-text' }, r.text),
    h('div', null, r.met ? versionState(['good', '✔', 'Met', '']) : versionState(['bad', '✖', 'Not met', r.detail || ''])),
    citations([r.cite])))));
  if (b.changes.length) {
    card.appendChild(h('h3', null, 'The changes'));
    card.appendChild(h('ul', { class: 'changes' }, b.changes.map((c) => h('li', null, c.text))));
  }
  card.appendChild(h('p', { class: 'hint' }, 'The baseline is this product’s own; each entry cites its source. The full list: cipherhorizon ssh baselines.'));
  return card;
}

/** baselineAction is the first action item of a server that does not meet its baseline: the lines to copy. */
function baselineAction(ctx) {
  const b = ctx.ev.baseline;
  if (!b || !b.judged || b.meets) return null;
  return h('div', { class: 'action-group' },
    h('div', { class: 'action-group-head' }, h('h3', null, 'Baseline'),
      h('p', { class: 'action-why' }, h('b', null, 'Why it matters: '), `The server offers algorithms ${b.title} leaves out, or lacks what it requires.`)),
    h('ol', { class: 'actions' }, h('li', { class: 'action sev-medium', id: 'issue-baseline' },
      h('div', { class: 'action-head' }, badge(`${plural(b.changes.length, 'change')}`, 'bad'), h('span', { class: 'action-title' }, `Meet ${b.title}`)),
      h('p', { class: 'action-fix' }, h('b', null, 'What to do: '), b.changes.slice(0, 3).map((c) => c.text).join(' '), b.changes.length > 3 ? ` And ${plural(b.changes.length - 3, 'more')}.` : ''),
      h('a', { href: '#sec-baseline', class: 'xlink action-more', onclick: (e) => { e.preventDefault(); ctx.goDetails('baseline'); } }, 'The sshd_config lines to copy'))));
}

registerProfile('ssh', {
  sections: SSH_SECTIONS,
  builders: () => ({ 'ssh-version': versionBody, 'key-exchange': kexBody, 'host-keys': hostKeysBody, encryption: encryptionBody,
    integrity: integrityBody, vulnerabilities: vulnerabilitiesBody }),
  strip: sshStrip, why: WHY, groupWord: GROUP_WORD, hygiene: null, matrix: baselineBlock, extraAction: baselineAction, skipCards: ['vulnerabilities'],
  stageTitles: { identification: 'Identification', algorithms: 'Algorithm lists', negotiation: 'Negotiation', 'host-keys': 'Host keys' },
  schema: 'ssh-report/1',
});
