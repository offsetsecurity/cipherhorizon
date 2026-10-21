// The SSH server report (PRD-008 WP-D, WP-G; PRD-014, UX-DESIGN-012). The tabs, verdict, Fix first,
// every-check list and CBOM are report.js's; this module gives them SSH's areas, summary tiles and
// words, and draws SSH's own Configuration: one page in the order an SSH reviewer checks, every
// quantity an instrument from viz.js, every source in a tooltip. Everything the server sent reaches
// the page through the textContent-only DOM builder.
import { h } from '../dom.js';
import { levelClass, levelName } from '../charts.js';
import { button, toast } from '../ui.js';
import { registerProfile, plural } from './report.js';
import { bitsBar, bitsAxis, pqGlyph, statusTile, levelStepper, jumpNav, bandOf } from '../viz.js';

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

const algsOf = (ev, kind) => (ev.sshAlgorithms || []).filter((a) => a.kind === kind);
const offCount = (all) => all.filter((a) => a.baseline === 'off').length;
const keyLabel = (k) => (k.algorithm === 'RSA' && k.bits ? `RSA ${k.bits}` : k.curve ? `${k.algorithm} ${k.curve}` : k.algorithm);
// Key exchange and host keys are what a quantum computer breaks; ciphers and MACs are not a quantum question.
const pqOf = (a) => (a.kind === 'kex' || a.kind === 'host-key' ? (a.verdict === 'post-quantum' ? 'quantum-safe' : a.verdict === 'unknown' ? 'unknown' : 'quantum-vulnerable') : '');
const citesTitle = (list) => (list || []).map((c) => c.title).filter(Boolean).join('\n');

// ---- the areas' one-line verdicts (the Summary's By area tiles) -------------------------------

function versionBody(ctx) {
  const id = ctx.rep.identification;
  if (!id) return { verdict: 'No identification was read.' };
  return { verdict: id.ssh1Only ? `SSH-1 only: ${id.software || 'software not named'}.` : `SSH-${id.protoVersion}, ${id.software || 'software not named'}. ${id.ssh1 ? 'SSH-1 is accepted too.' : 'SSH-1 is not offered.'}` };
}

function kexBody(ctx) {
  if (!ctx.rep.algorithms) return {};
  const pq = algsOf(ctx.ev, 'kex').filter((a) => a.verdict === 'post-quantum').map((a) => a.name);
  return { verdict: pq.length ? `Post-quantum hybrid offered: ${pq.join(', ')}.` : 'No post-quantum key exchange is offered.' };
}

function hostKeysBody(ctx) {
  const keys = ctx.rep.hostKeys || [];
  if (!keys.length) return {};
  return { verdict: `${keys.map(keyLabel).join(', ')}. ${keys.every((k) => k.verified) ? 'Every signature verified.' : 'Not every signature could be verified.'}` };
}

const countVerdict = (all, one) => {
  const bad = offCount(all);
  return `${plural(all.length, one)} offered, ${bad ? `${bad} to turn off` : 'none to turn off'}.`;
};
function encryptionBody(ctx) {
  return ctx.rep.algorithms ? { verdict: countVerdict(algsOf(ctx.ev, 'cipher'), 'cipher') } : {};
}
function integrityBody(ctx) {
  return ctx.rep.algorithms ? { verdict: countVerdict(algsOf(ctx.ev, 'mac'), 'MAC') } : {};
}
function vulnerabilitiesBody(ctx) {
  const list = ctx.rep.algorithms ? ctx.ev.vulnerabilities || [] : [];
  if (!list.length) return {};
  const exposed = list.filter((a) => a.status === 'exposed');
  return { verdict: exposed.length ? `Exposed to ${exposed.map((a) => a.name).join(', ')}.` : 'Not exposed to any attack this scan can infer.' };
}

// ---- the Summary: four instruments, and the baseline as the first thing to fix ------------------

/** The weakest classical strength among the server's algorithms, and which one sets it. */
function weakestSSH(ev) {
  const rank = { broken: 0, weak: 1, acceptable: 2, strong: 3 };
  const list = (ev.sshAlgorithms || []).filter((a) => bandOf(a.strength) !== 'na');
  return list.slice().sort((a, b) => (rank[bandOf(a.strength)] - rank[bandOf(b.strength)]) || ((a.strength.bits || 0) - (b.strength.bits || 0)))[0] || null;
}
// A host key is as strong as the best signature it can make; a weak signature algorithm is its own row.
function keyStrength(ev, k) {
  const rank = (a) => ({ broken: -1, na: -2 }[bandOf(a.strength)] ?? a.strength.bits);
  return algsOf(ev, 'host-key').filter((a) => (k.servedBy || []).includes(a.name) && a.strength).sort((a, b) => rank(b) - rank(a))[0] || null;
}
const SECTION_OF_KIND = { kex: 'key-exchange', 'host-key': 'host-keys', cipher: 'encryption', mac: 'integrity', compression: 'integrity' };

/** The summary tiles: readiness, the baseline, the weakest strength, the host key. An SSH server has no score. */
function sshStrip(ctx) {
  const { ev, rep } = ctx;
  const r = ev.readiness, b = ev.baseline;
  const tile = (sec, cls, label, ...body) => h('a', { class: `sumtile ${cls}`, href: `#sec-${sec}`, onclick: (e) => { e.preventDefault(); ctx.goDetails(sec); } },
    h('div', { class: 'sumtile-label' }, label), ...body);
  const fig = (big, sub, cls = '') => h('div', { class: 'sumtile-figure' }, h('span', { class: `sumtile-big ${cls}` }, big), h('span', { class: 'sumtile-sub' }, sub));
  const ready = tile('key-exchange', `sumtile-lead bigLevel ${levelClass(r.level)}`, 'Post-quantum readiness',
    fig(r.level < 0 ? '?' : `L${r.level}`, r.label || levelName(r.level), levelClass(r.level)), levelStepper(r.level));
  const [baseBig, baseTone, baseSub] = !b || !b.judged ? ['Not judged', 'lvu', b && b.reason ? b.reason : 'the server’s lists were not read']
    : b.meets ? ['✓ Meets', 'lv3', b.title] : [plural(b.changes.length, 'change'), 'lv0', `to meet ${b.title}`];
  const base = tile('baseline', `bigLevel ${baseTone}`, 'Baseline', fig(baseBig, baseSub, baseTone));
  const weak = weakestSSH(ev);
  const strength = tile(weak ? SECTION_OF_KIND[weak.kind] : 'key-exchange', 'sumtile-strength', 'Weakest classical strength',
    fig(weak ? (weak.strength.status === 'broken' ? 'broken' : String(weak.strength.bits)) : '·', weak ? `${weak.strength.status === 'broken' ? '' : 'bits · '}${weak.name}` : 'not rated'),
    weak ? bitsBar(weak.strength, { name: weak.name }) : null);
  const keys = rep.hostKeys || [];
  const k = keys.find((x) => (x.servedBy || []).includes((rep.negotiated || {}).hostKey)) || keys[0];
  // The key's tone follows its strength: post-quantum, strong, acceptable, or weak and broken.
  const kband = k && keyStrength(ev, k) ? bandOf(keyStrength(ev, k).strength) : 'na';
  const ktone = !k ? 'lvu' : kband === 'broken' || kband === 'weak' ? 'lv0' : kband === 'acceptable' ? 'lv1' : k.pq ? 'lv4' : 'lv3';
  const key = tile('host-keys', `bigLevel ${ktone}`, 'Host key',
    fig(k ? keyLabel(k) : 'None', k ? `${k.pq ? 'post-quantum' : 'classical'} · ${k.fingerprint.slice(0, 19)}…` : 'no host key fetched', ktone));
  return h('div', { class: 'sumstrip', role: 'group', 'aria-label': 'Where this server stands' }, ready, base, strength, key);
}

const KIND_WORD = { kex: ['key exchange', 'key exchanges'], 'host-key': ['host-key algorithm', 'host-key algorithms'], cipher: ['cipher', 'ciphers'],
  mac: ['MAC', 'MACs'], compression: ['compression method', 'compression methods'] };

/** The baseline's changes in a line: "Remove 8 algorithms; add mlkem768x25519-sha256; replace a host key."
 *  Each change's reason is in the row's tooltip. */
function changesLine(changes) {
  const parts = [];
  const removes = changes.filter((c) => c.action === 'remove');
  const kinds = [...new Set(removes.map((c) => c.kind))];
  if (removes.length === 1) parts.push(`remove ${removes[0].name}`);
  else if (removes.length) parts.push(`remove ${removes.length} ${kinds.length === 1 && KIND_WORD[kinds[0]] ? KIND_WORD[kinds[0]][1] : 'algorithms'}`);
  for (const c of changes.filter((x) => x.action === 'add')) parts.push(`add ${c.name}`);
  const rk = changes.filter((c) => c.action === 'replace-key').length;
  if (rk) parts.push(rk === 1 ? 'replace a host key' : `replace ${rk} host keys`);
  for (const c of changes.filter((x) => x.action === 'upgrade')) parts.push(c.text.replace(/\.$/, ''));
  const s = parts.join('; ');
  return s ? `${s[0].toUpperCase()}${s.slice(1)}.` : '';
}

/** The first Fix first line of a server that does not meet its baseline (report.js draws the row). */
function baselineAction(ctx) {
  const b = ctx.ev.baseline;
  if (!b || !b.judged || b.meets) return null;
  return { id: 'baseline', chip: plural(b.changes.length, 'change'), title: `Meet ${b.title}`, fix: changesLine(b.changes),
    why: b.changes.map((c) => c.text).join('\n'), link: b.sshdConfig ? 'The sshd_config lines' : 'The changes', go: () => ctx.goDetails('baseline') };
}

// ---- the Configuration: the one-stop check (UX-DESIGN-012 §3) ---------------------------------

const toneOf = (st) => ({ problem: 'problem', attention: 'attention', good: 'good' }[st] || 'na');

// Where a baseline change is drawn: with the algorithms it names; an upgrade with the version when the
// server speaks only SSH-1, else with the key exchange (strict key exchange).
function changeSection(ch, rep) {
  if (ch.action === 'upgrade') return rep.identification && rep.identification.ssh1Only ? 'ssh-version' : 'key-exchange';
  return SECTION_OF_KIND[ch.kind] || 'integrity';
}
const CHANGE_GLYPH = { remove: '−', add: '+', upgrade: '↑', 'replace-key': '⟲' };
const CHANGE_WORD = { remove: 'remove', add: 'add', upgrade: 'upgrade', 'replace-key': 'replace' };

/** One baseline change as a chip: what to do to which name; the reason and its source in the tooltip. */
function changeChip(c) {
  const named = c.action === 'remove' || c.action === 'add';
  return h('span', { class: `chg chg-${c.action}`, title: `${c.text}${c.cite && c.cite.title ? `\nSource: ${c.cite.title}` : ''}` },
    h('span', { class: 'chg-glyph', 'aria-hidden': 'true' }, CHANGE_GLYPH[c.action] || '·'),
    h('span', { class: 'sr-only' }, `${CHANGE_WORD[c.action] || c.action} `),
    named ? h('code', null, c.name) : h('span', null, c.text.replace(/\.$/, '')));
}

/** A part of the page: its heading and aside, its body, then its issues and baseline changes. */
function part(ctx, id, title, tone, aside, ...body) {
  const issues = ctx.issues[id] || [];
  const changes = ctx.changes[id] || [];
  return h('section', { class: `card cfg ssh-cfg cfg-${tone}`, id: `sec-${id}`, 'aria-labelledby': `sec-${id}-h` },
    h('div', { class: 'cfg-head' }, h('h2', { id: `sec-${id}-h` }, title), aside ? h('span', { class: 'cfg-aside' }, aside) : null), ...body,
    issues.length || changes.length ? h('div', { class: 'detcard-issues' },
      issues.length ? h('p', null, h('b', null, issues.length === 1 ? 'Issue: ' : 'Issues: '),
        issues.map((f, i) => [i ? ' · ' : '', h('a', { href: `#chk-${f.id}`, class: 'xlink', onclick: (e) => { e.preventDefault(); ctx.goIssue(f.id); } }, f.title)])) : null,
      changes.length ? h('p', { class: 'chg-row' }, h('b', null, 'Baseline: '), changes.map(changeChip)) : null) : null);
}

/** A part the scan could not read: why, in one muted line. */
const notRead = (ctx, id) => {
  const sec = (ctx.ev.sections || []).find((s) => s.id === id);
  if (!sec || !sec.reason) return h('p', { class: 'muted' }, 'Not read by this scan.');
  return h('p', { class: 'muted' }, `${sec.status === 'not-applicable' ? 'Does not apply' : 'Not read'}: ${sec.reason}.`);
};

/** The algorithm rows of one kind, in the order the server lists them, under the shared axis. */
function algoRows(ctx, kind, label) {
  const rows = algsOf(ctx.ev, kind);
  if (!rows.length) return null;
  const client = (ctx.rep.negotiated || {}).client || 'a current client';
  return h('div', { class: 'sshalgs', role: 'group', 'aria-label': label },
    h('div', { class: 'sshrow sshrow-axis', 'aria-hidden': 'true' }, h('span', { class: 'muted' }, label), bitsAxis(), h('span'), h('span', { class: 'muted' }, 'Baseline')),
    rows.map((a) => {
      const off = a.baseline === 'off';
      return h('div', { class: `sshrow${a.used ? ' is-used' : ''}${off ? ' is-off' : ''}`, 'data-kind': a.kind, 'data-name': a.name },
        h('span', { class: 'sshrow-alg' }, h('code', null, a.name),
          h('span', null, a.display || (a.verdict === 'unknown' ? 'not in this program’s registry' : ''),
            a.used ? h('span', { class: 'usedchip', title: `What ${client} negotiates` }, 'in use') : null)),
        bitsBar(a.strength, { name: a.name }),
        h('span', { class: 'sshrow-pq' }, pqGlyph(pqOf(a))),
        a.baseline === '' ? h('span', { class: 'bmark bmark-na', title: 'A signal, not an algorithm: the baseline does not judge it' }, '·')
          : h('span', { class: `bmark ${off ? 'bmark-off' : 'bmark-ok'}`, title: off ? (a.verdict === 'unknown' ? 'Not on the baseline, and not in this program’s registry' : 'Not on the baseline') : 'On the baseline' },
            h('span', { 'aria-hidden': 'true' }, off ? '✕' : '✓'), off ? 'should be off' : 'allowed'));
    }));
}

// 1. version and software
function versionPart(ctx, tone) {
  const { rep } = ctx;
  const id = rep.identification;
  const n = rep.negotiated;
  const plus = () => h('span', { class: 'nplus', 'aria-hidden': 'true' }, '+');
  const pqKex = n && algsOf(ctx.ev, 'kex').some((a) => a.name === n.kex && a.verdict === 'post-quantum');
  const banner = n && n.kex ? h('div', { class: 'negotiated', role: 'group', 'aria-label': 'What a current client gets', title: n.client || null },
    h('span', { class: 'negotiated-label' }, 'A current client gets'),
    h('code', { class: `nchip${pqKex ? ' nchip-pq' : ''}` }, pqKex ? pqGlyph('quantum-safe') : null, n.kex),
    n.hostKey ? [plus(), h('code', { class: 'nchip' }, n.hostKey)] : null,
    n.cipher ? [plus(), h('code', { class: 'nchip' }, n.cipher)] : null,
    n.cipher ? [plus(), n.mac ? h('code', { class: 'nchip' }, n.mac) : h('span', { class: 'nchip nchip-none', title: 'The cipher authenticates itself (AEAD), so no MAC is used' }, 'no MAC')] : null,
    h('span', { class: 'negotiated-alpn' }, n.verified ? 'signature verified' : n.completed ? 'completed, not verified' : 'not completed')) : null;
  if (!id) return part(ctx, 'ssh-version', 'Version and software', tone, null, notRead(ctx, 'ssh-version'));
  const software = statusTile('Software', `${id.software || 'Not named'}${id.comment ? ` (${id.comment})` : ''}`, 'na');
  software.title = 'As the server announces it. Its version is not matched against vendor advisories (see Weaknesses).';
  const pre = id.preamble || [];
  return part(ctx, 'ssh-version', 'Version and software', tone, null, banner, h('div', { class: 'stiles' },
    statusTile('Protocol', id.ssh1Only ? 'SSH-1 only' : id.ssh1 ? 'SSH-2, and SSH-1 accepted' : 'SSH-2 only', id.ssh1 ? 'problem' : 'good', null, null, id.raw),
    software,
    statusTile('Lines before the identification', pre.length ? plural(pre.length, 'line') : 'None', 'na', null, null, pre.length ? pre.join('\n') : null)));
}

// 2. key exchange
function kexPart(ctx, tone) {
  const { ev, rep } = ctx;
  const r = ev.readiness || {};
  const readiness = h('div', { class: 'readyrow' },
    h('span', { class: 'readyrow-level' }, h('b', null, r.level < 0 ? '?' : `L${r.level}`), h('span', null, r.label || '')),
    levelStepper(r.level),
    h('span', { class: 'readyrow-dims' }, [['Key establishment', r.keyEstablishment], ['Authentication', r.authentication], ['Symmetric', r.symmetric]].filter(([, d]) => d).map(([t, d]) =>
      h('span', { class: 'dimchip', title: [d.detail, citesTitle(d.citations)].filter(Boolean).join('\n\nSources:\n') }, h('span', { class: 'muted' }, `${t} `), d.status))));
  const next = (r.nextSteps || []).length ? h('ol', { class: 'next compact' }, r.nextSteps.map((s) => h('li', null, s))) : null;
  if (!rep.algorithms) return part(ctx, 'key-exchange', 'Key exchange', tone, null, readiness, notRead(ctx, 'key-exchange'), next);
  const terrapin = (ev.vulnerabilities || []).find((v) => v.name === 'Terrapin');
  const exposed = terrapin && terrapin.status === 'exposed';
  const strict = rep.algorithms.strictKex ? statusTile('Strict key exchange', 'On: the countermeasure to Terrapin', 'good')
    : statusTile('Strict key exchange', exposed ? 'Not offered: exposed to Terrapin' : 'Not offered', exposed ? 'problem' : 'attention');
  strict.title = 'CVE-2023-48795; OpenSSH 9.6 and later';
  return part(ctx, 'key-exchange', 'Key exchange', tone, 'Every list here is in the server’s order; in each, the client’s order decides (RFC 4253 §7.1).',
    readiness, algoRows(ctx, 'kex', 'Key exchange methods'), h('div', { class: 'stiles' }, strict), next);
}

// 3. host keys
function hostKeysPart(ctx, tone) {
  const { rep, ev } = ctx;
  if (!rep.algorithms) return part(ctx, 'host-keys', 'Host keys', tone, null, notRead(ctx, 'host-keys'));
  const keys = rep.hostKeys || [];
  const n = rep.negotiated || {};
  const cards = keys.map((k) => {
    const s = keyStrength(ev, k);
    const inUse = (k.servedBy || []).includes(n.hostKey);
    return h('li', { class: `chaincard keycard${inUse ? ' is-leaf' : ''}${k.verified ? '' : ' hasissue'}` },
      h('span', { class: 'cc-role' }, inUse ? 'In use' : 'Also offered'),
      h('span', { class: 'servedcn keycard-name' }, pqGlyph(k.pq ? 'quantum-safe' : 'quantum-vulnerable'), keyLabel(k)),
      s ? bitsBar(s.strength, { name: keyLabel(k) }) : null,
      h('span', { class: 'cc-chips' },
        h('span', { class: `tchip ${k.verified ? 'tchip-good' : 'tchip-warn'}`, title: k.verified ? 'The key signed the key exchange, and the signature verified' : (k.verifyNote || 'no reason given') },
          k.verified ? 'Signature verified ✓' : 'Not verified ?'),
        (k.servedBy || []).map((x) => h('span', { class: 'cchip', title: 'A host-key algorithm this key answers to' }, x))),
      h('code', { class: 'cc-names keycard-fp', title: 'SHA-256 fingerprint, as ssh-keygen -l shows it' }, k.fingerprint),
      k.certificate ? h('span', { class: 'cc-foot' }, `OpenSSH certificate from CA ${k.certificate.caFingerprint}`,
        (k.certificate.principals || []).length ? `, for ${k.certificate.principals.join(', ')}` : '') : null);
  });
  for (const a of (rep.hostKeyAttempts || []).filter((x) => x.outcome !== 'key')) {
    cards.push(h('li', { class: 'chaincard keycard is-missing' }, h('span', { class: 'cc-role cc-role-bad' }, 'Not fetched'),
      h('span', { class: 'servedcn' }, h('code', null, a.algorithm)), h('span', { class: 'cc-foot' }, a.detail || a.outcome)));
  }
  return part(ctx, 'host-keys', 'Host keys', tone, 'Each key the server proved it holds. A key is as strong as its best signature.',
    cards.length ? h('ol', { class: 'chainribbon keyribbon', 'aria-label': 'Host keys' }, cards) : h('p', { class: 'muted' }, 'No host key was fetched.'),
    algoRows(ctx, 'host-key', 'Host-key algorithms'));
}

// 4. ciphers
function cipherPart(ctx, tone) {
  const a = ctx.rep.algorithms;
  if (!a) return part(ctx, 'encryption', 'Ciphers', tone, null, notRead(ctx, 'encryption'));
  const twoLists = (a.cipherC2S || []).join() !== (a.cipherS2C || []).join();
  return part(ctx, 'encryption', 'Ciphers', tone, twoLists ? 'Each direction has its own list; both are shown, merged.' : null, algoRows(ctx, 'cipher', 'Ciphers'));
}

// 5. MACs and compression
function integrityPart(ctx, tone) {
  if (!ctx.rep.algorithms) return part(ctx, 'integrity', 'MACs and compression', tone, null, notRead(ctx, 'integrity'));
  const n = ctx.rep.negotiated || {};
  const comp = algsOf(ctx.ev, 'compression').map((a) => a.name);
  const before = comp.includes('zlib');
  const words = comp.map((c) => (c === 'zlib@openssh.com' ? 'zlib@openssh.com, after login' : c === 'zlib' ? 'zlib, before login' : c));
  const tile = statusTile('Compression', comp.length ? words.join(' · ') : 'Not listed', before ? 'attention' : comp.length ? 'good' : 'na');
  if (before) tile.title = 'Compression before login exposes the decompressor to anyone who can connect';
  return part(ctx, 'integrity', 'MACs and compression', tone,
    n.cipher && !n.mac ? `${n.cipher} authenticates itself, so a current client uses no MAC.` : null,
    algoRows(ctx, 'mac', 'MACs'), h('div', { class: 'stiles' }, tile));
}

const SSH_PARTS = [['ssh-version', 'Version & software'], ['key-exchange', 'Key exchange'], ['host-keys', 'Host keys'], ['encryption', 'Ciphers'],
  ['integrity', 'MACs & compression'], ['baseline', 'Baseline']];

// 6. baseline changes
function baselinePart(ctx, tone) {
  const b = ctx.ev.baseline;
  if (!b) return null;
  const aside = h('span', null, 'This product’s own; each entry cites its source. ', h('a', { href: '#/help?topic=baseline' }, 'The baseline, entry by entry'));
  if (!b.judged) return part(ctx, 'baseline', 'Baseline', tone, aside, h('div', { class: 'stiles' }, statusTile(b.title, `Not judged: ${b.reason || 'the server’s lists were not read'}`, 'na')));
  const verdict = statusTile(b.title, b.meets ? 'Meets the baseline' : `Does not meet it · ${plural(b.changes.length, 'change')} to make`, b.meets ? 'good' : 'problem');
  verdict.classList.add('stile-verdict');
  const reqs = (b.requires || []).map((r) => {
    const t = statusTile(r.text, r.met ? 'Met' : `Not met${r.detail ? `: ${r.detail.replace(/\.$/, '')}` : ''}`, r.met ? 'good' : 'problem', r.cite && r.cite.url ? r.cite.url : null);
    t.classList.add('reqtile');
    if (r.cite) {
      t.title = `Source: ${r.cite.title}`;
      if (r.cite.url) { t.target = '_blank'; t.rel = 'noopener noreferrer'; }
    }
    return t;
  });
  // The changes are drawn with the algorithms they name; this part leads to them.
  const where = SSH_PARTS.filter(([id]) => id !== 'baseline' && (ctx.changes[id] || []).length);
  const goTo = (id) => document.getElementById(`sec-${id}`)?.scrollIntoView({ block: 'start' });
  const body = [h('div', { class: 'stiles' }, verdict),
    reqs.length ? [h('h3', { class: 'cfg-sub' }, 'What the baseline requires'), h('div', { class: 'stiles' }, reqs)] : null,
    where.length ? h('p', { class: 'chg-where' }, h('span', { class: 'muted' }, 'The changes, in their parts: '),
      where.map(([id, label]) => h('a', { href: `#sec-${id}`, class: 'jump-chip', onclick: (e) => { e.preventDefault(); goTo(id); } }, `${label} · ${ctx.changes[id].length}`))) : null];
  if (b.sshdConfig) {
    const lines = b.sshdConfig.replace(/\n$/, '').split('\n');
    body.push(h('h3', { class: 'cfg-sub' }, 'Make this server meet the baseline'),
      h('pre', { class: 'sshdconf', 'aria-label': 'sshd_config lines', tabindex: '0' }, lines.map((l) => h('span', { class: l.startsWith('#') ? 'cmt' : null }, `${l}\n`))),
      h('div', { class: 'row' },
        button('Copy the lines', async () => {
          try { await navigator.clipboard.writeText(b.sshdConfig); toast('Copied', 'success'); } catch { toast('Select the lines and copy them', 'error'); }
        }, 'secondary', { class: 'btn btn-secondary btn-sm' }),
        h('span', { class: 'hint' }, 'Put them first in sshd_config (sshd keeps the first value of each keyword), then sshd -t, reload, and scan again.')));
  }
  return part(ctx, 'baseline', 'Baseline', tone, aside, ...body);
}

/** The whole Configuration tab for an SSH server, and the jump row that leads through it. */
function sshConfiguration(ctx, about) {
  const { ev, rep } = ctx;
  const sec = Object.fromEntries((ev.sections || []).map((x) => [x.id, x.status]));
  // Each finding once, under its part; the published attacks stay on Weaknesses.
  const issues = {};
  const seen = new Set();
  for (const f of ev.findings || []) {
    if (seen.has(f.id) || f.section === 'vulnerabilities') continue;
    seen.add(f.id);
    (issues[f.section] = issues[f.section] || []).push(f);
  }
  const changes = {};
  const b = ev.baseline;
  if (b && b.judged) {
    for (const c of b.changes || []) {
      const at = changeSection(c, rep);
      (changes[at] = changes[at] || []).push(c);
    }
  }
  const pctx = { ...ctx, issues, changes };
  const tones = Object.fromEntries(SSH_PARTS.map(([id]) => [id, toneOf(sec[id])]));
  tones.baseline = !b || !b.judged ? 'na' : b.meets ? 'good' : 'attention';
  const goTo = (id) => document.getElementById(id)?.scrollIntoView({ block: 'start' });
  return h('div', { class: 'report configuration ssh-config' },
    jumpNav(SSH_PARTS.filter(([id]) => id !== 'baseline' || b).map(([id, label]) => ({ id: `sec-${id}`, label, tone: tones[id] })), goTo),
    versionPart(pctx, tones['ssh-version']),
    kexPart(pctx, tones['key-exchange']),
    hostKeysPart(pctx, tones['host-keys']),
    cipherPart(pctx, tones.encryption),
    integrityPart(pctx, tones.integrity),
    baselinePart(pctx, tones.baseline),
    about);
}

registerProfile('ssh', {
  sections: SSH_SECTIONS,
  builders: () => ({ 'ssh-version': versionBody, 'key-exchange': kexBody, 'host-keys': hostKeysBody, encryption: encryptionBody,
    integrity: integrityBody, vulnerabilities: vulnerabilitiesBody }),
  strip: sshStrip, why: WHY, groupWord: GROUP_WORD, hygiene: null, configuration: sshConfiguration, extraAction: baselineAction, skipCards: ['vulnerabilities'],
  stageTitles: { identification: 'Identification', algorithms: 'Algorithm lists', negotiation: 'Negotiation', 'host-keys': 'Host keys' },
  schema: 'ssh-report/1',
});
