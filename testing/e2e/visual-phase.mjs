// PRD-013 (instruments, not paragraphs), driven through the browser on the other phases' data: the
// shared instruments carry their meaning in words; the Summary is instruments, Fix first, the checks
// bar and area tiles; the Configuration's suites, features and revocation agree with the API; the
// Inventory's charts open the lists they count; the SSH report (PRD-014) is the same one-stop page,
// its rows, banner, key cards, baseline tiles and Summary agreeing with the API; and every rebuilt
// screen fits 1440, 1100, 860 and 375 px, in light and dark, with readable contrast.

const words = (st) => (!st ? 'not rated' : st.status === 'rated' ? `${st.bits} bits` : st.status === 'disallowed' ? `${st.bits} bits, disallowed`
  : st.status === 'broken' ? 'broken' : 'not rated');

// The contrast of every instrument's text against what is drawn behind it (WCAG 2.x relative luminance).
const CONTRAST = `
  const rgb = (c) => { const m = c.match(/[\\d.]+/g); return m ? m.slice(0, 4).map(Number) : [0, 0, 0, 0]; };
  const lum = ([r, g, b]) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
  const bgOf = (el) => { for (let e = el; e; e = e.parentElement) { const c = rgb(getComputedStyle(e).backgroundColor); if (c[3] === undefined || c[3] > 0.5) return c; } return rgb(getComputedStyle(document.body).backgroundColor); };
  const ratio = (el) => { const a = lum(rgb(getComputedStyle(el).color)), b = lum(bgOf(el)); return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05); };
  const SEL = '.bb-value, .pcell, .schip, .stile b, .stile-state, .gchip, .tchip, .cchip, .jump-chip, .vchip, .lstep-l, .hist-n, .hist-label, .fix-n, .action-title, .cfg-aside, .lane-alg, .lane-uses, .xid-v, .specval, .nmchip, .usechip, .sshrow-alg code, .sshrow-alg > span, .usedchip, .bmark, .chg, .nchip, .keycard-fp, .dimchip';
  const low = [...document.querySelectorAll(SEL)].filter((el) => el.offsetParent !== null && el.textContent.trim())
    .map((el) => ({ el: el.className.baseVal ?? el.className, text: el.textContent.trim().slice(0, 24), r: Math.round(ratio(el) * 100) / 100 }))
    .filter((x) => x.r < 4.5);`;

export async function visualPhase({ check, js, go, sleep, shot, viewport }) {
  await viewport(1440, 900, false);
  const endpoints = await js(`return (await (await fetch('/api/v1/assets?kind=endpoint')).json()).filter((a) => a.lastDone)`);
  const tls = endpoints.filter((a) => a.protocol !== 'ssh');
  // The SSH reports: the legacy server (every kind of mark, a broken host-key algorithm, many changes),
  // the SSH-1-only one (nothing negotiated) and the hardened one (meets the baseline).
  const sshAll = endpoints.filter((a) => a.protocol === 'ssh');
  const ssh = sshAll.find((a) => a.port === 9462) || sshAll[0];
  const ssh1 = sshAll.find((a) => a.port === 9465);
  const sshGood = sshAll.find((a) => a.port === 9467);
  // The richest TLS report: the most suites (a legacy server shows every instrument).
  let target = tls[0], most = -1;
  for (const a of tls.slice(0, 8)) {
    const rep = await js(`return (await fetch('/api/v1/scans/${a.lastDone.id}/report')).json()`);
    if ((rep.suites || []).length > most) { most = (rep.suites || []).length; target = a; }
  }
  const scan = target.lastDone.id;
  const ev = await js(`return (await fetch('/api/v1/scans/${scan}/evaluation')).json()`);
  const rep = await js(`return (await fetch('/api/v1/scans/${scan}/report')).json()`);

  // E2E-VIS-1: every instrument says in words what it shows (role img and a label, or text beside it).
  const labelled = async () => js(`return {
    bars: [...document.querySelectorAll('#main .bitsbar')].map((b) => b.getAttribute('role') === 'img' && /(bits|broken|not rated)/.test(b.getAttribute('aria-label') || '')),
    glyphs: [...document.querySelectorAll('#main svg.pqg')].map((g) => g.getAttribute('role') === 'img' && /Quantum-(safe|vulnerable)/.test(g.getAttribute('aria-label') || '')),
    dots: [...document.querySelectorAll('#main span.pqg-na')].map((g) => !!g.querySelector('.sr-only')),
    tiles: [...document.querySelectorAll('#main .stile')].map((t) => !!t.querySelector('.sr-only, .secstatus')),
    others: [...document.querySelectorAll('#main .ltbar, #main .lstep, #main .stackbar, #main svg.gauge')].map((x) => x.getAttribute('role') === 'img' && (x.getAttribute('aria-label') || '').length > 2) }`);
  const tally = {};
  const pages = [['summary', `#/endpoints/${target.id}`], ['configuration', `#/endpoints/${target.id}?tab=configuration`], ['inventory', '#/inventory/algorithms']];
  if (ssh) pages.push(['ssh', `#/ssh/${ssh.id}?tab=configuration`], ['ssh-summary', `#/ssh/${ssh.id}`]);
  const leaf = ((rep.certificates || [])[0] || { chain: [] }).chain[0];
  if (leaf) pages.push(['certificate', `#/certificates/${leaf.sha256}?scan=${scan}`]);
  for (const [name, hash] of pages) {
    await go(hash);
    await sleep(1600);
    const l = await labelled();
    tally[name] = Object.fromEntries(Object.entries(l).map(([k, v]) => [k, `${v.filter(Boolean).length}/${v.length}`]));
    tally[name].ok = Object.values(l).every((v) => v.every(Boolean));
    tally[name].bars = l.bars.length;
  }
  check('E2E-VIS-1', 'the shared instruments are on every rebuilt screen and each one says in words what it shows',
    Object.values(tally).every((t) => t.ok) && ['configuration', 'inventory', 'certificate'].every((p) => tally[p] && tally[p].bars > 0) && (!ssh || tally.ssh.bars > 0),
    JSON.stringify(tally).slice(0, 500));

  // E2E-VIS-2: the Summary is four instruments, Fix first, one checks bar and the area tiles; each tile
  // opens its section in Configuration.
  await go(`#/endpoints/${target.id}`);
  await sleep(1500);
  const sum = await js(`const bar = document.querySelector('.checksbar .stackbar');
    const n = Number((document.querySelector('.checksbar .coverage-line')?.textContent || '').split(' ')[0]);
    const segs = [...(bar ? bar.querySelectorAll('.stack-seg') : [])].reduce((t, s) => t + Number(s.title.split(' ')[0]), 0);
    const tiles = [...document.querySelectorAll('#checks .area-tiles .stile')];
    const out = { instruments: [...document.querySelectorAll('.sumstrip .sumtile')].map((t) => t.querySelector('.sumtile-label')?.textContent),
      fix: document.querySelectorAll('#fix ol.fixlist > li').length, checks: n, segs, tiles: tiles.length,
      prose: /Why it matters|We ran \\d+ checks/.test(document.querySelector('.report.summary').innerText) };
    const t = tiles.find((x) => /certificate/i.test(x.textContent)) || tiles[0];
    const to = t.getAttribute('href');
    t.click();
    await new Promise((r) => setTimeout(r, 900));
    const sec = document.querySelector(to);
    out.opened = { to, tab: document.querySelector('.tab[aria-selected="true"]')?.textContent, inView: !!sec && sec.getBoundingClientRect().top < innerHeight && sec.getBoundingClientRect().bottom > 0 };
    return out;`);
  check('E2E-VIS-2', 'the Summary has the four instruments, Fix first, a checks bar that adds up to the checks run and an area tile that opens its section (PRD-013 REQ-VIS-2)',
    sum.instruments.length === 4 && sum.fix > 0 && sum.checks > 10 && sum.segs === sum.checks && sum.tiles === 8 && !sum.prose
      && sum.opened.tab === 'Configuration' && sum.opened.inView, JSON.stringify(sum));
  await shot('vis-summary');

  // E2E-VIS-3: each version's suites are the report's, in the server's order, each with its five cells
  // and the evaluation's word; the banner is what a current client negotiates.
  await go(`#/endpoints/${target.id}?tab=configuration`);
  await sleep(1500);
  const cfg = await js(`return { banner: [...document.querySelectorAll('.negotiated .nchip')].map((c) => c.textContent),
    blocks: [...document.querySelectorAll('#sec-protocols .ver-block')].map((b) => ({ v: b.id.replace('ver-', ''),
      rows: [...b.querySelectorAll('tbody tr')].map((tr) => ({ rank: tr.querySelector('.rank').textContent, name: tr.querySelector('code').textContent, cells: tr.querySelectorAll('td.pcol').length, word: tr.querySelector('.schip').textContent })) })) }`);
  const wrongSuites = [];
  for (const b of cfg.blocks) {
    const want = (rep.suites || []).filter((s) => s.version === b.v).slice().sort((x, y) => (x.rank || 99) - (y.rank || 99));
    if (want.map((s) => s.name).join() !== b.rows.map((r) => r.name).join()) wrongSuites.push({ v: b.v, want: want.map((s) => s.name).slice(0, 4), got: b.rows.map((r) => r.name).slice(0, 4) });
    for (const r of b.rows) {
      const st = (ev.suiteStrength || []).find((s) => s.version === b.v && s.name === r.name);
      const word = st ? st.word[0].toUpperCase() + st.word.slice(1) : 'Not rated';
      if (r.cells !== 5 || r.word !== word) wrongSuites.push({ v: b.v, suite: r.name, cells: r.cells, want: word, got: r.word });
    }
  }
  const versionsOn = (rep.protocols || []).filter((p) => p.supported).map((p) => p.version).sort();
  const n = rep.negotiated || {};
  check('E2E-VIS-3', 'each version that is on lists the report’s suites in the server’s order, five part cells each and the evaluation’s word, under the negotiated banner (PRD-013 REQ-VIS-3)',
    cfg.blocks.map((b) => b.v).sort().join() === versionsOn.join() && wrongSuites.length === 0 && (!n.version || cfg.banner[0] === n.version.replace('TLSv', 'TLS ').replace('SSLv', 'SSL ')),
    JSON.stringify({ versions: cfg.blocks.map((b) => b.v), versionsOn, banner: cfg.banner, wrong: wrongSuites.slice(0, 3) }).slice(0, 500));
  await shot('vis-configuration', { maxH: 5000 });

  // E2E-VIS-4: key exchange, revocation and features as chips and tiles: every feature the scan
  // records has a tile in the right state, and what was not probed says so.
  const feat = await js(`const tile = (sec, name) => [...document.querySelectorAll(sec + ' .stile')].find((t) => t.querySelector('b')?.textContent === name);
    const st = (sec, name) => { const t = tile(sec, name); return t ? { tone: [...t.classList].find((c) => c.startsWith('stile-') && c !== 'stile'), state: t.querySelector('.stile-state').textContent } : null; };
    const names = [...document.querySelectorAll('#sec-features .stile b')].map((b) => b.textContent);
    return { names, reneg: st('#sec-features', 'Secure renegotiation'), comp: st('#sec-features', 'Compression'), hb: st('#sec-features', 'Heartbeat'), rtt: st('#sec-features', '0-RTT early data'),
      rev: [...document.querySelectorAll('#sec-revocation .stile b')].map((b) => b.textContent),
      ready: document.querySelector('#sec-key-exchange .readyrow-level b')?.textContent, lstep: document.querySelectorAll('#sec-key-exchange .lstep-seg.on').length,
      groups: document.querySelectorAll('#sec-key-exchange .chiprow .gchip').length }`);
  const f = rep.features || {};
  const tone = (v, good) => (v === undefined || v === null ? 'stile-na' : v === good ? 'stile-good' : 'stile-problem');
  const r = ev.readiness || {};
  check('E2E-VIS-4', 'key exchange, revocation and features are chips and tiles that agree with the scan; 0-RTT says it was not probed (PRD-013 REQ-VIS-5)',
    ['Secure renegotiation', 'Extended master secret', 'Downgrade protection', 'Compression', 'Encrypt-then-MAC', 'Session tickets', 'ALPN', 'Client certificates', 'Heartbeat', '0-RTT early data', 'HSTS'].every((x) => feat.names.includes(x))
      && feat.reneg.tone === tone(f.secureRenegotiation, true) && feat.comp.tone === tone(f.compression, false) && /^Not probed/.test(feat.rtt.state)
      && (f.heartbeat === undefined ? /^Not probed/.test(feat.hb.state) : /egotiated/.test(feat.hb.state))
      && ['OCSP stapling', 'Must-staple', 'OCSP and CRL', 'Certificate Transparency'].every((x) => feat.rev.includes(x))
      && feat.ready === (r.level < 0 ? '?' : `L${r.level}`) && feat.lstep === Math.max(0, r.level + 1) && feat.groups > 0,
    JSON.stringify(feat).slice(0, 500));

  // E2E-VIS-5: the Inventory's charts count what their lists show; the list is weakest first.
  await go('#/inventory/algorithms');
  await sleep(1800);
  const inv = await js(`const cols = [...document.querySelectorAll('.hist .hist-col')].map((c) => ({ href: c.getAttribute('href'), n: Number(c.querySelector('.hist-n').textContent) }));
    const classes = [...document.querySelectorAll('.classrow')].map((c) => ({ href: c.getAttribute('href'), n: Number(c.querySelector('.classrow-n').textContent) }));
    return { cols, classes, rows: document.querySelectorAll('#main table.invtable tbody tr').length }`);
  const opened = [];
  for (const c of [...inv.cols.filter((x) => x.n > 0).slice(0, 3), ...inv.classes.slice(0, 1)]) {
    await go(c.href);
    await sleep(1500);
    opened.push({ href: c.href, want: c.n, got: await js(`return document.querySelectorAll('#main table.invtable tbody tr').length`) });
  }
  await go('#/inventory/algorithms');
  await sleep(1500);
  const ranks = await js(`const bucket = (label) => { if (/broken/.test(label)) return 0; if (/not rated/.test(label)) return 6; const b = Number((label.match(/(\\d+) bits/) || [])[1]); return b < 112 ? 1 : b < 128 ? 2 : b < 192 ? 3 : b < 256 ? 4 : 5; };
    return [...document.querySelectorAll('#main table.invtable tbody tr .bitsbar')].map((b) => bucket(b.getAttribute('aria-label') || ''))`);
  check('E2E-VIS-5', 'the class bars and the strength histogram count what the lists they open show, and the list is weakest first (PRD-013 REQ-VIS-8)',
    inv.cols.length === 7 && inv.cols.reduce((t, c) => t + c.n, 0) === inv.rows && inv.classes.length === 3 && opened.length > 1 && opened.every((o) => o.want === o.got)
      && ranks.every((x, i) => i === 0 || ranks[i - 1] <= x),
    JSON.stringify({ cols: inv.cols.map((c) => c.n), rows: inv.rows, opened, sorted: ranks.slice(0, 12) }).slice(0, 500));
  await shot('vis-inventory');

  // E2E-VIS-6: the SSH algorithm rows are the evaluation's sshAlgorithms, kind by kind in the server's
  // order, each with its bits bar, its post-quantum glyph (key exchange and host keys) and its baseline
  // mark (PRD-014 REQ-SSV-2; was PRD-013 REQ-VIS-10, which read the old tables' cells).
  if (ssh) {
    const sev = await js(`return (await fetch('/api/v1/scans/${ssh.lastDone.id}/evaluation')).json()`);
    await go(`#/ssh/${ssh.id}?tab=configuration`);
    await sleep(1600);
    const got = await js(`return [...document.querySelectorAll('.sshrow[data-kind]')].map((r) => ({ kind: r.dataset.kind, name: r.dataset.name,
      bar: r.querySelector('.bitsbar')?.getAttribute('aria-label') || '', pq: r.querySelector('svg.pqg-safe') ? 'quantum-safe' : r.querySelector('svg.pqg-vuln') ? 'quantum-vulnerable' : 'none',
      mark: r.querySelector('.bmark-off') ? 'off' : r.querySelector('.bmark-ok') ? 'allowed' : '', used: r.classList.contains('is-used') }))`);
    const want = (sev.sshAlgorithms || []).filter((a) => a.kind !== 'compression');
    const pqWant = (a) => (a.kind === 'kex' || a.kind === 'host-key' ? (a.verdict === 'post-quantum' ? 'quantum-safe' : a.verdict === 'unknown' ? 'none' : 'quantum-vulnerable') : 'none');
    const wrong = want.map((a, i) => [a, got[i] || {}]).filter(([a, g]) => g.kind !== a.kind || g.name !== a.name || g.bar !== `${a.name}: ${words(a.strength)}`
      || g.pq !== pqWant(a) || g.mark !== (a.baseline || '') || g.used !== !!a.used).map(([a, g]) => ({ want: a.name, got: g }));
    check('E2E-VIS-6', 'the SSH algorithm rows equal the evaluation’s algorithms in the server’s order, each with its bits bar, post-quantum glyph, baseline mark and in-use mark (PRD-014 REQ-SSV-2)',
      want.length > 0 && got.length === want.length && wrong.length === 0 && got.some((g) => g.mark === 'off') && got.some((g) => g.pq === 'quantum-vulnerable'),
      JSON.stringify({ want: want.length, got: got.length, wrong: wrong.slice(0, 3) }).slice(0, 500));
    await shot('vis-ssh', { maxH: 5000 });

    // E2E-VIS-8: one Configuration page in a reviewer's order, a jump row leading to each part, every
    // finding named once under its own part, the baseline as tiles and chips, and no list of sources.
    const ids = ['sec-ssh-version', 'sec-key-exchange', 'sec-host-keys', 'sec-encryption', 'sec-integrity', 'sec-baseline'];
    const cfg = await js(`const parts = [...document.querySelectorAll('.ssh-config > section.cfg')];
      const issueAt = {};
      for (const p of parts) for (const a of p.querySelectorAll('.detcard-issues a[href^="#chk-"]')) (issueAt[a.getAttribute('href').slice(5)] = issueAt[a.getAttribute('href').slice(5)] || []).push(p.id);
      const jump = [...document.querySelectorAll('.ssh-config nav.jump a')].map((a) => ({ href: a.getAttribute('href'), dot: !!a.querySelector('.jump-dot') }));
      const reqs = [...document.querySelectorAll('#sec-baseline .reqtile')].map((t) => ({ href: t.getAttribute('href'), title: t.title, target: t.target }));
      const chips = [...document.querySelectorAll('.ssh-config .chg')].map((c) => c.title.split(String.fromCharCode(10))[0]);
      const last = document.querySelector('.ssh-config > :last-child');
      const p = document.getElementById('sec-integrity');
      p.scrollIntoView({ block: 'start' });
      window.scrollTo(0, 0);
      document.querySelector('.ssh-config nav.jump a[href="#sec-integrity"]').click();
      await new Promise((r) => setTimeout(r, 400));
      const t = p.getBoundingClientRect().top;
      return { order: parts.map((x) => x.id), jump, issueAt, reqs, chips, cites: document.querySelectorAll('.ssh-config ul.cites').length,
        lastIsAbout: !!last && last.id === 'sec-details', jumped: t >= -2 && t < innerHeight / 2, sticky: getComputedStyle(document.querySelector('.ssh-config nav.jump')).position }`);
    const findings = [...new Map((sev.findings || []).filter((f) => f.section !== 'vulnerabilities').map((f) => [f.id, f])).values()];
    const misplaced = findings.filter((f) => (cfg.issueAt[f.id] || []).join() !== `sec-${f.section}`).map((f) => ({ id: f.id, at: cfg.issueAt[f.id] }));
    const b = sev.baseline || { requires: [], changes: [] };
    const reqsOk = cfg.reqs.length === (b.requires || []).length && (b.requires || []).every((r, i) => cfg.reqs[i] && cfg.reqs[i].href === r.cite.url && cfg.reqs[i].title === `Source: ${r.cite.title}` && cfg.reqs[i].target === '_blank');
    const chipsOk = cfg.chips.length === (b.changes || []).length && (b.changes || []).every((c) => cfg.chips.includes(c.text));
    check('E2E-VIS-8', 'the SSH Configuration is six parts in a reviewer’s order under a sticky jump row that leads to each; every finding is named once under its own part; each requirement is a tile linking to its source; each baseline change a chip; no list of sources; About last (PRD-014 REQ-SSV-1, 4, 5, 6)',
      cfg.order.join() === ids.join() && cfg.jump.map((j) => j.href).join() === ids.map((x) => `#${x}`).join() && cfg.jump.every((j) => j.dot) && cfg.sticky === 'sticky' && cfg.jumped
        && findings.length > 0 && misplaced.length === 0 && reqsOk && chipsOk && cfg.cites === 0 && cfg.lastIsAbout,
      JSON.stringify({ order: cfg.order, jumped: cfg.jumped, misplaced, reqs: cfg.reqs.length, chips: cfg.chips.length, changes: (b.changes || []).length, cites: cfg.cites }).slice(0, 500));

    // E2E-VIS-9: version, key exchange and host keys as instruments that agree with the report.
    const srep = await js(`return (await fetch('/api/v1/scans/${ssh.lastDone.id}/report')).json()`);
    const inst = await js(`const tile = (sec, name) => { const t = [...document.querySelectorAll(sec + ' .stile')].find((x) => x.querySelector('b')?.textContent === name); return t ? { tone: [...t.classList].find((c) => /^stile-(good|attention|problem|na)$/.test(c)), state: t.querySelector('.stile-state').textContent, detail: t.querySelector('.stile-detail')?.textContent || '' } : null; };
      return { banner: [...document.querySelectorAll('#sec-ssh-version .negotiated .nchip')].map((c) => c.textContent), protocol: tile('#sec-ssh-version', 'Protocol'), strict: tile('#sec-key-exchange', 'Strict key exchange'),
        level: document.querySelector('#sec-key-exchange .readyrow-level b')?.textContent, steps: document.querySelectorAll('#sec-key-exchange .lstep-seg.on').length,
        cards: [...document.querySelectorAll('#sec-host-keys .keycard')].map((c) => ({ missing: c.classList.contains('is-missing'), fp: c.querySelector('.keycard-fp')?.textContent || '', verified: /verified ✓/.test(c.textContent), bar: !!c.querySelector('.bitsbar') })) }`);
    const n = srep.negotiated || {};
    const keys = srep.hostKeys || [];
    const failed = (srep.hostKeyAttempts || []).filter((x) => x.outcome !== 'key').length;
    const r = sev.readiness || {};
    let ssh1View = null;
    if (ssh1) {
      await go(`#/ssh/${ssh1.id}?tab=configuration`);
      await sleep(1400);
      ssh1View = await js(`return { parts: document.querySelectorAll('.ssh-config > section.cfg').length, protocol: [...document.querySelectorAll('#sec-ssh-version .stile')].find((t) => t.querySelector('b')?.textContent === 'Protocol')?.querySelector('.stile-state').textContent,
        na: [...document.querySelectorAll('#sec-ciphers p.muted, #sec-encryption p.muted')].map((p) => p.textContent).join(' '), rows: document.querySelectorAll('.sshrow[data-kind]').length }`);
    }
    check('E2E-VIS-9', 'the SSH banner is what a current client negotiates; the protocol and strict key exchange tiles, the readiness level and stepper, and a card per host key (verified as the scan says) agree with the report; an SSH-1-only server still draws every part (PRD-014 REQ-SSV-3, 8)',
      inst.banner.slice(0, 3).join() === [n.kex, n.hostKey, n.cipher].join() && inst.banner[3] === (n.mac || 'no MAC')
        && inst.protocol && inst.protocol.detail === srep.identification.raw && inst.protocol.tone === (srep.identification.ssh1 ? 'stile-problem' : 'stile-good')
        && inst.strict && inst.strict.tone === (srep.algorithms.strictKex ? 'stile-good' : inst.strict.tone) && /^On/.test(inst.strict.state) === !!srep.algorithms.strictKex
        && inst.level === (r.level < 0 ? '?' : `L${r.level}`) && inst.steps === Math.max(0, r.level + 1)
        && inst.cards.filter((c) => !c.missing).length === keys.length && inst.cards.filter((c) => c.missing).length === failed
        && keys.every((k) => inst.cards.some((c) => c.fp === k.fingerprint && c.verified === !!k.verified && c.bar))
        && (!ssh1 || (ssh1View.parts === 6 && ssh1View.protocol === 'SSH-1 only' && /Does not apply/.test(ssh1View.na) && ssh1View.rows === 0)),
      JSON.stringify({ banner: inst.banner, n, protocol: inst.protocol, strict: inst.strict, level: inst.level, cards: inst.cards.length, keys: keys.length, ssh1View }).slice(0, 600));

    // E2E-VIS-10: the SSH Summary is four instruments; the weakest strength is the evaluation's weakest
    // rated algorithm; the baseline is line 1 of Fix first in the shared row shape, with no prose block.
    await go(`#/ssh/${ssh.id}`);
    await sleep(1400);
    const ss = await js(`return { labels: [...document.querySelectorAll('.sumstrip .sumtile')].map((t) => t.querySelector('.sumtile-label')?.textContent),
      weakest: document.querySelector('.sumtile-strength .bitsbar')?.getAttribute('aria-label') || '', stepper: !!document.querySelector('.sumstrip .lstep'),
      first: (() => { const li = document.querySelector('#fix ol.fixlist > li'); return li ? { n: li.querySelector('.fix-n')?.textContent, title: li.querySelector('.action-title')?.textContent, link: li.querySelector('.action-more')?.textContent } : null; })(),
      nums: [...document.querySelectorAll('#fix ol.fixlist > li .fix-n')].map((x) => x.textContent), prose: /Why it matters/.test(document.querySelector('.report.summary').innerText), lists: document.querySelectorAll('#fix ol').length }`);
    const rank = { broken: 0, weak: 1, acceptable: 2, strong: 3 };
    const band = (st) => (!st ? 'na' : st.status === 'broken' ? 'broken' : st.status !== 'rated' && st.status !== 'disallowed' ? 'na' : st.bits < 80 ? 'broken' : st.bits < 112 ? 'weak' : st.bits < 128 ? 'acceptable' : 'strong');
    const w = (sev.sshAlgorithms || []).filter((a) => band(a.strength) !== 'na').sort((x, y) => (rank[band(x.strength)] - rank[band(y.strength)]) || ((x.strength.bits || 0) - (y.strength.bits || 0)))[0];
    let good = null;
    if (sshGood) {
      await go(`#/ssh/${sshGood.id}`);
      await sleep(1200);
      good = await js(`return { first: document.querySelector('#fix ol.fixlist > li .action-title')?.textContent || '', tile: document.querySelectorAll('.sumstrip .sumtile')[1]?.innerText || '' }`);
    }
    check('E2E-VIS-10', 'the SSH Summary has readiness with the stepper, the baseline, the weakest classical strength (the evaluation’s weakest) and the host key; the baseline is Fix first line 1 in the shared row shape, numbered on from it, with no “Why it matters” (PRD-014 REQ-SSV-7)',
      ss.labels.join() === 'Post-quantum readiness,Baseline,Weakest classical strength,Host key' && ss.stepper && !!w && ss.weakest === `${w.name}: ${words(w.strength)}`
        && ss.first && ss.first.n === '1' && /^Meet /.test(ss.first.title) && /sshd_config/.test(ss.first.link) && ss.nums.every((x, i) => x === String(i + 1)) && ss.lists === 1 && !ss.prose
        && (!good || (/✓ Meets/.test(good.tile) && !/^Meet /.test(good.first))),
      JSON.stringify({ ss, weakest: w && w.name, good }).slice(0, 500));
    await shot('vis-ssh-summary');
  } else {
    for (const id of ['E2E-VIS-6', 'E2E-VIS-8', 'E2E-VIS-9', 'E2E-VIS-10']) check(id, 'the SSH report’s instruments', false, 'no SSH server was scanned');
  }

  // E2E-VIS-7: every rebuilt screen fits 1440, 1100, 860 and 375 px with no sideways scroll, every
  // control is reachable by Tab, and instrument text meets AA contrast in light and dark.
  const screens = [['summary', `#/endpoints/${target.id}`], ['configuration', `#/endpoints/${target.id}?tab=configuration`], ['inventory', '#/inventory/algorithms']];
  if (leaf) screens.push(['certificate', `#/certificates/${leaf.sha256}?scan=${scan}`]);
  if (ssh) screens.push(['ssh-summary', `#/ssh/${ssh.id}`], ['ssh-configuration', `#/ssh/${ssh.id}?tab=configuration`]);
  const fit = [];
  for (const [w, h, mobile] of [[1440, 900, false], [1100, 900, false], [860, 1000, false], [375, 812, true]]) {
    await viewport(w, h, false, mobile);
    for (const [name, hash] of screens) {
      await go(hash);
      await sleep(1400);
      const o = await js(`return { over: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        unreachable: [...document.querySelectorAll('#main a[href], #main button, #main summary, #main input, #main select')].filter((el) => el.tabIndex < 0 && el.offsetParent !== null).length }`);
      fit.push({ w, name, ...o });
      if (w === 375) await shot(`vis-${name}-375`, { maxH: 4000 });
    }
  }
  const contrast = [];
  for (const dark of [false, true]) {
    await viewport(1440, 900, dark);
    for (const [name, hash] of screens) {
      await go(hash);
      await sleep(1400);
      const low = await js(`${CONTRAST} return low.slice(0, 6);`);
      contrast.push({ dark, name, low });
      if (dark) await shot(`vis-${name}-dark`, { maxH: 3000 });
    }
  }
  await viewport(1440, 900, false);
  const bad = fit.filter((x) => x.over > 1 || x.unreachable > 0);
  const lowC = contrast.filter((c) => c.low.length);
  check('E2E-VIS-7', 'Summary, Configuration, the Inventory, the certificate page and the SSH Summary and Configuration fit 1440, 1100, 860 and 375 px, every control is reachable by Tab, and instrument text meets 4.5:1 contrast in light and dark (PRD-013 REQ-VIS-11, PRD-014 REQ-SSV-8)',
    bad.length === 0 && lowC.length === 0, JSON.stringify({ bad, lowContrast: lowC }).slice(0, 700));
}
