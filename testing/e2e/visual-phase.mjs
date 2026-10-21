// PRD-013 (instruments, not paragraphs), driven through the browser on the other phases' data: the
// shared instruments carry their meaning in words; the Summary is instruments, Fix first, the checks
// bar and area tiles; the Configuration's suites, features and revocation agree with the API; the
// Inventory's charts open the lists they count; the SSH tables use the same instruments; and every
// rebuilt screen fits 1440, 1100, 860 and 375 px, in light and dark, with readable contrast.

const words = (st) => (!st ? 'not rated' : st.status === 'rated' ? `${st.bits} bits` : st.status === 'disallowed' ? `${st.bits} bits, disallowed`
  : st.status === 'broken' ? 'broken' : 'not rated');

// The contrast of every instrument's text against what is drawn behind it (WCAG 2.x relative luminance).
const CONTRAST = `
  const rgb = (c) => { const m = c.match(/[\\d.]+/g); return m ? m.slice(0, 4).map(Number) : [0, 0, 0, 0]; };
  const lum = ([r, g, b]) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
  const bgOf = (el) => { for (let e = el; e; e = e.parentElement) { const c = rgb(getComputedStyle(e).backgroundColor); if (c[3] === undefined || c[3] > 0.5) return c; } return rgb(getComputedStyle(document.body).backgroundColor); };
  const ratio = (el) => { const a = lum(rgb(getComputedStyle(el).color)), b = lum(bgOf(el)); return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05); };
  const SEL = '.bb-value, .pcell, .schip, .stile b, .stile-state, .gchip, .tchip, .cchip, .jump-chip, .vchip, .lstep-l, .hist-n, .hist-label, .fix-n, .action-title, .cfg-aside, .lane-alg, .lane-uses, .xid-v, .specval, .nmchip, .usechip';
  const low = [...document.querySelectorAll(SEL)].filter((el) => el.offsetParent !== null && el.textContent.trim())
    .map((el) => ({ el: el.className.baseVal ?? el.className, text: el.textContent.trim().slice(0, 24), r: Math.round(ratio(el) * 100) / 100 }))
    .filter((x) => x.r < 4.5);`;

export async function visualPhase({ check, js, go, sleep, shot, viewport }) {
  await viewport(1440, 900, false);
  const endpoints = await js(`return (await (await fetch('/api/v1/assets?kind=endpoint')).json()).filter((a) => a.lastDone)`);
  const tls = endpoints.filter((a) => a.protocol !== 'ssh');
  const ssh = endpoints.find((a) => a.protocol === 'ssh');
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
  if (ssh) pages.push(['ssh', `#/endpoints/${ssh.id}?tab=configuration`]);
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

  // E2E-VIS-6: the SSH report's algorithm tables use the bits bar and the post-quantum glyph.
  if (ssh) {
    const sev = await js(`return (await fetch('/api/v1/scans/${ssh.lastDone.id}/evaluation')).json()`);
    await go(`#/endpoints/${ssh.id}?tab=configuration`);
    await sleep(1600);
    const s = await js(`return { bars: [...document.querySelectorAll('#main td.invbits .bitsbar')].map((b) => b.getAttribute('aria-label')),
      pq: [...document.querySelectorAll('#main td.invpq')].map((c) => c.querySelector('svg.pqg-safe') ? 'safe' : c.querySelector('svg.pqg-vuln') ? 'vulnerable' : 'none') }`);
    const rated = (sev.sshAlgorithms || []).filter((a) => a.kind !== 'compression' && a.strength);
    const wrongBars = rated.filter((a) => !s.bars.includes(`${a.name}: ${words(a.strength)}`)).map((a) => a.name);
    const kexPq = (sev.sshAlgorithms || []).filter((a) => a.kind === 'kex' && a.verdict === 'post-quantum').length;
    check('E2E-VIS-6', 'the SSH report’s algorithm tables show each strength as the bits bar and key exchange and host keys with the post-quantum glyph (PRD-013 REQ-VIS-10)',
      rated.length > 0 && wrongBars.length === 0 && s.pq.filter((p) => p === 'safe').length >= kexPq && s.pq.includes('vulnerable'),
      JSON.stringify({ rated: rated.length, wrongBars: wrongBars.slice(0, 4), pq: s.pq.join('').length ? s.pq.slice(0, 12) : [] }));
    await shot('vis-ssh');
  } else check('E2E-VIS-6', 'the SSH report’s algorithm tables use the bits bar and the post-quantum glyph', false, 'no SSH endpoint was scanned');

  // E2E-VIS-7: every rebuilt screen fits 1440, 1100, 860 and 375 px with no sideways scroll, every
  // control is reachable by Tab, and instrument text meets AA contrast in light and dark.
  const screens = [['summary', `#/endpoints/${target.id}`], ['configuration', `#/endpoints/${target.id}?tab=configuration`], ['inventory', '#/inventory/algorithms']];
  if (leaf) screens.push(['certificate', `#/certificates/${leaf.sha256}?scan=${scan}`]);
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
  check('E2E-VIS-7', 'Summary, Configuration, the Inventory and the certificate page fit 1440, 1100, 860 and 375 px, every control is reachable by Tab, and instrument text meets 4.5:1 contrast in light and dark (PRD-013 REQ-VIS-11)',
    bad.length === 0 && lowC.length === 0, JSON.stringify({ bad, lowContrast: lowC }).slice(0, 700));
}
