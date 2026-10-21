// PRD-011 (algorithm classes and a flow that explains itself), driven through the browser on the
// other phases' data: the Algorithms in use card agrees with the evaluation API row for row, a
// suite's strength opens to its parts, the Inventory filters by class, and the Summary and the
// Overview say what UX-REVIEW-010 asked for.

const words = (st) => (!st ? 'not rated' : st.status === 'rated' ? `${st.bits} bits` : st.status === 'disallowed' ? `${st.bits} bits, disallowed`
  : st.status === 'broken' ? 'broken' : 'not rated');

export async function classesPhase({ check, js, go, sleep, shot, viewport }) {
  await viewport(1440, 900, false);
  const endpoints = await js(`return (await (await fetch('/api/v1/assets?kind=endpoint')).json()).filter((a) => a.protocol !== 'ssh' && a.lastDone)`);

  // E2E-CLS-1: the first Configuration card is Algorithms in use, and every algorithm the API lists
  // is a row under its class with the same role, strength and weakest mark.
  const bad = [];
  let rows = 0, first = 0;
  for (const a of endpoints.slice(0, 6)) {
    const ev = await js(`return (await fetch('/api/v1/scans/${a.lastDone.id}/evaluation')).json()`);
    await go(`#/endpoints/${a.id}?tab=configuration`);
    await sleep(1400);
    const page = await js(`const card = document.querySelector('#main .report.configuration > section');
      const tables = [...document.querySelectorAll('#sec-algorithms h3.algos-class')].map((h3) => ({ cls: h3.textContent, rows: [...h3.nextElementSibling.querySelectorAll('tbody tr')]
        .map((tr) => ({ name: tr.cells[0].textContent, role: tr.cells[1].textContent, strength: tr.cells[2].textContent, weakest: tr.classList.contains('weakest') })) }));
      return { firstId: card && card.id, tables }`);
    if (page.firstId === 'sec-algorithms') first++;
    for (const al of ev.algorithms || []) {
      rows++;
      const t = page.tables.find((x) => x.cls.toLowerCase().includes(al.class));
      const r = t && t.rows.find((x) => x.name === al.name && x.role.toLowerCase() === al.role.toLowerCase());
      if (!r || !r.strength.startsWith(words(al.strength)) || r.weakest !== !!al.weakest) bad.push({ endpoint: a.name, al: `${al.class}/${al.role}/${al.name}`, want: words(al.strength), got: r && r.strength });
    }
  }
  check('E2E-CLS-1', 'Configuration opens with Algorithms in use, and every algorithm the API lists is there under its class with its role, strength and weakest mark',
    rows > 20 && bad.length === 0 && first === Math.min(6, endpoints.length), JSON.stringify({ rows, first, bad: bad.slice(0, 3) }));
  await shot('classes-algorithms');

  // E2E-CLS-2: a suite's strength opens to its parts, each with its class, the weakest marked.
  const ev0 = await js(`return (await fetch('/api/v1/scans/${endpoints[0].lastDone.id}/evaluation')).json()`);
  await go(`#/endpoints/${endpoints[0].id}?tab=configuration`);
  await sleep(1400);
  const parts = await js(`for (const d of document.querySelectorAll('details.ver-row')) d.open = true;
    const cell = document.querySelector('.ver-body details.strength-cell');
    if (!cell) return null;
    cell.querySelector('summary').click();
    await new Promise((r) => setTimeout(r, 150));
    const name = cell.closest('tr').querySelector('code').textContent;
    return { name, open: cell.open, items: [...cell.querySelectorAll('.partlist li')].map((li) => ({ cls: li.querySelector('.clstag')?.textContent, text: li.textContent, weakest: li.classList.contains('weakest') })) }`);
  const want = parts && (ev0.suiteStrength || []).find((s) => s.name === parts.name);
  check('E2E-CLS-2', 'a suite’s strength opens to every part with its class, the weakest marked',
    !!parts && parts.open && want && parts.items.length === want.parts.length && parts.items.every((i) => i.cls) && parts.items.filter((i) => i.weakest).length === 1
      && parts.items.some((i) => /Hash/.test(i.cls)),
    JSON.stringify({ parts, want: want && want.parts.map((p) => `${p.class}:${p.role}:${p.name}`) }).slice(0, 400));

  // E2E-CLS-3: the Inventory's Class filter (in the address), and the CBOM tab's classical strength.
  await go('#/inventory/algorithms?class=hash');
  await sleep(1500);
  const inv = await js(`const kinds = [...document.querySelectorAll('#main tbody tr')].map((tr) => tr.cells[1].textContent);
    const sel = [...document.querySelectorAll('#main select')].find((s) => s.getAttribute('aria-label') === 'Class');
    return { n: kinds.length, all: kinds.every((k) => k.startsWith('Hash')), value: sel && sel.value, hash: location.hash }`);
  await go(`#/endpoints/${endpoints[0].id}?tab=cbom`);
  await sleep(1600);
  const cb = await js(`const head = [...document.querySelectorAll('.report.cbom thead th')].map((x) => x.textContent);
    const i = head.indexOf('Classical strength');
    return { i, bits: i < 0 ? 0 : [...document.querySelectorAll('.report.cbom tbody tr')].filter((tr) => / bits$/.test(tr.cells[i].textContent)).length }`);
  check('E2E-CLS-3', 'the Inventory filters algorithms by class from the address, and the CBOM tab shows each algorithm’s classical strength',
    inv.n > 0 && inv.all && inv.value === 'hash' && cb.i >= 0 && cb.bits > 0, JSON.stringify({ inv, cb }));

  // E2E-UXF-1: the Summary names the first thing to fix under its headline, says the weakest suite,
  // and its TLS hygiene figure opens how the score was worked out.
  const withFix = endpoints.find((a) => a.lastDone.high || a.lastDone.critical || a.lastDone.medium) || endpoints[0];
  const evF = await js(`return (await fetch('/api/v1/scans/${withFix.lastDone.id}/evaluation')).json()`);
  await go(`#/endpoints/${withFix.id}`);
  await sleep(1400);
  const sum = await js(`const first = document.querySelector('.verdict-first')?.textContent || '';
    const suites = [...document.querySelectorAll('.check-row')].find((r) => /Cipher suites/.test(r.textContent))?.querySelector('.check-verdict')?.textContent || '';
    const tile = [...document.querySelectorAll('.sumtile')].find((t) => /TLS hygiene/.test(t.textContent));
    tile && tile.click();
    await new Promise((r) => setTimeout(r, 700));
    const score = document.getElementById('score');
    return { first, suites, onWeak: document.querySelector('[role=tab][aria-selected=true]')?.textContent, score: !!score, scoreTop: score ? Math.round(score.getBoundingClientRect().top) : null }`);
  const act = (evF.findings || []).filter((f) => f.severity !== 'info');
  check('E2E-UXF-1', 'the Summary’s first line names the first thing to fix, the suites row names the weakest suite, and the hygiene figure opens how it was worked out',
    (!act.length || /^First: /.test(sum.first)) && /the weakest is/.test(sum.suites) && sum.onWeak === 'Weaknesses' && sum.score && sum.scoreTop < 450, JSON.stringify(sum));
  await shot('classes-summary');

  // E2E-UXF-2: a not-rated Inventory cell says why; no screen shows an old band name; the Overview's
  // TLS tile keeps to the count and the exposed figure.
  await go('#/inventory/algorithms');
  await sleep(1500);
  const why = await js(`const head = [...document.querySelectorAll('#main thead th')].map((x) => x.textContent);
    const i = head.indexOf('Classical strength');
    const nr = [...document.querySelectorAll('#main tbody tr')].filter((tr) => /^not rated/.test(tr.cells[i].textContent));
    return { notRated: nr.length, withWhy: nr.filter((tr) => tr.cells[i].querySelector('.cell-why')?.textContent).length }`);
  await go('#/endpoints');
  await sleep(1400);
  const bands = await js(`return [...document.querySelectorAll('.badge.band')].map((b) => b.textContent.replace(/\\s*\\d+$/, '').trim())`);
  await go('#/');
  await sleep(1400);
  const tile = await js(`return [...document.querySelectorAll('.stat-cell')].find((s) => /TLS endpoints/.test(s.textContent))?.textContent || ''`);
  const old = bands.filter((b) => ['Strong', 'Sound', 'Weak', 'Broken'].includes(b));
  check('E2E-UXF-2', 'every not-rated Inventory cell says why, no band reads Strong, Sound, Weak or Broken, and the Overview’s TLS tile has no band count',
    why.notRated > 0 && why.withWhy === why.notRated && bands.length > 0 && old.length === 0 && !/rated Strong or Sound/.test(tile), JSON.stringify({ why, bands, old, tile: tile.slice(0, 160) }));
}
