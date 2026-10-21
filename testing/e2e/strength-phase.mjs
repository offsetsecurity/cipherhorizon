// PRD-010 (classical strength), driven through the browser on the other phases' data: the TLS
// report shows each suite's strength exactly as the evaluation API states it, groups show their
// bits, and the Inventory shows a classical strength for every algorithm, broken ones included.

export async function strengthPhase({ check, js, go, sleep, shot, viewport }) {
  await viewport(1440, 900, false);

  // E2E-STR-1: on every scanned TLS endpoint, every suite row's Strength cell is the evaluation's word.
  const endpoints = await js(`return (await (await fetch('/api/v1/assets?kind=endpoint')).json()).filter((a) => a.protocol !== 'ssh' && a.lastDone)`);
  const bad = [];
  let suites = 0, groups = 0;
  for (const a of endpoints.slice(0, 6)) {
    const ev = await js(`return (await fetch('/api/v1/scans/${a.lastDone.id}/evaluation')).json()`);
    await go(`#/endpoints/${a.id}?tab=configuration`);
    await sleep(1400);
    const page = await js(`await new Promise((r) => setTimeout(r, 200));
      for (const d of document.querySelectorAll('details.ver-row')) d.open = true;
      return { rows: [...document.querySelectorAll('.ver-body tbody tr')].map((tr) => ({ name: tr.querySelector('code')?.textContent, cell: tr.querySelector('.strength-cell')?.textContent || tr.textContent })),
        groups: [...document.querySelectorAll('table')].filter((t) => /Classical strength/.test(t.querySelector('thead')?.textContent || '')).flatMap((t) => [...t.querySelectorAll('tbody tr')].map((tr) => tr.textContent)) }`);
    for (const s of ev.suiteStrength || []) {
      const row = page.rows.find((r) => r.name === s.name);
      suites++;
      const word = s.word[0].toUpperCase() + s.word.slice(1);
      if (!row || !row.cell.includes(word) || (s.bits && !row.cell.includes(`${s.bits} bits`))) bad.push({ endpoint: a.name, suite: s.name, want: `${word} ${s.bits}`, got: row && row.cell });
    }
    groups += page.groups.filter((g) => /\d+ bits|broken|not rated/.test(g)).length;
  }
  check('E2E-STR-1', 'every suite on every TLS report shows the strength the evaluation API states (word and bits), and groups show their bits',
    suites > 10 && bad.length === 0 && groups > 0, JSON.stringify({ suites, groups, bad: bad.slice(0, 3) }));
  await shot('strength-report');

  // E2E-STR-3: the legend's link opens Help at the Classical strength topic, not at its top.
  const link = await js(`const a = [...document.querySelectorAll('#main a')].find((x) => /How strength is worked out/.test(x.textContent)); if (!a) return null; a.click(); return a.getAttribute('href')`);
  await sleep(1500);
  const helpAt = await js(`const s = document.getElementById('help-strength'); return s ? Math.round(s.getBoundingClientRect().top) : null`);
  check('E2E-STR-3', 'the strength legend opens Help at the Classical strength topic',
    link === '#/help?topic=strength' && helpAt !== null && helpAt >= -5 && helpAt < 200, JSON.stringify({ link, helpAt }));

  // E2E-STR-2: the Inventory's Classical strength column; broken algorithms say so.
  await go('#/inventory/algorithms');
  await sleep(1500);
  const inv = await js(`const head = [...document.querySelectorAll('#main thead th')].map((x) => x.textContent);
    const i = head.indexOf('Classical strength');
    return { i, rows: [...document.querySelectorAll('#main tbody tr')].map((tr) => ({ name: tr.cells[0].textContent, strength: i >= 0 ? tr.cells[i].textContent : '' })) }`);
  const by = Object.fromEntries(inv.rows.map((r) => [r.name, r.strength]));
  const empty = inv.rows.filter((r) => !r.strength || r.strength === '·');
  check('E2E-STR-2', 'the Inventory lists a classical strength for every algorithm: 3DES 112 disallowed, RC4 broken, AES-256-GCM 256',
    inv.i >= 0 && empty.length === 0 && /112 bits/.test(by['3DES'] || '') && /disallowed/.test(by['3DES'] || '') && /broken/.test(by.RC4 || '') && /256 bits/.test(by['AES-256-GCM'] || ''),
    JSON.stringify({ column: inv.i, empty: empty.map((r) => r.name), '3DES': by['3DES'], RC4: by.RC4, AES256: by['AES-256-GCM'] }));
  await shot('strength-inventory');
}
