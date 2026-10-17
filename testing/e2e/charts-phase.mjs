// PRD-009 WP-1 and WP-2 (UX-DESIGN-008): charts you can act on, filters in the address, and quiet
// motion. Runs after the other phases, on their data: TLS endpoints at several levels, SSH servers,
// machines and imported CBOMs. QA-PLAN-007 §2 lists the checks.

export async function chartsPhase({ check, js, go, sleep, shot, viewport, send }) {
  await viewport(1440, 900, false);
  // A headless page has no window focus, so focus events would not fire on .focus(): emulate it.
  await send('Emulation.setFocusEmulationEnabled', { enabled: true });
  const rows = () => js(`return document.querySelectorAll('#main tbody tr').length`);

  // CHT-1: every linked readiness level on the Overview opens a list as long as its count.
  await go('#/');
  await sleep(1500);
  const levels = await js(`return [...document.querySelectorAll('.hero-scale .level')].map((li) => ({
    level: li.dataset.level, href: li.getAttribute('data-href'), count: Number(li.querySelector('.level-count')?.textContent) || 0,
    split: [...li.querySelectorAll('.level-split a')].map((a) => ({ href: a.getAttribute('href'), n: parseInt(a.textContent, 10) })) }))`);
  const targets = levels.flatMap((l) => (l.href ? [{ href: l.href, n: l.count }] : l.split));
  const got = [];
  for (const t of targets) {
    await go(t.href);
    await sleep(900);
    got.push({ ...t, rows: await rows(), chip: await js(`return document.querySelector('.fchip')?.textContent || ''`) });
  }
  check('E2E-CHT-1', 'each readiness level on the Overview opens the list of what is at that level, as long as its count, with a chip naming the level',
    targets.length >= 3 && got.every((g) => g.rows === g.n && /PQC readiness L\d/.test(g.chip)), JSON.stringify(got));

  // CHT-2: the filter is in the address; a change is written back without a new history entry; Back returns.
  await go('#/');
  await sleep(1200);
  // history.length is capped (50) by the browser, so it cannot show that no entry was added;
  // Back landing on the chart can.
  await js(`document.querySelector('.hero-scale .level.mark, .level-split a').click()`);
  await sleep(1200);
  const landed = await js(`return location.hash`);
  await js(`document.querySelector('.fchip-x').click()`);
  await sleep(700);
  const cleared = await js(`return { hash: location.hash }`);
  await js(`history.back()`);
  await sleep(1300);
  const back = await js(`return location.hash`);
  check('E2E-CHT-2', 'a chart opens a filtered address; removing the chip rewrites it in place; Back returns to the chart',
    /level=\d/.test(landed) && !/level=/.test(cleared.hash) && (back === '#/' || back === ''), JSON.stringify({ landed, cleared, back }));

  // CHT-3: every Inventory mark opens a list whose length is its figure (the ring counts algorithms and keys).
  // Earlier phases leave rescans running, and each one that finishes changes the inventory: compare
  // a still inventory, or a figure read now is measured against a list read later.
  for (let i = 0; i < 240; i++) {
    const busy = await js(`return (await (await fetch('/api/v1/assets')).json()).filter((a) => a.latest && ['queued', 'running'].includes(a.latest.status)).length`);
    if (!busy) break;
    await sleep(500);
  }
  await go('#/inventory');
  await sleep(1500);
  const marks = await js(`return [...document.querySelectorAll('#main .mark[data-href]')].map((m) => ({ href: m.getAttribute('data-href'), tip: m.getAttribute('data-tip'),
    n: Number((m.getAttribute('aria-label').match(/: (\\d+)\\. Open/) || [])[1]) || null }))`);
  const bad = [];
  for (const m of marks) {
    await go(m.href);
    await sleep(1100);
    const r = await js(`return { rows: document.querySelectorAll('#main tbody tr').length,
      keys: Number((document.querySelector('#main .hint a[href*="/keys"]')?.parentElement.textContent.match(/^(\\d+)/) || [])[1]) || 0 }`);
    const exact = /[?&]name=/.test(m.href);
    if (m.n !== null && r.rows + r.keys !== m.n) {
      const quantum = new URLSearchParams(m.href.split('?')[1] || '').get('quantum');
      r.apiKeys = quantum ? await js(`return (await (await fetch('/api/v1/inventory?kind=key&imported=1&quantum=${quantum}')).json()).rows.length`) : null;
      r.note = await js(`return [...document.querySelectorAll('#main .hint')].map((x) => x.textContent).join(' | ')`);
      bad.push({ ...m, ...r });
    }
    if (exact && r.rows !== 1) bad.push({ ...m, ...r, why: 'an exact name lists one row' });
  }
  check('E2E-CHT-3', 'every Inventory mark opens a list whose length is the figure clicked (algorithms plus keys for the ring), a named row exactly one item',
    marks.length >= 8 && bad.length === 0, JSON.stringify({ marks: marks.length, bad }).slice(0, 600));

  // CHT-4: the status band's severity chips and exposed counts open their filtered lists; no link inside a link.
  await go('#/');
  await sleep(1300);
  const band = await js(`return { nested: document.querySelectorAll('a a').length,
    links: [...document.querySelectorAll('.stat-links a')].map((a) => ({ href: a.getAttribute('href'), n: parseInt(a.textContent, 10) })) }`);
  const sevLink = band.links.find((l) => /severity=/.test(l.href));
  const expLink = band.links.find((l) => /exposed=1/.test(l.href));
  let sev = null, exp = null;
  if (sevLink) {
    await go(sevLink.href);
    await sleep(1300);
    sev = await js(`return { sel: document.querySelector('select[aria-label="Filter by severity"]').value,
      places: [...document.querySelectorAll('.fgroup-places li')].length }`);
  }
  if (expLink) {
    await go(expLink.href);
    await sleep(1100);
    exp = { rows: await rows() };
  }
  check('E2E-CHT-4', 'a severity chip opens findings of that severity, an exposed count opens the exposed endpoints, and no link is nested in another',
    band.nested === 0 && sevLink && sev && sevLink.href.endsWith(sev.sel) && sev.places === sevLink.n && expLink && exp.rows === expLink.n,
    JSON.stringify({ band, sev, exp }));

  // CHT-5: a history point opens that scan's report.
  const many = await js(`const a = (await (await fetch('/api/v1/assets?kind=endpoint')).json());
    for (const x of a) { const h = await (await fetch('/api/v1/assets/' + x.id + '/history')).json(); if (h.filter((p) => p.status === 'done').length >= 2) return { id: x.id, protocol: x.protocol, first: h.find((p) => p.status === 'done').scanId }; } return null`);
  let hist = null;
  if (many) {
    await go(`${many.protocol === 'ssh' ? '#/ssh' : '#/endpoints'}/${many.id}?tab=history`);
    await sleep(1500);
    hist = await js(`const d = document.querySelector('.dotmark.mark'); const href = d.getAttribute('data-href'); d.dispatchEvent(new MouseEvent('click', { bubbles: true })); await new Promise((r) => setTimeout(r, 1500));
      return { href, hash: location.hash, past: /Viewing a past scan/.test(document.querySelector('main').innerText) }`);
  }
  check('E2E-CHT-5', 'a point of Readiness over time opens the report of that scan',
    many && hist && hist.hash.endsWith(`?scan=${many.first}`) && hist.past, JSON.stringify({ many, hist }));

  // CHT-6: a mark is a named link reached by Tab; focus shows the tooltip and dims its siblings; Enter opens it.
  await go('#/inventory');
  await sleep(1500);
  const a11y = await js(`const m = [...document.querySelectorAll('.mark[data-href]')];
    return { all: m.length, named: m.filter((x) => x.getAttribute('role') === 'link' && x.getAttribute('tabindex') === '0' && (x.getAttribute('aria-label') || '').length > 5).length }`);
  const focus = await js(`const seg = document.querySelector('.ring-seg.mark'); seg.focus(); await new Promise((r) => setTimeout(r, 400));
    const tip = document.querySelector('.charttip'); const sib = [...document.querySelectorAll('.pq-split .ring-seg')].find((x) => x !== seg);
    const r = { focused: document.activeElement === seg, tip: tip && !tip.hidden ? tip.textContent : '', sibling: sib ? getComputedStyle(sib).opacity : '1', href: seg.getAttribute('data-href') };
    return r`);
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
  await sleep(1200);
  const after = await js(`return location.hash`);
  check('E2E-CHT-6', 'every mark is a named link in the Tab order; focus shows its tooltip and dims the other marks; Enter opens it',
    a11y.all > 0 && a11y.named === a11y.all && focus.focused && /Click to open the list/.test(focus.tip) && Number(focus.sibling) < 0.5 && after === focus.href,
    JSON.stringify({ a11y, focus, after }));
  await go('#/inventory');
  await sleep(300);
  await shot('chart-tooltip-inventory');

  // MOT-1 and MOT-2: draw-ins and counting happen on arrival only.
  // Sampled in the page from the first moment the ring exists: a navigation from outside would
  // arrive after the draw-in had finished.
  await go('#/');
  await sleep(800);
  const early = await js(`location.hash = '#/inventory';
    for (let i = 0; i < 150; i++) {
      const seg = document.querySelector('.ring-seg');
      if (seg) return { enter: document.querySelector('#main').classList.contains('enter'), anim: getComputedStyle(seg).animationName, tile: document.querySelector('.sumtile-big').textContent };
      await new Promise((r) => setTimeout(r, 10));
    }
    return null`);
  await sleep(1500);
  const settled = await js(`return { enter: document.querySelector('#main').classList.contains('enter'), tiles: [...document.querySelectorAll('.sumtile-big')].map((x) => x.textContent) }`);
  const api = await js(`const d = await (await fetch('/api/v1/inventory/dashboard')).json(); return String(d.totals.algorithm || 0)`);
  check('E2E-MOT-1', 'on arrival the ring sweeps (and the page has .enter); a moment later the page holds still',
    early && early.enter && early.anim === 'sweep' && !settled.enter, JSON.stringify({ early, settled }));
  check('E2E-MOT-2', 'figures count up to their value and end on it', settled.tiles[0] === api, JSON.stringify({ early: early.tile, settled: settled.tiles[0], api }));

  // MOT-R: reduced motion switches every animation off and figures show their value at once.
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }] });
  await go('#/inventory');
  const reduced = await js(`await new Promise((r) => setTimeout(r, 100)); return { anim: getComputedStyle(document.querySelector('.ring-seg')).animationName,
    tile: document.querySelector('.sumtile-big').textContent }`);
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'no-preference' }] });
  check('E2E-MOT-R', 'with reduced motion nothing animates and figures are shown at once', reduced.anim === 'none' && reduced.tile === api, JSON.stringify(reduced));
}
