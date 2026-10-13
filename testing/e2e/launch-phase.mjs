// PRD-007 (launch 1.0), driven through the browser: the product tells its story (Overview, About),
// the Offset theme is what renders (fonts, contrast), STARTTLS endpoints, the Activity tab, and the
// inventory scripts' safer run command. Runs signed in as the administrator.

const contrastOf = `
  const lum = (c) => { const m = c.match(/\\d+(\\.\\d+)?/g).map(Number); const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; };
    return 0.2126 * f(m[0]) + 0.7152 * f(m[1]) + 0.0722 * f(m[2]); };
  const bgOf = (e) => { for (let x = e; x; x = x.parentElement) { const b = getComputedStyle(x).backgroundColor; if (!/rgba\\(0, 0, 0, 0\\)|transparent/.test(b)) return b; } return 'rgb(255,255,255)'; };
  const ratio = (e) => { const a = lum(getComputedStyle(e).color), b = lum(bgOf(e)); return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05); };`;

export async function launchPhase({ check, js, go, sleep, shot, viewport, clickText }) {
  // REQ-ST-2 / REQ-BR-2: the Overview's eyebrow and serif headline, in the bundled fonts.
  await go('#/');
  await sleep(900);
  const ov = await js(`await document.fonts.ready;
    const h1 = document.querySelector('main h1');
    return { eyebrows: document.querySelectorAll('main .eyebrow').length, eyebrow: document.querySelector('main .eyebrow')?.textContent || '',
      h1font: getComputedStyle(h1).fontFamily, body: getComputedStyle(document.body).fontFamily,
      loaded: [...document.fonts].filter((f) => f.status === 'loaded').map((f) => f.family.replace(/"/g, '')),
      external: performance.getEntriesByType('resource').filter((r) => !r.name.startsWith(location.origin)).map((r) => r.name) }`);
  check('E2E-B.2', 'the Overview has one mono eyebrow (post-quantum readiness, TLS, SSH, CBOM) and a Newsreader headline',
    ov.eyebrows === 1 && /Post-quantum readiness/i.test(ov.eyebrow) && /TLS · SSH/.test(ov.eyebrow) && /Newsreader/.test(ov.h1font), JSON.stringify(ov));
  check('E2E-B.4', 'Geist, Geist Mono and Newsreader load from this server, and nothing loads from anywhere else',
    ['Geist', 'Geist Mono', 'Newsreader'].every((f) => ov.loaded.includes(f)) && /Geist/.test(ov.body) && ov.external.length === 0, JSON.stringify(ov));

  // REQ-BR-5: rendered text contrast, light and dark.
  for (const dark of [false, true]) {
    await viewport(1280, 900, dark);
    for (const at of ['#/', '#/about', '#/help', '#/settings']) {
      await go(at);
      await sleep(800);
      const worst = await js(`${contrastOf}
        const els = [...document.querySelectorAll('main h1, main h2, main p, main li, main td, main .hint, main .muted, main a, #nav a, .sidefoot-label, .eyebrow')]
          .filter((e) => e.offsetParent && e.textContent.trim() && getComputedStyle(e).visibility !== 'hidden');
        const r = els.map((e) => ({ t: e.textContent.trim().slice(0, 30), c: ratio(e), cls: e.className }));
        r.sort((a, b) => a.c - b.c);
        return r.slice(0, 3);`);
      check(`NFR-a11y.contrast${dark ? '-dark' : ''}${at === '#/' ? '' : `-${at.slice(2)}`}`, `rendered text meets 4.5:1 on ${at} in ${dark ? 'dark' : 'light'} mode`,
        worst.length && worst[0].c >= 4.5, JSON.stringify(worst));
    }
  }
  await viewport(1280, 900);

  // UX-REVIEW-008 S4: About says what the product is; Help how to use it; Settings who may use it.
  await go('#/about');
  await sleep(800);
  const ab = await js(`const m = document.querySelector('main'); return { text: m.innerText, height: document.documentElement.scrollHeight,
    scripts: m.querySelectorAll('.dlbox').length, levels: m.querySelectorAll('.readylist').length,
    offset: [...m.querySelectorAll('a')].map((a) => a.href).filter((h) => /offsetsecurity\\.net/.test(h)) }`);
  check('E2E-B.3', 'About is short and about the product: version, standards, the Offset credit, licences and reference data; no how-to (scripts, levels) on it',
    /Version/.test(ab.text) && /NIST IR 8547/.test(ab.text) && /Developed by/.test(ab.text) && /Open-source components/.test(ab.text)
    && ab.scripts === 0 && ab.levels === 0 && ab.offset.some((h) => /post-quantum-cryptography-readiness/.test(h)) && !/grade/i.test(ab.text), JSON.stringify({ ...ab, text: ab.text.slice(0, 160) }));
  await shot('about');
  const sideNav = await js(`return [...document.querySelectorAll('.sidefoot a.sidefoot-action')].map((a) => a.textContent.trim())`);
  check('E2E-S.0', 'the sidebar foot offers Settings, Help and About', sideNav.join('|') === 'Settings|Help|About', sideNav.join('|'));
  await go('#/help');
  await sleep(900);
  const hp = await js(`return { toc: [...document.querySelectorAll('.help-toc a')].map((a) => a.textContent), scripts: document.querySelectorAll('.help-body .dlbox .scriptrow').length,
    levels: document.querySelectorAll('.help-body .readylist-row').length }`);
  check('E2E-S.1', 'Help has a contents list, the inventory scripts and the readiness levels',
    hp.toc.length >= 7 && hp.toc[0] === 'Protocols, and how each is judged' && hp.scripts === 2 && hp.levels >= 5, JSON.stringify(hp));
  await shot('help-page');
  await go('#/settings');
  await sleep(900);
  const sett = await js(`const m = document.querySelector('main'); return { text: m.innerText, rows: m.querySelectorAll('table tbody tr').length }`);
  check('E2E-S.2', 'Settings shows sign-in (on, set by --sign-in on on this server) and the server\'s configuration with the option for each',
    /Sign-in/.test(sett.text) && /\bOn\b/.test(sett.text) && /--sign-in on/.test(sett.text) && sett.rows >= 7 && /--scan-allow/.test(sett.text), sett.text.slice(0, 300));
  await shot('settings');
  // UX-REVIEW-008 O1: the Overview's scale counts this fleet's endpoints by level.
  await go('#/');
  await sleep(1400);
  const lv = await js(`const n = [...document.querySelectorAll('.hero-scale .level-count')].map((e) => Number(e.textContent || 0));
    const assets = await (await fetch('/api/v1/assets?kind=tls-endpoint')).json();
    return { counts: n, sum: n.reduce((a, b) => a + b, 0), scanned: assets.filter((a) => a.lastDone && a.lastDone.readinessLevel >= 0).length,
      head: document.getElementById('scale-h')?.textContent }`);
  check('E2E-O.1', 'the readiness scale on the Overview counts your endpoints at each level',
    lv.counts.length === 5 && lv.sum === lv.scanned && lv.scanned > 0 && /Your endpoints/.test(lv.head), JSON.stringify(lv));

  // REQ-TR-7, REQ-TR-8: the run command uses RemoteSigned first; the dialog says how to check a script.
  await go('#/inventory');
  await sleep(700);
  await clickText('Add data');
  await sleep(300);
  await clickText('Show me how', "document.querySelector('.modal')");
  await sleep(500);
  const how = await js(`return document.querySelector('.modal')?.textContent || ''`);
  check('E2E-14.5', 'the Windows command unblocks the file and runs it under RemoteSigned, Bypass only as a fallback; the dialog explains how to check a script',
    /Unblock-File/.test(how) && /RemoteSigned/.test(how) && how.indexOf('RemoteSigned') < how.indexOf('Bypass') && /Check the script before you run it/.test(how)
    && /cipherhorizon scripts list/.test(how), how.slice(0, 200));
  await clickText('Close', "document.querySelector('.modal')");
  await sleep(300);

  // REQ-SX-3: an SMTP endpoint added with its STARTTLS choice, scanned, and labelled.
  await go('#/endpoints');
  await sleep(700);
  await clickText('Add TLS endpoints');
  await sleep(300);
  await js(`document.getElementById('add-scan').checked = false; document.getElementById('add-scan').dispatchEvent(new Event('change')); document.getElementById('add-target').value = '127.0.0.1:9451'; document.getElementById('add-protocol').value = 'smtp';
    document.getElementById('add-name').value = 'mail-starttls'; document.querySelector('.modal form').requestSubmit();`);
  await sleep(1200);
  const assets = await js(`return (await fetch('/api/v1/assets')).json()`);
  const smtp = assets.find((a) => a.port === 9451);
  await js(`await fetch('/api/v1/assets/${smtp?.id}/scan', { method: 'POST', headers: { 'X-Requested-With': 'cipherhorizon' } })`);
  let done = null;
  for (let i = 0; i < 120 && !done; i++) {
    await sleep(500);
    const a = await js(`return (await fetch('/api/v1/assets/${smtp?.id}')).json()`);
    if (a.lastDone) done = a;
  }
  await go(`#/endpoints/${smtp?.id}`);
  await sleep(1200);
  const rep = await js(`return { head: document.querySelector('.report-head')?.innerText || '', text: document.querySelector('main').innerText }`);
  check('E2E-X.1', 'an SMTP endpoint added with STARTTLS is scanned through it: the report says "via STARTTLS (SMTP)", readiness L3, HTTP does not apply',
    smtp?.starttls === 'smtp' && done?.lastDone?.readinessLevel === 3 && /via STARTTLS \(SMTP\)/.test(rep.head) && /do not apply/.test(rep.text),
    JSON.stringify({ starttls: smtp?.starttls, level: done?.lastDone?.readinessLevel, head: rep.head.slice(0, 120) }));
  await shot('report-starttls');

  // REQ-AC-3, REQ-AC-4: the Activity tab lists sign-ins and changes, filters by person, exports CSV;
  // a scan names who started it.
  await go('#/users?tab=activity');
  await sleep(1200);
  const act = await js(`const rows = [...document.querySelectorAll('main table.activity tbody tr')].map((r) => r.innerText.replace(/\\s+/g, ' '));
    const csv = await fetch('/api/v1/audit.csv'); const body = await csv.text();
    return { rows: rows.length, sample: rows.slice(0, 6), signin: rows.some((r) => /Signed in/.test(r)), change: rows.some((r) => /Endpoint added/.test(r)),
      csvType: csv.headers.get('content-type'), csvRows: body.trim().split('\\n').length, filters: !!document.getElementById('act-person') && !!document.getElementById('act-source') }`);
  check('E2E-A.11', 'Users → Activity lists sign-ins and changes together, with filters and a CSV export',
    act.rows > 3 && act.signin && act.change && /text\/csv/.test(act.csvType) && act.csvRows > 3 && act.filters, JSON.stringify(act));
  await js(`const s = document.getElementById('act-source'); s.value = 'change'; s.dispatchEvent(new Event('change'));`);
  await sleep(900);
  const only = await js(`return [...document.querySelectorAll('main table.activity tbody tr')].map((r) => r.innerText)`);
  check('E2E-A.12', 'filtering Activity to changes leaves no sign-in rows', only.length > 0 && !only.some((r) => /Signed in|Signed out/.test(r)), only.slice(0, 3).join(' | '));
  await shot('users-activity');
  await go('#/scans');
  await sleep(900);
  const by = await js(`return [...document.querySelectorAll('main tbody tr')].map((r) => r.children[4]?.innerText || '')`);
  check('E2E-A.13', 'the scans list says who started each scan', by.length > 0 && by.every((w) => w && w !== 'Not recorded'), JSON.stringify(by.slice(0, 6)));
}
